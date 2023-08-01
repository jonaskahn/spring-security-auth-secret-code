package one.ifelse.springsecurity.apikey.authentication;


import one.ifelse.springsecurity.apikey.core.userdetails.ApiKeyUserDetailsService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;

public class ExternalApiKeyAuthenticationProvider implements AuthenticationProvider,
        InitializingBean, MessageSourceAware {

    private final ApiKeyUserDetailsService apiKeyUserDetailsService;
    private final UserDetailsChecker postAuthenticationChecks = new AccountStatusUserDetailsChecker();
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    public ExternalApiKeyAuthenticationProvider(
            ApiKeyUserDetailsService apiKeyUserDetailsService
    ) {
        this.apiKeyUserDetailsService = apiKeyUserDetailsService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(final Authentication authentication)
            throws AuthenticationException {
        final ApiKeyAuthenticationToken apiKeyAuthenticationToken = (ApiKeyAuthenticationToken) authentication;
        final String apiKey = (String) apiKeyAuthenticationToken.getPrincipal();
        UserDetails user = apiKeyUserDetailsService.loadUserByApiKey(apiKey);
        postAuthenticationChecks.check(user);
        return new ApiKeyAuthenticationToken(user);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.messages, "A message source must be set");
        Assert.notNull(this.apiKeyUserDetailsService, "A apiKeyUserDetailsService must be set.");
        Assert.notNull(this.postAuthenticationChecks, "A postAuthenticationChecks must be set.");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

}
