package one.ifelse.springsecurity.apikey;


import one.ifelse.springsecurity.apikey.authentication.ExternalApiKeyAuthenticationProvider;
import one.ifelse.springsecurity.apikey.core.userdetails.ApiKeyUserDetailsService;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class ExternalApiKeyLoginConfigurer<H extends HttpSecurityBuilder<H>>
        extends
        AbstractAuthenticationFilterConfigurer<H, ExternalApiKeyLoginConfigurer<H>,
                ExternalUserLoginAuthenticationFilter> {

    private final ApiKeyUserDetailsService apiKeyUserDetailsService;

    public ExternalApiKeyLoginConfigurer(ApiKeyUserDetailsService apiKeyUserDetailsService) {
        super(new ExternalUserLoginAuthenticationFilter(), "/login/key");
        this.apiKeyUserDetailsService = apiKeyUserDetailsService;
        apiKeyParameter("X-KEY");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void configure(H http) throws Exception {
        http.addFilterAfter(getAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class);

        super.configure(http);
    }

    @Override
    public ExternalApiKeyLoginConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(H http) throws Exception {
        super.init(http);

        ExternalApiKeyAuthenticationProvider authenticationProvider = new ExternalApiKeyAuthenticationProvider(
                apiKeyUserDetailsService);
        postProcess(authenticationProvider);
        http.authenticationProvider(authenticationProvider);

        initDefaultLoginFilter(http);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(
            String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, "POST");
    }

    private void initDefaultLoginFilter(H http) {
        DefaultLoginPageGeneratingFilter loginPageGeneratingFilter = http
                .getSharedObject(DefaultLoginPageGeneratingFilter.class);
        if (loginPageGeneratingFilter != null && !isCustomLoginPage()) {
            String loginPageUrl = loginPageGeneratingFilter.getLoginPageUrl();
            if (loginPageUrl == null) {
                loginPageGeneratingFilter.setLoginPageUrl(getLoginPage());
                loginPageGeneratingFilter.setFailureUrl(getFailureUrl());
            }
        }
    }

    public ExternalApiKeyLoginConfigurer<H> apiKeyParameter(String apiKey) {
        getAuthenticationFilter().setApiKey(apiKey);
        return this;
    }
}
