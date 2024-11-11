package one.ifelse.tools.springauthsecretcode;


import one.ifelse.tools.springauthsecretcode.authentication.SecretCodeAuthenticationProvider;
import one.ifelse.tools.springauthsecretcode.core.userdetails.SecretCodeUserDetailsService;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class SecretCodeLoginConfigurer<H extends HttpSecurityBuilder<H>>
        extends
        AbstractAuthenticationFilterConfigurer<H, SecretCodeLoginConfigurer<H>,
                SecretCodeLoginAuthenticationFilter> {

    private final SecretCodeUserDetailsService secretCodeUserDetailsService;

    public SecretCodeLoginConfigurer(SecretCodeUserDetailsService secretCodeUserDetailsService) {
        super(new SecretCodeLoginAuthenticationFilter(), "/login/key");
        this.secretCodeUserDetailsService = secretCodeUserDetailsService;
        secretCodeParameter("X-KEY");
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
    public SecretCodeLoginConfigurer<H> loginPage(String loginPage) {
        return super.loginPage(loginPage);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(H http) throws Exception {
        super.init(http);

        SecretCodeAuthenticationProvider authenticationProvider = new SecretCodeAuthenticationProvider(
                secretCodeUserDetailsService);
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

    public SecretCodeLoginConfigurer<H> secretCodeParameter(String secretCode) {
        getAuthenticationFilter().setSecretCode(secretCode);
        return this;
    }
}
