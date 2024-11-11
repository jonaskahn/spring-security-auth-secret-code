package one.ifelse.tools.springauthsecretcode;

import one.ifelse.tools.springauthsecretcode.authentication.SecretCodeAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SecretCodeLoginAuthenticationFilter
        extends AbstractAuthenticationProcessingFilter {

    public static final String SPRING_SECURITY_FORM_API_KEY = "X-KEY";

    private String apiKeyParameter = SPRING_SECURITY_FORM_API_KEY;

    public SecretCodeLoginAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login/key", "POST"));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        final String apiKey = request.getParameter(apiKeyParameter);

        final SecretCodeAuthenticationToken authRequest = new SecretCodeAuthenticationToken(apiKey);
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    public void setApiKey(String apiKeyParameter) {
        Assert.hasText(apiKeyParameter, "X-KEY parameter must not be empty or null");
        this.apiKeyParameter = apiKeyParameter;
    }

}
