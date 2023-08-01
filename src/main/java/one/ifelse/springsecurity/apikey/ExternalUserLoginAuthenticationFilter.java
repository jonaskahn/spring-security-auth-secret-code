package one.ifelse.springsecurity.apikey;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import one.ifelse.springsecurity.apikey.authentication.ApiKeyAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

public class ExternalUserLoginAuthenticationFilter
        extends AbstractAuthenticationProcessingFilter {

    public static final String SPRING_SECURITY_FORM_API_KEY = "X-KEY";

    private String apiKeyParameter = SPRING_SECURITY_FORM_API_KEY;

    public ExternalUserLoginAuthenticationFilter() {
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

        final ApiKeyAuthenticationToken authRequest = new ApiKeyAuthenticationToken(apiKey);
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    public void setApiKey(String apiKeyParameter) {
        Assert.hasText(apiKeyParameter, "X-KEY parameter must not be empty or null");
        this.apiKeyParameter = apiKeyParameter;
    }

}
