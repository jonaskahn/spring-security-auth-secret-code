package one.ifelse.tools.springauthsecretcode;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import one.ifelse.tools.springauthsecretcode.authentication.SecretCodeAuthenticationToken;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

public class SecretCodeLoginAuthenticationFilter
		extends AbstractAuthenticationProcessingFilter {

	public static final String SPRING_SECURITY_FORM_SECRET_CODE = "X-CODE";

	private String secretCodeParam = SPRING_SECURITY_FORM_SECRET_CODE;

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

		final String secretCode = request.getParameter(secretCodeParam);

		final SecretCodeAuthenticationToken authRequest = new SecretCodeAuthenticationToken(secretCode);
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
		return this.getAuthenticationManager().authenticate(authRequest);
	}

	public void setSecretCode(String secretCodeParam) {
		Assert.hasText(secretCodeParam, "X-CODE parameter must not be empty or null");
		this.secretCodeParam = secretCodeParam;
	}

}
