package one.ifelse.tools.springauthsecretcode.authentication;

import java.io.Serial;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

public class SecretCodeAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 2021112801L;

	private final Object principal;

	private Object credentials;

	public SecretCodeAuthenticationToken(String code) {
		super(null);
		this.principal = code;
		this.credentials = code;
		setAuthenticated(false);
	}

	public SecretCodeAuthenticationToken(UserDetails userDetails) {
		super(userDetails.getAuthorities());
		this.principal = userDetails;
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated,
				"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}

}
