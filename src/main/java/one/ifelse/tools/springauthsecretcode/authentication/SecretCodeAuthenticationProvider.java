package one.ifelse.tools.springauthsecretcode.authentication;


import one.ifelse.tools.springauthsecretcode.SecretCodeGenerator;
import one.ifelse.tools.springauthsecretcode.core.userdetails.SecretCodeInvalidException;
import one.ifelse.tools.springauthsecretcode.core.userdetails.SecretCodeUserDetailsService;

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

public class SecretCodeAuthenticationProvider implements AuthenticationProvider,
		InitializingBean, MessageSourceAware {

	private final SecretCodeUserDetailsService secretCodeUserDetailsService;

	private final SecretCodeGenerator secretCodeGenerator;

	private final UserDetailsChecker postAuthenticationChecks = new AccountStatusUserDetailsChecker();

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	public SecretCodeAuthenticationProvider(
			SecretCodeUserDetailsService secretCodeUserDetailsService, SecretCodeGenerator secretCodeGenerator
	) {
		this.secretCodeUserDetailsService = secretCodeUserDetailsService;
		this.secretCodeGenerator = secretCodeGenerator;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Authentication authenticate(final Authentication authentication)
			throws AuthenticationException {
		final SecretCodeAuthenticationToken secretCodeAuthenticationToken = (SecretCodeAuthenticationToken) authentication;
		final String secretCode = (String) secretCodeAuthenticationToken.getPrincipal();
		if (!secretCodeGenerator.valid(secretCode)) {
			throw new SecretCodeInvalidException();
		}
		UserDetails user = secretCodeUserDetailsService.loadUserBySecretCode(secretCode);
		postAuthenticationChecks.check(user);
		return new SecretCodeAuthenticationToken(user);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return SecretCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.messages, "A message source must be set");
		Assert.notNull(this.secretCodeUserDetailsService, "A secretCodeUserDetailsService must be set.");
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
