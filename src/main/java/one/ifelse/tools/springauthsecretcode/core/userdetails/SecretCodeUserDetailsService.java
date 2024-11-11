package one.ifelse.tools.springauthsecretcode.core.userdetails;

import org.springframework.security.core.userdetails.UserDetails;

public interface SecretCodeUserDetailsService {

	UserDetails loadUserBySecretCode(String secretCode) throws SecretCodeInvalidException;
}
