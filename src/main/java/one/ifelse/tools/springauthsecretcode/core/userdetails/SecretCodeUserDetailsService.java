package one.ifelse.tools.springauthsecretcode.core.userdetails;

import org.springframework.security.core.userdetails.UserDetails;

public interface SecretCodeUserDetailsService {

    UserDetails loadUserByApiKey(String apiKey) throws SecretCodeUserInfoNotFoundException;
}
