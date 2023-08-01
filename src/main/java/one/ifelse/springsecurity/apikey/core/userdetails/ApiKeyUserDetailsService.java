package one.ifelse.springsecurity.apikey.core.userdetails;

import org.springframework.security.core.userdetails.UserDetails;

public interface ApiKeyUserDetailsService {

    UserDetails loadUserByApiKey(String apiKey) throws ApiKeyUserInfoNotFoundException;
}
