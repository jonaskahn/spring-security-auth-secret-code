package one.ifelse.springsecurity.apikey.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 2021112801L;

    private final Object principal;

    private Object credentials;

    public ApiKeyAuthenticationToken(String apiKey) {
        super(null);
        this.principal = apiKey;
        this.credentials = apiKey;
        setAuthenticated(false);
    }

    public ApiKeyAuthenticationToken(UserDetails userDetails) {
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
