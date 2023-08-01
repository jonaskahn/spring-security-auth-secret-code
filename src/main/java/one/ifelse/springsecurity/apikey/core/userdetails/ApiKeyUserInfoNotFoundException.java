package one.ifelse.springsecurity.apikey.core.userdetails;

import org.springframework.security.core.AuthenticationException;

public class ApiKeyUserInfoNotFoundException extends AuthenticationException {

    private static final long serialVersionUID = 2017062701L;

    public ApiKeyUserInfoNotFoundException() {
        super("X-KEY was not existed or removed.");
    }

    public ApiKeyUserInfoNotFoundException(String msg) {
        super(msg);
    }

    public ApiKeyUserInfoNotFoundException(String msg, Throwable t) {
        super(msg, t);
    }

}
