package one.ifelse.tools.springauthsecretcode.core.userdetails;

import org.springframework.security.core.AuthenticationException;

import java.io.Serial;

public class SecretCodeUserInfoNotFoundException extends AuthenticationException {

    @Serial
    private static final long serialVersionUID = 2017062701L;

    public SecretCodeUserInfoNotFoundException() {
        super("X-KEY was not existed or removed.");
    }

    public SecretCodeUserInfoNotFoundException(String msg) {
        super(msg);
    }

    public SecretCodeUserInfoNotFoundException(String msg, Throwable t) {
        super(msg, t);
    }

}
