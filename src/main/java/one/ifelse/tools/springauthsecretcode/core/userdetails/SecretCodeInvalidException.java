package one.ifelse.tools.springauthsecretcode.core.userdetails;

import java.io.Serial;

import org.springframework.security.core.AuthenticationException;

public class SecretCodeInvalidException extends AuthenticationException {

	@Serial
	private static final long serialVersionUID = 2017062701L;

	public SecretCodeInvalidException() {
		super("X-KEY was not existed or removed.");
	}

	public SecretCodeInvalidException(String msg) {
		super(msg);
	}

	public SecretCodeInvalidException(String msg, Throwable t) {
		super(msg, t);
	}

}
