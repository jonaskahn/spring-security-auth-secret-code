package one.ifelse.tools.springauthsecretcode;

public interface SecretCodeGenerator {

	String generate();

	boolean matches(String code);
}
