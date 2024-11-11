package one.ifelse.tools.springauthsecretcode;

public interface SecretCodeGenerator {

	String generate();

	default boolean valid(String code) {
		return true;
	}
}
