// RULE: cwe798-passwordauthentication-hardcoded-password  CWE: CWE-798  LANE: literal
package corpus.cwe798_passwordauthentication_hardcoded_password;
import java.net.PasswordAuthentication;
public class Case {
    // POSITIVE: a non-empty hard-coded password char[] as arg1 of new PasswordAuthentication.
    PasswordAuthentication vulnerable() {
        return new PasswordAuthentication("user", "secret".toCharArray()); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    PasswordAuthentication safe() {
        return new PasswordAuthentication("user", "".toCharArray()); // EXPECT-NOFLAG
    }
}
