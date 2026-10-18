// RULE: cwe798-hardcoded-secret-in-credentials  CWE: CWE-798  LANE: literal
package corpus.cwe798_hardcoded_secret_in_credentials;
import okhttp3.Credentials;
public class Case {
    // POSITIVE: a non-empty hard-coded password as arg1 of okhttp3 Credentials.basic.
    String vulnerable() {
        return Credentials.basic("user", "secret"); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    String safe() {
        return Credentials.basic("user", ""); // EXPECT-NOFLAG
    }
}
