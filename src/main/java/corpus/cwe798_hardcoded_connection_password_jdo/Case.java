// RULE: cwe798-hardcoded-connection-password-jdo  CWE: CWE-798  LANE: literal
package corpus.cwe798_hardcoded_connection_password_jdo;
import javax.jdo.PersistenceManagerFactory;
public class Case {
    // POSITIVE: a non-empty hard-coded password to PersistenceManagerFactory.setConnectionPassword.
    void vulnerable(PersistenceManagerFactory pmf) {
        pmf.setConnectionPassword("secret"); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    void safe(PersistenceManagerFactory pmf) {
        pmf.setConnectionPassword(""); // EXPECT-NOFLAG
    }
}
