// RULE: cwe798-jsch-hardcoded-secret  CWE: CWE-798  LANE: literal
package corpus.cwe798_jsch_hardcoded_secret;
import com.jcraft.jsch.Session;
public class Case {
    // POSITIVE: a non-empty hard-coded SSH password to JSch Session.setPassword.
    void vulnerable(Session session) {
        session.setPassword("hunter2"); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    void safe(Session session) {
        session.setPassword(""); // EXPECT-NOFLAG
    }
}
