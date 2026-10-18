// RULE: cwe798-jedis-auth-hardcoded-secret  CWE: CWE-798  LANE: literal
package corpus.cwe798_jedis_auth_hardcoded_secret;
import redis.clients.jedis.Jedis;
public class Case {
    // POSITIVE: a non-empty hard-coded password to Jedis.auth.
    void vulnerable(Jedis jedis) {
        jedis.auth("hardcodedpassword"); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    void safe(Jedis jedis) {
        jedis.auth(""); // EXPECT-NOFLAG
    }
}
