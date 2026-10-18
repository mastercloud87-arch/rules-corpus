// RULE: cwe798-jedis-jedisfactory-hardcoded-password  CWE: CWE-798  LANE: literal
package corpus.cwe798_jedis_jedisfactory_hardcoded_password;
import redis.clients.jedis.JedisFactory;
public class Case {
    // POSITIVE: a non-empty hard-coded password on a JedisFactory receiver.
    void vulnerable(JedisFactory factory) {
        factory.setPassword("secret"); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    void safe(JedisFactory factory) {
        factory.setPassword(""); // EXPECT-NOFLAG
    }
}
