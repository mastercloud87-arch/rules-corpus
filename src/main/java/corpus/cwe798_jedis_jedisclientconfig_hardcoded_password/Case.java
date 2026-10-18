// RULE: cwe798-jedis-jedisclientconfig-hardcoded-password  CWE: CWE-798  LANE: literal
package corpus.cwe798_jedis_jedisclientconfig_hardcoded_password;
import redis.clients.jedis.DefaultJedisClientConfig;
public class Case {
    // POSITIVE: a non-empty hard-coded password on a DefaultJedisClientConfig builder.
    void vulnerable() {
        DefaultJedisClientConfig.builder().password("secret").build(); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    void safe() {
        DefaultJedisClientConfig.builder().password("").build(); // EXPECT-NOFLAG
    }
}
