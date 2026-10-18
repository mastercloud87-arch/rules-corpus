// RULE: cwe798-jedis-hardcoded-uri  CWE: CWE-798  LANE: literal
package corpus.cwe798_jedis_hardcoded_uri;
import redis.clients.jedis.Jedis;
public class Case {
    // POSITIVE: a hard-coded redis URI literal carrying user:password@ credentials.
    Jedis vulnerable() {
        return new Jedis("redis://user:s3cr3t@localhost:6379"); // EXPECT-FLAG
    }
    // NEGATIVE: a redis URI with no userinfo (no embedded credentials) -> must not flag.
    Jedis safe() {
        return new Jedis("redis://localhost:6379"); // EXPECT-NOFLAG
    }
}
