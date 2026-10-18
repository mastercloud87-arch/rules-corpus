// RULE: cwe327-jjwt-none-alg  CWE: CWE-327  LANE: pattern
package corpus.cwe327_jjwt_none_alg;
import io.jsonwebtoken.Jwts;
import java.security.Key;
public class Case {
    // POSITIVE: JWT built without signWith(...) in the enclosing method -> unsigned token
    String vulnerable() {
        return Jwts.builder().setSubject("x").compact(); // EXPECT-FLAG
    }
    // NEGATIVE: token is signed via signWith(...) -> must not flag
    String safe(Key key) {
        return Jwts.builder().setSubject("x").signWith(key).compact(); // EXPECT-NOFLAG
    }
}
