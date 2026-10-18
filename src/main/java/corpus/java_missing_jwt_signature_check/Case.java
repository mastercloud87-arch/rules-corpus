// RULE: java/missing-jwt-signature-check  CWE: CWE-347  LANE: taint
package corpus.java_missing_jwt_signature_check;
import io.jsonwebtoken.Jwts;
public class Case {
    // POSITIVE: a signing key is set, but parse() does not verify the signature
    void vulnerable(String key, String token) {
        Jwts.parser().setSigningKey(key).parse(token); // EXPECT-FLAG
    }
    // NEGATIVE: parseClaimsJws verifies the signature
    void safe(String key, String token) {
        Jwts.parser().setSigningKey(key).parseClaimsJws(token); // EXPECT-NOFLAG
    }
}
