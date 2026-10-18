// RULE: cwe798-base64-encoded-hardcoded-secret  CWE: CWE-798  LANE: pattern
package corpus.cwe798_base64_encoded_hardcoded_secret;
import java.net.HttpURLConnection;
import java.util.Base64;
public class Case {
    // POSITIVE: an Authorization header value built from a constant Base64 encoding of a literal.
    void vulnerable(HttpURLConnection conn) {
        conn.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes())); // EXPECT-FLAG
    }
    // NEGATIVE: the value is a runtime-computed token (no constant Base64 encode) -> must not flag.
    void safe(HttpURLConnection conn, String token) {
        conn.setRequestProperty("Authorization", "Basic " + token); // EXPECT-NOFLAG
    }
}
