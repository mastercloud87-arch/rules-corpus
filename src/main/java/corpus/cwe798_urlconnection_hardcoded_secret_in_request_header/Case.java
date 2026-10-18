// RULE: cwe798-urlconnection-hardcoded-secret-in-request-header  CWE: CWE-798  LANE: literal
package corpus.cwe798_urlconnection_hardcoded_secret_in_request_header;
import java.net.HttpURLConnection;
public class Case {
    // POSITIVE: a plain constant Authorization header value on a URLConnection.
    void vulnerable(HttpURLConnection conn) {
        conn.setRequestProperty("Authorization", "Basic dXNlcjpwYXNz"); // EXPECT-FLAG
    }
    // NEGATIVE: the value is a non-constant concatenation -> must not flag.
    void safe(HttpURLConnection conn, String token) {
        conn.setRequestProperty("Authorization", "Basic " + token); // EXPECT-NOFLAG
    }
}
