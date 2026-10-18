// RULE: cwe798-httprequest-hardcoded-secret-in-request-header  CWE: CWE-798  LANE: literal
package corpus.cwe798_httprequest_hardcoded_secret_in_request_header;
import java.net.http.HttpRequest;
public class Case {
    // POSITIVE: a non-empty hard-coded Authorization header on a java.net.http HttpRequest.Builder.
    HttpRequest.Builder vulnerable() {
        return HttpRequest.newBuilder().header("Authorization", "Bearer abc123token"); // EXPECT-FLAG
    }
    // NEGATIVE: the value is a runtime token (not a constant literal) -> must not flag.
    HttpRequest.Builder safe(String token) {
        return HttpRequest.newBuilder().header("Authorization", token); // EXPECT-NOFLAG
    }
}
