// RULE: cwe798-hardcoded-secret-in-request-header  CWE: CWE-798  LANE: literal
package corpus.cwe798_hardcoded_secret_in_request_header;
import okhttp3.Request;
public class Case {
    // POSITIVE: a non-empty hard-coded Authorization header on an okhttp3 Request.Builder.
    void vulnerable(Request.Builder builder) {
        builder.header("Authorization", "Basic dXNlcjpwYXNz"); // EXPECT-FLAG
    }
    // NEGATIVE: the value is a runtime token (not a constant literal) -> must not flag.
    void safe(Request.Builder builder, String token) {
        builder.header("Authorization", token); // EXPECT-NOFLAG
    }
}
