// RULE: cwe183-permissive-cors  CWE: CWE-183  LANE: literal
package corpus.cwe183_permissive_cors;
import jakarta.servlet.http.HttpServletResponse;
public class Case {
    // POSITIVE: Access-Control-Allow-Origin header set to the wildcard "*"
    void vulnerable(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "*"); // EXPECT-FLAG
    }
    // NEGATIVE: a specific, trusted origin value
    void safe(HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "https://trusted.example"); // EXPECT-NOFLAG
    }
}
