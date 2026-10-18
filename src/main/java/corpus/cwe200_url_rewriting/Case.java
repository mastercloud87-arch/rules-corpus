// RULE: cwe200-url-rewriting  CWE: CWE-200  LANE: pattern
package corpus.cwe200_url_rewriting;
import jakarta.servlet.http.HttpServletResponse;
public class Case {
    // POSITIVE: encodeURL on an HttpServletResponse leaks the session id into the URL
    String vulnerable(HttpServletResponse response, String url) {
        return response.encodeURL(url); // EXPECT-FLAG
    }
    // NEGATIVE: a method named encodeURL on an unrelated (non-response) object
    String safe(UrlHelper helper, String url) {
        return helper.encodeURL(url); // EXPECT-NOFLAG
    }
    static class UrlHelper {
        String encodeURL(String u) { return u; }
    }
}
