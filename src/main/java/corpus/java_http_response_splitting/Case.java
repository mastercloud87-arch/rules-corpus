// RULE: java/http-response-splitting  CWE: CWE-113  LANE: taint
package corpus.java_http_response_splitting;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
public class Case {
    // POSITIVE: a request parameter flows unsanitized into a response header
    void vulnerable(HttpServletRequest request, HttpServletResponse response) {
        String v = request.getParameter("v");
        response.setHeader("X-Val", v); // EXPECT-FLAG
    }
    // NEGATIVE: a constant header value -> not user-controlled
    void safe(HttpServletResponse response) {
        response.setHeader("X-Val", "application/json"); // EXPECT-NOFLAG
    }
}
