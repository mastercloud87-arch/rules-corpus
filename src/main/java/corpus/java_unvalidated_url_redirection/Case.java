// RULE: java/unvalidated-url-redirection  CWE: CWE-601  LANE: taint
package corpus.java_unvalidated_url_redirection;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
public class Case {
    // POSITIVE: a remote parameter is used as the redirect target
    void vulnerable(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        response.sendRedirect(url); // EXPECT-FLAG
    }
    // NEGATIVE: a constant redirect target
    void safe(HttpServletResponse response) throws IOException {
        response.sendRedirect("/home"); // EXPECT-NOFLAG
    }
}
