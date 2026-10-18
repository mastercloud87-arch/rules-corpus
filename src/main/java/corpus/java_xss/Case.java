// RULE: java/xss  CWE: CWE-079  LANE: taint
package corpus.java_xss;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
public class Case {
    // POSITIVE: remote value written unescaped to the servlet response writer
    void vulnerable(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.getWriter().println(request.getParameter("q")); // EXPECT-FLAG
    }
    // NEGATIVE: a constant string written to the same writer -> no user-provided value
    void safe(HttpServletResponse response) throws IOException {
        response.getWriter().println("static content"); // EXPECT-NOFLAG
    }
}
