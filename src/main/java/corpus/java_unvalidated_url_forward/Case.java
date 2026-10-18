// RULE: java/unvalidated-url-forward  CWE: CWE-552  LANE: taint
package corpus.java_unvalidated_url_forward;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletException;
import java.io.IOException;
public class Case {
    // POSITIVE: a remote parameter is forwarded to (url-forward sink)
    void vulnerable(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String page = request.getParameter("page");
        request.getRequestDispatcher(page).forward(request, response); // EXPECT-FLAG
    }
    // NEGATIVE: a constant forward target
    void safe(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        request.getRequestDispatcher("/home.jsp").forward(request, response); // EXPECT-NOFLAG
    }
}
