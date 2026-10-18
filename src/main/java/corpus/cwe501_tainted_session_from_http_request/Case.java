// RULE: cwe501-tainted-session-from-http-request  CWE: CWE-501  LANE: taint
package corpus.cwe501_tainted_session_from_http_request;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
public class Case {
    // POSITIVE: remote input stored into the HTTP session (trust boundary violation)
    void vulnerable(HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.setAttribute("data", request.getParameter("v")); // EXPECT-FLAG
    }
    // NEGATIVE: a constant value stored into the session (no remote source)
    void safe(HttpServletRequest request) {
        HttpSession session = request.getSession();
        session.setAttribute("data", "constant"); // EXPECT-NOFLAG
    }
}
