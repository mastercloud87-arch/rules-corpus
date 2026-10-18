// RULE: cwe93-crlf-injection-logs-deep  CWE: CWE-093  LANE: taint
package corpus.cwe93_crlf_injection_logs_deep;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class Case {
    private static final Logger log = LoggerFactory.getLogger(Case.class);
    // POSITIVE: remote input logged without neutralisation
    void vulnerable(HttpServletRequest request) {
        log.info("login for user: " + request.getParameter("user")); // EXPECT-FLAG
    }
    // NEGATIVE: a numeric (simple-type) value is sanitized by the type barrier
    void safe(HttpServletRequest request) {
        int id = Integer.parseInt(request.getParameter("id"));
        log.info("record id: " + id); // EXPECT-NOFLAG
    }
}
