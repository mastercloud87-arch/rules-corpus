// RULE: cwe489-active-debug-code-printstacktrace  CWE: CWE-489  LANE: pattern
package corpus.cwe489_active_debug_code_printstacktrace;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
public class Case {
    // POSITIVE (per FP04 fix intent): stack trace written to the HTTP response -> info exposure
    void vulnerable(HttpServletResponse response) throws IOException {
        try { risky(); } catch (Exception e) { e.printStackTrace(response.getWriter()); } // EXPECT-FLAG
    }
    // NEGATIVE (FP04): stack trace to stderr in a catch block -> not a vulnerability
    void safe() {
        try { risky(); } catch (Exception e) { e.printStackTrace(); } // EXPECT-NOFLAG
    }
    void risky() throws Exception { throw new Exception("x"); }
}
