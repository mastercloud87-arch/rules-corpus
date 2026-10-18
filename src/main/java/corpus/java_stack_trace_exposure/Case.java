// RULE: java/stack-trace-exposure  CWE: CWE-209  LANE: taint
package corpus.java_stack_trace_exposure;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
public class Case {
    // POSITIVE (path A): the stack trace is printed to the servlet response writer
    void vulnerable(HttpServletResponse response) {
        try {
            risky();
        } catch (Exception e) {
            try {
                e.printStackTrace(response.getWriter()); // EXPECT-FLAG
            } catch (IOException io) { /* ignore */ }
        }
    }
    // NEGATIVE (FP04): printing to stderr does not expose externally
    void safe() {
        try {
            risky();
        } catch (Exception e) {
            e.printStackTrace(); // EXPECT-NOFLAG
        }
    }
    void risky() throws Exception { throw new Exception("boom"); }
}
