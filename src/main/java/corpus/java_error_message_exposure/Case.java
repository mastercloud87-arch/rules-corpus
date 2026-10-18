// RULE: java/error-message-exposure  CWE: CWE-209  LANE: taint
package corpus.java_error_message_exposure;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
public class Case {
    // POSITIVE: Throwable.getMessage() written to the servlet response writer
    void vulnerable(HttpServletResponse response) throws IOException {
        try { risky(); }
        catch (Exception e) { response.getWriter().println(e.getMessage()); } // EXPECT-FLAG
    }
    // NEGATIVE: the message goes to stderr, not an external response writer
    void safe() {
        try { risky(); }
        catch (Exception e) { System.err.println(e.getMessage()); } // EXPECT-NOFLAG
    }
    void risky() throws Exception { throw new Exception("boom"); }
}
