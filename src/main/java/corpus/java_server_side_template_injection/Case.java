// RULE: java/server-side-template-injection  CWE: CWE-1336  LANE: taint
package corpus.java_server_side_template_injection;
import jakarta.servlet.http.HttpServletRequest;
import java.io.StringWriter;
public class Case {
    // Stand-in for org.apache.velocity.app.Velocity (Velocity is not on the allowed
    // library list). The MaD "template-injection" sink keys on the real owner, so the
    // positive below is faithful in shape (evaluate(...) with a tainted template arg).
    static class Velocity {
        static boolean evaluate(Object ctx, StringWriter out, String logTag, String template) { return true; }
    }
    // POSITIVE: remote value evaluated as a template
    void vulnerable(HttpServletRequest request) {
        String tpl = request.getParameter("tpl");
        Velocity.evaluate(null, new StringWriter(), "t", tpl); // EXPECT-FLAG
    }
    // NEGATIVE: a constant template string
    void safe() {
        String tpl = "Hello $name";
        Velocity.evaluate(null, new StringWriter(), "t", tpl); // EXPECT-NOFLAG
    }
}
