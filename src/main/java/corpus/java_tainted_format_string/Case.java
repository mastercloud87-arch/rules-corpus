// RULE: java/tainted-format-string  CWE: CWE-134  LANE: taint
package corpus.java_tainted_format_string;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // POSITIVE: the format string itself is remote-controlled
    String vulnerable(HttpServletRequest request) {
        String fmt = request.getParameter("fmt");
        return String.format(fmt, "arg"); // EXPECT-FLAG
    }
    // NEGATIVE: constant format string (the remote value is only a format argument)
    String safe(HttpServletRequest request) {
        return String.format("literal %s", request.getParameter("x")); // EXPECT-NOFLAG
    }
}
