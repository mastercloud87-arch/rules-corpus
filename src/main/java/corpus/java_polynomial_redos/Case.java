// RULE: java/polynomial-redos  CWE: CWE-1333  LANE: taint
package corpus.java_polynomial_redos;
import jakarta.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;
public class Case {
    // POSITIVE: a remote (non length-restricted) value matched against a polynomial regex
    boolean vulnerable(HttpServletRequest request) {
        String s = request.getParameter("s");
        return Pattern.compile("a+a+").matcher(s).matches(); // EXPECT-FLAG
    }
    // NEGATIVE: the source is a length-restricted getter (getHeader) -> excluded source + barrier
    boolean safe(HttpServletRequest request) {
        String s = request.getHeader("X-Thing");
        return Pattern.compile("a+a+").matcher(s).matches(); // EXPECT-NOFLAG
    }
}
