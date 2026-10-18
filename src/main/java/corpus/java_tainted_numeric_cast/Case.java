// RULE: java/tainted-numeric-cast  CWE: CWE-681  LANE: taint
package corpus.java_tainted_numeric_cast;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // POSITIVE: a remote long is narrowed to int (NumericNarrowingCastExpr over a variable)
    int vulnerable(HttpServletRequest request) {
        long n = Long.parseLong(request.getParameter("n"));
        return (int) n; // EXPECT-FLAG
    }
    // NEGATIVE: the narrowed value comes from a literal
    int safe() {
        long n = Long.parseLong("42");
        return (int) n; // EXPECT-NOFLAG
    }
}
