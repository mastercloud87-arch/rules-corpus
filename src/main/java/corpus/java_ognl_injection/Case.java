// RULE: java/ognl-injection  CWE: CWE-917  LANE: taint
package corpus.java_ognl_injection;
import jakarta.servlet.http.HttpServletRequest;
// NOTE: OGNL (ognl / org.apache.commons.ognl) is not on the corpus classpath;
// this local Ognl stand-in mirrors the static getValue(expr, context, root) sink
// shape. The MaD "ognl-injection" sink is keyed on the real Ognl owner, which the
// stand-in cannot reproduce.
public class Case {
    // POSITIVE: a remote value is evaluated as an OGNL expression
    Object vulnerable(HttpServletRequest request, Object context, Object root) {
        String expr = request.getParameter("expr");
        return Ognl.getValue(expr, context, root); // EXPECT-FLAG
    }
    // NEGATIVE: a constant expression -> not user-controlled
    Object safe(Object context, Object root) {
        return Ognl.getValue("name", context, root); // EXPECT-NOFLAG
    }
    static class Ognl { static Object getValue(String expr, Object context, Object root) { return null; } }
}
