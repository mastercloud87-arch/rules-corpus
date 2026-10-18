// RULE: java/mvel-expression-injection  CWE: CWE-094  LANE: taint
package corpus.java_mvel_expression_injection;
import jakarta.servlet.http.HttpServletRequest;
// NOTE: MVEL (org.mvel2) is not on the corpus classpath; this local MVEL stand-in
// mirrors the static eval(String) sink shape. The MaD "mvel-injection" sink is
// keyed on the real org.mvel2.MVEL owner, which the stand-in cannot reproduce.
public class Case {
    // POSITIVE: a remote value is evaluated as an MVEL expression
    Object vulnerable(HttpServletRequest request) {
        String e = request.getParameter("e");
        return MVEL.eval(e); // EXPECT-FLAG
    }
    // NEGATIVE: a constant expression -> not user-controlled
    Object safe() {
        return MVEL.eval("1 + 1"); // EXPECT-NOFLAG
    }
    static class MVEL { static Object eval(String expr) { return null; } }
}
