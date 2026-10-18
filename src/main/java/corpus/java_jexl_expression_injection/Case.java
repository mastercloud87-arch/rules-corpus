// RULE: java/jexl-expression-injection  CWE: CWE-094  LANE: taint
package corpus.java_jexl_expression_injection;
import jakarta.servlet.http.HttpServletRequest;
// NOTE: Apache Commons JEXL is not on the corpus classpath; these local stand-ins
// mirror the JexlBuilder/JexlEngine/JexlExpression API shape and method names so
// the file resolves. The MaD "jexl-injection" sink is keyed on the real
// org.apache.commons.jexl3 owners, which these stand-ins cannot reproduce.
public class Case {
    // POSITIVE: a remote value is compiled and evaluated as a JEXL expression
    Object vulnerable(HttpServletRequest request, JexlContext jc) {
        String e = request.getParameter("e");
        return new JexlBuilder().create().createExpression(e).evaluate(jc); // EXPECT-FLAG
    }
    // NEGATIVE: a constant expression -> not user-controlled
    Object safe(JexlContext jc) {
        return new JexlBuilder().create().createExpression("1 + 1").evaluate(jc); // EXPECT-NOFLAG
    }
    static class JexlContext {}
    static class JexlExpression { Object evaluate(JexlContext c) { return null; } }
    static class JexlEngine { JexlExpression createExpression(String expr) { return new JexlExpression(); } }
    static class JexlBuilder { JexlEngine create() { return new JexlEngine(); } }
}
