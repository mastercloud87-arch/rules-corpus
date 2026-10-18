// RULE: java/spel-expression-injection  CWE: CWE-094  LANE: taint
package corpus.java_spel_expression_injection;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
public class Case {
    // POSITIVE: remote value parsed into a SpEL Expression, then evaluated
    Object vulnerable(HttpServletRequest request) {
        String e = request.getParameter("e");
        Expression expr = new SpelExpressionParser().parseExpression(e);
        return expr.getValue(); // EXPECT-FLAG
    }
    // NEGATIVE: a constant expression string
    Object safe() {
        Expression expr = new SpelExpressionParser().parseExpression("1 + 1");
        return expr.getValue(); // EXPECT-NOFLAG
    }
}
