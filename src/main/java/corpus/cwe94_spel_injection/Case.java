// RULE: cwe94-spel-injection  CWE: CWE-094  LANE: pattern
package corpus.cwe94_spel_injection;
import org.springframework.expression.spel.standard.SpelExpressionParser;
public class Case {
    // POSITIVE: a SpEL expression parsed from a non-constant string
    Object vulnerable(String expr) {
        SpelExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expr); // EXPECT-FLAG
    }
    // NEGATIVE: a compile-time constant SpEL expression
    Object safe() {
        SpelExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression("T(java.lang.Math).PI"); // EXPECT-NOFLAG
    }
}
