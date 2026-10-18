// RULE: cwe94-el-injection  CWE: CWE-094  LANE: pattern
package corpus.cwe94_el_injection;
public class Case {
    // local stand-in for javax.el/jakarta.el.ExpressionFactory (lib not on classpath)
    static class ExpressionFactory {
        Object createValueExpression(Object ctx, String expr, Class<?> t) { return null; }
    }
    // POSITIVE: the EL expression (argument 1) is a non-constant string
    Object vulnerable(ExpressionFactory factory, Object ctx, String expr) {
        return factory.createValueExpression(ctx, expr, Object.class); // EXPECT-FLAG
    }
    // NEGATIVE: a compile-time constant EL expression
    Object safe(ExpressionFactory factory, Object ctx) {
        return factory.createValueExpression(ctx, "#{bean.x}", Object.class); // EXPECT-NOFLAG
    }
}
