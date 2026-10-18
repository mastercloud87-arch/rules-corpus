// RULE: cwe94-dangerous-groovy-shell  CWE: CWE-094  LANE: pattern
package corpus.cwe94_dangerous_groovy_shell;
public class Case {
    // local stand-in for groovy.lang.GroovyShell (lib not on classpath)
    static class GroovyShell { Object evaluate(String s) { return null; } }
    // POSITIVE: GroovyShell evaluates a non-constant string
    Object vulnerable(String code) {
        GroovyShell shell = new GroovyShell();
        return shell.evaluate(code); // EXPECT-FLAG
    }
    // NEGATIVE: a compile-time constant script
    Object safe() {
        GroovyShell shell = new GroovyShell();
        return shell.evaluate("2+2"); // EXPECT-NOFLAG
    }
}
