// RULE: cwe89-jdo-sqli  CWE: CWE-089  LANE: pattern
package corpus.cwe89_jdo_sqli;
public class Case {
    // local stand-in for javax.jdo.PersistenceManager (lib not on classpath)
    static class PersistenceManager { Object newQuery(Class<?> c, String filter) { return null; } }
    // POSITIVE: a formatted/concatenated query string (non-const operand) at a JDO builder
    Object vulnerable(PersistenceManager pm, String name) {
        return pm.newQuery(Object.class, "name == '" + name + "'"); // EXPECT-FLAG
    }
    // NEGATIVE: a fully-constant query string
    Object safe(PersistenceManager pm) {
        return pm.newQuery(Object.class, "name == 'admin'"); // EXPECT-NOFLAG
    }
}
