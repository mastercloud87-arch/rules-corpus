// RULE: cwe89-jdo-sqli-spring  CWE: CWE-089  LANE: taint
package corpus.cwe89_jdo_sqli_spring;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // local stand-in for javax.jdo.PersistenceManager (lib not on classpath)
    static class PersistenceManager { Object newQuery(Class<?> c, String filter) { return null; } }
    // POSITIVE: remote input flows unsanitized into the JDO query builder
    Object vulnerable(HttpServletRequest request, PersistenceManager pm) {
        return pm.newQuery(Object.class, request.getParameter("f")); // EXPECT-FLAG
    }
    // NEGATIVE: a constant filter -> no remote taint
    Object safe(PersistenceManager pm) {
        return pm.newQuery(Object.class, "name == 'admin'"); // EXPECT-NOFLAG
    }
}
