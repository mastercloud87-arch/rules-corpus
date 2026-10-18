// RULE: java/tainted-permissions-check  CWE: CWE-807  LANE: taint
package corpus.java_tainted_permissions_check;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // A PermissionsConstruction (clause b): a method named %permitted% with one parameter.
    boolean isPermitted(String perm) { return true; }

    // POSITIVE: the permission check argument is remote-controlled
    void vulnerable(HttpServletRequest request) {
        String role = request.getParameter("role");
        if (isPermitted(role)) { grant(); } // EXPECT-FLAG
    }
    // NEGATIVE: the check argument is a constant
    void safe() {
        if (isPermitted("admin")) { grant(); } // EXPECT-NOFLAG
    }
    void grant() {}
}
