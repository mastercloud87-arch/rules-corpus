// RULE: cwe287-anonymous-ldap-bind  CWE: CWE-287  LANE: pattern
package corpus.cwe287_anonymous_ldap_bind;
import javax.naming.Context;
import java.util.Hashtable;
public class Case {
    // POSITIVE: LDAP environment configured for anonymous authentication ("none")
    void vulnerable() {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.SECURITY_AUTHENTICATION, "none"); // EXPECT-FLAG
    }
    // NEGATIVE: authenticated bind ("simple")
    void safe() {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple"); // EXPECT-NOFLAG
    }
}
