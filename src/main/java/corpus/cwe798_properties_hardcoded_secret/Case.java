// RULE: cwe798-properties-hardcoded-secret  CWE: CWE-798  LANE: literal
package corpus.cwe798_properties_hardcoded_secret;
import java.util.Hashtable;
import javax.naming.Context;
public class Case {
    // POSITIVE: a non-empty hard-coded value stored under the JNDI SECURITY_CREDENTIALS key.
    void vulnerable(Hashtable<String, String> env) {
        env.put(Context.SECURITY_CREDENTIALS, "secret"); // EXPECT-FLAG
    }
    // NEGATIVE: a non-credentials key (SECURITY_PRINCIPAL) -> must not flag.
    void safe(Hashtable<String, String> env) {
        env.put(Context.SECURITY_PRINCIPAL, "cn=admin"); // EXPECT-NOFLAG
    }
}
