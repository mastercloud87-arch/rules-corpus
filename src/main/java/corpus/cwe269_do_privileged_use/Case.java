// RULE: cwe269-do-privileged-use  CWE: CWE-269  LANE: pattern
package corpus.cwe269_do_privileged_use;
import java.security.AccessController;
import java.security.PrivilegedAction;
public class Case {
    // POSITIVE: a call to AccessController.doPrivileged (usage audit)
    void vulnerable() {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> { return null; }); // EXPECT-FLAG
    }
    // NEGATIVE: a non-doPrivileged call on the same class
    Object safe() {
        return AccessController.getContext(); // EXPECT-NOFLAG
    }
}
