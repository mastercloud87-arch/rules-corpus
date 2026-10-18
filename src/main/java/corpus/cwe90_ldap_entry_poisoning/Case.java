// RULE: cwe90-ldap-entry-poisoning  CWE: CWE-090  LANE: pattern
package corpus.cwe90_ldap_entry_poisoning;
import javax.naming.directory.SearchControls;
public class Case {
    // POSITIVE: 6-arg SearchControls ctor with returningObjFlag (arg#4) = true
    SearchControls vulnerable() {
        return new SearchControls(SearchControls.SUBTREE_SCOPE, 0L, 0, null, true, false); // EXPECT-FLAG
    }
    // NEGATIVE: returningObjFlag = false -> object return not enabled
    SearchControls safe() {
        return new SearchControls(SearchControls.SUBTREE_SCOPE, 0L, 0, null, false, false); // EXPECT-NOFLAG
    }
}
