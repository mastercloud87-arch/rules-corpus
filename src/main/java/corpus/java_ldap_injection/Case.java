// RULE: java/ldap-injection  CWE: CWE-090  LANE: taint
package corpus.java_ldap_injection;
import jakarta.servlet.http.HttpServletRequest;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
public class Case {
    // POSITIVE: a remote value is concatenated into an LDAP search filter
    NamingEnumeration<SearchResult> vulnerable(HttpServletRequest request, DirContext ctx,
                                               SearchControls controls) throws NamingException {
        String u = request.getParameter("u");
        return ctx.search("(uid=" + u + ")", controls); // EXPECT-FLAG
    }
    // NEGATIVE: a constant filter -> not user-controlled
    NamingEnumeration<SearchResult> safe(DirContext ctx, SearchControls controls) throws NamingException {
        return ctx.search("(uid=admin)", controls); // EXPECT-NOFLAG
    }
}
