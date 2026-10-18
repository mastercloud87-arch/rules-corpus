// RULE: cwe89-hibernate-sqli  CWE: CWE-089  LANE: pattern
package corpus.cwe89_hibernate_sqli;
import org.hibernate.Session;
public class Case {
    // POSITIVE: a concatenated (non-constant) HQL/SQL string passed to Session.createQuery.
    Object vulnerable(Session session, String name) {
        return session.createQuery("from User where name='" + name + "'"); // EXPECT-FLAG
    }
    // NEGATIVE: a constant HQL string -> must not flag.
    Object safe(Session session) {
        return session.createQuery("from User"); // EXPECT-NOFLAG
    }
}
