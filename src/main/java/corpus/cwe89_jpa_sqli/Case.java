// RULE: cwe89-jpa-sqli  CWE: CWE-089  LANE: pattern
package corpus.cwe89_jpa_sqli;
public class Case {
    // local stand-in for javax/jakarta.persistence.EntityManager (lib not on classpath)
    static class EntityManager {
        Object createQuery(String q) { return null; }
        Object createNativeQuery(String q) { return null; }
    }
    // POSITIVE: a formatted/concatenated JPQL string (non-const operand) at createQuery
    Object vulnerable(EntityManager em, String name) {
        return em.createQuery("SELECT u FROM User u WHERE u.name='" + name + "'"); // EXPECT-FLAG
    }
    // NEGATIVE: a fully-constant JPQL string
    Object safe(EntityManager em) {
        return em.createQuery("SELECT u FROM User u"); // EXPECT-NOFLAG
    }
}
