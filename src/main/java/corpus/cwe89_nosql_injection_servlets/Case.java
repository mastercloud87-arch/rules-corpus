// RULE: cwe89-nosql-injection-servlets  CWE: CWE-089  LANE: taint
package corpus.cwe89_nosql_injection_servlets;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // local stand-in for com.mongodb.BasicDBObject (lib not on classpath)
    static class BasicDBObject {
        Object put(String k, Object v) { return null; }
        Object append(String k, Object v) { return null; }
    }
    // POSITIVE: remote input flows unsanitized into a BasicDBObject query value
    void vulnerable(HttpServletRequest request) {
        BasicDBObject query = new BasicDBObject();
        query.put("user", request.getParameter("u")); // EXPECT-FLAG
    }
    // NEGATIVE: a constant value -> no remote taint
    void safe() {
        BasicDBObject query = new BasicDBObject();
        query.put("user", "admin"); // EXPECT-NOFLAG
    }
}
