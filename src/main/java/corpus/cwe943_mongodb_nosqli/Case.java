// RULE: cwe943-mongodb-nosqli  CWE: CWE-943  LANE: pattern
package corpus.cwe943_mongodb_nosqli;
public class Case {
    // local stand-in for com.mongodb.BasicDBObject (lib not on classpath)
    static class BasicDBObject {
        Object put(String k, Object v) { return null; }
        Object append(String k, Object v) { return null; }
    }
    // POSITIVE: non-constant data in a MongoDB "$where" clause
    void vulnerable(String userJs) {
        BasicDBObject query = new BasicDBObject();
        query.put("$where", userJs); // EXPECT-FLAG
    }
    // NEGATIVE: a constant "$where" JS predicate
    void safe() {
        BasicDBObject query = new BasicDBObject();
        query.put("$where", "this.qty > 10"); // EXPECT-NOFLAG
    }
}
