// RULE: cwe89-vertx-sqli  CWE: CWE-089  LANE: pattern
package corpus.cwe89_vertx_sqli;
public class Case {
    // local stand-in for io.vertx.*.SqlClient (lib not on classpath)
    static class SqlClient { Object query(String sql) { return null; } }
    // POSITIVE: a concatenated SQL string (non-const operand) at SqlClient.query
    Object vulnerable(SqlClient client, String v) {
        return client.query("SELECT * FROM t WHERE x=" + v); // EXPECT-FLAG
    }
    // NEGATIVE: a fully-constant SQL string
    Object safe(SqlClient client) {
        return client.query("SELECT * FROM t WHERE x=1"); // EXPECT-NOFLAG
    }
}
