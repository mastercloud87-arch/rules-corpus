// RULE: cwe89-turbine-sqli  CWE: CWE-089  LANE: pattern
package corpus.cwe89_turbine_sqli;
public class Case {
    // local stand-in for an Apache Turbine *.BasePeer (lib not on classpath)
    static class BasePeer { static Object executeQuery(String q) { return null; } }
    // POSITIVE: a concatenated SQL string (non-const operand) at BasePeer.executeQuery
    Object vulnerable(String v) {
        return BasePeer.executeQuery("SELECT * FROM t WHERE x=" + v); // EXPECT-FLAG
    }
    // NEGATIVE: a fully-constant SQL string
    Object safe() {
        return BasePeer.executeQuery("SELECT * FROM t WHERE x=1"); // EXPECT-NOFLAG
    }
}
