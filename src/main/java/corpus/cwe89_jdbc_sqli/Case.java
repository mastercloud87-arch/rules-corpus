// RULE: cwe89-jdbc-sqli  CWE: CWE-089  LANE: pattern
package corpus.cwe89_jdbc_sqli;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.SQLException;
public class Case {
    // POSITIVE: a formatted/concatenated SQL string (non-const operand) at a JDBC Statement exec
    void vulnerable(Connection con, String name) throws SQLException {
        Statement stmt = con.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name='" + name + "'"); // EXPECT-FLAG
    }
    // NEGATIVE: a fully-constant SQL string -> not a formatted string
    void safe(Connection con) throws SQLException {
        Statement stmt = con.createStatement();
        stmt.executeQuery("SELECT * FROM users"); // EXPECT-NOFLAG
    }
}
