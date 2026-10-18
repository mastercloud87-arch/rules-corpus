// RULE: cwe89-find-sql-string-concatenation  CWE: CWE-089  LANE: pattern
package corpus.cwe89_find_sql_string_concatenation;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
public class Case {
    // POSITIVE: a SQL string built by '+' concatenation with a non-constant operand.
    PreparedStatement vulnerable(Connection conn, String name) throws SQLException {
        return conn.prepareStatement("SELECT * FROM users WHERE name='" + name + "'"); // EXPECT-FLAG
    }
    // NEGATIVE: a constant parameterized query -> must not flag.
    PreparedStatement safe(Connection conn) throws SQLException {
        return conn.prepareStatement("SELECT * FROM users WHERE id = ?"); // EXPECT-NOFLAG
    }
}
