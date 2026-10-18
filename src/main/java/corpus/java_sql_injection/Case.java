// RULE: java/sql-injection  CWE: CWE-089  LANE: taint
package corpus.java_sql_injection;
import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.SQLException;
public class Case {
    // POSITIVE: remote source flows unsanitized into the query
    void vulnerable(HttpServletRequest request, Connection con) throws SQLException {
        String id = request.getParameter("id");
        Statement stmt = con.createStatement();
        stmt.executeQuery("SELECT * FROM t WHERE id=" + id); // EXPECT-FLAG
    }
    // NEGATIVE: the same sink fed a literal (no remote source) -> must not flag
    void safe(Connection con) throws SQLException {
        String id = "42";
        Statement stmt = con.createStatement();
        stmt.executeQuery("SELECT * FROM t WHERE id=" + id); // EXPECT-NOFLAG
    }
}
