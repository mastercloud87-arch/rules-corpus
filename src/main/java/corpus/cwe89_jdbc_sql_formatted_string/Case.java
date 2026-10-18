// RULE: cwe89-jdbc-sql-formatted-string  CWE: CWE-089  LANE: pattern
package corpus.cwe89_jdbc_sql_formatted_string;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
public class Case {
    // POSITIVE: user input concatenated into the SQL string
    void vulnerable(HttpServletRequest request, JdbcTemplate jdbc) {
        String q = "SELECT * FROM t WHERE id=" + request.getParameter("id");
        jdbc.execute(q); // EXPECT-FLAG
    }
    // NEGATIVE (FP10): variable reassigned to a complete SQL LITERAL right before execute -> must not flag
    void safe(JdbcTemplate jdbc) {
        String q = "SELECT * FROM t WHERE id=" + 1; // (not reached by execute below)
        q = "INSERT INTO roles VALUES ('role1')";
        jdbc.execute(q); // EXPECT-NOFLAG
    }
}
