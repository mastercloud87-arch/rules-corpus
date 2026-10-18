// RULE: cwe798-drivermanager-hardcoded-secret  CWE: CWE-798  LANE: literal
package corpus.cwe798_drivermanager_hardcoded_secret;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
public class Case {
    // POSITIVE: a non-empty hard-coded password literal as the 3rd arg of getConnection.
    Connection vulnerable(String url) throws SQLException {
        return DriverManager.getConnection(url, "root", "p@ssw0rd"); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    Connection safe(String url) throws SQLException {
        return DriverManager.getConnection(url, "root", ""); // EXPECT-NOFLAG
    }
}
