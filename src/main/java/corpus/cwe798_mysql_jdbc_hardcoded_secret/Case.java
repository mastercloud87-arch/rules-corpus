// RULE: cwe798-mysql-jdbc-hardcoded-secret  CWE: CWE-798  LANE: literal
package corpus.cwe798_mysql_jdbc_hardcoded_secret;
import com.mysql.cj.jdbc.MysqlDataSource;
public class Case {
    // POSITIVE: a non-empty hard-coded password on a MysqlDataSource receiver.
    void vulnerable(MysqlDataSource ds) {
        ds.setPassword("secret"); // EXPECT-FLAG
    }
    // NEGATIVE: empty-string password (the semgrep safe case) -> must not flag.
    void safe(MysqlDataSource ds) {
        ds.setPassword(""); // EXPECT-NOFLAG
    }
}
