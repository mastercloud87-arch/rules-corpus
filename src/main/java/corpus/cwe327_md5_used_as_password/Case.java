// RULE: cwe327-md5-used-as-password  CWE: CWE-327  LANE: taint
package corpus.cwe327_md5_used_as_password;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // sink: a call whose method name contains "password" (case-insensitive)
    static void md5Password(String p) {}

    // POSITIVE: remote request value flows into a password-named call argument
    void vulnerable(HttpServletRequest request) {
        String pw = request.getParameter("pw");
        md5Password(pw); // EXPECT-FLAG
    }
    // NEGATIVE: same password-named sink fed a literal (no remote source)
    void safe() {
        md5Password("constant-secret"); // EXPECT-NOFLAG
    }
}
