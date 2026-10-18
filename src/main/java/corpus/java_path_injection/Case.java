// RULE: java/path-injection  CWE: CWE-022  LANE: taint
package corpus.java_path_injection;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
public class Case {
    // POSITIVE: remote parameter flows unsanitized into a File path
    File vulnerable(HttpServletRequest request) {
        String name = request.getParameter("name");
        return new File(name); // EXPECT-FLAG
    }
    // NEGATIVE: same sink fed a String literal (no remote source)
    File safe() {
        String name = "/etc/app/config.properties";
        return new File(name); // EXPECT-NOFLAG
    }
}
