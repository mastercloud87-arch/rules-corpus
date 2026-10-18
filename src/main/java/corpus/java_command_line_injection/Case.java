// RULE: java/command-line-injection  CWE: CWE-078  LANE: taint
package corpus.java_command_line_injection;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
public class Case {
    // POSITIVE: remote value flows unsanitized into Runtime.exec
    void vulnerable(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd); // EXPECT-FLAG
    }
    // NEGATIVE: a constant command line -> not user-controlled
    void safe() throws IOException {
        Runtime.getRuntime().exec("/bin/ls -l"); // EXPECT-NOFLAG
    }
}
