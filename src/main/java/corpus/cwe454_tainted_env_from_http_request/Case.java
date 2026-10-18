// RULE: cwe454-tainted-env-from-http-request  CWE: CWE-454  LANE: taint
package corpus.cwe454_tainted_env_from_http_request;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
public class Case {
    // POSITIVE: remote input flows into the environment (envp) argument of Runtime.exec
    void vulnerable(HttpServletRequest request) throws IOException {
        String v = request.getParameter("v");
        Runtime.getRuntime().exec("/bin/run", new String[]{ "CONFIG=" + v }); // EXPECT-FLAG
    }
    // NEGATIVE: a constant environment (no remote source reaches envp)
    void safe() throws IOException {
        Runtime.getRuntime().exec("/bin/run", new String[]{ "CONFIG=prod" }); // EXPECT-NOFLAG
    }
}
