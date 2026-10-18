// RULE: java/ssrf  CWE: CWE-918  LANE: taint
package corpus.java_ssrf;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URL;
import java.net.URLConnection;
import java.io.IOException;
public class Case {
    // POSITIVE: remote value used to open a connection (request-forgery sink)
    URLConnection vulnerable(HttpServletRequest request) throws IOException {
        String u = request.getParameter("url");
        return new URL(u).openConnection(); // EXPECT-FLAG
    }
    // NEGATIVE: a constant URL
    URLConnection safe() throws IOException {
        return new URL("https://safe.example.com/status").openConnection(); // EXPECT-NOFLAG
    }
}
