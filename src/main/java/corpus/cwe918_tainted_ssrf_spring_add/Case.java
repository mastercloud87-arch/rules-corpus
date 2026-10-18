// RULE: cwe918-tainted-ssrf-spring-add  CWE: CWE-918  LANE: taint
package corpus.cwe918_tainted_ssrf_spring_add;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URL;
import java.net.MalformedURLException;
public class Case {
    // local stand-in for com.google.common.io.Resources (Guava not on classpath)
    static class Resources { static Object asByteSource(URL u) { return null; } }
    // POSITIVE: remote input builds the URL fetched by Guava Resources.asByteSource
    Object vulnerable(HttpServletRequest request) throws MalformedURLException {
        return Resources.asByteSource(new URL(request.getParameter("u"))); // EXPECT-FLAG
    }
    // NEGATIVE: a constant URL -> no remote taint
    Object safe() throws MalformedURLException {
        return Resources.asByteSource(new URL("http://localhost/health")); // EXPECT-NOFLAG
    }
}
