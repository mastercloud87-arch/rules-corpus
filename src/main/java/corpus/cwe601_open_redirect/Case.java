// RULE: cwe601-open-redirect  CWE: CWE-601  LANE: taint
package corpus.cwe601_open_redirect;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // POSITIVE: remote parameter flows into a "Location" response header
    Object vulnerable(HttpServletRequest request) {
        String url = request.getParameter("url");
        HttpResponse r = HttpResponse.ok();
        return r.header("Location", url); // EXPECT-FLAG
    }
    // NEGATIVE: constant Location value -> no taint
    Object safe() {
        HttpResponse r = HttpResponse.ok();
        return r.header("Location", "/home"); // EXPECT-NOFLAG
    }
    // minimal Micronaut HttpResponse stand-in (io.micronaut.http.HttpResponse not on the classpath)
    static final class HttpResponse {
        static HttpResponse ok() { return new HttpResponse(); }
        HttpResponse header(String name, String value) { return this; }
    }
}
