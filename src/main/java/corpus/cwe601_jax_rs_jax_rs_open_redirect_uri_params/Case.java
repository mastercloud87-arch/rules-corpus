// RULE: cwe601-jax-rs-jax-rs-open-redirect-uri-params  CWE: CWE-601  LANE: taint
package corpus.cwe601_jax_rs_jax_rs_open_redirect_uri_params;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
public class Case {
    // POSITIVE: remote parameter flows into Response.created(<tainted URI>)
    Object vulnerable(HttpServletRequest request) {
        String u = request.getParameter("u");
        return Response.created(URI.create(u)).build(); // EXPECT-FLAG
    }
    // NEGATIVE: constant destination -> no taint
    Object safe() {
        return Response.created(URI.create("/home")).build(); // EXPECT-NOFLAG
    }
    // minimal JAX-RS core Response stand-in (javax/jakarta.ws.rs.core.Response not on the classpath)
    static final class Response {
        static Response created(URI u) { return new Response(); }
        Object build() { return null; }
    }
}
