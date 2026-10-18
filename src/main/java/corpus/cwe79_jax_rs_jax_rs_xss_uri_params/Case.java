// RULE: cwe79-jax-rs-jax-rs-xss-uri-params  CWE: CWE-079  LANE: taint
package corpus.cwe79_jax_rs_jax_rs_xss_uri_params;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
public class Case {
    // POSITIVE: tainted value returned from a @Produces String resource method
    @Produces("text/html")
    public String vulnerable(HttpServletRequest request) {
        String q = request.getParameter("q");
        return "<b>" + q + "</b>"; // EXPECT-FLAG
    }
    // NEGATIVE: constant body from a @Produces String method
    @Produces("text/html")
    public String safe() {
        return "<b>ok</b>"; // EXPECT-NOFLAG
    }
    // minimal JAX-RS @Produces stand-in (javax/jakarta.ws.rs.Produces not on the classpath)
    @Retention(RetentionPolicy.RUNTIME)
    @interface Produces { String value(); }
}
