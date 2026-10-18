// RULE: cwe502-insecure-resteasy-deserialization  CWE: CWE-502  LANE: pattern
package corpus.cwe502_insecure_resteasy_deserialization;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
// javax/jakarta.ws.rs is not an available library; minimal local @Consumes stand-in
// keeps the matched simple name and its string value faithful.
public class Case {
    // POSITIVE: @Consumes with a wildcard media type
    @Consumes("*/*") // EXPECT-FLAG
    public Response vulnerable(Foo f) {
        return new Response();
    }
    // NEGATIVE: a concrete, safe media type
    @Consumes("application/json") // EXPECT-NOFLAG
    public Response safe(Foo f) {
        return new Response();
    }

    @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.METHOD, ElementType.TYPE}) @interface Consumes { String[] value(); }
    static class Response {}
    static class Foo {}
}
