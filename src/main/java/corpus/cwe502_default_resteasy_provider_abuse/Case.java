// RULE: cwe502-default-resteasy-provider-abuse  CWE: CWE-502  LANE: pattern
package corpus.cwe502_default_resteasy_provider_abuse;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
// javax/jakarta.ws.rs is not an available library; minimal local JAX-RS stand-in
// annotations keep the matched simple names (Path / GET / POST / Consumes) faithful.
public class Case {
    // POSITIVE: @Path method, not @GET and not @Consumes, in a class without @Consumes
    @Path("/create") @POST
    public Response vulnerable(Foo f) { // EXPECT-FLAG
        return new Response();
    }
    // NEGATIVE: @GET exempts the method
    @GET @Path("/read")
    public Response safe() { // EXPECT-NOFLAG
        return new Response();
    }

    @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.METHOD, ElementType.TYPE}) @interface Path { String value(); }
    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) @interface GET {}
    @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) @interface POST {}
    @Retention(RetentionPolicy.RUNTIME) @Target({ElementType.METHOD, ElementType.TYPE}) @interface Consumes { String[] value(); }
    static class Response {}
    static class Foo {}
}
