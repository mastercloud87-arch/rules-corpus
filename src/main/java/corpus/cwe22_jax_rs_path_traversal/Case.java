// RULE: cwe22-jax-rs-path-traversal  CWE: CWE-022  LANE: pattern
package corpus.cwe22_jax_rs_path_traversal;
import java.io.File;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
public class Case {
    // JAX-RS @PathParam is not in the available libraries; a minimal stand-in whose name
    // ends in "PathParam" (what the rule matches) is declared locally.
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.PARAMETER)
    @interface PathParam { String value(); }

    // POSITIVE: a @PathParam value used directly to build a File
    File vulnerable(@PathParam("name") String name) {
        return new File("/base", name); // EXPECT-FLAG
    }
    // NEGATIVE: a constant child component (the parameter is not used in the File path)
    File safe(@PathParam("name") String name) {
        return new File("/base", "fixed.txt"); // EXPECT-NOFLAG
    }
}
