// RULE: cwe345-java-jwt-decode-without-verify  CWE: CWE-345  LANE: pattern
package corpus.cwe345_java_jwt_decode_without_verify;
// com.auth0.jwt is not an available library; a minimal local stand-in keeps the
// matched shape faithful: JWT.decode(...) (receiver named `JWT`) and a verify() step.
public class Case {
    // POSITIVE: JWT.decode in a type with no verify() call -> unverified decode
    Object vulnerable(String token) {
        return JWT.decode(token); // EXPECT-FLAG
    }

    // NEGATIVE: a type that also calls verify() before decoding (verify step present).
    // Scoped to its OWN enclosing type so it does not suppress the positive above.
    static class Safe {
        Object safe(String token) {
            JWT.verify(token);
            return JWT.decode(token); // EXPECT-NOFLAG
        }
    }

    static class JWT {
        static Object decode(String s) { return null; }
        static void verify(String s) {}
    }
}
