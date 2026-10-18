// RULE: cwe327-java-jwt-none-alg  CWE: CWE-327  LANE: pattern
package corpus.cwe327_java_jwt_none_alg;
public class Case {
    // local stand-ins for com.auth0 java-jwt (lib not on classpath)
    static class Algorithm {
        static Algorithm none() { return new Algorithm(); }
        static Algorithm HMAC256(String secret) { return new Algorithm(); }
    }
    static class JWTBuilder {
        JWTBuilder withIssuer(String issuer) { return this; }
        String sign(Algorithm alg) { return ""; }
    }
    static class JWT { static JWTBuilder create() { return new JWTBuilder(); } }
    // POSITIVE: token signed with the 'none' algorithm
    String vulnerable() {
        return JWT.create().withIssuer("x").sign(Algorithm.none()); // EXPECT-FLAG
    }
    // NEGATIVE: token signed with a real HMAC algorithm
    String safe() {
        return JWT.create().withIssuer("x").sign(Algorithm.HMAC256("secret")); // EXPECT-NOFLAG
    }
}
