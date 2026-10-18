// RULE: cwe798-java-jwt-hardcoded-secret  CWE: CWE-798  LANE: literal
package corpus.cwe798_java_jwt_hardcoded_secret;
import com.auth0.jwt.algorithms.Algorithm;
public class Case {
    // POSITIVE: a non-empty hard-coded HMAC secret to Algorithm.HMAC256.
    Algorithm vulnerable() {
        return Algorithm.HMAC256("hardcodedsecret"); // EXPECT-FLAG
    }
    // NEGATIVE: the secret comes from a runtime source (not a literal) -> must not flag.
    Algorithm safe(String fromEnv) {
        return Algorithm.HMAC256(fromEnv); // EXPECT-NOFLAG
    }
}
