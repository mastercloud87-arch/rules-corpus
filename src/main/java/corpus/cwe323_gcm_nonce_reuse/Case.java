// RULE: cwe323-gcm-nonce-reuse  CWE: CWE-323  LANE: pattern
package corpus.cwe323_gcm_nonce_reuse;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
public class Case {
    // POSITIVE: GCM nonce is a hardcoded constant string's bytes (reused nonce)
    GCMParameterSpec vulnerable() {
        return new GCMParameterSpec(128, "hardcodednonce".getBytes()); // EXPECT-FLAG
    }
    // NEGATIVE: IV randomised via SecureRandom.nextBytes -> safe
    GCMParameterSpec safe() {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        return new GCMParameterSpec(128, iv); // EXPECT-NOFLAG
    }
}
