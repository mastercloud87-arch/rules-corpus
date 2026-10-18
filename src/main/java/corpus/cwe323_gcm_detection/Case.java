// RULE: cwe323-gcm-detection  CWE: CWE-323  LANE: pattern
package corpus.cwe323_gcm_detection;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
public class Case {
    // POSITIVE: GCMParameterSpec whose IV is not produced by a CSPRNG
    GCMParameterSpec vulnerable() {
        byte[] iv = new byte[12];
        return new GCMParameterSpec(128, iv); // EXPECT-FLAG
    }
    // NEGATIVE: IV randomised via SecureRandom.nextBytes -> safe
    GCMParameterSpec safe() {
        SecureRandom sr = new SecureRandom();
        byte[] iv = new byte[12];
        sr.nextBytes(iv);
        return new GCMParameterSpec(128, iv); // EXPECT-NOFLAG
    }
}
