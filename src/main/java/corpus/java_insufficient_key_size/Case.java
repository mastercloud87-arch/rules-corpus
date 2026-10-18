// RULE: java/insufficient-key-size  CWE: CWE-326  LANE: pattern
package corpus.java_insufficient_key_size;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
public class Case {
    // POSITIVE: RSA key generator initialized to 1024 bits (< 2048 minimum)
    void vulnerable() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024); // EXPECT-FLAG
    }
    // NEGATIVE: RSA at 2048 bits meets the recommended minimum
    void safe() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // EXPECT-NOFLAG
    }
}
