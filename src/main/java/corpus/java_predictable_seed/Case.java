// RULE: java/predictable-seed  CWE: CWE-335  LANE: pattern
package corpus.java_predictable_seed;
import java.security.SecureRandom;
public class Case {
    // POSITIVE: SecureRandom seeded with a constant, then nextX() is reported
    int vulnerable() {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(123L);
        return sr.nextInt(); // EXPECT-FLAG
    }
    // NEGATIVE: unseeded SecureRandom (self-seeded securely)
    int safe() {
        SecureRandom sr = new SecureRandom();
        return sr.nextInt(); // EXPECT-NOFLAG
    }
}
