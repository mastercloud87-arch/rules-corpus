// RULE: cwe330-weak-random  CWE: CWE-330  LANE: pattern
package corpus.cwe330_weak_random;
import java.util.Random;
import java.security.SecureRandom;
public class Case {
    // POSITIVE: predictable RNG (java.util.Random)
    int vulnerable() {
        Random r = new Random(); // EXPECT-FLAG
        return r.nextInt();
    }
    // NEGATIVE: SecureRandom is not java.util.Random
    int safe() {
        SecureRandom r = new SecureRandom(); // EXPECT-NOFLAG
        return r.nextInt();
    }
}
