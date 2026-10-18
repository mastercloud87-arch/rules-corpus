// RULE: java/jhipster-prng  CWE: CWE-338  LANE: pattern
package corpus.java_jhipster_prng;
import org.apache.commons.lang3.RandomStringUtils;
public class Case {
    // The rule flags a RandomUtil.generate* : String whose body is a single return
    // of a predictable RandomStringUtils call (any method except "random").
}
class RandomUtil {
    // POSITIVE: generate* returning String from a non-secure RandomStringUtils overload
    public static String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(20); // EXPECT-FLAG
    }
    // NEGATIVE: the one secure "random" overload
    public static String generateSecret() {
        return RandomStringUtils.random(20); // EXPECT-NOFLAG
    }
}
