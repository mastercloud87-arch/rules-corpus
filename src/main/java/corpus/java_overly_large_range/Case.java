// RULE: java/overly-large-range  CWE: CWE-020  LANE: pattern
package corpus.java_overly_large_range;
import java.util.regex.Pattern;
public class Case {
    // POSITIVE: the range A-z spans Z-a (includes [ \ ] ^ _ `), an overly-wide class
    Pattern vulnerable() {
        return Pattern.compile("[A-z]"); // EXPECT-FLAG
    }
    // NEGATIVE: tight, intentional alphabetic ranges
    Pattern safe() {
        return Pattern.compile("[A-Za-z]"); // EXPECT-NOFLAG
    }
}
