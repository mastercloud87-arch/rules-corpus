// RULE: java/redos  CWE: CWE-1333  LANE: pattern
package corpus.java_redos;
import java.util.regex.Pattern;
public class Case {
    // POSITIVE: nested-quantifier regex with exponential backtracking
    boolean vulnerable(String input) {
        return Pattern.compile("(a+)+$").matcher(input).matches(); // EXPECT-FLAG
    }
    // NEGATIVE: a linear regex
    boolean safe(String input) {
        return Pattern.compile("[a-z]+").matcher(input).matches(); // EXPECT-NOFLAG
    }
}
