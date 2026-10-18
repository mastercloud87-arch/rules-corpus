// RULE: cwe1333-java-pattern-from-string-parameter  CWE: CWE-1333  LANE: pattern
package corpus.cwe1333_java_pattern_from_string_parameter;
import java.util.regex.Pattern;
public class Case {
    // POSITIVE: a String method parameter used directly as the regex of Pattern.compile
    Pattern vulnerable(String re) {
        return Pattern.compile(re); // EXPECT-FLAG
    }
    // NEGATIVE: a constant regex literal -> not a parameter-derived pattern
    Pattern safe() {
        return Pattern.compile("[a-z]+"); // EXPECT-NOFLAG
    }
}
