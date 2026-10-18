// RULE: java/regex-injection  CWE: CWE-730  LANE: taint
package corpus.java_regex_injection;
import jakarta.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;
public class Case {
    // POSITIVE: remote value used as a regex pattern
    Pattern vulnerable(HttpServletRequest request) {
        String re = request.getParameter("regex");
        return Pattern.compile(re); // EXPECT-FLAG
    }
    // NEGATIVE: Pattern.quote neutralizes the metacharacters (RegexInjectionSanitizer barrier)
    Pattern safe(HttpServletRequest request) {
        String re = Pattern.quote(request.getParameter("regex"));
        return Pattern.compile(re); // EXPECT-NOFLAG
    }
}
