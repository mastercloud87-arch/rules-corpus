// RULE: cwe601-spring-unvalidated-redirect  CWE: CWE-601  LANE: taint
package corpus.cwe601_spring_unvalidated_redirect;
import org.springframework.web.bind.annotation.RequestParam;
public class Case {
    // POSITIVE: user input concatenated after the Spring "redirect:" view prefix
    String vulnerable(@RequestParam String url) {
        return "redirect:" + url; // EXPECT-FLAG
    }
    // NEGATIVE: constant redirect destination
    String safe() {
        return "redirect:/home"; // EXPECT-NOFLAG
    }
}
