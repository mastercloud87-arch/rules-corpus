// RULE: cwe79-tainted-html-string  CWE: CWE-079  LANE: taint
package corpus.cwe79_tainted_html_string;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;
public class Case {
    // POSITIVE: tainted value passed into a Spring ResponseEntity body
    ResponseEntity<String> vulnerable(@RequestParam String p) {
        return ResponseEntity.ok("<b>" + p + "</b>"); // EXPECT-FLAG
    }
    // NEGATIVE: constant HTML body
    ResponseEntity<String> safe() {
        return ResponseEntity.ok("<b>ok</b>"); // EXPECT-NOFLAG
    }
}
