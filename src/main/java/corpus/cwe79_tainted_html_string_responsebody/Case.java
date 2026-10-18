// RULE: cwe79-tainted-html-string-responsebody  CWE: CWE-079  LANE: taint
package corpus.cwe79_tainted_html_string_responsebody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.GetMapping;
public class Case {
    // POSITIVE: tainted value returned verbatim from a @ResponseBody method
    @GetMapping("/x")
    @ResponseBody
    public String vulnerable(@RequestParam String p) {
        return "<b>" + p + "</b>"; // EXPECT-FLAG
    }
    // NEGATIVE: constant return body
    @GetMapping("/y")
    @ResponseBody
    public String safe() {
        return "<b>ok</b>"; // EXPECT-NOFLAG
    }
}
