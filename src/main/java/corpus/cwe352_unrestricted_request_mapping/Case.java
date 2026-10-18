// RULE: cwe352-unrestricted-request-mapping  CWE: CWE-352  LANE: pattern
package corpus.cwe352_unrestricted_request_mapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
public class Case {
    // POSITIVE: @RequestMapping with no method= attribute on a state-changing endpoint
    @RequestMapping("/transfer") // EXPECT-FLAG
    public String vulnerable() {
        return "ok";
    }
    // NEGATIVE: an explicit method= restriction
    @RequestMapping(value = "/home", method = RequestMethod.GET) // EXPECT-NOFLAG
    public String safe() {
        return "home";
    }
}
