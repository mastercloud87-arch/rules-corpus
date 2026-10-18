// RULE: cwe79-xssrequestwrapper-is-insecure  CWE: CWE-079  LANE: pattern
package corpus.cwe79_xssrequestwrapper_is_insecure;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
public class Case {
    // POSITIVE (arm A): the known-insecure dzone XSSRequestWrapper anti-pattern:
    // a class that extends *HttpServletRequestWrapper.
    public static class XSSRequestWrapper extends HttpServletRequestWrapper { // EXPECT-FLAG
        public XSSRequestWrapper(HttpServletRequest request) { super(request); }
    }
    // NEGATIVE: a class that does NOT extend HttpServletRequestWrapper -> must not flag.
    public static class SafeRequestHelper { // EXPECT-NOFLAG
        String clean(String s) { return s; }
    }
}
