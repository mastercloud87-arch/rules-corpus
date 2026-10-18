// RULE: cwe470-unsafe-reflection  CWE: CWE-470  LANE: pattern
package corpus.cwe470_unsafe_reflection;
import jakarta.servlet.http.HttpServletRequest;
public class Case {
    // POSITIVE: Class.forName with a non-constant (request-derived) class name
    Object vulnerable(HttpServletRequest request) throws Exception {
        return Class.forName(request.getParameter("cls")).getDeclaredConstructor().newInstance(); // EXPECT-FLAG
    }
    // NEGATIVE: Class.forName with a compile-time constant string
    Class<?> safe() throws Exception {
        return Class.forName("java.util.List"); // EXPECT-NOFLAG
    }
}
