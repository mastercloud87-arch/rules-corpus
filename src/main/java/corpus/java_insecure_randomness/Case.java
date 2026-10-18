// RULE: java/insecure-randomness  CWE: CWE-330  LANE: taint
package corpus.java_insecure_randomness;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Random;
import java.security.SecureRandom;
public class Case {
    // POSITIVE: a java.util.Random value used as a cookie (session) value
    void vulnerable(HttpServletResponse response) {
        int r = new Random().nextInt();
        Cookie c = new Cookie("sid", "" + r); // EXPECT-FLAG
        response.addCookie(c);
    }
    // NEGATIVE: a cryptographically secure RNG feeds the same sink
    void safe(HttpServletResponse response) {
        int r = new SecureRandom().nextInt();
        Cookie c = new Cookie("sid", "" + r); // EXPECT-NOFLAG
        response.addCookie(c);
    }
}
