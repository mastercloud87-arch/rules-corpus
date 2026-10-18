// RULE: java/insecure-cookie  CWE: CWE-614  LANE: pattern
package corpus.java_insecure_cookie;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
public class Case {
    // POSITIVE: a cookie added without the Secure flag ever being set
    void vulnerable(String v, HttpServletResponse response) {
        Cookie c = new Cookie("sid", v);
        response.addCookie(c); // EXPECT-FLAG
    }
    // NEGATIVE: setSecure(true) on the same cookie object -> proven secure
    void safe(String v, HttpServletResponse response) {
        Cookie c = new Cookie("sid", v);
        c.setSecure(true);
        response.addCookie(c); // EXPECT-NOFLAG
    }
}
