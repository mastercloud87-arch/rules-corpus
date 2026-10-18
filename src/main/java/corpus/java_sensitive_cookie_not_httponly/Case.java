// RULE: java/sensitive-cookie-not-httponly  CWE: CWE-1004  LANE: taint
package corpus.java_sensitive_cookie_not_httponly;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
public class Case {
    // POSITIVE: a sensitively-named cookie added without the HttpOnly flag
    void vulnerable(HttpServletResponse response, String value) {
        Cookie c = new Cookie("sessionToken", value);
        response.addCookie(c); // EXPECT-FLAG
    }
    // NEGATIVE: setHttpOnly(true) marks the cookie safe before addCookie
    void safe(HttpServletResponse response, String value) {
        Cookie c = new Cookie("sessionToken", value);
        c.setHttpOnly(true);
        response.addCookie(c); // EXPECT-NOFLAG
    }
}
