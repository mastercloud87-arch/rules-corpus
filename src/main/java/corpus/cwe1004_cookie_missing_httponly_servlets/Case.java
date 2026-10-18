// RULE: cwe1004-cookie-missing-httponly-servlets  CWE: CWE-1004  LANE: pattern
package corpus.cwe1004_cookie_missing_httponly_servlets;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
public class Case {
    // POSITIVE: a (non-sensitive-named) cookie added to the response without setHttpOnly
    void vulnerable(HttpServletResponse response, String v) {
        Cookie c = new Cookie("prefs", v);
        response.addCookie(c); // EXPECT-FLAG
    }
    // NEGATIVE: setHttpOnly(true) on the same cookie object -> secured
    void safe(HttpServletResponse response, String v) {
        Cookie c = new Cookie("prefs", v);
        c.setHttpOnly(true);
        response.addCookie(c); // EXPECT-NOFLAG
    }
}
