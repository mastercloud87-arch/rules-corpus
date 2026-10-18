// RULE: cwe352-cookie-missing-samesite  CWE: CWE-352  LANE: pattern
package corpus.cwe352_cookie_missing_samesite;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
public class Case {
    // POSITIVE: addCookie on a response that never emits a SameSite Set-Cookie header
    void vulnerable(HttpServletResponse response) {
        Cookie c = new Cookie("sid", "v");
        response.addCookie(c); // EXPECT-FLAG
    }
    // NEGATIVE: the same response declaration also writes a SameSite Set-Cookie header
    void safe(HttpServletResponse response) {
        response.setHeader("Set-Cookie", "sid=v; HttpOnly; SameSite=Strict"); // EXPECT-NOFLAG
        Cookie c = new Cookie("sid", "v");
        response.addCookie(c); // EXPECT-NOFLAG
    }
}
