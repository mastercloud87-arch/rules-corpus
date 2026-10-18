// RULE: java/cleartext-storage-in-cookie  CWE: CWE-315  LANE: taint
package corpus.java_cleartext_storage_in_cookie;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
public class Case {
    // POSITIVE: a sensitively-named value stored in a cookie in cleartext
    void vulnerable(String password, HttpServletResponse response) {
        Cookie c = new Cookie("sess", password);
        response.addCookie(c); // EXPECT-FLAG
    }
    // NEGATIVE: a non-sensitive value (name/value not in the secret lexicon)
    void safe(String theme, HttpServletResponse response) {
        Cookie c = new Cookie("theme", theme);
        response.addCookie(c); // EXPECT-NOFLAG
    }
}
