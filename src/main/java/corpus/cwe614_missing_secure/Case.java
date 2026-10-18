// RULE: cwe614-missing-secure  CWE: CWE-614  LANE: pattern
package corpus.cwe614_missing_secure;
public class Case {
    // POSITIVE: cookie with the Secure flag explicitly disabled
    Object vulnerable(String v) {
        Cookie c = Cookie.of("sid", v);
        return c.secure(false); // EXPECT-FLAG
    }
    // NEGATIVE: Secure flag enabled
    Object safe(String v) {
        Cookie c = Cookie.of("sid", v);
        return c.secure(true); // EXPECT-NOFLAG
    }
    // minimal Micronaut Cookie stand-in (io.micronaut.http.cookie.Cookie not on the classpath)
    static final class Cookie {
        static Cookie of(String name, String value) { return new Cookie(); }
        Cookie secure(boolean b) { return this; }
    }
}
