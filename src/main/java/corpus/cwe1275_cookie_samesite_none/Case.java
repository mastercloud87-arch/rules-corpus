// RULE: cwe1275-cookie-samesite-none  CWE: CWE-1275  LANE: pattern
package corpus.cwe1275_cookie_samesite_none;
// NOTE: Micronaut cookie API (Cookie.of / SameSite) is absent from the available libraries;
// the rule matches these bare/unresolved names, which is how it fires in practice.
public class Case {
    // POSITIVE: a Micronaut cookie with SameSite explicitly set to NONE
    Object vulnerable(String v) {
        return Cookie.of("sid", v).sameSite(SameSite.NONE); // EXPECT-FLAG
    }
    // NEGATIVE: SameSite set to STRICT (not None)
    Object safe(String v) {
        return Cookie.of("sid", v).sameSite(SameSite.STRICT); // EXPECT-NOFLAG
    }
}
