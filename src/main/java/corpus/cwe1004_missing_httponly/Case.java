// RULE: cwe1004-missing-httponly  CWE: CWE-1004  LANE: pattern
package corpus.cwe1004_missing_httponly;
// NOTE: Micronaut cookie types (NettyCookie/SimpleCookie/Cookie) are not in the available
// libraries; the rule matches these bare type names (unresolved), which is how it fires in
// practice (benchmark note: "API absent from corpus"). Left intentionally unresolved.
public class Case {
    // POSITIVE: a Micronaut cookie created with no httpOnly(...) call on the same object
    Object vulnerable(String v) {
        return new NettyCookie("sid", v); // EXPECT-FLAG
    }
    // NEGATIVE: httpOnly(true) applied to the same cookie object
    Object safe(String v) {
        NettyCookie c = new NettyCookie("sid", v);
        c.httpOnly(true);
        return c; // EXPECT-NOFLAG
    }
}
