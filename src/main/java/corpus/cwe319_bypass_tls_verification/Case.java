// RULE: cwe319-bypass-tls-verification  CWE: CWE-319  LANE: pattern
package corpus.cwe319_bypass_tls_verification;
import java.security.cert.X509Certificate;
public class Case {
    // POSITIVE: a custom (trust-all) Apache HttpClient TrustStrategy implementation
    TrustStrategy vulnerable() {
        return new TrustStrategy() { // EXPECT-FLAG
            public boolean isTrusted(X509Certificate[] chain, String authType) {
                return true;
            }
        };
    }
    // NEGATIVE: an anonymous implementation of a different interface (not a TrustStrategy)
    CertChecker safe() {
        return new CertChecker() {
            public boolean isTrusted(X509Certificate[] chain, String authType) { // EXPECT-NOFLAG
                return false;
            }
        };
    }
}
// Apache HttpClient's TrustStrategy is not in the available libraries; a top-level stand-in
// whose fully-qualified name ends in ".TrustStrategy" (what the rule matches), plus an
// unrelated interface used for the negative near-miss.
interface TrustStrategy {
    boolean isTrusted(X509Certificate[] chain, String authType);
}
interface CertChecker {
    boolean isTrusted(X509Certificate[] chain, String authType);
}
