// RULE: cwe319-tls-renegotiation  CWE: CWE-319  LANE: literal
package corpus.cwe319_tls_renegotiation;
public class Case {
    // POSITIVE: enabling unsafe TLS renegotiation
    void vulnerable() {
        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true"); // EXPECT-FLAG
    }
    // NEGATIVE: value is "false" -> renegotiation not enabled
    void safe() {
        System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "false"); // EXPECT-NOFLAG
    }
}
