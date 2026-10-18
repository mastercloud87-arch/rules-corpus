// RULE: cwe319-disallow-old-tls-versions2  CWE: CWE-319  LANE: literal
package corpus.cwe319_disallow_old_tls_versions2;
public class Case {
    // POSITIVE: client protocols property set to a weak TLS version
    void vulnerable() {
        System.setProperty("jdk.tls.client.protocols", "TLSv1"); // EXPECT-FLAG
    }
    // NEGATIVE: strong protocol value -> must not flag
    void safe() {
        System.setProperty("jdk.tls.client.protocols", "TLSv1.2"); // EXPECT-NOFLAG
    }
}
