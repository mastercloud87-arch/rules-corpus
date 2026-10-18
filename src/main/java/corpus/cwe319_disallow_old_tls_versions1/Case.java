// RULE: cwe319-disallow-old-tls-versions1  CWE: CWE-319  LANE: pattern
package corpus.cwe319_disallow_old_tls_versions1;
public class Case {
    // local stand-in for Apache HttpComponents SSLConnectionSocketFactory (lib not on classpath)
    static class SSLConnectionSocketFactory {
        SSLConnectionSocketFactory(Object ctx) {}
        SSLConnectionSocketFactory(Object ctx, String[] protocols, Object v, Object h) {}
    }
    // POSITIVE: creation does not restrict protocols to TLSv1.2/TLSv1.3
    Object vulnerable(Object sslContext) {
        return new SSLConnectionSocketFactory(sslContext); // EXPECT-FLAG
    }
    // NEGATIVE: protocols array pins TLSv1.2/TLSv1.3 -> safe
    Object safe(Object sslContext) {
        return new SSLConnectionSocketFactory(sslContext, new String[]{"TLSv1.2", "TLSv1.3"}, null, null); // EXPECT-NOFLAG
    }
}
