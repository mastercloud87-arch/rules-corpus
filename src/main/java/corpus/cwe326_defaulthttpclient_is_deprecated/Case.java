// RULE: cwe326-defaulthttpclient-is-deprecated  CWE: CWE-326  LANE: pattern
package corpus.cwe326_defaulthttpclient_is_deprecated;
public class Case {
    // local stand-ins for Apache HTTP Components (lib not on classpath)
    static class DefaultHttpClient {}
    static class CloseableHttpClient {}
    static class HttpClients { static CloseableHttpClient createDefault() { return new CloseableHttpClient(); } }
    // POSITIVE: deprecated DefaultHttpClient creation (no TLS1.2 support)
    Object vulnerable() {
        return new DefaultHttpClient(); // EXPECT-FLAG
    }
    // NEGATIVE: modern client builder -> not a DefaultHttpClient creation
    Object safe() {
        return HttpClients.createDefault(); // EXPECT-NOFLAG
    }
}
