// RULE: cwe319-httpget-http-request  CWE: CWE-319  LANE: literal
package corpus.cwe319_httpget_http_request;
public class Case {
    // local stand-in for org.apache.http.client.methods.HttpGet (lib not on classpath)
    static class HttpGet { HttpGet(String url) {} }
    // POSITIVE: HttpGet built with an http:// URL literal
    Object vulnerable() {
        return new HttpGet("http://example.com"); // EXPECT-FLAG
    }
    // NEGATIVE: https:// URL literal -> encrypted transport
    Object safe() {
        return new HttpGet("https://example.com"); // EXPECT-NOFLAG
    }
}
