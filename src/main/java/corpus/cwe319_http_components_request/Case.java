// RULE: cwe319-http-components-request  CWE: CWE-319  LANE: pattern
package corpus.cwe319_http_components_request;
public class Case {
    // local stand-ins for Apache HTTP Components (lib not on classpath)
    static class HttpGet { HttpGet(String url) {} }
    static class HttpClient { Object execute(Object req) { return null; } }
    // POSITIVE: request built with an http:// URL is executed
    void vulnerable(HttpClient client) {
        HttpGet get = new HttpGet("http://example.com/api");
        client.execute(get); // EXPECT-FLAG
    }
    // NEGATIVE: https:// request -> encrypted transport
    void safe(HttpClient client) {
        HttpGet get = new HttpGet("https://example.com/api");
        client.execute(get); // EXPECT-NOFLAG
    }
}
