// RULE: cwe319-unirest-http-request  CWE: CWE-319  LANE: literal
package corpus.cwe319_unirest_http_request;
public class Case {
    // local stand-in for Unirest (lib not on classpath)
    static class Unirest {
        static Object get(String url) { return null; }
        static Object post(String url) { return null; }
    }
    // POSITIVE: Unirest request to an http:// URL literal
    Object vulnerable() {
        return Unirest.get("http://example.com"); // EXPECT-FLAG
    }
    // NEGATIVE: https:// URL literal -> encrypted transport
    Object safe() {
        return Unirest.get("https://example.com"); // EXPECT-NOFLAG
    }
}
