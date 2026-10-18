// RULE: cwe319-httpurlconnection-http-request  CWE: CWE-319  LANE: pattern
package corpus.cwe319_httpurlconnection_http_request;
import java.net.URL;
import java.net.HttpURLConnection;
public class Case {
    // POSITIVE: new URL("http://...") opened as a connection
    void vulnerable() throws Exception {
        URL url = new URL("http://example.com"); // EXPECT-FLAG
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.getInputStream();
    }
    // NEGATIVE: https:// URL -> encrypted transport
    void safe() throws Exception {
        URL url = new URL("https://example.com"); // EXPECT-NOFLAG
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.getInputStream();
    }
}
