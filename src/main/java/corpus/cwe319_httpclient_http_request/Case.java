// RULE: cwe319-httpclient-http-request  CWE: CWE-319  LANE: pattern
package corpus.cwe319_httpclient_http_request;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
public class Case {
    // POSITIVE: URI.create("http://...") in a method that sends via HttpClient
    void vulnerable() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        URI u = URI.create("http://example.com"); // EXPECT-FLAG
        HttpRequest req = HttpRequest.newBuilder(u).build();
        client.send(req, HttpResponse.BodyHandlers.ofString());
    }
    // NEGATIVE: https:// URI -> encrypted transport
    void safe() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        URI u = URI.create("https://example.com"); // EXPECT-NOFLAG
        HttpRequest req = HttpRequest.newBuilder(u).build();
        client.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
