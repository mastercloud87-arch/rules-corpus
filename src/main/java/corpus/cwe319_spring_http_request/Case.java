// RULE: cwe319-spring-http-request  CWE: CWE-319  LANE: literal
package corpus.cwe319_spring_http_request;
import org.springframework.web.client.RestTemplate;
public class Case {
    // POSITIVE: RestTemplate call to an http:// URL literal
    String vulnerable(RestTemplate restTemplate) {
        return restTemplate.getForObject("http://example.com", String.class); // EXPECT-FLAG
    }
    // NEGATIVE: https:// URL literal -> encrypted transport
    String safe(RestTemplate restTemplate) {
        return restTemplate.getForObject("https://example.com", String.class); // EXPECT-NOFLAG
    }
}
