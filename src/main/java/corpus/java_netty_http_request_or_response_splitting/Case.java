// RULE: java/netty-http-request-or-response-splitting  CWE: CWE-113  LANE: pattern
package corpus.java_netty_http_request_or_response_splitting;
// NOTE: Netty (io.netty) is not on the corpus classpath; this local stand-in
// mirrors DefaultHttpResponse(version, status, validateHeaders) so the file
// resolves. The rule matches the real io.netty.handler.codec.http owner with a
// `false` header-validation argument (arg index 2), which the stand-in cannot
// reproduce by fully-qualified type.
public class Case {
    // POSITIVE: header validation disabled (false) at the validate-headers argument
    DefaultHttpResponse vulnerable(HttpVersion v, HttpResponseStatus s) {
        return new DefaultHttpResponse(v, s, false); // EXPECT-FLAG
    }
    // NEGATIVE: header validation enabled (true)
    DefaultHttpResponse safe(HttpVersion v, HttpResponseStatus s) {
        return new DefaultHttpResponse(v, s, true); // EXPECT-NOFLAG
    }
    static class HttpVersion {}
    static class HttpResponseStatus {}
    static class DefaultHttpResponse {
        DefaultHttpResponse(HttpVersion version, HttpResponseStatus status, boolean validateHeaders) {}
    }
}
