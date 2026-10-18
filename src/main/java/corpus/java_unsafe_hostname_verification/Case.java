// RULE: java/unsafe-hostname-verification  CWE: CWE-297  LANE: flow
package corpus.java_unsafe_hostname_verification;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
public class Case {
    // POSITIVE: a TrustAll verifier (always returns true) installed as the hostname verifier
    void vulnerable() {
        HostnameVerifier v = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) { return true; }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(v); // EXPECT-FLAG
    }
    // NEGATIVE: a verifier that actually checks the hostname is not a TrustAll source
    void safe() {
        HostnameVerifier v = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return hostname.equals(session.getPeerHost());
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(v); // EXPECT-NOFLAG
    }
}
