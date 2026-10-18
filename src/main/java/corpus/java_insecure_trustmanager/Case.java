// RULE: java/insecure-trustmanager  CWE: CWE-295  LANE: flow
package corpus.java_insecure_trustmanager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
public class Case {
    // POSITIVE: a TrustManager whose checkServerTrusted never throws reaches SSLContext.init
    void vulnerable() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] tms = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tms, null); // EXPECT-FLAG
    }
    // NEGATIVE: checkServerTrusted actually validates (throws) -> not an insecure manager
    void safe() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] tms = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
                    throw new CertificateException("reject");
                }
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tms, null); // EXPECT-NOFLAG
    }
}
