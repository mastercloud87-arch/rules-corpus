// RULE: cwe326-weak-ssl-context  CWE: CWE-326  LANE: literal
package corpus.cwe326_weak_ssl_context;
import javax.net.ssl.SSLContext;
import java.security.NoSuchAlgorithmException;
public class Case {
    // POSITIVE: weak SSL/TLS protocol literal
    SSLContext vulnerable() throws NoSuchAlgorithmException {
        return SSLContext.getInstance("TLS"); // EXPECT-FLAG
    }
    // NEGATIVE: strong protocol literal -> must not flag
    SSLContext safe() throws NoSuchAlgorithmException {
        return SSLContext.getInstance("TLSv1.2"); // EXPECT-NOFLAG
    }
}
