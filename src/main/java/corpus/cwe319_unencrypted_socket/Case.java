// RULE: cwe319-unencrypted-socket  CWE: CWE-319  LANE: pattern
package corpus.cwe319_unencrypted_socket;
import java.net.Socket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
public class Case {
    // POSITIVE: plaintext socket to a remote host
    void vulnerable() throws IOException {
        Socket s = new Socket("example.com", 8080); // EXPECT-FLAG
        s.close();
    }
    // NEGATIVE (FP05): a TLS socket is not cleartext -> must not flag
    void safe() throws IOException {
        Socket s = SSLSocketFactory.getDefault().createSocket("example.com", 443); // EXPECT-NOFLAG
        s.close();
    }
}
