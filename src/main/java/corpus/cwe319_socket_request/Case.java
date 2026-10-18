// RULE: cwe319-socket-request  CWE: CWE-319  LANE: literal
package corpus.cwe319_socket_request;
import java.net.Socket;
import java.io.IOException;
public class Case {
    // POSITIVE: raw Socket opened to a cleartext-scheme (http://) endpoint literal
    void vulnerable() throws IOException {
        Socket s = new Socket("http://example.com", 80); // EXPECT-FLAG
        s.close();
    }
    // NEGATIVE: plain host literal (no http/telnet/ftp scheme) -> this rule stays quiet
    void safe() throws IOException {
        Socket s = new Socket("example.com", 443); // EXPECT-NOFLAG
        s.close();
    }
}
