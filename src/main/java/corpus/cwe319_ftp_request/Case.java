// RULE: cwe319-ftp-request  CWE: CWE-319  LANE: pattern
package corpus.cwe319_ftp_request;
public class Case {
    // local stand-in for Apache Commons Net FTPClient / secure FTPSClient (lib not on classpath)
    static class FTPClient { void connect(String host) {} }
    static class FTPSClient { void connect(String host) {} }
    // POSITIVE: plaintext FTP connection
    void vulnerable() {
        FTPClient ftp = new FTPClient();
        ftp.connect("files.example.com"); // EXPECT-FLAG
    }
    // NEGATIVE: implicit-TLS FTPS client -> not plaintext FTP
    void safe() {
        FTPSClient ftps = new FTPSClient();
        ftps.connect("files.example.com"); // EXPECT-NOFLAG
    }
}
