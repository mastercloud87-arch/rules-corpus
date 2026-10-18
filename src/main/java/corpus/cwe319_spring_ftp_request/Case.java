// RULE: cwe319-spring-ftp-request  CWE: CWE-319  LANE: pattern
package corpus.cwe319_spring_ftp_request;
public class Case {
    // local stand-in for Spring Integration DefaultFtpSessionFactory (lib not on classpath)
    static class DefaultFtpSessionFactory { void setHost(String host) {} }
    // POSITIVE: plaintext ftp:// host on the FTP session factory
    void vulnerable() {
        DefaultFtpSessionFactory f = new DefaultFtpSessionFactory();
        f.setHost("ftp://files.example.com"); // EXPECT-FLAG
    }
    // NEGATIVE: bare hostname (no ftp:// scheme literal) -> must not flag
    void safe() {
        DefaultFtpSessionFactory f = new DefaultFtpSessionFactory();
        f.setHost("files.example.com"); // EXPECT-NOFLAG
    }
}
