// RULE: cwe319-telnet-request  CWE: CWE-319  LANE: pattern
package corpus.cwe319_telnet_request;
public class Case {
    // local stand-ins for Apache Commons Net TelnetClient / an encrypted alternative (lib not on classpath)
    static class TelnetClient { void connect(String host) {} }
    static class SSHClient { void connect(String host) {} }
    // POSITIVE: cleartext telnet connection
    void vulnerable() {
        TelnetClient tc = new TelnetClient();
        tc.connect("host"); // EXPECT-FLAG
    }
    // NEGATIVE: encrypted SSH client connect -> not TelnetClient
    void safe() {
        SSHClient ssh = new SSHClient();
        ssh.connect("host"); // EXPECT-NOFLAG
    }
}
