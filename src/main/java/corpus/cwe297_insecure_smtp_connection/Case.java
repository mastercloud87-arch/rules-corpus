// RULE: cwe297-insecure-smtp-connection  CWE: CWE-297  LANE: pattern
package corpus.cwe297_insecure_smtp_connection;
public class Case {
    // POSITIVE: SimpleEmail.send() without setSSLCheckServerIdentity(true)
    void vulnerable() {
        SimpleEmail e = new SimpleEmail();
        e.send(); // EXPECT-FLAG
    }
    // NEGATIVE: setSSLCheckServerIdentity(true) called before send()
    void safe() {
        SimpleEmail e = new SimpleEmail();
        e.setSSLCheckServerIdentity(true);
        e.send(); // EXPECT-NOFLAG
    }
}
// Apache Commons Email is not in the available libraries; a top-level stand-in whose
// fully-qualified name ends in ".SimpleEmail" (what the rule matches) with faithful methods.
class SimpleEmail {
    void setSSLCheckServerIdentity(boolean b) { }
    String send() { return "ok"; }
}
