// RULE: cwe798-system-setproperty-hardcoded-secret  CWE: CWE-798  LANE: literal
package corpus.cwe798_system_setproperty_hardcoded_secret;
public class Case {
    // POSITIVE: a non-empty hard-coded value under a keystore-password System property key.
    void vulnerable() {
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit"); // EXPECT-FLAG
    }
    // NEGATIVE: a non-password property key -> must not flag.
    void safe() {
        System.setProperty("user.workingDirectory", "/tmp"); // EXPECT-NOFLAG
    }
}
