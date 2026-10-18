// RULE: cwe798-hardcoded-secret-key-spec  CWE: CWE-798  LANE: literal
package corpus.cwe798_hardcoded_secret_key_spec;
import javax.crypto.spec.SecretKeySpec;
public class Case {
    // POSITIVE: key bytes derived from a String literal passed to new SecretKeySpec.
    SecretKeySpec vulnerable() {
        return new SecretKeySpec("1234567890123456".getBytes(), "AES"); // EXPECT-FLAG
    }
    // NEGATIVE: key bytes from a non-constant source -> must not flag.
    SecretKeySpec safe(byte[] keyFromKeystore) {
        return new SecretKeySpec(keyFromKeystore, "AES"); // EXPECT-NOFLAG
    }
}
