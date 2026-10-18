// RULE: cwe327-no-null-cipher  CWE: CWE-327  LANE: pattern
package corpus.cwe327_no_null_cipher;
import javax.crypto.Cipher;
import javax.crypto.NullCipher;
import java.security.GeneralSecurityException;
public class Case {
    // POSITIVE: new NullCipher() performs no encryption
    void vulnerable() {
        Cipher c = new NullCipher(); // EXPECT-FLAG
    }
    // NEGATIVE: a real cipher creation is not a NullCipher
    void safe() throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // EXPECT-NOFLAG
    }
}
