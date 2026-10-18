// RULE: java/weak-cryptographic-algorithm  CWE: CWE-327  LANE: taint
package corpus.java_weak_cryptographic_algorithm;
import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
public class Case {
    // POSITIVE: insecure algorithm literal "DES" reaches Cipher.getInstance (CryptoAlgoSpec sink)
    void vulnerable() throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("DES"); // EXPECT-FLAG
    }
    // NEGATIVE: strong algorithm literal -> not matched by the insecure-algorithm regex
    void safe() throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // EXPECT-NOFLAG
    }
}
