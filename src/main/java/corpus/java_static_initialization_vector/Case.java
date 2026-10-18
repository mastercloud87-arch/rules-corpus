// RULE: java/static-initialization-vector  CWE: CWE-1204  LANE: taint
package corpus.java_static_initialization_vector;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
public class Case {
    // POSITIVE: a static (never dynamically filled) IV used to encrypt
    void vulnerable(Cipher cipher, Key key) throws Exception {
        byte[] iv = new byte[16];
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)); // EXPECT-FLAG
    }
    // NEGATIVE: the IV is filled by a CSPRNG before use
    void safe(Cipher cipher, Key key) throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv)); // EXPECT-NOFLAG
    }
}
