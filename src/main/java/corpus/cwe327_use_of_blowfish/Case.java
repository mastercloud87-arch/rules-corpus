// RULE: cwe327-use-of-blowfish  CWE: CWE-327  LANE: literal
package corpus.cwe327_use_of_blowfish;
import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
public class Case {
    // POSITIVE: Blowfish literal as the algorithm argument of Cipher.getInstance
    void vulnerable() throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("Blowfish/CBC/PKCS5Padding"); // EXPECT-FLAG
    }
    // NEGATIVE: a strong algorithm literal
    void safe() throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // EXPECT-NOFLAG
    }
}
