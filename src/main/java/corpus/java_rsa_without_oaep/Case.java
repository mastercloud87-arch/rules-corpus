// RULE: java/rsa-without-oaep  CWE: CWE-780  LANE: taint
package corpus.java_rsa_without_oaep;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
public class Case {
    // POSITIVE: an "RSA/..." spec string without OAEP padding
    Cipher vulnerable() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("RSA/ECB/PKCS1Padding"); // EXPECT-FLAG
    }
    // NEGATIVE: OAEP padding present in the spec string
    Cipher safe() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // EXPECT-NOFLAG
    }
}
