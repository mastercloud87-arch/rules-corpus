// RULE: cwe327-ecb-cipher  CWE: CWE-327  LANE: literal
package corpus.cwe327_ecb_cipher;
import javax.crypto.Cipher;
import java.util.Properties;
public class Case {
    // POSITIVE: weak cipher algorithm read from a .properties file flows into Cipher.getInstance
    Cipher vulnerable(Properties props) throws Exception {
        String alg = props.getProperty("cryptoAlg1");
        return Cipher.getInstance(alg); // EXPECT-FLAG
    }
    // NEGATIVE: a safe literal transformation (not config-driven) -> must not flag
    Cipher safe() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding"); // EXPECT-NOFLAG
    }
}
