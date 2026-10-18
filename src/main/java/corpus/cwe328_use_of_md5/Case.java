// RULE: cwe328-use-of-md5  CWE: CWE-328  LANE: literal
package corpus.cwe328_use_of_md5;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
public class Case {
    // POSITIVE: weak hash literal
    void vulnerable() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5"); // EXPECT-FLAG
    }
    // NEGATIVE: strong hash literal -> must not flag
    void safe() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256"); // EXPECT-NOFLAG
    }
}
