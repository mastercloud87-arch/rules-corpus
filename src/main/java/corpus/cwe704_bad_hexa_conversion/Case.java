// RULE: cwe704-bad-hexa-conversion  CWE: CWE-704  LANE: pattern
package corpus.cwe704_bad_hexa_conversion;
import java.security.MessageDigest;
public class Case {
    // POSITIVE: Integer.toHexString on MessageDigest.digest() output in the same method
    String vulnerable(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < h.length; i++) {
            sb.append(Integer.toHexString(h[i])); // EXPECT-FLAG
        }
        return sb.toString();
    }
    // NEGATIVE: Integer.toHexString with no MessageDigest.digest in the method
    String safe(int x) {
        return Integer.toHexString(x); // EXPECT-NOFLAG
    }
}
