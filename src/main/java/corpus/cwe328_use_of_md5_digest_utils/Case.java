// RULE: cwe328-use-of-md5-digest-utils  CWE: CWE-328  LANE: pattern
package corpus.cwe328_use_of_md5_digest_utils;
import org.apache.commons.codec.digest.DigestUtils;
public class Case {
    // POSITIVE: .digest(...) whose receiver is DigestUtils.getMd5Digest()
    byte[] vulnerable(byte[] data) {
        return DigestUtils.getMd5Digest().digest(data); // EXPECT-FLAG
    }
    // NEGATIVE: SHA-256 digest via DigestUtils (different, strong receiver)
    byte[] safe(byte[] data) {
        return DigestUtils.getSha256Digest().digest(data); // EXPECT-NOFLAG
    }
}
