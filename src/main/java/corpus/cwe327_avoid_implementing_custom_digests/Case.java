// RULE: cwe327-avoid-implementing-custom-digests  CWE: CWE-327  LANE: pattern
package corpus.cwe327_avoid_implementing_custom_digests;
import java.security.MessageDigest;
public class Case {
    // POSITIVE: a class rolling its own digest by extending MessageDigest
    static class MyDigest extends MessageDigest { // EXPECT-FLAG
        MyDigest() { super("MyDigest"); }
        protected byte[] engineDigest() { return new byte[0]; }
        protected void engineReset() {}
        protected void engineUpdate(byte input) {}
        protected void engineUpdate(byte[] input, int offset, int len) {}
    }
    // NEGATIVE: uses the JDK digest, does not subclass MessageDigest
    static class SafeHasher { // EXPECT-NOFLAG
        MessageDigest md;
    }
}
