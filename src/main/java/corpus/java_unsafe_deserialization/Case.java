// RULE: java/unsafe-deserialization  CWE: CWE-502  LANE: taint
package corpus.java_unsafe_deserialization;
import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
public class Case {
    // POSITIVE: a remote stream is deserialized via ObjectInputStream.readObject
    Object vulnerable(HttpServletRequest request) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject(); // EXPECT-FLAG
    }
    // NEGATIVE: a trusted (non-remote) byte[] is deserialized
    Object safe(byte[] trusted) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(trusted));
        return ois.readObject(); // EXPECT-NOFLAG
    }
}
