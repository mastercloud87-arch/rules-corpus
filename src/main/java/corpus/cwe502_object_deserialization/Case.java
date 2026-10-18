// RULE: cwe502-object-deserialization  CWE: CWE-502  LANE: pattern
package corpus.cwe502_object_deserialization;
import java.io.ObjectInputStream;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
public class Case {
    // POSITIVE: any new ObjectInputStream(...) uses native Java deserialization
    Object vulnerable(InputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(in); // EXPECT-FLAG
        return ois.readObject();
    }
    // NEGATIVE: a non-deserializing stream creation (not ObjectInputStream)
    InputStream safe(byte[] b) {
        return new ByteArrayInputStream(b); // EXPECT-NOFLAG
    }
}
