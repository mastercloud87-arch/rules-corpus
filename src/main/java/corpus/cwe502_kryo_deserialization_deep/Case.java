// RULE: cwe502-kryo-deserialization-deep  CWE: CWE-502  LANE: taint
package corpus.cwe502_kryo_deserialization_deep;
import jakarta.servlet.http.HttpServletRequest;
import java.io.InputStream;
// com.esotericsoftware.kryo is not an available library; minimal local stand-ins keep
// the matched shape faithful: Kryo.readClassAndObject(new Input(remoteStream)).
public class Case {
    // POSITIVE: remote input reaches arg 0 (the Input) of Kryo.readClassAndObject
    Object vulnerable(HttpServletRequest request, Kryo kryo) throws Exception {
        Input in = new Input(request.getInputStream());
        return kryo.readClassAndObject(in); // EXPECT-FLAG
    }
    // NEGATIVE: a local (non-remote) stream source
    Object safe(Kryo kryo, InputStream local) {
        Input in = new Input(local);
        return kryo.readObject(in, Object.class); // EXPECT-NOFLAG
    }

    static class Kryo {
        Object readClassAndObject(Input in) { return null; }
        Object readObject(Input in, Class<?> t) { return null; }
    }
    static class Input {
        Input(InputStream s) {}
    }
}
