// RULE: cwe502-objectinputstream-deserialization-servlets  CWE: CWE-502  LANE: taint
package corpus.cwe502_objectinputstream_deserialization_servlets;
import jakarta.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
// org.apache.commons.io.input.ClassLoaderObjectInputStream is not an available library;
// a minimal local stand-in keeps the matched shape faithful: the 2-arg
// (ClassLoader, InputStream) constructor whose arg 1 is the stream.
public class Case {
    // POSITIVE: remote input reaches arg 1 of new ClassLoaderObjectInputStream(cl, in)
    Object vulnerable(HttpServletRequest request) throws Exception {
        ClassLoader cl = getClass().getClassLoader();
        ClassLoaderObjectInputStream ois = new ClassLoaderObjectInputStream(cl, request.getInputStream()); // EXPECT-FLAG
        return ois.readObject();
    }
    // NEGATIVE: a local (non-remote) stream in arg 1
    Object safe(byte[] local) throws Exception {
        ClassLoader cl = getClass().getClassLoader();
        ClassLoaderObjectInputStream ois = new ClassLoaderObjectInputStream(cl, new ByteArrayInputStream(local)); // EXPECT-NOFLAG
        return ois.readObject();
    }

    static class ClassLoaderObjectInputStream {
        ClassLoaderObjectInputStream(ClassLoader cl, InputStream in) {}
        Object readObject() { return null; }
    }
}
