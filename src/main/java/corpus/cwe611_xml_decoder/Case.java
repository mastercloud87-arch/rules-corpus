// RULE: cwe611-xml-decoder  CWE: CWE-611  LANE: pattern
package corpus.cwe611_xml_decoder;
import java.io.InputStream;
public class Case {
    // POSITIVE: XMLDecoder over a non-constant (stream) source
    Object vulnerable(InputStream in) {
        return new XMLDecoder(in).readObject(); // EXPECT-FLAG
    }
    // NEGATIVE: XMLDecoder over a constant string
    Object safe() {
        return new XMLDecoder("<constant/>").readObject(); // EXPECT-NOFLAG
    }
    // minimal java.beans.XMLDecoder stand-in (arg typed Object so the const-string near-miss compiles)
    static final class XMLDecoder {
        XMLDecoder(Object in) {}
        Object readObject() { return null; }
    }
}
