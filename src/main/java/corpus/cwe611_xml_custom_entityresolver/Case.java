// RULE: cwe611-xml-custom-entityresolver  CWE: CWE-611  LANE: pattern
package corpus.cwe611_xml_custom_entityresolver;
import org.xml.sax.XMLReader;
import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import java.io.IOException;
public class Case {
    // POSITIVE: a parser is given a custom EntityResolver
    void vulnerable(XMLReader reader) {
        reader.setEntityResolver(new MyResolver()); // EXPECT-FLAG
    }
    // NEGATIVE: no setEntityResolver call -> a different configuration call
    void safe(XMLReader reader) {
        reader.setErrorHandler(new MyErrorHandler()); // EXPECT-NOFLAG
    }
    static final class MyResolver implements EntityResolver {
        public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException { return null; }
    }
    static final class MyErrorHandler implements ErrorHandler {
        public void warning(SAXParseException e) {}
        public void error(SAXParseException e) {}
        public void fatalError(SAXParseException e) {}
    }
}
