// RULE: java/xxe  CWE: CWE-611  LANE: taint
package corpus.java_xxe;
import jakarta.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;
import java.io.IOException;
public class Case {
    // POSITIVE: remote stream parsed by a non-hardened DocumentBuilder
    void vulnerable(HttpServletRequest request) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(request.getInputStream()); // EXPECT-FLAG
    }
    // NEGATIVE: a constant URI (no user-provided value) parsed by the same parser
    void safe() throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse("local-config.xml"); // EXPECT-NOFLAG
    }
}
