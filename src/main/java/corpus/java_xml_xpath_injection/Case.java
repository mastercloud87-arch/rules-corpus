// RULE: java/xml/xpath-injection  CWE: CWE-643  LANE: taint
package corpus.java_xml_xpath_injection;
import jakarta.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpressionException;
import org.w3c.dom.Document;
public class Case {
    // POSITIVE: remote value concatenated into the XPath expression (XPath.evaluate arg0)
    void vulnerable(HttpServletRequest request, Document doc) throws XPathExpressionException {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.evaluate("/users/user[@name='" + request.getParameter("n") + "']", doc); // EXPECT-FLAG
    }
    // NEGATIVE: constant expression -> no user-provided value reaches the sink
    void safe(Document doc) throws XPathExpressionException {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.evaluate("/users/user[@name='admin']", doc); // EXPECT-NOFLAG
    }
}
