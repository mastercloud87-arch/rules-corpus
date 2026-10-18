// RULE: cwe611-documentbuilderfactory-disallow-doctype-decl-missing  CWE: CWE-611  LANE: pattern
package corpus.cwe611_documentbuilderfactory_disallow_doctype_decl_missing;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
public class Case {
    // POSITIVE: builder built from a factory variable with no hardening setFeature
    DocumentBuilder vulnerable() throws ParserConfigurationException {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        return f.newDocumentBuilder(); // EXPECT-FLAG
    }
    // NEGATIVE: the factory is hardened via setFeature before building
    DocumentBuilder safe() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return f.newDocumentBuilder(); // EXPECT-NOFLAG
    }
}
