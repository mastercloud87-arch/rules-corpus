// RULE: cwe611-saxparserfactory-disallow-doctype-decl-missing  CWE: CWE-611  LANE: pattern
package corpus.cwe611_saxparserfactory_disallow_doctype_decl_missing;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;
public class Case {
    // POSITIVE: parser built from a factory variable with no hardening setFeature
    SAXParser vulnerable() throws Exception {
        SAXParserFactory f = SAXParserFactory.newInstance();
        return f.newSAXParser(); // EXPECT-FLAG
    }
    // NEGATIVE: the factory is hardened via setFeature before building
    SAXParser safe() throws Exception {
        SAXParserFactory f = SAXParserFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return f.newSAXParser(); // EXPECT-NOFLAG
    }
}
