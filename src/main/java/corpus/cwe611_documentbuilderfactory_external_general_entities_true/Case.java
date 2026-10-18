// RULE: cwe611-documentbuilderfactory-external-general-entities-true  CWE: CWE-611  LANE: pattern
package corpus.cwe611_documentbuilderfactory_external_general_entities_true;
import javax.xml.parsers.DocumentBuilderFactory;
public class Case {
    // POSITIVE: setFeature affirmatively enabling external general entities
    void vulnerable() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", true); // EXPECT-FLAG
    }
    // NEGATIVE: disallow-doctype-decl set to true is a safe hardening call
    void safe() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); // EXPECT-NOFLAG
    }
}
