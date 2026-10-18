// RULE: cwe611-saxbuilder-xxe  CWE: CWE-611  LANE: pattern
package corpus.cwe611_saxbuilder_xxe;
public class Case {
    // POSITIVE: SAXBuilder stored in a local with no hardening call
    Object vulnerable() {
        SAXBuilder b = new SAXBuilder(); // EXPECT-FLAG
        return b;
    }
    // NEGATIVE: disallow-doctype-decl feature set -> hardened
    Object safe() {
        SAXBuilder b = new SAXBuilder(); // EXPECT-NOFLAG
        b.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return b;
    }
    // minimal JDOM SAXBuilder stand-in (org.jdom2.input.SAXBuilder not on the classpath)
    static final class SAXBuilder {
        void setFeature(String name, boolean value) {}
        void setExpandEntities(boolean b) {}
    }
}
