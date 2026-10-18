// RULE: cwe611-saxreader-xxe  CWE: CWE-611  LANE: pattern
package corpus.cwe611_saxreader_xxe;
public class Case {
    // POSITIVE: SAXReader stored in a local with no hardening call
    Object vulnerable() {
        SAXReader r = new SAXReader(); // EXPECT-FLAG
        return r;
    }
    // NEGATIVE: disallow-doctype-decl feature set -> hardened
    Object safe() {
        SAXReader r = new SAXReader(); // EXPECT-NOFLAG
        r.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return r;
    }
    // minimal dom4j SAXReader stand-in (org.dom4j.io.SAXReader not on the classpath)
    static final class SAXReader {
        void setFeature(String name, boolean value) {}
    }
}
