// RULE: cwe611-transformerfactory-dtds-not-disabled  CWE: CWE-611  LANE: pattern
package corpus.cwe611_transformerfactory_dtds_not_disabled;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
public class Case {
    // POSITIVE: transformer built from a factory variable with no setAttribute hardening
    Transformer vulnerable() throws Exception {
        TransformerFactory f = TransformerFactory.newInstance();
        return f.newTransformer(); // EXPECT-FLAG
    }
    // NEGATIVE: external DTD access disabled via setAttribute -> hardened
    Transformer safe() throws Exception {
        TransformerFactory f = TransformerFactory.newInstance();
        f.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
        return f.newTransformer(); // EXPECT-NOFLAG
    }
}
