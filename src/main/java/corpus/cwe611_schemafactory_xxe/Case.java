// RULE: cwe611-schemafactory-xxe  CWE: CWE-611  LANE: pattern
package corpus.cwe611_schemafactory_xxe;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Schema;
import javax.xml.XMLConstants;
public class Case {
    // POSITIVE: schema built from a factory variable with no external-access hardening
    Schema vulnerable() throws Exception {
        SchemaFactory f = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        return f.newSchema(); // EXPECT-FLAG
    }
    // NEGATIVE: external DTD access disabled -> hardened
    Schema safe() throws Exception {
        SchemaFactory f = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        f.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        return f.newSchema(); // EXPECT-NOFLAG
    }
}
