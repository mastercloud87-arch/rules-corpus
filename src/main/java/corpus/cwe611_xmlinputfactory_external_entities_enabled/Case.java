// RULE: cwe611-xmlinputfactory-external-entities-enabled  CWE: CWE-611  LANE: pattern
package corpus.cwe611_xmlinputfactory_external_entities_enabled;
import javax.xml.stream.XMLInputFactory;
public class Case {
    // POSITIVE: setProperty affirmatively enabling external entities
    void vulnerable() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty("javax.xml.stream.isSupportingExternalEntities", true); // EXPECT-FLAG
    }
    // NEGATIVE: external entities disabled
    void safe() {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false); // EXPECT-NOFLAG
    }
}
