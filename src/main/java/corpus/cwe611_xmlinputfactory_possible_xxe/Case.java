// RULE: cwe611-xmlinputfactory-possible-xxe  CWE: CWE-611  LANE: pattern
package corpus.cwe611_xmlinputfactory_possible_xxe;
import javax.xml.stream.XMLInputFactory;
public class Case {
    // POSITIVE: factory created via newFactory with no disabling setProperty in this method
    XMLInputFactory vulnerable() {
        return XMLInputFactory.newFactory(); // EXPECT-FLAG
    }
    // NEGATIVE: same method disables external entities
    XMLInputFactory safe() {
        XMLInputFactory f = XMLInputFactory.newFactory(); // EXPECT-NOFLAG
        f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        return f;
    }
}
