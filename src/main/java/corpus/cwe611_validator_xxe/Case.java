// RULE: cwe611-validator-xxe  CWE: CWE-611  LANE: pattern
package corpus.cwe611_validator_xxe;
import javax.xml.validation.Validator;
import javax.xml.validation.Schema;
import javax.xml.XMLConstants;
public class Case {
    // POSITIVE: a Validator declared with no hardening on it
    void vulnerable(Schema schema) throws Exception {
        Validator v = schema.newValidator(); // EXPECT-FLAG
    }
    // NEGATIVE: hardened with secure processing
    void safe(Schema schema) throws Exception {
        Validator v = schema.newValidator(); // EXPECT-NOFLAG
        v.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    }
}
