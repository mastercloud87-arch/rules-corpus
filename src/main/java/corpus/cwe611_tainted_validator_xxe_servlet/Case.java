// RULE: cwe611-tainted-validator-xxe-servlet  CWE: CWE-611  LANE: taint
package corpus.cwe611_tainted_validator_xxe_servlet;
import jakarta.servlet.http.HttpServletRequest;
import javax.xml.validation.Validator;
import javax.xml.validation.Schema;
import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
public class Case {
    // POSITIVE: remote request body validated -> XXE
    void vulnerable(HttpServletRequest request, Schema schema) throws Exception {
        Validator v = schema.newValidator();
        v.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); // keeps the config-audit rule quiet
        v.validate(new StreamSource(request.getInputStream())); // EXPECT-FLAG
    }
    // NEGATIVE: a local file source, not remote
    void safe(Schema schema) throws Exception {
        Validator v = schema.newValidator();
        v.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        v.validate(new StreamSource(new File("x.xml"))); // EXPECT-NOFLAG
    }
}
