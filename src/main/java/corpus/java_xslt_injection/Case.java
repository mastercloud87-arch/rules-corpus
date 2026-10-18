// RULE: java/xslt-injection  CWE: CWE-074  LANE: taint
package corpus.java_xslt_injection;
import jakarta.servlet.http.HttpServletRequest;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamSource;
import javax.xml.transform.stream.StreamResult;
public class Case {
    // POSITIVE: user-controlled stylesheet source carried into the Transformer, then transform() (sink = receiver)
    void vulnerable(HttpServletRequest request) throws TransformerException {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer t = factory.newTransformer(new StreamSource(request.getParameter("xsl")));
        t.transform(new StreamSource("in.xml"), new StreamResult(System.out)); // EXPECT-FLAG
    }
    // NEGATIVE: trusted/constant stylesheet source -> nothing user-controlled reaches the transformer
    void safe() throws TransformerException {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer t = factory.newTransformer(new StreamSource("trusted.xsl"));
        t.transform(new StreamSource("in.xml"), new StreamResult(System.out)); // EXPECT-NOFLAG
    }
}
