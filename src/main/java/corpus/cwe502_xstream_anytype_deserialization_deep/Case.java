// RULE: cwe502-xstream-anytype-deserialization-deep  CWE: CWE-502  LANE: taint
package corpus.cwe502_xstream_anytype_deserialization_deep;
import jakarta.servlet.http.HttpServletRequest;
// com.thoughtworks.xstream is not an available library; a minimal local stand-in keeps
// the matched shape faithful: XStream.fromXML(remoteXml), a receiver typed XStream.
public class Case {
    // POSITIVE: remote input reaches arg 0 (the XML) of XStream.fromXML
    Object vulnerable(HttpServletRequest request) {
        XStream xs = new XStream();
        return xs.fromXML(request.getParameter("xml")); // EXPECT-FLAG
    }
    // NEGATIVE: a constant XML literal (no remote source)
    Object safe() {
        XStream xs = new XStream();
        return xs.fromXML("<root/>"); // EXPECT-NOFLAG
    }

    static class XStream {
        Object fromXML(String xml) { return null; }
    }
}
