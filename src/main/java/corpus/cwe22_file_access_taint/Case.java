// RULE: cwe22-file-access-taint  CWE: CWE-022  LANE: taint
package corpus.cwe22_file_access_taint;
import jakarta.servlet.http.HttpServletRequest;
import javax.xml.transform.stream.StreamSource;
public class Case {
    // POSITIVE: remote path used to construct a StreamSource (file/URI opened from untrusted data)
    StreamSource vulnerable(HttpServletRequest request) {
        return new StreamSource(request.getParameter("uri")); // EXPECT-FLAG
    }
    // NEGATIVE: a constant path (no user-provided value)
    StreamSource safe() {
        return new StreamSource("/etc/app/config.xml"); // EXPECT-NOFLAG
    }
}
