// RULE: cwe23-tainted-file-path  CWE: CWE-023  LANE: taint
package corpus.cwe23_tainted_file_path;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.io.ClassPathResource;
public class Case {
    // POSITIVE: remote path used to construct a Spring ClassPathResource
    ClassPathResource vulnerable(HttpServletRequest request) {
        return new ClassPathResource(request.getParameter("f")); // EXPECT-FLAG
    }
    // NEGATIVE: a constant resource path (no user-provided value)
    ClassPathResource safe() {
        return new ClassPathResource("templates/app.xml"); // EXPECT-NOFLAG
    }
}
