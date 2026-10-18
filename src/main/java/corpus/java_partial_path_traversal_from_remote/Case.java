// RULE: java/partial-path-traversal-from-remote  CWE: CWE-023  LANE: taint
package corpus.java_partial_path_traversal_from_remote;
import jakarta.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
public class Case {
    // POSITIVE: canonical path (from a remote-derived File) guarded by a
    // prefix that is NOT slash-terminated -> partial path traversal
    boolean vulnerable(HttpServletRequest request, String baseDir) throws IOException {
        File f = new File(baseDir, request.getParameter("p"));
        String canon = f.getCanonicalPath();
        return canon.startsWith(baseDir); // EXPECT-FLAG
    }
    // NEGATIVE: the prefix is slash-terminated -> the guard is correct
    boolean safe(HttpServletRequest request, String baseDir) throws IOException {
        File f = new File(baseDir, request.getParameter("p"));
        String canon = f.getCanonicalPath();
        return canon.startsWith(baseDir + "/"); // EXPECT-NOFLAG
    }
}
