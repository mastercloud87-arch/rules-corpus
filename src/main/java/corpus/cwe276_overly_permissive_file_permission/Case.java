// RULE: cwe276-overly-permissive-file-permission  CWE: CWE-276  LANE: pattern
package corpus.cwe276_overly_permissive_file_permission;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
public class Case {
    // POSITIVE: POSIX permissions granting read/write/execute to OTHERS
    void vulnerable(Path p) throws IOException {
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxrwxrwx")); // EXPECT-FLAG
    }
    // NEGATIVE: OTHERS permission set to "---" (no world access)
    void safe(Path p) throws IOException {
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxrwx---")); // EXPECT-NOFLAG
    }
}
