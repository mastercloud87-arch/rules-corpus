// RULE: java/world-writable-file-read  CWE: CWE-732  LANE: pattern
package corpus.java_world_writable_file_read;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
public class Case {
    // POSITIVE: the same local File variable is both read from and made world-writable
    void vulnerable() throws IOException {
        File f = new File("/tmp/shared");
        f.setWritable(true, false); // EXPECT-FLAG
        FileInputStream in = new FileInputStream(f);
        in.close();
    }
    // NEGATIVE: ownerOnly=true -> not world-writable, so no finding even though it is read
    void safe() throws IOException {
        File f = new File("/tmp/priv");
        f.setWritable(true, true); // EXPECT-NOFLAG
        FileInputStream in = new FileInputStream(f);
        in.close();
    }
}
