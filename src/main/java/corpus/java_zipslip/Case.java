// RULE: java/zipslip  CWE: CWE-022  LANE: taint
package corpus.java_zipslip;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
public class Case {
    // POSITIVE: archive entry name (may contain "..") used to build a file path, then written
    void vulnerable(ZipEntry zipEntry, File destDir) throws IOException {
        File f = new File(destDir, zipEntry.getName());
        FileOutputStream fos = new FileOutputStream(f); // EXPECT-FLAG
        fos.close();
    }
    // NEGATIVE: a constant child name -> no archive-entry source flows into the path
    void safe(File destDir) throws IOException {
        File f = new File(destDir, "safe.txt");
        FileOutputStream fos = new FileOutputStream(f); // EXPECT-NOFLAG
        fos.close();
    }
}
