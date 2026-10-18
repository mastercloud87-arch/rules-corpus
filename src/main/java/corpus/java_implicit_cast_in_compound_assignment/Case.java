// RULE: java/implicit-cast-in-compound-assignment  CWE: CWE-190  LANE: pattern
package corpus.java_implicit_cast_in_compound_assignment;
public class Case {
    // POSITIVE: '+=' whose RHS (long, width 8) is wider than the dest (int, width 4)
    void vulnerable() {
        long big = 1L << 40;
        int i = 0;
        i += big; // EXPECT-FLAG
    }
    // NEGATIVE: dest (long) is at least as wide as the RHS (int) -> no narrowing
    void safe() {
        int small = 5;
        long x = 0L;
        x += small; // EXPECT-NOFLAG
    }
}
