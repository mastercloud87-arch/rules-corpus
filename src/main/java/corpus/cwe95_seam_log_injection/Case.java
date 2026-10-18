// RULE: cwe95-seam-log-injection  CWE: CWE-095  LANE: pattern
package corpus.cwe95_seam_log_injection;
public class Case {
    // local stand-in for org.jboss.seam.log.Log (lib not on classpath)
    static class Log { void info(Object m) {} }
    // POSITIVE: Seam Log message is a '+' of two non-constant operands (EL evaluated)
    void vulnerable(Log log, String user, String action) {
        log.info(user + action); // EXPECT-FLAG
    }
    // NEGATIVE: operand 0 is a constant prefix -> not the dangerous shape
    void safe(Log log, String x) {
        log.info("hello " + x); // EXPECT-NOFLAG
    }
}
