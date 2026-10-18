// RULE: java/spring-disabled-csrf-protection  CWE: CWE-352  LANE: pattern
package corpus.java_spring_disabled_csrf_protection;
public class Case {
    // Stand-ins for Spring Security (not on the allowed library list). Names are kept
    // faithful to the CodeQL owner regexes: the disable() call's owner must match
    // ".*CsrfConfigurer.*", invoked on an HttpSecurity value.
    static class CsrfConfigurer {
        CsrfConfigurer disable() { return this; }
        CsrfConfigurer ignoringRequestMatchers(String m) { return this; }
    }
    static class HttpSecurity {
        CsrfConfigurer csrf() { return new CsrfConfigurer(); }
    }

    // POSITIVE: CSRF protection is explicitly disabled
    void vulnerable(HttpSecurity http) {
        http.csrf().disable(); // EXPECT-FLAG
    }
    // NEGATIVE: csrf() is configured but not disabled
    void safe(HttpSecurity http) {
        http.csrf().ignoringRequestMatchers("/api/webhook"); // EXPECT-NOFLAG
    }
}
