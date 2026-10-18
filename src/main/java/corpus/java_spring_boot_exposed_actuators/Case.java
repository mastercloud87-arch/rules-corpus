// RULE: java/spring-boot-exposed-actuators  CWE: CWE-200  LANE: pattern
package corpus.java_spring_boot_exposed_actuators;
import java.util.function.Consumer;
public class Case {
    // Stand-ins for Spring Security / Spring Boot actuator types (not on the allowed
    // library list). Names are kept faithful to the CodeQL owner regexes:
    //   permitAll() owner matches ".*AuthorizedUrl.*"
    //   requestMatchers()/anyRequest() owner matches ".*ExpressionInterceptUrlRegistry.*"
    //   EndpointRequest.toAnyEndpoint() is the distinctive actuator anchor.
    static class EndpointRequest {
        static Object toAnyEndpoint() { return new Object(); }
    }
    static class AuthorizedUrl {
        ExpressionInterceptUrlRegistry permitAll() { return new ExpressionInterceptUrlRegistry(); }
    }
    static class ExpressionInterceptUrlRegistry {
        AuthorizedUrl requestMatchers(Object... matchers) { return new AuthorizedUrl(); }
        AuthorizedUrl anyRequest() { return new AuthorizedUrl(); }
    }
    static class HttpSecurity {
        HttpSecurity authorizeHttpRequests(Consumer<ExpressionInterceptUrlRegistry> c) {
            c.accept(new ExpressionInterceptUrlRegistry());
            return this;
        }
    }

    // POSITIVE: actuator endpoints are permitted without authentication
    void vulnerable(HttpSecurity http) {
        http.authorizeHttpRequests(authz ->
            authz.requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()); // EXPECT-FLAG
    }
    // NEGATIVE: a non-actuator matcher permitted (no EndpointRequest.toAnyEndpoint anchor)
    void safe(HttpSecurity http) {
        http.authorizeHttpRequests(authz ->
            authz.requestMatchers("/public").permitAll()); // EXPECT-NOFLAG
    }
}
