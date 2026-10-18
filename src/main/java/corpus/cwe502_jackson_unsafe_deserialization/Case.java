// RULE: cwe502-jackson-unsafe-deserialization  CWE: CWE-502  LANE: pattern
package corpus.cwe502_jackson_unsafe_deserialization;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
public class Case {
    // POSITIVE: readValue on a mapper that had enableDefaultTyping() enabled
    Object vulnerable(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping();
        return mapper.readValue(json, Object.class); // EXPECT-FLAG
    }
    // NEGATIVE: readValue on a mapper that never enabled default typing
    Object safe(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, Object.class); // EXPECT-NOFLAG
    }
}
