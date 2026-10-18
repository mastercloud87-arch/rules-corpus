// RULE: cwe502-insecure-jms-deserialization  CWE: CWE-502  LANE: pattern
package corpus.cwe502_insecure_jms_deserialization;
// javax/jakarta.jms is not an available library; minimal local stand-ins keep the
// matched shape faithful: a 0-arg getObject() on an ObjectMessage-typed/cast receiver.
public class Case {
    // POSITIVE: ((ObjectMessage) msg).getObject() deserializes the payload
    Object vulnerable(Message msg) {
        return ((ObjectMessage) msg).getObject(); // EXPECT-FLAG
    }
    // NEGATIVE: 1-arg getObject(String) on a MapMessage is a keyed lookup, not native deserialization
    Object safe(MapMessage map) {
        return map.getObject("key"); // EXPECT-NOFLAG
    }

    interface Message {}
    interface ObjectMessage extends Message { Object getObject(); }
    interface MapMessage extends Message { Object getObject(String key); }
}
