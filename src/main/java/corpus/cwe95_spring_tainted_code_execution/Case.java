// RULE: cwe95-spring-tainted-code-execution  CWE: CWE-095  LANE: taint
package corpus.cwe95_spring_tainted_code_execution;
import jakarta.servlet.http.HttpServletRequest;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
public class Case {
    // POSITIVE: remote input flows unsanitized into ScriptEngine.eval
    Object vulnerable(HttpServletRequest request) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(request.getParameter("s")); // EXPECT-FLAG
    }
    // NEGATIVE: a compile-time constant script -> no remote taint
    Object safe() throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval("1+1"); // EXPECT-NOFLAG
    }
}
