// RULE: cwe94-script-engine-injection  CWE: CWE-094  LANE: pattern
package corpus.cwe94_script_engine_injection;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
public class Case {
    // POSITIVE: ScriptEngine.eval fed a non-constant string
    Object vulnerable(String code) throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(code); // EXPECT-FLAG
    }
    // NEGATIVE: a compile-time constant script
    Object safe() throws ScriptException {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval("1+1"); // EXPECT-NOFLAG
    }
}
