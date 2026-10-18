// RULE: cwe502-use-snakeyaml-constructor  CWE: CWE-502  LANE: pattern
package corpus.cwe502_use_snakeyaml_constructor;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;
public class Case {
    // POSITIVE: load() on a Yaml built with the zero-arg (unsafe) constructor
    Object vulnerable(String input) {
        Yaml y = new Yaml();
        return y.load(input); // EXPECT-FLAG
    }
    // NEGATIVE: load() on a Yaml built with a SafeConstructor
    Object safe(String input) {
        Yaml y = new Yaml(new SafeConstructor(new LoaderOptions()));
        return y.load(input); // EXPECT-NOFLAG
    }
}
