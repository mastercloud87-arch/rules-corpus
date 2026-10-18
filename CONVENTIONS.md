# Rule-corpus conventions (ground-truth test suite for the 169-rule bundle)

Goal: one self-contained test module per rule that exercises **both** recall (a real
must-flag case) and precision (near-miss / sanitized / FP-pattern must-not-flag cases),
with a machine-checkable ground-truth manifest. Running the scanner on this corpus and
diffing against the manifest yields a **per-rule FP/FN scorecard**.

## Layout
- One Java file per rule: `src/main/java/corpus/<pkg>/Case.java`
  - `<pkg>` = rule_id sanitized: lowercase, every non-alphanumeric → `_`
    (e.g. `java/sql-injection` → `java_sql_injection`; `cwe319-unencrypted-socket` → `cwe319_unencrypted_socket`).
- Rules where location matters also get a **test-source** copy of the positive under
  `src/test/java/corpus/<pkg>/CaseTest.java` → it must **NOT** flag (FP02 test-exclusion).

## Each Case.java
```java
// RULE: <rule_id>  CWE: <cwe>  LANE: <lane>
package corpus.<pkg>;
<imports>
public class Case {
    // POSITIVE — must flag. Every sink line that must produce a finding ends with // EXPECT-FLAG
    <returnType> vulnerable(<remote/untrusted inputs>) {
        ...
        <sink>;   // EXPECT-FLAG
    }
    // NEGATIVE — must NOT flag. Sanitized / near-miss / FP-pattern variant(s).
    <returnType> safe(...) {
        ...
        <sanitized or non-matching sink>;   // EXPECT-NOFLAG
    }
}
```

### Positive design by lane
- **taint / flow**: source = a real remote/untrusted input (`request.getParameter(...)`,
  `@RequestParam`, `req.getInputStream()`, socket read). Flow it unsanitized into the sink.
- **pattern**: the exact matched construct (e.g. `new Socket(host,port)`, `Pattern.compile("[A-z]")`).
- **literal**: the matched literal/value in the sink arg (e.g. `getInstance("MD5")`).

### Negative design (the precision tests — most valuable)
Write the smallest change that SHOULD make the rule go quiet:
- taint: the same sink but fed a **literal/constant**, or a **sanitized** value (the rule's barrier).
- pattern/literal near-miss: the safe API or safe value (`SSLSocket`, `"SHA-256"`, `[A-Za-z]`).
- **FP-pattern negatives** (from fp-catalog.jsonl) where applicable — these are regression guards:
  - FP04: `e.printStackTrace()` to stderr → NOFLAG; `e.printStackTrace(response.getWriter())` → FLAG.
  - FP06: `Class.forName(CONFIG_STRING)` → NOFLAG; `Class.forName(request.getParameter("c"))` → FLAG.
  - FP05: `new Socket()` for a health check / loopback → NOFLAG; plaintext send of sensitive data → FLAG.
  - FP07: `new Random()` for non-security → NOFLAG; `new Random()` feeding a token/password → FLAG.
  - FP10: `q="insert into t values('x')"; execute(q)` (literal, reassigned) → NOFLAG; concat with `request.getParameter` → FLAG.
  - FP11: `@RequestMapping("/home")` GET render → NOFLAG; state-changing handler w/o token → FLAG.
  - FP02: positive copied under `src/test/` → NOFLAG.

## Ground-truth manifest: expected.jsonl
One line per **expected finding** (the EXPECT-FLAG sink lines only):
`{"rule_id":"<id>","cwe":"CWE-089","file":"src/main/java/corpus/<pkg>/Case.java","line":<n>,"kind":"pos"}`
- Negatives have NO manifest entry. Any scanner finding on a corpus file NOT in the manifest = **FP**.
- An expected entry with no matching scanner finding = **FN**.

## Scorecard (scorecard.py)
Extract facts → run the compiled binary → read `finding_detail.csv` → diff vs `expected.jsonl`:
- per rule: TP (expected & found), FN (expected & missing), FP (found & not expected).
- cross-rule triggers are attributed by rule_id/cwe and noted, not double-counted.

## Type resolution
`pom.xml` declares the libraries the rules reference (jackson, servlet, spring, snakeyaml,
commons, jjwt, …) so the extractor resolves owners/overloads. A finding that fails to fire
because a type did not resolve is a **corpus bug**, not an FN — the scorecard flags unresolved
sink owners separately.
