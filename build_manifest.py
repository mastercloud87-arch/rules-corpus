#!/usr/bin/env python3
"""Derive expected.jsonl from the corpus: one entry per `// EXPECT-FLAG` line.
Reads rule_id/cwe from each Case file's `// RULE: <id>  CWE: <cwe>  LANE: <lane>` header.
Negatives (EXPECT-NOFLAG / no marker) produce no entry -> any finding there is an FP."""
import re, json, sys, pathlib
ROOT = pathlib.Path(__file__).parent
HDR = re.compile(r"//\s*RULE:\s*(\S+)\s+CWE:\s*(\S+)\s+LANE:\s*(\S+)")
out = []
for f in sorted(ROOT.glob("src/**/*.java")):
    text = f.read_text(encoding="utf-8", errors="replace").splitlines()
    m = None
    for ln in text[:3]:
        m = HDR.search(ln)
        if m: break
    if not m:
        print(f"WARN no RULE header: {f.relative_to(ROOT)}", file=sys.stderr); continue
    rule_id, cwe, lane = m.group(1), m.group(2), m.group(3)
    rel = str(f.relative_to(ROOT))
    for i, line in enumerate(text, start=1):
        if "EXPECT-FLAG" in line:
            out.append({"rule_id": rule_id, "cwe": cwe, "lane": lane, "file": rel, "line": i, "kind": "pos"})
(ROOT/"expected.jsonl").write_text("\n".join(json.dumps(o) for o in out) + "\n")
print(f"expected.jsonl: {len(out)} expected findings across {len({o['rule_id'] for o in out})} rules")
