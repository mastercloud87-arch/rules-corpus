#!/usr/bin/env python3
"""Per-rule FP/FN scorecard: diff a scan's finding_detail.csv against expected.jsonl.

Usage: scorecard.py <scan_out_dir>
  <scan_out_dir>/finding_detail.csv : ruleId,cwe,sev,kind,node,path,sl,sc,el,ec,msg (tab-sep)

Matching: a finding "covers" an expected line when same corpus file + line in [sl..el]
(or ==sl) + rule_id match (or normalized CWE match, to tolerate lane/id differences).
Per rule: TP=expected&found, FN=expected&missing, FP=found-on-corpus & not expected."""
import sys, json, csv, pathlib, collections
ROOT = pathlib.Path(__file__).parent
def ncwe(c):
    import re
    m = re.match(r"CWE-0*(\d+)", c or ""); return f"CWE-{m.group(1)}" if m else (c or "")
exp = [json.loads(l) for l in (ROOT/"expected.jsonl").read_text().splitlines() if l.strip()]
out = pathlib.Path(sys.argv[1])
fd = out/"finding_detail.csv"
findings = []
if fd.is_file():
    for r in csv.reader(fd.open(), delimiter="\t"):
        if len(r) < 11: continue
        rid, cwe, path = r[0], r[1], r[5]
        try: sl, el = int(r[6]), int(r[8])
        except ValueError: continue
        # only corpus files
        if "rule-corpus/" in path or path.startswith("src/"):
            p = path.split("rule-corpus/")[-1]
            findings.append({"rule_id": rid, "cwe": ncwe(cwe), "file": p, "sl": sl, "el": el})
def covers(f, e):
    return f["file"] == e["file"] and e["line"] >= f["sl"] and e["line"] <= max(f["el"], f["sl"])
def rule_match(f, e):
    return f["rule_id"] == e["rule_id"] or f["cwe"] == ncwe(e["cwe"])
# TP / FN per expected
per = collections.defaultdict(lambda: {"TP":0,"FN":0,"FP":0})
used = set()
for e in exp:
    hit = None
    for i, f in enumerate(findings):
        if covers(f, e) and rule_match(f, e): hit = i; break
    if hit is not None: per[e["rule_id"]]["TP"] += 1; used.add(hit)
    else: per[e["rule_id"]]["FN"] += 1
# FP = corpus findings not covering any expected line of a matching rule
for i, f in enumerate(findings):
    if i in used: continue
    if any(covers(f, e) and rule_match(f, e) for e in exp): continue
    per[f["rule_id"]]["FP"] += 1
# report
rules_tested = {e["rule_id"] for e in exp}
tot = {"TP":0,"FN":0,"FP":0}
print(f"{'rule_id':46} TP  FN  FP")
for r in sorted(per):
    s = per[r]; tot["TP"]+=s["TP"]; tot["FN"]+=s["FN"]; tot["FP"]+=s["FP"]
    flag = "" if (s["FN"]==0 and s["FP"]==0) else ("  <-- FN" if s["FN"] else "") + ("  <-- FP" if s["FP"] else "")
    print(f"  {r:44} {s['TP']:3} {s['FN']:3} {s['FP']:3}{flag}")
print(f"  {'TOTAL':44} {tot['TP']:3} {tot['FN']:3} {tot['FP']:3}")
print(f"\nrules with an expected finding: {len(rules_tested)}  |  clean rules: {sum(1 for r in per if per[r]['FN']==0 and per[r]['FP']==0)}")
print(f"rules FN (missed positive): {sorted(r for r in per if per[r]['FN'])}")
print(f"rules FP (flagged negative): {sorted(r for r in per if per[r]['FP'])}")
