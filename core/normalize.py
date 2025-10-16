SEV_MAP = {
  "note":"low","info":"low","low":"low",
  "medium":"medium","moderate":"medium",
  "high":"high","critical":"critical",
}

def dedupe(findings):
    seen=set(); out=[]
    for f in findings:
        key=(f.tool, f.id, f.file, f.start_line, f.component)
        if key not in seen:
            seen.add(key); out.append(f)
    return out
