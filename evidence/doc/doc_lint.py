#!/usr/bin/env python3
"""doc_lint.py - documentation consistency checks for F:\\rtsc\\docs\\spec.

Design and rationale: docs/spec/doc-lint.plan.md
Checks:
  F1 table row integrity          (fail)
  F2 defect-count claim agreement (warn)
  F3 absolute file reference exists (fail)
  F4 file-qualified section ref exists (fail, design docs only)
  F5 heading number uniqueness    (fail, design docs only)

Audit reports (*.consult-*.md / *.audit-*.md) run F1+F3 only: they legitimately
quote old values ("originally 21 items"), so F2/F4 would be pure noise.

Exit code: 1 if any fail, else 0 (warnings never fail).
"""
import io
import os
import re
import sys

ROOT_DEFAULT = r"F:\rtsc"
SPEC_REL = r"docs\spec"

DOCS = [
    ("connection-initiation.md", "spec"),
    ("mcs-connect.md", "spec"),
    ("mcs-domain.md", "spec"),
    ("security-layer.md", "spec"),
    ("share-data.md", "spec"),
    ("licensing.md", "spec"),
    ("capabilities.md", "spec"),
    ("tls-backend.design-a.md", "design"),
    ("tls-backend.design-b.md", "design"),
    ("capabilities.consult-a.md", "audit"),
    ("capabilities.consult-b.md", "audit"),
    ("tls-backend.consult-b.md", "audit"),
]

FENCE = re.compile(r"^\s*```")
# Heading number: "## 8." / "### 3.4" / "#### §3.4.1" then a word/space/punct.
HEAD = re.compile(r"^(#{1,6})\s+§?\s*(\d+(?:\.\d+)*)\.?(?=[\s\u4e00-\u9fff（(：:]|$)")
CLAIM = re.compile(
    r"(?:最终条数|合并后|最终|共计|合计)\s*[:：]?\s*\*{0,2}\s*(\d+)\s*\*{0,2}\s*条"
)
HIST = re.compile(
    r"原写|最初|原本|撤回|降级|演变|历史|修订|变更|留痕|"
    r"→|->|原 \d+|旧值|乙说|它说|说「|引用|转述|合并前|旧稿"
)
# "最终条数" is an authoritative current claim even if the line mentions a
# downgrade -- but NOT when the whole claim sits inside inline code, which marks
# it as a quotation of an older statement.
FORCE_CUR = re.compile(r"最终条数")
ABS = re.compile(r"F:\\rtsc\\[^\s`\)\]|,;]*")
EXT = re.compile(r"\.(md|cpp|h|hpp|py|ps1|txt|json|lib|exe|out|log)$", re.I)
QREF = re.compile(r"([A-Za-z0-9_.\-]+\.md)\s*(?:的\s*)?§\s*(\d+(?:\.\d+)*)")
INLINE_CODE = re.compile(r"`[^`]*`")


def read_lines(path):
    with io.open(path, encoding="utf-8", newline="") as f:
        return f.read().split("\n")


def headings(lines):
    """Set of section numbers declared by headings (code fences skipped)."""
    out = set()
    fence = False
    for raw in lines:
        if FENCE.match(raw):
            fence = not fence
            continue
        if fence:
            continue
        m = HEAD.match(raw.strip())
        if m:
            out.add(m.group(2))
    return out


def f1_tables(lines):
    problems = []
    fence = False
    for i, raw in enumerate(lines, 1):
        if FENCE.match(raw):
            fence = not fence
            continue
        if fence:
            continue
        s = raw.strip()
        if not s.startswith("|"):
            continue
        if not s.endswith("|"):
            problems.append((i, "row-not-closed", s[:90]))
            continue
        nocode = INLINE_CODE.sub("``", s)
        if "||" in nocode:
            problems.append((i, "sticky-cells", s[:90]))
    return problems


def f2_counts(lines):
    """Split count claims into current vs historical.

    A claim is historical when the line quotes an older statement or another
    author's position. Two guards keep this precise:
      * inline code spans are removed before matching, so a claim that only
        appears inside `...` is a quotation and is dropped entirely;
      * `最终条数` is authoritative only when it is NOT inside inline code.
    """
    cur, hist = [], []
    for i, s in enumerate(lines, 1):
        nocode = INLINE_CODE.sub("``", s)
        for m in CLAIM.finditer(nocode):
            if FORCE_CUR.search(nocode) and not HIST.search(nocode):
                cur.append((i, m.group(1), s.strip()[:90]))
            elif HIST.search(s):
                hist.append((i, m.group(1), s.strip()[:90]))
            else:
                cur.append((i, m.group(1), s.strip()[:90]))
    return cur, hist


def f3_file_refs(text):
    bad = []
    for m in ABS.finditer(text):
        raw = m.group(0).rstrip(".,;:'\"")
        path = re.sub(r":\d+(-\d+)?$", "", raw)
        if ".tmp" in path.lower():
            continue
        if "*" in path:
            continue
        if not EXT.search(path):
            continue
        if not os.path.exists(path):
            bad.append(raw)
    return bad


def f4_qualified(lines, heading_cache):
    bad = []
    fence = False
    for i, raw in enumerate(lines, 1):
        if FENCE.match(raw):
            fence = not fence
            continue
        if fence:
            continue
        for m in QREF.finditer(raw):
            doc = os.path.basename(m.group(1))
            sec = m.group(2)
            if doc not in heading_cache:
                bad.append((i, "unknown-doc:%s §%s" % (doc, sec), raw.strip()[:90]))
            elif sec not in heading_cache[doc]:
                bad.append((i, "missing-section:%s §%s" % (doc, sec), raw.strip()[:90]))
    return bad


def f5_dup_headings(lines):
    seen = {}
    fence = False
    for i, raw in enumerate(lines, 1):
        if FENCE.match(raw):
            fence = not fence
            continue
        if fence:
            continue
        m = HEAD.match(raw.strip())
        if m:
            seen.setdefault(m.group(2), []).append(i)
    return {k: v for k, v in seen.items() if len(v) > 1}


def main(argv):
    root = ROOT_DEFAULT
    only = None
    targets = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--root":
            i += 1
            root = argv[i]
        elif a == "--only":
            i += 1
            only = set(x.strip().upper() for x in argv[i].split(","))
        elif a.startswith("-"):
            pass
        else:
            targets.append(a)
        i += 1

    spec_dir = os.path.join(root, SPEC_REL)
    if not os.path.isdir(spec_dir):
        print("ERROR: spec dir not found: %s" % spec_dir)
        return 2

    docs = DOCS
    if targets:
        docs = [(t, "design") for t in targets]

    # Pre-compute heading sets for F4 (needs every doc, not just the target).
    heading_cache = {}
    for name, _kind in DOCS:
        p = os.path.join(spec_dir, name)
        if os.path.exists(p):
            heading_cache[name] = headings(read_lines(p))

    def want(check):
        return only is None or check in only

    total_fail = 0
    total_warn = 0
    for name, kind in docs:
        path = os.path.join(spec_dir, name)
        if not os.path.exists(path):
            print("%-34s MISSING" % name)
            total_fail += 1
            continue
        lines = read_lines(path)
        with io.open(path, encoding="utf-8", newline="") as f:
            text = f.read()

        fails = []
        warns = []
        parts = []

        if want("F1"):
            p = f1_tables(lines)
            parts.append("F1 %s" % ("ok" if not p else "FAIL(%d)" % len(p)))
            fails.extend(("F1", x) for x in p)

        if want("F2"):
            if kind == "audit":
                parts.append("F2 skip")
            else:
                cur, hist = f2_counts(lines)
                vals = sorted(set(c[1] for c in cur))
                if len(vals) > 1:
                    parts.append("F2 WARN(%s)" % "/".join(vals))
                    warns.append(("F2", (0, "conflicting counts: %s" % ",".join(vals), "")))
                    for c in cur:
                        warns.append(("F2", (c[0], "value=%s" % c[1], c[2])))
                else:
                    parts.append("F2 ok%s" % ("(%s)" % vals[0] if vals else "(n/a)"))

        if want("F3"):
            p = f3_file_refs(text)
            parts.append("F3 %s" % ("ok" if not p else "FAIL(%d)" % len(p)))
            fails.extend(("F3", (0, x, "")) for x in p)

        if want("F4"):
            if kind == "audit":
                parts.append("F4 skip")
            else:
                p = f4_qualified(lines, heading_cache)
                parts.append("F4 %s" % ("ok" if not p else "FAIL(%d)" % len(p)))
                fails.extend(("F4", x) for x in p)

        if want("F5"):
            if kind == "audit":
                parts.append("F5 skip")
            else:
                dup = f5_dup_headings(lines)
                parts.append("F5 %s" % ("ok" if not dup else "FAIL(%d)" % len(dup)))
                if dup:
                    for k, v in dup.items():
                        fails.append(("F5", (v[0], "duplicate heading %s" % k,
                                             "lines=%s" % v)))

        total_fail += len(fails)
        total_warn += len(warns)
        print("%-34s %-58s fail=%d warn=%d"
              % (name, " ".join(parts), len(fails), len(warns)))
        for tag, (ln, msg, ctx) in fails:
            print("    FAIL %s:%d %s %s" % (tag, ln, msg, ctx))
        for tag, (ln, msg, ctx) in warns:
            print("    WARN %s:%d %s %s" % (tag, ln, msg, ctx))

    print("")
    print("TOTAL fail=%d warn=%d" % (total_fail, total_warn))
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
