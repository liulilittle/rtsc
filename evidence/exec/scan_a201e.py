"""Exhaustive scanner for stale tls_schannel.cpp line references (A20-1).

The point of this script is the *criterion*, not the regex list.  Audit A
proposed a machine-decidable rule:

    batch 0 inserted 2 lines before the old :42, so for any n >= 42,
    if backup[n] == current[n+2] byte-for-byte, then n is a PRE-batch-0
    line number and the reference is stale.

That rule needs no understanding of what each citation means, which is what my
earlier two-pass script got wrong: it only handled two of the four syntactic
forms and therefore reported RESIDUAL 0 while 58 stale references remained.

This scanner:
  1. finds every reference in all four forms:
        `t:NNN`  `t:NNN-MMM`  `tls_schannel.cpp:NNN`  `tls_schannel.cpp:NNN-MMM`
        `src/net/tls_schannel.cpp:NNN[-MMM]`
  2. classifies each by the byte-level shift rule
  3. separately flags references whose target content MOVED to another file
     (batch 0 moved CreateTlsTransport / EnumerateTlsBackends to tls_factory.cpp)

Usage: python scan_a201e.py [--doc PATH] [--json OUT]
"""
import io
import json
import re
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
OLD = r'F:\rtsc\.opencode\backups\src_net_tls_schannel.cpp.20261023-085223'
NEW = r'F:\rtsc\src\net\tls_schannel.cpp'
FACTORY = r'F:\rtsc\src\net\tls_factory.cpp'

INSERT_AT = 42          # batch 0 inserted 2 lines before old line 42
SHIFT = 2


def load_lines(path):
    return io.open(path, encoding='utf-8').read().splitlines()


def find_refs(doc_lines):
    """Return [(doc_line_no, form, start, end, raw)] for all four forms."""
    patterns = [
        # t:NNN  and  t:NNN-MMM   (shorthand inside this document)
        ('short', re.compile(r'`t:(\d+)(?:-(\d+))?`')),
        # tls_schannel.cpp:NNN[-MMM]  with optional src/net/ prefix
        ('full', re.compile(r'`(?:src/net/)?tls_schannel\.cpp:(\d+)(?:-(\d+))?`')),
    ]
    out = []
    for idx, line in enumerate(doc_lines):
        for form, pat in patterns:
            for m in pat.finditer(line):
                a = int(m.group(1))
                b = int(m.group(2)) if m.group(2) is not None else None
                out.append((idx + 1, form, a, b, m.group(0)))
    return out


def classify(a, b, old, new, factory):
    """Return (verdict, detail) for a reference starting at line a."""
    # Did the target content move to another file?
    moved = []
    if a - 1 < len(old):
        target = old[a - 1].strip()
        if target:
            for name, lines in (('tls_factory.cpp', factory),):
                for i, l in enumerate(lines):
                    if l.strip() == target:
                        moved.append('%s:%d' % (name, i + 1))
                        break
            # If the text is NOT in the new tls_schannel.cpp at all, it moved.
            if not any(l.strip() == target for l in new):
                if moved:
                    return 'MOVED', 'content now at ' + ', '.join(moved)

    if a < INSERT_AT:
        return 'OK', 'before insertion point, no shift'
    if a + SHIFT - 1 < len(new) and a - 1 < len(old):
        if old[a - 1] == new[a + SHIFT - 1]:
            return 'STALE', 'backup[%d] == current[%d]' % (a, a + SHIFT)
    return 'AMBIGUOUS', 'could not prove by byte equality'


def main():
    doc = load_lines(DOC)
    old = load_lines(OLD)
    new = load_lines(NEW)
    factory = load_lines(FACTORY)

    refs = find_refs(doc)
    results = []
    for doc_ln, form, a, b, raw in refs:
        verdict, detail = classify(a, b, old, new, factory)
        results.append({
            'doc_line': doc_ln, 'form': form, 'start': a, 'end': b,
            'raw': raw, 'verdict': verdict, 'detail': detail,
        })

    from collections import Counter
    counts = Counter(r['verdict'] for r in results)
    print('=== A20-1 exhaustive scan ===')
    print('doc:', DOC)
    print('total references:', len(results))
    for k in ('STALE', 'MOVED', 'AMBIGUOUS', 'OK'):
        print('  %-10s %d' % (k, counts.get(k, 0)))

    bad = [r for r in results if r['verdict'] in ('STALE', 'MOVED', 'AMBIGUOUS')]
    if bad:
        print()
        print('=== references needing repair (%d) ===' % len(bad))
        for r in bad:
            print('  doc:%-5d %-42s %-10s %s'
                  % (r['doc_line'], r['raw'], r['verdict'], r['detail']))

    with io.open(r'F:\rtsc\evidence\exec\a201-scan.json', 'w',
                 encoding='utf-8', newline='') as f:
        f.write(json.dumps(results, ensure_ascii=False, indent=1))
    print()
    print('wrote evidence/exec/a201-scan.json')
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
