"""A20-1 scanner v2: semantic criterion, not positional.

Why v1 (and audit A's rule) were both wrong
-------------------------------------------
Audit A proposed: "batch 0 inserted 2 lines before old :42, so for any n >= 42,
if backup[n] == current[n+2], then n is a stale reference."

That rule is *tautological*: it holds for EVERY line at or after the insertion
point, because the whole tail shifted. Measured: 658/658 lines in [42,700)
satisfy it. It therefore cannot distinguish

    (a) a reference still saying the OLD number n        -> genuinely stale
    (b) a reference already fixed to the NEW number n+2  -> correct

Both satisfy backup[n] == current[n+2] when you feed the number that appears in
the document. v1 (mine) reported 86 "stale"; audit A reported 58. Both were
measuring "did this line shift", not "is this citation wrong".

The criterion that actually decides the question
------------------------------------------------
A citation `path:N` is correct iff the text at line N is the thing the document
says it is. So the only sound test is:

    for each reference, look at the surrounding prose for a backticked code
    fragment; assert that fragment appears at (or within a few lines of) the
    cited line.

When the prose gives no fragment, the reference is UNCHECKABLE by machine and
must be reported as such rather than guessed at.

This scanner also handles the two forms v1 missed: `t:NNN-MMM` and
`tls_schannel.cpp:NNN-MMM`, plus the five references whose target content moved
to tls_factory.cpp during batch 0 (those cannot be fixed by any offset).
"""
import io
import json
import re
import sys
from collections import Counter

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
SRC = r'F:\rtsc\src\net\tls_schannel.cpp'
FACTORY = r'F:\rtsc\src\net\tls_factory.cpp'

# Text that used to live in tls_schannel.cpp and was moved out by batch 0.
MOVED_MARKERS = ('CreateTlsTransport', 'EnumerateTlsBackends')


def load(path):
    return io.open(path, encoding='utf-8').read().splitlines()


def refs_in(doc_lines):
    """All four syntactic forms, with both endpoints when a range is given."""
    pat = re.compile(
        r'`(?:src/net/)?(?:tls_schannel\.cpp|t):(\d+)(?:-(\d+))?`')
    out = []
    for i, line in enumerate(doc_lines):
        for m in pat.finditer(line):
            out.append({
                'doc_line': i + 1,
                'text': line,
                'start': int(m.group(1)),
                'end': int(m.group(2)) if m.group(2) else None,
                'raw': m.group(0),
            })
    return out


def backticked_fragments(text):
    """Code fragments in backticks on this line, excluding the citation itself."""
    frags = re.findall(r'`([^`]+)`', text)
    out = []
    for f in frags:
        if re.match(r'^(?:src/net/)?(?:tls_schannel\.cpp|t):\d', f):
            continue
        if len(f) < 6:
            continue
        out.append(f)
    return out


def near(lines, n, window=2):
    lo = max(0, n - 1 - window)
    hi = min(len(lines), n - 1 + window + 1)
    return lines[lo:hi]


def classify(ref, src, factory):
    """Return (verdict, detail)."""
    text = ref['text']
    a = ref['start']

    # 1) content that moved to another file: no offset can repair it
    for marker in MOVED_MARKERS:
        if marker in text:
            hits = [i + 1 for i, l in enumerate(factory) if marker in l]
            if hits:
                return 'MOVED', '%s now in tls_factory.cpp:%s' % (
                    marker, ','.join(str(h) for h in hits[:3]))

    # 2) semantic check: does a quoted fragment appear near the cited line?
    frags = backticked_fragments(text)
    if not frags:
        return 'UNCHECKABLE', 'no quoted fragment on this line to compare against'

    if a - 1 >= len(src):
        return 'OUT_OF_RANGE', 'line %d beyond EOF (%d)' % (a, len(src))

    for f in frags:
        # Normalise whitespace so wrapped/quoted code still matches.
        key = ' '.join(f.split())
        for ln in near(src, a):
            if key in ' '.join(ln.split()):
                return 'OK', 'fragment %r found near :%d' % (f[:30], a)

    # Not near the cited line: is it near the +2 line?  If so the citation was
    # written pre-batch-0 and never updated.
    for f in frags:
        key = ' '.join(f.split())
        for ln in near(src, a + 2):
            if key in ' '.join(ln.split()):
                return 'STALE', 'fragment %r is at ~:%d, citation says :%d' % (
                    f[:30], a + 2, a)

    return 'MISMATCH', 'fragment %r not found near :%d nor :%d' % (
        frags[0][:30], a, a + 2)


def main():
    doc = load(DOC)
    src = load(SRC)
    factory = load(FACTORY)

    refs = refs_in(doc)
    results = []
    for r in refs:
        verdict, detail = classify(r, src, factory)
        r2 = dict(r)
        r2.pop('text', None)
        r2['verdict'] = verdict
        r2['detail'] = detail
        results.append(r2)

    counts = Counter(r['verdict'] for r in results)
    print('=== A20-1 scan v2 (semantic criterion) ===')
    print('total references:', len(results))
    for k in ('STALE', 'MISMATCH', 'MOVED', 'OUT_OF_RANGE', 'UNCHECKABLE', 'OK'):
        print('  %-13s %d' % (k, counts.get(k, 0)))

    bad = [r for r in results
           if r['verdict'] in ('STALE', 'MISMATCH', 'MOVED', 'OUT_OF_RANGE')]
    if bad:
        print()
        print('=== requiring repair (%d) ===' % len(bad))
        for r in bad:
            print('  doc:%-5d %-34s %-12s %s'
                  % (r['doc_line'], r['raw'], r['verdict'], r['detail']))

    with io.open(r'F:\rtsc\evidence\exec\a201-scan-v2.json', 'w',
                 encoding='utf-8', newline='') as f:
        f.write(json.dumps(results, ensure_ascii=False, indent=1))
    print()
    print('wrote evidence/exec/a201-scan-v2.json')
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
