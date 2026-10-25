#!/usr/bin/env python
# Cross-check every `c:NNN` / `t:NNN` / `h:NN` citation in the report against the
# real source, and report the ones whose content does not plausibly match.
# Heuristic: only verifies that the cited line EXISTS and prints it, so a human
# (or the next audit round) can eyeball mismatches. No exe is run.
import io, re, os

REPORT = r'F:\rtsc\docs\spec\batch1-audit-a.md'
FILES = {
    'c': r'F:\rtsc\src\credssp\credssp.cpp',
    't': r'F:\rtsc\tests\test_credssp_sm.cpp',
    'h': r'F:\rtsc\include\rtsc\credssp\credssp.h',
    'ts': r'F:\rtsc\src\credssp\ts_request.cpp',
}

cache = {}
def lines(tag):
    if tag not in cache:
        cache[tag] = io.open(FILES[tag], encoding='utf-8', errors='replace').read().splitlines()
    return cache[tag]

text = io.open(REPORT, encoding='utf-8').read()

# match citations like `c:232`, `t:110`, `h:61`, `ts:216`
cites = set()
for m in re.finditer(r'`(c|t|h|ts):(\d+)`', text):
    cites.add((m.group(1), int(m.group(2))))

by_tag = {}
for tag, n in sorted(cites):
    by_tag.setdefault(tag, []).append(n)

for tag in sorted(by_tag):
    L = lines(tag)
    print('=== %s (%s) : %d distinct citations, file has %d lines' % (
        tag, os.path.basename(FILES[tag]), len(by_tag[tag]), len(L)))
    oob = [n for n in by_tag[tag] if n < 1 or n > len(L)]
    if oob:
        print('  OUT OF RANGE:', oob)
    for n in by_tag[tag]:
        if 1 <= n <= len(L):
            print('  %4d | %s' % (n, L[n - 1].strip()[:100]))
    print()
