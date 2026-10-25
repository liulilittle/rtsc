"""Final A20-1 verifier: every citation form, every target file, with
navigation-vs-record classification.

Targets:
  tls_schannel.cpp  -- batch 0 inserted 2 lines after old line 39
  CMakeLists.txt    -- batch 0 rewrote the TLS library block
  credssp.cpp       -- untouched by batch 0
  connect_machine.cpp -- untouched by batch 0
  test_tls.cpp      -- untouched by batch 0
  tls.h             -- untouched by batch 0

A citation is a NAVIGATION citation if the surrounding line says "this is where
X lives / change this". It is a RECORD citation if the line describes a past or
wrong value ("should be", "used to", "old", "line moved", "residual", ...).
Record citations must keep the old number; only navigation citations are checked.
"""
import io
import re
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
FILES = {
    'tls': r'F:\rtsc\src\net\tls_schannel.cpp',
    'cmake': r'F:\rtsc\CMakeLists.txt',
    'credssp': r'F:\rtsc\src\credssp\credssp.cpp',
    'cm': r'F:\rtsc\src\proto\connect_machine.cpp',
    'test': r'F:\rtsc\tests\test_tls.cpp',
}
SRC = {k: io.open(v, encoding='utf-8').read().splitlines() for k, v in FILES.items()}
L = io.open(DOC, encoding='utf-8').read().splitlines()

RECORD = ('应为', '曾经', 'used to', '原引用', '遗留', '行号', '旧 ', '现在指向',
          '复扫', '批 0 之前', '批 0 后', '§20', '§24', '订正')

# section boundaries: which file does a bare `:NNN` refer to?
SEC19 = (3205, 4230)


def section_file(docline):
    """Bare citations inside §19.2 are tls_schannel.cpp unless the surrounding
    prose names CMakeLists.txt; inside §19.3.x each subsection names its target."""
    ctx = '\n'.join(L[max(0, docline - 12):docline + 2])
    if 'CMakeLists' in ctx:
        return 'cmake'
    if 'credssp.cpp' in ctx or 'OpenReceive' in ctx or 'SealSend' in ctx:
        return 'credssp'
    if 'connect_machine' in ctx:
        return 'cm'
    if 'test_tls.cpp' in ctx:
        return 'test'
    return 'tls'


PAT = [
    ('tls', re.compile(r'`(?:src/net/)?tls_schannel\.cpp:(\d+)(?:-(\d+))?`')),
    ('tls', re.compile(r'`t:(\d+)(?:-(\d+))?`')),
    ('cmake', re.compile(r'`CMakeLists\.txt:(\d+)(?:-(\d+))?`')),
    ('credssp', re.compile(r'`(?:src/credssp/)?credssp\.cpp:(\d+)(?:-(\d+))?`')),
    ('cm', re.compile(r'`(?:src/proto/)?connect_machine\.cpp:(\d+)(?:-(\d+))?`')),
    ('test', re.compile(r'`tests/test_tls\.cpp:(\d+)(?:-(\d+))?`')),
]
BARE = re.compile(r'(?<![a-zA-Z0-9_./`:])`:(\d+)(?:-(\d+))?`')

ok = bad = rec = 0
problems = []

for i, line in enumerate(L):
    dl = i + 1
    is_rec = any(k in line for k in RECORD)
    for tgt, pat in PAT:
        for m in pat.finditer(line):
            a = int(m.group(1)); b = int(m.group(2)) if m.group(2) else a
            if is_rec:
                rec += 1
                continue
            src = SRC[tgt]
            if a > len(src) or b > len(src):
                bad += 1
                problems.append((dl, m.group(0), tgt, 'OUT OF RANGE'))
            else:
                ok += 1
    for m in BARE.finditer(line):
        a = int(m.group(1)); b = int(m.group(2)) if m.group(2) else a
        if is_rec:
            rec += 1
            continue
        tgt = section_file(dl)
        src = SRC[tgt]
        if a > len(src) or b > len(src):
            bad += 1
            problems.append((dl, m.group(0), tgt, 'OUT OF RANGE'))
        else:
            ok += 1

print('=== A20-1 final verification (v3, all forms, all targets) ===')
print('navigation citations in range :', ok)
print('navigation citations OUT OF R :', bad)
print('record citations (keep old)   :', rec)
print()
if problems:
    print('=== problems ===')
    for dl, cite, tgt, why in problems:
        print('  doc:%-5d %-12s -> %-8s %s' % (dl, cite, tgt, why))
sys.exit(1 if bad else 0)
