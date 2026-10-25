"""Collect the delivery baseline: sha256 + sizes + line counts + gate exits.

This is section 1 of the toolchain final report. Every value is measured, not
recalled (rule F), and the gate exit codes come from actually running each
gate rather than from the last session's memory.
"""
import hashlib
import io
import json
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = r'F:\rtsc'
EVID = os.path.join(ROOT, 'evidence', 'tls')
OUT = os.path.join(EVID, 'final-baseline.json')

FILES = [
    ('design doc', r'docs\spec\tls-backend.design-a.md'),
    ('design doc B', r'docs\spec\tls-backend.design-b.md'),
    ('audit report', r'docs\spec\tls-backend.consult-b.md'),
    ('gate: structure', r'evidence\tls\pseudo_lint.py'),
    ('gate: redtest', r'evidence\tls\pseudo_lint_redtest.py'),
    ('gate: semantics', r'evidence\tls\verify_elif_semantics.py'),
    ('gate: sideeffect', r'evidence\tls\verify_sideeffect_leaf.py'),
    ('gate: secrefs', r'evidence\tls\count_sec_refs.py'),
    ('gate: g13', r'evidence\tls\verify_g13.py'),
    ('gate: state', r'evidence\tls\state_snapshot.py'),
    ('gate: diff', r'evidence\tls\diff_state.py'),
    ('runner', r'verify.ps1'),
    ('index', r'evidence\tls\probes\INDEX.md'),
    ('snap readme', r'evidence\tls\snapshots\README.md'),
    ('probes readme', r'evidence\tls\probes\README.md'),
    ('bcgr source', r'evidence\capabilities\bcgr-source.md'),
]

SNAPS = [
    r'evidence\tls\snapshots\design-a.bak.md',
    r'evidence\tls\snapshots\design-a.step7.snapshot.md',
    r'evidence\tls\snapshots\design-a.step7.v2.md',
    r'evidence\tls\snapshots\design-a.step8.base.md',
]

GATES = [
    ('S1_structure', [sys.executable, os.path.join(EVID, 'pseudo_lint.py'),
                      '--file', os.path.join(ROOT, 'docs', 'spec', 'tls-backend.design-a.md')]),
    ('S2_redtest', [sys.executable, os.path.join(EVID, 'pseudo_lint_redtest.py')]),
    ('S3_semantics', [sys.executable, os.path.join(EVID, 'verify_elif_semantics.py')]),
    ('S4_regress', [sys.executable, os.path.join(EVID, 'pseudo_lint.py'), '--regress']
     + [os.path.join(ROOT, s) for s in SNAPS]
     + ['--current', os.path.join(ROOT, 'docs', 'spec', 'tls-backend.design-a.md')]),
    ('S5_sideeffect', [sys.executable, os.path.join(EVID, 'verify_sideeffect_leaf.py')]),
    ('S6_secrefs', [sys.executable, os.path.join(EVID, 'count_sec_refs.py'), '--check']),
    ('S7_g13', [sys.executable, os.path.join(EVID, 'verify_g13.py')]),
    ('S8_doclint', [sys.executable, os.path.join(ROOT, 'evidence', 'doc', 'doc_lint.py'),
                    '--root', ROOT]),
]


def info(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return {'exists': False}
    b = open(p, 'rb').read()
    return {
        'exists': True,
        'bytes': len(b),
        'lines': len(b.decode('utf-8', 'replace').splitlines()),
        'sha256': hashlib.sha256(b).hexdigest(),
    }


report = {'files': {}, 'snapshots': {}, 'gates': {}}

for label, rel in FILES:
    report['files'][label] = dict(info(rel), path=rel.replace('\\', '/'))
for rel in SNAPS:
    report['snapshots'][os.path.basename(rel)] = dict(
        info(rel), path=rel.replace('\\', '/'))

for name, cmd in GATES:
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    tail = [l for l in (r.stdout or '').splitlines() if l.strip()]
    report['gates'][name] = {
        'exit': r.returncode,
        'last_line': tail[-1] if tail else '',
    }

io.open(OUT, 'w', encoding='utf-8', newline='').write(
    json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + '\n')

print('wrote', OUT)
print()
print('== files ==')
for label in sorted(report['files']):
    d = report['files'][label]
    print('%-18s %8s B %5s lines  %s' % (
        label, d.get('bytes', '-'), d.get('lines', '-'),
        (d.get('sha256') or '')[:16]))
print()
print('== snapshots ==')
for n in sorted(report['snapshots']):
    d = report['snapshots'][n]
    print('%-32s %8s B  %s' % (n, d.get('bytes', '-'), (d.get('sha256') or '')[:16]))
print()
print('== gates ==')
bad = 0
for n in sorted(report['gates']):
    g = report['gates'][n]
    if g['exit'] != 0:
        bad += 1
    print('%-16s exit=%d  %s' % (n, g['exit'], g['last_line'][:60]))
print()
print('non-zero gates:', bad)
