"""Diff two machine-generated state snapshots (rule F evidence).

consult-b step 19 随修: "the ruler changed" and "the measured object changed"
are two different facts.  Mixing them hides the latter, so a change to
state_snapshot.py itself (the measuring instrument) is reported in its own
section with an explicit comparability warning.

Schema evolution is handled on the intersection of fields; anything absent on
one side is reported rather than silently skipped.
"""
import io
import json
import sys

A = r'F:\rtsc\evidence\tls\state-after-step17.json'
B = r'F:\rtsc\evidence\tls\state-after-step18.json'

# The measuring instrument. Its own sha changing means the yardstick moved.
TOOL = 'evidence/tls/state_snapshot.py'

a = json.load(io.open(A, encoding='utf-8'))
b = json.load(io.open(B, encoding='utf-8'))

print('before: %s (step %s, schema %s)'
      % (A.rsplit('\\', 1)[-1], a.get('step'), a.get('schema', 1)))
print('after : %s (step %s, schema %s)'
      % (B.rsplit('\\', 1)[-1], b.get('step'), b.get('schema', 1)))
print('after generated_at: %s' % b.get('generated_at', '<absent>'))
print('')

fa, fb = a['files'], b['files']

print('== files ==')
only_a = sorted(set(fa) - set(fb))
only_b = sorted(set(fb) - set(fa))
for k in only_a:
    print('  - removed from watch : %s' % k)
for k in only_b:
    print('  + added to watch     : %s  (no before record)' % k)

tool_changed = False
for k in sorted(set(fa) & set(fb)):
    sa, sb = fa[k]['sha256'], fb[k]['sha256']
    if sa == sb:
        continue
    if k == TOOL:
        tool_changed = True
        continue
    print('  ~ CHANGED            : %s  %s -> %s  (%s -> %s B)'
          % (k, (sa or '')[:16], (sb or '')[:16], fa[k]['bytes'], fb[k]['bytes']))
unchanged = [k for k in sorted(set(fa) & set(fb))
             if fa[k]['sha256'] == fb[k]['sha256']]
for k in unchanged:
    print('  = unchanged          : %s' % k)

print('')
print('== measuring instrument ==')
if TOOL not in fa and TOOL not in fb:
    print('  not watched in either snapshot')
elif TOOL not in fa and TOOL in fb:
    # The instrument was only added to the watch list in the later snapshot.
    # Saying "unchanged" here would be false: there is no before record at all.
    print('  ? INSTRUMENT NEW IN AFTER: %s  (no before record)' % TOOL)
    print('    ! comparability reduced: this snapshot was produced by a version')
    print('      of the instrument that the previous snapshot never recorded.')
elif TOOL in fa and TOOL not in fb:
    print('  ? INSTRUMENT REMOVED FROM WATCH: %s' % TOOL)
elif tool_changed:
    print('  ~ TOOL CHANGED (measurement instrument): %s  %s -> %s'
          % (TOOL, (fa[TOOL]['sha256'] or '')[:16], (fb[TOOL]['sha256'] or '')[:16]))
    print('    ! comparability reduced: metric deltas below may come from the')
    print('      instrument, not from the measured object. Judge per metric.')
else:
    print('  = instrument unchanged: %s' % TOOL)

print('')
print('== metrics ==')
ma, mb = a['metrics'], b['metrics']
instrument_touched = tool_changed or (TOOL in only_b)
for k in sorted(set(ma) | set(mb)):
    va, vb = ma.get(k, '<absent>'), mb.get(k, '<absent>')
    mark = '=' if va == vb else '~'
    note = ''
    if mark == '~' and instrument_touched and (va == '<absent>' or vb == '<absent>'):
        note = '  <- new metric, instrument changed'
    elif mark == '~' and instrument_touched:
        note = '  <- verify: instrument or object?'
    print('  %s %-32s %-10s -> %-10s%s' % (mark, k, va, vb, note))

print('')
print('== gate_exits ==')
ge = b.get('gate_exits', {})
if not ge:
    print('  <none recorded>')
else:
    for k in sorted(ge):
        print('  %-16s exit=%s' % (k, ge[k]))

sys.exit(0)
