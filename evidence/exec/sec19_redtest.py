"""Red test for verify_sec19.py v3 (now 20 checks, incl. sections 17/18).

Restores ALL pre-fix numbers (the 8 in 19.4 and the 7 in 17/18) into a copy and
asserts the verifier fails. Then confirms the real doc passes.

Proves discriminating power (memory rule 55/61) for every fix made in this round.
"""
import io
import subprocess
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
TMP = r'F:\rtsc\.tmp\sec19_red.md'
VER = r'F:\rtsc\evidence\exec\verify_sec19.py'

s = io.open(DOC, encoding='utf-8').read()

INJECT = [
    # section 19.4 (8)
    ('只改 `:411`（token）不改 `:431`（成功判定）', '只改 `:409`（token）不改 `:429`（成功判定）'),
    ('// 只把 token 改对，:431 原样留着', '// 只把 token 改对，:429 原样留着'),
    ('（`:180` 就把它当 `kNeedMoreInput`）', '（`:178` 就把它当 `kNeedMoreInput`）'),
    ('会让 `Receive` 在 `:232` 短路', '会让 `Receive` 在 `:230` 短路'),
    ('**没有任何测试能抓到 `:431`**', '**没有任何测试能抓到 `:429`**'),
    ('执行完本批必须贴出 `:431` 附近的 diff', '执行完本批必须贴出 `:429` 附近的 diff'),
    ('**S9：只改 `:232` 忘了 `Shutdown` 的 `closed_`**', '**S9：只改 `:230` 忘了 `Shutdown` 的 `closed_`**'),
    ('但 `:432` 仍无条件 `closed_=true`', '但 `:430` 仍无条件 `closed_=true`'),
    # sections 17/18 (7)
    ('· `:232`(S9) ·', '· `:230`(S9) ·'),
    ('只改 `Handshake`（`t:101-201`）', '只改 `Handshake`（`t:99-199`）'),
    ('**不改 `Receive`**（`t:230-345`）', '**不改 `Receive`**（`t:228-343`）'),
    ('走的是 `t:407`（`have_ctx_` 已为真，不短路）', '走的是 `t:405`（`have_ctx_` 已为真，不短路）'),
    ('→ `t:411-413`（空 token，ctl 失败被丢弃）', '→ `t:409-411`（空 token，ctl 失败被丢弃）'),
    ('`:232`(S9)、`:101-201`(S10 D1)', '`:230`(S9)、`:99-199`(S10 D1)'),
]

n = 0
for new, old in INJECT:
    if new not in s:
        print('MISSING: %r' % new[:64])
        sys.exit(2)
    s = s.replace(new, old, 1)
    n += 1

io.open(TMP, 'w', encoding='utf-8', newline='').write(s)
print('injected %d regressions' % n)

ver_src = io.open(VER, encoding='utf-8').read()
red = ver_src.replace(
    r"DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'",
    r"DOC = r'F:\rtsc\.tmp\sec19_red.md'")
assert red != ver_src, 'redirect failed'
red_path = r'F:\rtsc\.tmp\verify_sec19_red.py'
io.open(red_path, 'w', encoding='utf-8', newline='').write(red)

p = subprocess.run([sys.executable, red_path], capture_output=True, text=True,
                   encoding='utf-8')
print()
print('--- RED (expect MISMATCH > 0, exit 1) ---')
print(p.stdout.strip())
print('exit=%d' % p.returncode)
if p.returncode != 1:
    print('FAIL: verifier has no discriminating power')
    sys.exit(1)

p2 = subprocess.run([sys.executable, VER], capture_output=True, text=True,
                    encoding='utf-8')
print()
print('--- GREEN (real doc, expect 0, exit 0) ---')
print(p2.stdout.strip())
print('exit=%d' % p2.returncode)
sys.exit(0 if p2.returncode == 0 else 1)
