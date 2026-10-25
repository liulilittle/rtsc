"""Red test for verify_citations.py.

Injects every pre-fix value back into a copy and asserts the verifier fails.
Covers all three fix rounds:
  round 2: section 19.4 (8)
  round 3: sections 15/17/18 (7)
  round 4: auditor B's 9 reachable + doc:3822 function names (10)
"""
import io
import subprocess
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
TMP = r'F:\rtsc\.tmp\cit_red.md'
VER = r'F:\rtsc\evidence\exec\verify_citations.py'

s = io.open(DOC, encoding='utf-8').read()

INJECT = [
    # --- round 2: section 19.4 ---
    ('#### 陷阱 2：S24 只改 `:411`（token）不改 `:431`（成功判定）',
     '#### 陷阱 2：S24 只改 `:409`（token）不改 `:429`（成功判定）'),
    ('// 只把 token 改对，:431 原样留着', '// 只把 token 改对，:429 原样留着'),
    ('（`:180` 就把它当 `kNeedMoreInput`）', '（`:178` 就把它当 `kNeedMoreInput`）'),
    ('会让 `Receive` 在 `:232` 短路', '会让 `Receive` 在 `:230` 短路'),
    ('**没有任何测试能抓到 `:431`**', '**没有任何测试能抓到 `:429`**'),
    ('执行完本批必须贴出 `:431` 附近的 diff', '执行完本批必须贴出 `:429` 附近的 diff'),
    ('**S9：只改 `:232` 忘了 `Shutdown` 的 `closed_`**',
     '**S9：只改 `:230` 忘了 `Shutdown` 的 `closed_`**'),

    # --- round 3: sections 17/18 ---
    ('| 改哪些文件 | `src/net/tls_schannel.cpp:101-201`',
     '| 改哪些文件 | `src/net/tls_schannel.cpp:99-199`'),
    ('2. D1 只改 `Handshake`（`t:101-201`）', '2. D1 只改 `Handshake`（`t:99-199`）'),
    ('走的是 `t:407`（`have_ctx_` 已为真，不短路）',
     '走的是 `t:405`（`have_ctx_` 已为真，不短路）'),

    # --- round 4: B's nine ---
    ('| **`kClosed` + 剩余明文 > 0** |', '| **`kClosed` + 剩余明文 > 0** |'),
    ('会去改 **`:411`（检查 ctl）** 与 **`:431`（别把 CONTINUE_NEEDED 当成功）**',
     '会去改 **`:411`（检查 ctl）** 与 **`:429`（别把 CONTINUE_NEEDED 当成功）**'),
    ('证明不了「`:431` 不再把 CONTINUE_NEEDED 当成功」',
     '证明不了「`:429` 不再把 CONTINUE_NEEDED 当成功」'),
    ('所以 S24 的修复范围必须**同时**包含 `:431`',
     '所以 S24 的修复范围必须**同时**包含 `:429`'),
    ('| **S24-b** | `:431` 把 `SEC_I_CONTINUE_NEEDED`',
     '| **S24-b** | `:429` 把 `SEC_I_CONTINUE_NEEDED`'),
    ('| **S24-b** | `:431` 恢复', '| **S24-b** | `:429` 恢复'),
    ('| **S9** | `:232` 恢复 `if (closed_) return kClosed`',
     '| **S9** | `:230` 恢复 `if (closed_) return kClosed`'),
    ('的 `shutdown_sent_` 使第二次返回空', '的 `t:404` 的 `shutdown_sent_` 使第二次返回空'),
    ('前加 `if (!handshake_complete_) return kProtocolError`',
     '在 `:405` 前加 `if (!handshake_complete_) return kProtocolError`'),
    ('`Send`（:209）、`Receive`（:232）各一处',
     '`Handshake`、`Shutdown`、`Receive` 各一处'),

    # --- round 5: auditor A's P1 + P2 ---
    ('；`:169`（注释断言「SChannel\'s stream handshake does not report EXTRA」并直接 `consumed = in_size`）',
     '；`:167`（注释断言「SChannel\'s stream handshake does not report EXTRA」并直接 `consumed = in_size`）'),
    ('| **S10** | `:169` 恢复 `consumed = in_size` 且不吸收尾部',
     '| **S10** | `:167` 恢复 `consumed = in_size` 且不吸收尾部'),
    ('后续 `Receive` 会在 `:232` 直接返回 `kClosed`',
     '后续 `Receive` 会在 `:230` 直接返回 `kClosed`'),
    ('与 `:232`（Receive 入口 `if (closed_) return kClosed`）；`rx_buffer_` 的入队/消费在 `:236`',
     '与 `:230`（Receive 入口 `if (closed_) return kClosed`）；`rx_buffer_` 的入队/消费在 `:233`'),
    ('（`closed_` 在 `:232` 直接短路 `Receive`）',
     '（`closed_` 在 `:230` 直接短路 `Receive`）'),
]

n = 0
for new, old in INJECT:
    if new not in s:
        print('MISSING: %r' % new[:64])
        sys.exit(2)
    if new == old:
        continue
    s = s.replace(new, old, 1)
    n += 1

# doc:2443's t:244 -> t:242 (unique inside section 17)
if '`t:244`（<5 字节返回 kOk）' in s:
    s = s.replace('`t:244`（<5 字节返回 kOk）', '`t:242`（<5 字节返回 kOk）', 1)
    n += 1

io.open(TMP, 'w', encoding='utf-8', newline='').write(s)
print('injected %d regressions' % n)

ver = io.open(VER, encoding='utf-8').read()
red = ver.replace(
    r"DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'",
    r"DOC = r'F:\rtsc\.tmp\cit_red.md'")
assert red != ver
rp = r'F:\rtsc\.tmp\verify_citations_red.py'
io.open(rp, 'w', encoding='utf-8', newline='').write(red)

p = subprocess.run([sys.executable, rp], capture_output=True, text=True, encoding='utf-8')
print()
print('--- RED (expect FAILED > 0, exit 1) ---')
print(p.stdout.strip())
print('exit=%d' % p.returncode)
if p.returncode != 1:
    print('FAIL: no discriminating power')
    sys.exit(1)

p2 = subprocess.run([sys.executable, VER], capture_output=True, text=True, encoding='utf-8')
print()
print('--- GREEN (real doc) ---')
print(p2.stdout.strip())
print('exit=%d' % p2.returncode)
sys.exit(0 if p2.returncode == 0 else 1)
