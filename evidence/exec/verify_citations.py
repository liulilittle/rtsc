"""Verify line-number citations by CONTENT ANCHOR within a bounded section.

History of this script (each version died to a red test):
  v1  keyed on doc line numbers            -> inserting 5 lines broke everything
  v2  keyed on content anchor, whole doc   -> later sections quote earlier ones
                                              verbatim, so anchors were ambiguous
  v3  this: content anchor + section bound

Why the section bound is necessary, not cosmetic: sections 20-28 quote earlier
sections verbatim when reviewing them. Searching the whole document for
"#### 陷阱 2：S24 只改" finds 4 hits (the real one plus three quotations).
A verifier that reports "ambiguous" for all of them is useless.

Each check names: the section, a unique substring of the doc line, the file, the
construct that must sit at the cited line, and which citation on the line to use.
"""
import io
import re
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'
FILES = {
    'tls': r'F:\rtsc\src\net\tls_schannel.cpp',
    'credssp': r'F:\rtsc\src\credssp\credssp.cpp',
    'cm': r'F:\rtsc\src\proto\connect_machine.cpp',
    'test': r'F:\rtsc\tests\test_tls.cpp',
}
SRC = {k: io.open(v, encoding='utf-8').read().splitlines() for k, v in FILES.items()}
L = io.open(DOC, encoding='utf-8').read().splitlines()

# 1-based inclusive line ranges. Sections 20+ are audit history that quote
# earlier sections verbatim; including them makes every anchor ambiguous.
# Section ranges are computed from the headings, not hardcoded. Hardcoding them
# is the same mistake as hardcoding doc line numbers: inserting 5 lines anywhere
# shifts every later section and silently truncates the search window.
_HEAD = re.compile(r'^##\s+(\d+)\.')
_starts = [(int(m.group(1)), i) for i, l in enumerate(L)
           if (m := _HEAD.match(l))]
SECTIONS = {}
for k, (num, start) in enumerate(_starts):
    end = _starts[k + 1][1] - 1 if k + 1 < len(_starts) else len(L) - 1
    SECTIONS[str(num)] = (start + 1, end + 1)

SHUTDOWN_IF = 'if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {'
CLOSED_SHORT = 'if (closed_) return MakeError(Status::kClosed'
DECODE_FAIL = 'if (!e.ok()) return Fail(e.status, "cannot decode TSRequest");'

# (section, unique doc-line anchor, file, construct at cited line, cited line)
CHECKS = [
    # ---- section 19 ----
    ('19', '在 `:40`（`#include "rtsc/net/tls.h"` 之后）',
     'tls', '#include "rtsc/net/tls.h"', 40),
    ('19', '| **S1** | `credssp.cpp:52` 改回',
     'credssp', 'RandomBytes(nonce_, kNonceSize)', 52),
    ('19', '| **S5** | 删掉 `credssp.cpp:127-129` 的版本下界校验',
     'credssp', 'if (req.version < kMinVersion) {', 127),
    ('19', '| **S11** | 删掉 `credssp.cpp:423-443` 的 seq 校验与 MAC 比对',
     'credssp', 'if (seq != recv_seq_) {', 423),
    ('19', '| **S20** | `:168` 恢复无条件回填 password',
     'cm', 'pdu.info.password', 168),
    ('19', '#### 陷阱 2：S24 只改 `:411`（token）不改 `:431`（成功判定）',
     'tls', 'SecBuffer token{0, SECBUFFER_TOKEN, nullptr};', 411),
    ('19', '// 只把 token 改对，:431 原样留着',
     'tls', SHUTDOWN_IF, 431),
    ('19', '（`:180` 就把它当 `kNeedMoreInput`）',
     'tls', 'kNeedMoreInput', 180),
    ('19', '会让 `Receive` 在 `:232` 短路',
     'tls', CLOSED_SHORT, 232),
    ('19', '**没有任何测试能抓到 `:431`**',
     'tls', SHUTDOWN_IF, 431),
    ('19', '执行完本批必须贴出 `:431` 附近的 diff',
     'tls', SHUTDOWN_IF, 431),
    ('19', '只有 `:745`/`:792` 的 `Send` 有',
     'test', 'CHECK_EQ(consumed, pt.size());', 745),
    ('19', '**S9：只改 `:232` 忘了 `Shutdown` 的 `closed_`**',
     'tls', CLOSED_SHORT, 232),
    ('19', '`Handshake`（:106）、`Send`（:209）、`Receive`（:232）各一处',
     'tls', CLOSED_SHORT, 209),

    # ---- section 17 (reached from section 19) ----
    ('17', '| 改哪些文件 | `src/net/tls_schannel.cpp:101-201`',
     'tls', CLOSED_SHORT, 232),
    ('17', '2. D1 只改 `Handshake`（`t:101-201`）',
     'tls', 'Error Handshake(const uint8_t* in, size_t in_size, size_t& consumed,', 101),
    ('17', '| **`kClosed` + 剩余明文 > 0** |',
     'tls', 'return (progressed != 0 || produced != 0)', 245),

    # ---- section 18 (reached from section 19) ----
    ('18', '走的是 `t:407`（`have_ctx_` 已为真，不短路）',
     'tls', 'if (!have_ctx_) {', 407),
    ('18', '| **批2**<br>TLS 后端 |',
     'tls', CLOSED_SHORT, 232),
    ('18', '会去改 **`:411`（检查 ctl）**',
     'tls', SHUTDOWN_IF, 431),
    ('18', '证明不了「`:431` 不再把 CONTINUE_NEEDED 当成功」',
     'tls', SHUTDOWN_IF, 431),
    ('18', '所以 S24 的修复范围必须**同时**包含 `:431`',
     'tls', SHUTDOWN_IF, 431),
    ('18', '| **S24-b** | `:431` 把 `SEC_I_CONTINUE_NEEDED`',
     'tls', SHUTDOWN_IF, 431),
    ('18', '| **S24-b** | `:431` 恢复',
     'tls', SHUTDOWN_IF, 431),
    ('18', '| **S9** | `:232` 恢复 `if (closed_) return kClosed`',
     'tls', CLOSED_SHORT, 232),
    ('18', '的 `shutdown_sent_` 使第二次返回空',
     'tls', 'if (shutdown_sent_) return MakeError(Status::kOk, 0, "");', 406),
    ('18', '前加 `if (!handshake_complete_) return kProtocolError`',
     'tls', 'if (!have_ctx_) {', 407),

    # ---- round 5: auditor A's P1 mutation-table hits + 3 P2 ----
    ('6', '| **S10** | **`Handshake` 无条件 `consumed = in_size`**',
     'tls', 'consumed = in_size;', 169),
    ('18', '| **S10** | `:169` 恢复 `consumed = in_size` 且不吸收尾部',
     'tls', 'consumed = in_size;', 169),
    ('5', '后续 `Receive` 会在 `:232` 直接返回 `kClosed`',
     'tls', CLOSED_SHORT, 232),
    ('6', '| **S9** | **`Shutdown()` 后 `Receive` 短路**',
     'tls', CLOSED_SHORT, 232),
    ('13', '（`closed_` 在 `:232` 直接短路 `Receive`）',
     'tls', CLOSED_SHORT, 232),

    # ---- round 6: auditor B's seven mechanical shifts (+2) ----
    ('6', '| **S10** | **`Handshake` 无条件 `consumed = in_size`**',
     'tls', 'in_bufs[0].cbBuffer = static_cast<unsigned long>(token.size());', 126),
    ('15', '| **S7** | P1 | `kPeerAlert` 从不产生',
     'tls', 'constexpr uint8_t kRecordAlert = 21;', 53),
    ('15', '| **S9** | P1 | `Shutdown()` 置 `closed_`（`t:432`）',
     'tls', 'closed_ = true;', 432),
    ('15', '| **N10** | **§15.1 的行号在多项修复后必然漂移**',
     'tls', 'Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {', 371),
    ('17', '| **A-E2** | 我 S9 引 `src/net/tls_schannel.cpp:432`',
     'tls', 'closed_ = true;', 432),
    ('18', '| `closed() = true` |',
     'tls', 'closed_ = true;', 432),
    ('18', '| `Shutdown again -> status=0 out=0 bytes` |',
     'tls', 'if (shutdown_sent_) return MakeError(Status::kOk, 0, "");', 406),

    # ---- round 8: batch-1 / batch-4 red-test rows (auditor B coverage gap) ----
    ('19', '| **S12** | `connect_machine.cpp:353-357` 恢复 no-op',
     'cm', 'if (state_.phase != ConnectPhase::kAwaitExternalSecurity) {', 353),
    ('19', '| **S20** | `:168` 恢复无条件回填 password',
     'cm', 'pdu.info.password = credentials_.password;', 168),
    ('19', '| **S9** | 取 `Receive` 签名',
     'tls', CLOSED_SHORT, 232),
    ('19', '（只有 `:745`/`:792` 的 `Send` 有）',
     'test', 'CHECK_EQ(consumed, pt.size());', 745),
]

CITE = re.compile(r'`(?:(?:credssp\.cpp|tls_schannel\.cpp|connect_machine\.cpp|tls\.h|'
                  r'test_tls\.cpp)|t)?:(\d+)(?:-(\d+))?`')
CITE_BARE = re.compile(r'(?<![`\w]):(\d+)(?:-(\d+))?(?!`)')

ok = bad = 0
problems = []

for sec, anchor, tgt, needle, req in CHECKS:
    lo, hi = SECTIONS[sec]
    hits = [i for i in range(lo - 1, min(hi, len(L))) if anchor in L[i]]
    if not hits:
        bad += 1
        problems.append((sec, anchor, 'anchor not found in section %s' % sec))
        continue
    if len(hits) > 1:
        bad += 1
        problems.append((sec, anchor,
                         'anchor ambiguous inside section %s (%d hits: %s)'
                         % (sec, len(hits), [h + 1 for h in hits])))
        continue
    line = L[hits[0]]
    nums = [(int(m.group(1)), int(m.group(2)) if m.group(2) else int(m.group(1)))
            for m in CITE.finditer(line)]
    if not nums:
        nums = [(int(m.group(1)), int(m.group(2)) if m.group(2) else int(m.group(1)))
                for m in CITE_BARE.finditer(line)]
    if not nums:
        bad += 1
        problems.append((sec, anchor, 'no citation on doc:%d' % (hits[0] + 1)))
        continue
    src = SRC[tgt]
    want = ' '.join(needle.split())
    cands = [(a, b) for a, b in nums if req is None or a == req]
    if not cands:
        bad += 1
        problems.append((sec, anchor,
                         'doc:%d does not cite :%d (has %s)'
                         % (hits[0] + 1, req, [a for a, _ in nums])))
        continue
    hit = False
    for a, b in cands:
        if a <= len(src) and b <= len(src):
            head = ' '.join(src[a - 1].split())
            if want in head:
                hit = True
                break
            if a != b and want in ' '.join(' '.join(src[a - 1:b]).split()):
                hit = True
                break
    if hit:
        ok += 1
    else:
        a = cands[0][0]
        actual = src[a - 1].strip()[:60] if a <= len(src) else '<OOR>'
        bad += 1
        problems.append((sec, anchor,
                         'doc:%d cites :%d -> %r' % (hits[0] + 1, a, actual)))

print('=== citation check: content anchor + section bound ===')
print('checks passed :', ok)
print('checks FAILED :', bad)
if problems:
    print()
    for sec, anchor, why in problems:
        print('  [§%s] %r' % (sec, anchor[:58]))
        print('        %s' % why)
sys.exit(1 if bad else 0)
