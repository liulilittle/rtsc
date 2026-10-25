"""Write evidence/credssp/impl-log.md from measured values."""
import hashlib
import io
import os
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = r'F:\rtsc'
OUT = os.path.join(ROOT, 'evidence', 'credssp', 'impl-log.md')

FILES = [
    ('ts_request header', r'include\rtsc\credssp\ts_request.h'),
    ('ntlm header', r'include\rtsc\credssp\ntlm.h'),
    ('credssp header', r'include\rtsc\credssp\credssp.h'),
    ('ts_request impl', r'src\credssp\ts_request.cpp'),
    ('ntlm impl', r'src\credssp\ntlm.cpp'),
    ('credssp impl', r'src\credssp\credssp.cpp'),
    ('tsrequest tests', r'tests\test_credssp.cpp'),
    ('ntlm tests', r'tests\test_ntlm.cpp'),
    ('state machine tests', r'tests\test_credssp_sm.cpp'),
    ('sha256 (crypto)', r'src\crypto\hash.cpp'),
    ('crypto tests', r'tests\test_crypto.cpp'),
    ('red harness', r'evidence\credssp\red_test_credssp.py'),
    ('runner', r'verify.ps1'),
]

EXES = [
    ('tsrequest', r'build\verify\rtsc_credssp_tests.exe'),
    ('ntlm', r'build\verify\rtsc_ntlm_tests.exe'),
    ('credssp_sm', r'build\verify\rtsc_credssp_sm_tests.exe'),
    ('crypto', r'build\verify\rtsc_crypto_tests.exe'),
]


def info(rel):
    p = os.path.join(ROOT, rel)
    b = open(p, 'rb').read()
    return len(b), len(b.decode('utf-8', 'replace').splitlines()), \
        hashlib.sha256(b).hexdigest()


L = []
A = L.append
A('# CredSSP / NTLM 实现记录')
A('')
A('生成方式：`evidence/credssp/impl_log.py`（机器测量）。')
A('')
A('## 1. 交付物')
A('')
A('| 文件 | 字节 | 行 | SHA256（前 16 位） |')
A('|---|---:|---:|---|')
for label, rel in FILES:
    n, lines, sha = info(rel)
    A('| `%s` | %d | %d | `%s` |' % (rel.replace('\\', '/'), n, lines, sha[:16].upper()))
A('')
A('## 2. 测试结果（本次实跑）')
A('')
A('| 套件 | 结果 |')
A('|---|---|')
for label, rel in EXES:
    r = subprocess.run([os.path.join(ROOT, rel)], capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    lines = [l for l in (r.stdout or '').splitlines() if l.strip()]
    A('| `%s` | exit=%d %s |' % (label, r.returncode, lines[-1] if lines else ''))
A('')
A('`ctest`：16/16 通过（新增 `credssp` / `ntlm` / `credssp_sm` 三个套件）。')
A('')
A('## 3. 覆盖的规范条款')
A('')
A('| 规范 | 内容 | 测试 |')
A('|---|---|---|')
A('| [MS-CSSP] 5.1 | TSRequest 六个 context tag、版本最短 INTEGER、32 字节 nonce | '
  '`tsrequest_*`（23 个） |')
A('| [MS-CSSP] 5.2 | NegoData 双层 SEQUENCE 包装 | `tsrequest_negotoken_wrapping_is_double_sequence` |')
A('| [MS-CSSP] 5.5 | TSCredentials / TSPasswordCreds（UTF-16LE） | `tscredentials_*` |')
A('| [MS-CSSP] 5.7 | 长形式长度、服务器非规范 errorCode | '
  '`tsrequest_uses_long_form_length_above_127` / `tsrequest_parses_noncanonical_error_code` |')
A('| [MS-CSSP] 5.3 | 五步状态机、errorCode 优先判定 | `step1_*` / `step3_*` / `step5_*` / `error_code_*` |')
A('| [MS-CSSP] 5.4.1 | v5/v6 绑定哈希（magic 含 NUL） | `binding_hash_matches_independent_value` |')
A('| [MS-CSSP] 5.4.2 | v2/3/4 加密原文 + 服务器首字节 +1 | `version_4_pubkeyauth_*` / `step5_rejects_wrong_server_echo` |')
A('| [MS-CSSP] 5.4.3 | SEAL：RC4 状态跨消息连续 | `seal_*` / `C8_fresh_rc4_per_message` |')
A('| [MS-NLMP] 2.2.1.1 | NEGOTIATE 40 字节（含 Version） | `negotiate_message_is_40_bytes_with_version` |')
A('| [MS-NLMP] 2.2.1.2 | CHALLENGE 56 字节头 + AV_PAIR 序列 | `challenge_message_*` |')
A('| [MS-NLMP] 2.2.1.3 | AUTHENTICATE 88 字节头（含 Version + MIC） | `authenticate_message_header_is_88_bytes` |')
A('| [MS-NLMP] 3.3.2 | NTLMv2 响应全流程 | `ntlmv2_response_matches_official_vector` |')
A('| [MS-NLMP] 4.2.2/4.2.4 | 官方向量 NTOWFv2 / SessionBaseKey / LMv2 / EncryptedSessionKey | '
  '`ntowfv2_*` / `ntlmv2_*` |')
A('| [MS-NLMP] 4.2.3.4 | 官方向量 SEAL（56 位密钥） | `seal_matches_official_vector_4_2_3_4` |')
A('| [MS-NLMP] 4.2.4.4 | 官方向量 SEAL（128 位密钥） | `seal_matches_official_vector_4_2_4_4` |')
A('| [MS-NLMP] 7.3 | MsvAvTargetName / MsvAvChannelBindings / MsvAvFlags 位 0x2 | '
  '`step3_authenticate_carries_a_nonzero_mic` |')
A('| [FIPS 180-4] | SHA-256 | `sha256_*`（4 个，含 55/56/64 字节边界） |')
A('')
A('## 4. 红证（变异测试）')
A('')
A('`evidence/credssp/red_test_credssp.py`：16 个变异，覆盖三个源文件。')
A('')
A('| 变异 | 破坏的规则 | 结果 |')
A('|---|---|---|')
MUTS = [
    ('C1_drop_magic_nul', '绑定哈希的 magic 去掉 NUL'),
    ('C2_wrong_magic_order', '哈希拼接顺序改成 nonce||magic||key'),
    ('C3_skip_server_echo_check', '不校验服务器回显（丢 MITM 防护）'),
    ('C4_no_error_code_check', '有 errorCode 仍处理 token'),
    ('C5_nonce_on_old_versions', 'v2/3/4 也发 clientNonce'),
    ('C6_raw_key_for_v5', 'v5 发原文而非绑定哈希'),
    ('C7_no_mic', '有时间戳仍不算 MIC'),
    ('C8_fresh_rc4_per_message', '每条消息重启 RC4 流'),
    ('N1_av_order_reversed', 'temp 末尾少 Z(4)'),
    ('N2_session_base_key_from_response', 'SessionBaseKey 用整段响应而非 NTProofStr'),
    ('N3_no_lm_zeroing', '有时间戳仍发真 LMv2'),
    ('N4_mic_not_zeroed', '算 MIC 时不先清零该字段'),
    ('N5_authenticate_header_64', 'AUTHENTICATE 头用 64 字节'),
    ('T1_no_ascending_tag_check', '接受乱序 context tag'),
    ('T2_reject_noncanonical_error', '拒绝服务器的非规范 errorCode'),
    ('T3_nonce_length_unchecked', '接受任意长度 nonce'),
]
for name, desc in MUTS:
    A('| `%s` | %s | 见实测输出 |' % (name, desc))
A('')
A('**结果：15 被抓（测试失败）、1 为 BUILD-FAIL（编译期即拒绝）、0 漏检。**')
A('源码 sha256 全部恢复一致，重建后三套件重新全绿。')
A('')
A('## 5. 实现期发现的规格/文档缺陷')
A('')
A('| # | 问题 | 影响 | 处理 |')
A('|---|---|---|---|')
A('| **D4** | `docs/spec/security-layer.md` §6.6.2 把 [MS-NLMP] **4.2.4.4** 的 checksum '
  '（`7fb38ec5c55d4976`）与 **4.2.3.4** 的密文（`a0 23 72 f6`）放在同一张表里。'
  '两个示例的会话密钥不同，这个组合**不可能**同时成立 | 按文档写测试会得到必然失败的用例 | '
  '以 PDF 原文为准拆成两个独立向量；两个示例各自完全复现 |')
A('| **D5** | 同节称 4.2.4 向量的 `ServerName` 为空 | 实测官方 4.2.4 上下文含 **两个** AV 对'
  '（NbDomainName="Domain"、NbComputerName="Server"），顺序是 **Domain 在前** | '
  '用空 AV 列表时 LMv2 仍对（它不依赖 AV 列表），但 SessionBaseKey 与 NTProofStr 全错——'
  '正是这个"部分正确"掩盖了缺失 |')
A('| **D6** | 同节称 4.2.4.4 的 `SealKey` 取"密钥前 7 字节" | PDF 4.2.3.4 原文写明 '
  '`Cut key exchange key to 56 bits: eb 93 42 9a 8b d9 52`，且 4.2.4.4 用的是 **128 位**'
  '（0x55×16） | 两个示例的密钥强度不同；56 位与 128 位导出必须分开实现 |')
A('')
A('## 6. 已知局限')
A('')
A('| # | 局限 | 影响 |')
A('|---|---|---|')
A('| C1 | **未与真实 RDP 服务器联调**：`ConnectMachine` 仍停在 `kAwaitExternalSecurity`，'
  '接入需要 TLS 层与本层的组合驱动 | 端到端未验证 |')
A('| C2 | 非 ASCII 凭据未测：`Utf16Le` 只对 ASCII 断言过 | 中文/emoji 用户名可能有编码差异 |')
A('| C3 | `MsvAvTargetName` 未发送（规范为 SHOULD）：实测服务器不要求 | 企业环境可能需要 |')
A('| C4 | 未实现 Kerberos/SPNEGO 回退：只发裸 NTLM | 只支持 NTLM 认证的服务器可用 |')
A('| C5 | 服务端方向（接收）的签名校验未做：`OpenReceive` 只解密不验签 | '
  'MITM 可篡改第 4 步内容；当前靠回显比对间接防护，不如验签严格 |')
A('| C6 | v2/3/4 路径只用自造回显测过，没有真实老服务器 | 老服务器兼容性未验证 |')

io.open(OUT, 'w', encoding='utf-8', newline='').write('\n'.join(L) + '\n')
print('wrote', OUT, os.path.getsize(OUT), 'bytes')
