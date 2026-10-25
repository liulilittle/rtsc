# SChannel 探针源码索引

本目录 50 个 `.cpp` 是 TLS 后端选型阶段的实测探针源码，
从 `F:\rtsc\.tmp\tlsprobe\` 复制而来（`.tmp` 是临时目录，可能被清理）。

## 为什么保留源码

探针的**输出**证明「实测结果是什么」，源码证明「实测是怎么做的」。
两者合起来才构成完整证据链——只留输出无法复核方法是否正确。

**未被文档引用的探针同样保留**：它们可能是「负证据」（证明某条路走不通）。
成本也极低：合计 358 KB。

## 三个引用口径（必须全部列出，否则数字不可复核）

| 口径 | 判据 | 被引用 | 未引用 | 用途 |
|---|---|---:|---:|---|
| **C（主口径）** | 任一种具体证据形式（见下） | **36** | **14** | **统计依据** |
| A | `<stem>.cpp` 文件全名 | 26 | 24 | 参考：最保守 |
| B | `\b<stem>\b` 裸编号 | 36 | 14 | **不作依据**（有已知碰撞） |

### 口径 C 的判据（任一条成立即算引用）

1. `<stem>.cpp` —— 明确写出文件名
2. `<stem>.exe` —— 探针二进制的输出被引用
3. `<stem>` 出现在 `[BASH:...]` / `[READ:...]` 证据标记内
4. `consult-b <stem>` —— 作为另一审计方的证据被采信

**每个文件的具体理由都在表格「证据形式」列**，可逐条复核。

### 为什么 A（26）不够

实测发现 **10 个探针只以裸编号形式被引用**：

```
probe10, probe12, probe15, probe17, probe22, probe3, probe31, probe41, probe44, probe6
```

逐个查看上下文，**全部是真实证据引用**，例如：

- `[BASH:probe10/probe12/probe17/probe27/probe36]` —— 一组回归探针
- `probe15.exe → "target=wrong name, manual only ... OK"` —— 实测输出
- `consult-b probe41 → 0x1302 TLS_AES_256_GCM_SHA384` —— 采信另一审计方

**所以 A=26 少算了 10 个。**

### 为什么 B（36）集合对但不可作为依据

B 的**集合**（36）与 C 相同，但它的**计数**有假阳性：

`probe.cpp` 的 stem 是 `probe`，`\bprobe\b` 会命中 `schannel-probe.txt`
和英文普通单词 `probe`。实测：

| 文档 | `\bprobe\b` | `\bprobe\.cpp\b` | 假阳性 |
|---|---:|---:|---:|
| design-a | 18 | 2 | 16 |
| design-b | 4 | 0 | 4 |
| **合计** | **22** | **2** | **20** |

**22 是总出现次数，其中 20 次是假阳性**——真引用只有 2 次，
即 design-a 里的 `[READ:F:\rtsc\.tmp\tlsprobe\probe.cpp:61]`（两处）。

> 注：consult-b 第⑳步建议把口径 B 改成 35/15，前提是「`probe.cpp` 被误算已引用」。
> 但实测 `probe.cpp` 有 2 次真实 `.cpp` 引用，**它确实是已引用**，
> 所以 36/14 的集合是对的，只有计数需要说明。35/15 不成立。

## 引用统计的假阳性来源（本项目踩过三个）

### 1. 子串匹配（consult-b 第⑱步）

`stem in doc` 让 `iso` 命中 `poisoned` 里的 `iso`。**修法：`\b<文件名>\b`。**

### 2. 自指污染（第⑲步，比第 1 类更隐蔽）

在**审计报告**上统计引用是自指的：审计报告必然讨论「哪些没被引用」。
实测含 `consult-b.md` 时是**「引用 50 / 未引用 0」——100% 全覆盖**，即污染铁证。

**修法：统计源只取「消费方文档」**（design-a / design-b），排除「元文档」（consult-b）。
判据不是文档类型，而是**该文档是否以这些名字为讨论对象**。

### 3. 单词/文件名碰撞（第⑳步）

`probe.cpp` 的 stem 是 `probe`，`\bprobe\b` 命中英文单词与 `schannel-probe.txt`。
**修法：主口径要求具体证据形式，并逐文件列出理由。**

## 用途列的权威来源

**「用途」的权威来源是消费方文档的结论，不是 API 列表。**
API 只说明「调了什么」（手段），不说明「验证了什么」（目的）。

| 来源 | 数量 | 说明 |
|---|---:|---|
| `design-b` 探针表结论 | 24 | 权威：消费方文档写了它证明了什么 |
| 作者注释 | 2 | 次权威：写探针时留的 `//` 注释 |
| **有结论合计** | **26** | 24 + 2 |
| 无 | 24 | 既无结论也无注释 |

> **「—」表示无权威结论**，不是「没有用途」。
> 对于这些行，源码**能看出**调用了哪些 API，但**无法推断验证意图**——
> 所以「用途」留空，「调用」列仍如实列出（那是事实，不是推断）。

## 文件清单

| 文件 | 字节 | 用途（结论） | 结论摘要 | 来源 | 证据形式 | 调用（辅助） |
|---|---:|---|---|---|---|---|
| `iso.cpp` | 7637 | — | — | 无 | — | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `link1.cpp` | 270 | — | — | 无 | — | — |
| `link2.cpp` | 292 | — | — | 无 | — | — |
| `matrix.cpp` | 9714 | — | — | 无 | — | AcceptSecurityContext, DecryptMessage, EncryptMessage, ApplyControlTok |
| `probe.cpp` | 14655 | — | — | 无 | cpp×2, evtag×12 | AcquireCredentialsHandle x2, AcceptSecurityContext, DecryptMessage, En |
| `probe10.cpp` | 9164 | — | — | 无 | evtag×1 | AcceptSecurityContext, DecryptMessage x2, EncryptMessage, FreeContextB |
| `probe11.cpp` | 10291 | 累计缓冲 | 只喂剩余 → `0x80090308`；喂累计 → OK | design-b 探针表 | cpp×1, evtag×1 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe12.cpp` | 9261 | — | — | 无 | exe×1, evtag×2 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe13.cpp` | 8899 | — | — | 无 | — | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe14.cpp` | 9727 | — | — | 无 | — | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe15.cpp` | 5507 | — | — | 无 | exe×1, evtag×1 | DeleteSecurityContext, FreeContextBuffer |
| `probe16.cpp` | 4872 | TLS1.3 与 legacy cred | `SP_PROT_TLS1_3_CLIENT` → cred `0x80090331`；`1.2\\|1.3` → `proto=0x0800`（静默降级） | design-b 探针表 | cpp×1, exe×1, evtag×1 | DeleteSecurityContext, FreeContextBuffer |
| `probe17.cpp` | 8003 | — | — | 无 | evtag×1 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe18.cpp` | 10300 | 丢 `EXTRA` | 后续记录 `0x80090330`（TLS1.2/1.3 均如此） | design-b 探针表 | cpp×1, evtag×1 | AcceptSecurityContext, DecryptMessage x2, EncryptMessage, FreeContextB |
| `probe19.cpp` | 1551 | 差分预言机 | BCrypt 支持 MD4/RC4/MD5/SHA*/AES/3DES/ECDH_P256；HMAC-MD5 需 `HMAC_FLAG` | design-b 探针表 | cpp×1, exe×1, evtag×1 | BCryptOpenAlgorithmProvider x2 |
| `probe20.cpp` | 8001 | 4-SecBuffer 下限 | nbuf=1..3 → `0x80090308`；nbuf=4 → OK | design-b 探针表 | cpp×1, exe×1, evtag×2 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe21.cpp` | 6591 | `cbTrailer` 是上界 | TLS1.3 `hdr=5 trl=44` 但 `payload=16` 时实际线长 38 | design-b 探针表 | cpp×1, exe×1, evtag×2 | AcceptSecurityContext, EncryptMessage, FreeContextBuffer x2, CertCreat |
| `probe22.cpp` | 5904 | — | — | 无 | exe×1, evtag×1 | DeleteSecurityContext, FreeContextBuffer |
| `probe23.cpp` | 4004 | — | — | 无 | — | FreeContextBuffer |
| `probe24.cpp` | 12189 | 重协商 | TLS1.2 `SEC_I_RENEGOTIATE` → 197/822/206 字节多轮；TLS1.3 → `0x00090360` | design-b 探针表 | cpp×2 | AcceptSecurityContext x3, DecryptMessage, EncryptMessage, FreeContextB |
| `probe25.cpp` | 7570 | 篡改记录 | TLS1.2 poisoned 10/10；TLS1.3 recovered 10/10 | design-b 探针表 | cpp×1, exe×1, evtag×1 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe26.cpp` | 8437 | 篡改记录 | TLS1.2 poisoned 10/10；TLS1.3 recovered 10/10 | design-b 探针表 | cpp×1, audit×2 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe27.cpp` | 10725 | 4-SecBuffer 下限 | nbuf=1..3 → `0x80090308`；nbuf=4 → OK | design-b 探针表 | cpp×2, exe×3, evtag×5, audit×1 | AcceptSecurityContext, DecryptMessage x3, EncryptMessage, FreeContextB |
| `probe28.cpp` | 4723 | — | — | 无 | — | DeleteSecurityContext, FreeContextBuffer |
| `probe29.cpp` | 4771 | 真实套件 | TLS1.2 = `0x009D TLS_RSA_WITH_AES_256_GCM_SHA384`；禁 RSA kex → `0xC030` | design-b 探针表 | cpp×1, exe×1, evtag×1 | DeleteSecurityContext, FreeContextBuffer |
| `probe3.cpp` | 12028 | — | — | 无 | evtag×1 | AcquireCredentialsHandle x2, AcceptSecurityContext, DecryptMessage, En |
| `probe30.cpp` | 5020 | — | — | 无 | — | DeleteSecurityContext, FreeContextBuffer |
| `probe31.cpp` | 5781 | — | — | 无 | exe×1, evtag×1 | DeleteSecurityContext, FreeContextBuffer |
| `probe32.cpp` | 8995 | 零长/双向认证 | `EncryptMessage(0)` OK；`ASC_REQ_MUTUAL_AUTH` → `0x00090320` | design-b 探针表 | cpp×1, exe×2, evtag×2 | AcceptSecurityContext, DecryptMessage, EncryptMessage x2, FreeContextB |
| `probe33.cpp` | 5799 | — | — | 无 | — | DecryptMessage, DeleteSecurityContext, FreeContextBuffer |
| `probe34.cpp` | 8665 | TLS1.3 票据 | `SEC_I_RENEGOTIATE` + `EXTRA=103`（`16 03 03 00 62 04 ...` = NewSessionTicket）；`ISC` 后必须视为已消费 | design-b 探针表 | cpp×1 | DecryptMessage, EncryptMessage, DeleteSecurityContext, FreeContextBuff |
| `probe35.cpp` | 5350 | SPKI 提取 | `PublicKey.pbData` 270 字节，verbatim 在 SPKI 偏移 24、证书偏移 134 | design-b 探针表 | cpp×1 | DeleteSecurityContext, FreeContextBuffer, CryptEncodeObjectEx x2 |
| `probe36.cpp` | 6989 | `MISSING` 语义 | 1 字节时 `MISSING=12`；13 字节时 `MISSING=32`（总数 45） | design-b 探针表 | cpp×1, exe×2, evtag×3 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe37.cpp` | 6917 | `EXTRA` 别名 | `buf[3] type=5 cb=37 offsetFromStart=37 inInputRange=1` | design-b 探针表 | cpp×1, exe×1, evtag×1 | AcceptSecurityContext, DecryptMessage, EncryptMessage, FreeContextBuff |
| `probe38.cpp` | 5002 | 真实套件 | TLS1.2 = `0x009D TLS_RSA_WITH_AES_256_GCM_SHA384`；禁 RSA kex → `0xC030` | design-b 探针表 | cpp×1, exe×1, evtag×1 | DeleteSecurityContext, FreeContextBuffer |
| `probe39.cpp` | 7932 | TLS1.3 票据 | `SEC_I_RENEGOTIATE` + `EXTRA=103`（`16 03 03 00 62 04 ...` = NewSessionTicket）；`ISC` 后必须视为已消费 | design-b 探针表 | cpp×1, evtag×1, audit×3 | DecryptMessage x3, EncryptMessage x2, FreeContextBuffer x2 |
| `probe4.cpp` | 12924 | close_notify | 无 `ALLOCATE_MEMORY` → `0x80090300`；有 → 24 字节，对端 `0x00090317` | design-b 探针表 | cpp×1, audit×3 | AcceptSecurityContext, DecryptMessage, EncryptMessage, ApplyControlTok |
| `probe40.cpp` | 4561 | close_notify 标志隔离 | 只给 `ISC_REQ_STREAM`（无论 null 还是空 desc）→ `0x80090300`；加 `ISC_REQ_ALLOCATE_MEMORY` → `0x00000000 out=24 | design-b 探针表 | cpp×1 | AcceptSecurityContext, ApplyControlToken, FreeContextBuffer x3, CertCr |
| `probe41.cpp` | 9271 | — | — | 无 | audit×2 | AcceptSecurityContext, DeleteSecurityContext x2, FreeContextBuffer x2, |
| `probe42.cpp` | 7129 | — | — | 无 | — | AcceptSecurityContext, DeleteSecurityContext x2, FreeContextBuffer x2, |
| `probe43.cpp` | 6051 | — | — | 无 | — | AcceptSecurityContext, FreeContextBuffer x2, CertCreateSelfSignCertifi |
| `probe44.cpp` | 6245 | Clean single-call measurement: does ISC ever leave | — | 作者注释 | audit×3 | AcceptSecurityContext, DeleteSecurityContext x2, FreeContextBuffer x3, |
| `probe5.cpp` | 6635 | 证书策略矩阵 | 无 manual → `0x80090325`；MANUAL → 成功但 `CERT_CHECK_RESULT=0x80090301`；DEFERRED → `hr=0x800B0109` | design-b 探针表 | cpp×1, exe×1, evtag×2 | DeleteSecurityContext, FreeContextBuffer, CryptEncodeObjectEx x2, BCry |
| `probe6.cpp` | 12605 | — | — | 无 | exe×2, evtag×3 | AcquireCredentialsHandle, AcceptSecurityContext x4, DecryptMessage x2, |
| `probe7.cpp` | 10832 | — | — | 无 | cpp×3, evtag×4, audit×4 | AcceptSecurityContext, DecryptMessage x3, EncryptMessage, FreeContextB |
| `probe8.cpp` | 11411 | — | — | 无 | — | AcceptSecurityContext x3, DecryptMessage x4, EncryptMessage, ApplyCont |
| `probe9.cpp` | 11643 | TLS1.3 与 legacy cred | `SP_PROT_TLS1_3_CLIENT` → cred `0x80090331`；`1.2\\|1.3` → `proto=0x0800`（静默降级） | design-b 探针表 | cpp×1, exe×1, evtag×2, audit×1 | AcceptSecurityContext, DecryptMessage, EncryptMessage x2, FreeContextB |
| `tpkt_tls.cpp` | 2258 | Red-evidence probe: what happens if the existing T | — | 作者注释 | — | — |
| `tpkt_tls2.cpp` | 1580 | 两层混用 | 密文喂 `TpktStream` → `NeedMoreData` + `dropped=2`；构造密文可被当作合法 PDU | design-b 探针表 | cpp×1, exe×1, evtag×1 | — |
| `tpkt_tls3.cpp` | 2618 | 两层混用 | 密文喂 `TpktStream` → `NeedMoreData` + `dropped=2`；构造密文可被当作合法 PDU | design-b 探针表 | cpp×1, exe×1, evtag×1 | — |

## 注意

- 编译产物（`.exe`/`.obj`）**未保留**：可由源码重建，且与编译器版本绑定。
- 编译命令见 `docs/spec/tls-backend.design-a.md` §7.5 / §7.5b。
- 源码**冻结不改**。需修改时新建文件，保留历史。
- 本表由 `evidence/tls/gen_probe_index.py` 从源码与文档**解析生成**，非人工填写。
