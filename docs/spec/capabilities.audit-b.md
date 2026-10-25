# `capabilities.md` 独立交叉审计报告（审计 AI 乙）

- 审计对象：`F:\rtsc\docs\spec\capabilities.md`（2497 行）
- 权威依据：[MS-RDPBCGR] 官方 DOCX 抽文本 `F:\rtsc\.tmp\bcgr.txt`（13226 行）+ `F:\rtsc\.tmp\egdi.txt` + 官方目录 `F:\rtsc\.tmp\toc.txt`
- 审计角度：G/H/I/J/K/L（**刻意避开**甲负责的 §8 字段宽度逐项复核、编号表、位域、错误策略、dump 真实性、长度模型脚本）
- 本报告**未修改** `capabilities.md`，未写任何 C++ 代码。
- 所有结论均为"可执行复现"或"原文行号定位"，脚本落在 `F:\rtsc\.tmp\auditb_*.py`。

---

## 0. 结论摘要

| 项 | 判定 | 一句话 |
|---|---|---|
| G 客户端能力最小集合与正确性 | **FAIL** | §7.1 的 MUST 清单基本正确，但 §7.3 把"规范 MUST"与"本项目需要"混在同一张"必须"表里，且完全未提 3 个服务端拒绝码 |
| H Confirm Active 字段完整性 | **PARTIAL** | 9 个字段的顺序/宽度/字节序**全对**；但 U-13 的降级表述不完整，且 §5.5 的"服务端不校验"被 ERRINFO 表直接反证 |
| I 长度与畸形处理策略 | **FAIL** | 遍历伪码缺 3 类边界检查（可复现 OOB/下溢），且 assert 失败无处置策略；U-14"后者覆盖前者"对安全相关位不安全 |
| J 状态机完整性 | **FAIL** | 缺 Set Error Info、Monitor Layout、通用"意外 PDU"分支、超时；U-03 未区分持久缓存，照字面实现会破坏持久位图缓存 |
| K Font List/Map 与 Deactivate All | **PASS** | 章节号、4 个固定值、26 字节 dump 全部与规范逐字节一致；仅 1 处 `S59 系列` 引用不精确 |
| L 文档内部一致性 | **FAIL** | §7.2 合计 492 与自身 466 矛盾、§8.18 自相矛盾、2 处断引用、§15.1 自我矛盾、U-20 前提事实错误、URL 验证覆盖不足 |

缺陷合计 **28 条**（D-01 … D-28），其中 **5 条为"会导致实现错误"级别**：
D-03（shareID/originatorID 校验断言错误）、D-07/D-08（遍历越界）、D-16（持久缓存被误清）、D-28（Fast-Path dump 密文写成明文）。

---

## G. 客户端能力声明的最小集合与正确性

### G.1 先抄规范：客户端到底"必须"发什么

**结论先行**：规范**没有**一节列出"客户端 Confirm Active 必须包含哪些 capability set"。这一点文档 §7.1 第 976 行的判断是**正确**的。

可抄出的全部规范性依据只有四类：

**(a) 全集层面的 MUST（不含任何 capability 名）**

| # | 原文（`bcgr.txt` 行） | 强度 |
|---|---|---|
| 1 | `After successfully processing the Demand Active PDU, the client MUST send the Confirm Active PDU`（7410） | **MUST** |
| 2 | `the embedded initiator field MUST be set to the User Channel ID ... channelId field MUST be set to the MCS I/O channel ID`（7414） | **MUST** |
| 3 | `After sending the Confirm Active PDU, the client MUST send the Synchronize PDU`（7418） | **MUST** |
| 4 | `If Enhanced RDP Security ... securityHeader field MUST NOT be present`（7415） | **MUST NOT** |
| 5 | `If the data is to be encrypted, the embedded flags field MUST contain SEC_ENCRYPT`（7416） | **MUST** |

**(b) 单 set 内的字段级 MUST（只在"你发了这个 set"时成立）**

| capability | 字段级 MUST | 原文行 |
|---|---|---|
| 0x0001 General | `protocolVersion` MUST = 0x0200；`compressionTypes`/`updateCapabilityFlag`/`remoteUnshareFlag`/`compressionLevel` MUST = 0 | 3194, 3196, 3215-3217 |
| 0x0002 Bitmap | `bitmapCompressionFlag` MUST = TRUE **"because support for compressed bitmaps is required for a connection to proceed"**；`multipleRectangleSupport` MUST = TRUE（同句） | 3257, 3268 |
| 0x0003 Order | `NEGOTIATEORDERSUPPORT` `This flag MUST be set.`；`ZEROBOUNDSDELTASSUPPORT` `The client MUST set this flag.` | 3303, 3304 |
| 0x000D Input | `At a minimum, the INPUT_FLAG_SCANCODES flag MUST be set` | 3483 |
| 0x0010 GlyphCache | 若 `GlyphSupportLevel > 0`，client MUST 支持 GlyphIndex 或 FastIndex 订单 | 3540 |
| 0x0004 / 0x0013 BitmapCache | 声明即 MUST 支持 MemBlt/Mem3Blt | 3362, 3392 |
| 0x000C Sound | 若声明 beeps，MUST 支持 Play Sound PDU | 3600 |
| 0x001C SurfCmds | 声明即 MUST 在 General 置 `FASTPATH_OUTPUT_SUPPORTED` | 3730 |
| 0x001B LargePointer | 双方 MUST 交换 MultifragUpdate，且 MaxRequestSize ≥ 38055 / 608299 | 3677 |
| 0x001D BitmapCodecs | NSCODEC 的 `codecID` MUST = 0x01，且 0x01 不得分配给他者 | 3770 |

**(c) 方向约束（不是"必须发"，是"只能谁发"）**

| 原文措辞 | 行 | 适用 set |
|---|---|---|
| `sent by both client and server` | 3155/3231/3271/3436/3455/3569/3644/3655/3666/3676/3699/3714/3733 | General, Bitmap, Order, Pointer, Input, VC, Share, Font, Multifrag, LargePointer, CompDesk, SurfCmds, BitmapCodecs |
| `only sent from client to server` | 3361/3391/3502/3518/3551/3587 | BitmapCache Rev1, Rev2, Brush, GlyphCache, Offscreen, Sound |
| `only sent from server to client` | 3604 | BmpCacheHostSupport |
| `only sent from client to server and the server ignores its contents` | 3616/3630 | Control, Activation |

**(d) 唯一一条"连接能否继续"的硬约束**

`bitmapCompressionFlag MUST be set to TRUE ... because support for compressed bitmaps is required for a connection to proceed`（3257）。
这是规范里唯一把某个 capability 字段与"连接可否继续"直接绑定的句子——**因此 Bitmap capability 事实上不可省**（该 flag 没有别的载体）。

### G.2 §7.3"最小集合"逐项对照表

文档 §7.3（行 1038-1047）列出 8 个"必须"，逐项判定：

| 文档"必须"项 | 文档理由（行） | 规范原文依据 | 判定 | 说明 |
|---|---|---|---|---|
| 0x0001 General | 承载 extraFlags（1040） | 3155 `sent by both client and server`；无"必须发"句 | **不成立（应为"建议"）** | 只有当你要声明 fast-path 输出/salted MAC 时才需要；规范未要求必发 |
| 0x0002 Bitmap | 两个 MUST 位（1041） | 3257/3268 `MUST ... required for a connection to proceed` | **成立（真 MUST）** | 唯一有"连接继续"级硬约束的 set |
| 0x0003 Order | 承载订单支持位图（1042） | 3271 双向；3303/3304 字段级 MUST | **不成立（应为"建议"）** | 不发 Order 时，2.2.7.1.3 的字段级 MUST 不触发；规范只说"服务端会用更低效手段" |
| 0x0008 Pointer | 指针缓存槽数（1043） | 3436 双向；无"必须发"句 | **不成立（应为"建议"）** | 但见 D-02：两个 cache size 都为 0 会触发 ERRINFO_NOCURSORCACHE |
| 0x000D Input | SCANCODES 必须置位（1044） | 3483 `At a minimum ... MUST be set` | **条件成立** | 该 MUST 是"字段级"：仅在声明 Input 时成立；文档已写"若声明"，但 §7.3 表头是"必须"，口径不统一 |
| 0x0009 Share | 回传 nodeID（1045） | 3644 双向；3652 `nodeID SHOULD be set to zero by the client` | **不成立（应为"建议"）** | 全 SHOULD，无 MUST |
| 0x0014 VirtualChannel | 声明虚拟通道压缩能力（1046） | 3569 双向；无"必须发"句 | **不成立（应为"建议"）** | 无 MUST |
| 0x000E Font | 与 Font List/Map 配套（1047） | 3655 双向；3663 `fontSupportFlags SHOULD be set to FONTSUPPORT_FONTLIST` | **不成立（应为"建议"）** | 全 SHOULD；且 3.2.5.3.18 的 Font List 发送规则不以此 flag 为前置条件（文档 §15 U-06 自己也这么说） |

**漏项检查**（任务点名要求）：General / Bitmap / Order / Input / Pointer / VirtualChannel / Share / Font / ColorTable / BitmapCache

| 点名项 | 文档是否覆盖 | 是否该进"最小集合" | 结论 |
|---|---|---|---|
| General | §7.3 必须 | 否（建议） | 分类错误 |
| Bitmap | §7.3 必须 | 是 | 正确 |
| Order | §7.3 必须 | 否（建议） | 分类错误 |
| Input | §7.3 必须 | 条件（字段级） | 口径应注明"条件 MUST" |
| Pointer | §7.3 必须 | 否（建议），但有 ERRINFO_NOCURSORCACHE 风险 | 分类错误 + 漏风险 |
| VirtualChannel | §7.3 必须 | 否（建议） | 分类错误 |
| Share | §7.3 必须 | 否（建议） | 分类错误 |
| Font | §7.3 必须 | 否（建议） | 分类错误 |
| ColorTable (0x000A) | §7.3 建议 | 否（EGDI 称 unused capability set） | 正确 |
| BitmapCache (0x0004/0x0013) | §7.3 建议 | 否（但见 ERRINFO_CACHECAPNOTSET） | 正确，但漏风险 |

### G.3 回显字段核对（shareId / serverCapabilities 位）

- **shareId**：2.2.1.13.2.1 原文只写 `The share identifier for the packet (see [T128] section 8.4.2 for more information regarding share IDs)`（`bcgr.txt:2372`），**无 MUST、无"回填"字样**。回填的依据只能来自 3.2.5.3.13.1 的 `The contents of the shareID field MUST be stored in the Share ID store (section 3.2.1.8)`（7409）——但 3.2.1.8 说的是该 store `is used to initialize the shareID field of the Share Data Header when sending basic client-to-server slow-path PDUs`（7199），**并没有说用于 Confirm Active**。
  → 文档 §7.1 第 3 条（983 行）与 U-13（2378 行）的措辞"工程必要但规范未用 MUST"**在文字层面正确**。
  → 但**后果判断错误**，见 D-03 / D-04。
- **originatorID**：2.2.1.13.2.1 明确 `This field MUST be set to the server channel ID (0x03EA)`（2373）。文档 §5.3 行 794 正确。
- **serverCapabilities 的位**：规范**没有**任何"客户端必须回显服务端 capability 位"的要求。真正的要求是反向的：`The capabilities received from the server MUST be stored ... and MUST be used to determine what subset of RDP to send to the server`（7409），加上 1.7 `The client and server do not violate any peer capabilities when sending data on the wire`（1026）。文档 §4.4 第 6 条（761 行）已覆盖。→ **PASS**。
- **唯一真正"必须回显/一致"的其他字段**是 `inputFlags`/`keyboardLayout` 与 Client Core Data 一致，但规范用 SHOULD（3485 `SHOULD be the same as the keyboard layout specified in the Client Core Data`）。文档 §8.11 行 1305 写了 SHOULD。→ **PASS**。

### G.4 G 项判定：**FAIL**

MUST 清单抄得对（§7.1 的 13 条我能逐条对上原文，仅第 3 条的"依据"过强、第 13 条属推断），但**最小集合的推导把 6 个纯 SHOULD/无约束的 set 归入"必须"**，与文档自己 §6.3 第 901 行"Mandatory 指的是该小节下的集合在 RDP 中必被实现，不是每次都必须发送"的表述互相打脸；且完全遗漏了规范中三个直接针对客户端 capability 的服务端拒绝码。

---

## H. Confirm Active 的字段完整性

### H.1 逐字段核对（2.2.1.13.2.1，`bcgr.txt:2357-2379`）

| 文档（行 788-800） | 规范原文（行） | 顺序 | 宽度 | 字节序 | 判定 |
|---|---|---|---|---|---|
| `shareControlHeader.totalLength` @0 2B | 2371 `shareControlHeader (6 bytes)` | ✔ | 2+2+2 | LE（2.2 行 1035 `All multiple-byte fields ... MUST be marshaled in little-endian`） | PASS |
| `shareControlHeader.pduType` @2 2B | 2371 `type ... MUST be set to PDUTYPE_CONFIRMACTIVEPDU (3), and the PDUVersion subfield MUST be set to TS_PROTOCOL_VERSION (0x1)` | ✔ | 2 | LE | PASS（但文档漏写 PDUVersion 的 MUST，见 D-06） |
| `shareControlHeader.pduSource` @4 2B | 3826 通用定义 | ✔ | 2 | LE | PASS |
| `shareID` @6 4B | 2372 `(4 bytes)` | ✔ | 4 | LE | PASS |
| `originatorID` @10 2B | 2373 `(2 bytes) ... MUST be set to the server channel ID (0x03EA)` | ✔ | 2 | LE | PASS |
| `lengthSourceDescriptor` @12 2B | 2374 `(2 bytes)` | ✔ | 2 | LE | PASS |
| `lengthCombinedCapabilities` @14 2B | 2375 `(2 bytes) ... combined size in bytes of the numberCapabilities, pad2Octets and capabilitySets fields` | ✔ | 2 | LE | PASS |
| `sourceDescriptor` @16 var | 2376 `(variable)` | ✔ | var | — | PASS |
| `numberCapabilities` @16+L 2B | 2377 `(2 bytes)` | ✔ | 2 | LE | PASS |
| `pad2Octets` @18+L 2B | 2378 `(2 bytes) ... Values in this field MUST be ignored` | ✔ | 2 | LE | PASS |
| `capabilitySets` @20+L var | 2379 `(variable) ... The number of capability sets is specified by the numberCapabilities field` | ✔ | var | — | PASS |

偏移自洽性用官方 dump 4.1.13 机器验证：

```
[BASH: python -X utf8 F:\rtsc\.tmp\auditb_fields.py]
confirm Order len 88 orderFlags=0x002a ... textANSICodePage=0x04e4
confirm Bitmap bpp=24 w=1280 h=1024
confirm Rev2 CacheFlags=0x0003 NumCellCaches=3 Cache0=0x00000078 Cache1=0x00000078 Cache2=0x800009fb
confirm Offscreen level=1 sizeKB=7680 entries=100
confirm NineGrid level=2 sizeKB=2560 entries=256
```

→ 文档 §13.2 行 2080-2097 的逐字段注解（orderFlags=0x002A、textANSICodePage=0x04E4、Cache2CellInfo=0x800009FB、offscreen 7680/100、NineGrid 2560/256）**全部与实测一致**。

### H.2 特别验证：U-13 的降级表述是否成立

文档 U-13（2378 行）与 §5.5（822 行）两处表述：

> §5.5：「服务端**不校验** `originatorID` / `shareID` 是否与自己的 Demand Active 一致（**规范未提出此要求**）。」
> U-13：「`shareID` 按 3.2.5.3.13.1 的 Share ID store 语义回填（**工程上必要，但规范未用 MUST 表述**）」

**"规范未用 MUST 表述"→ 成立**（2.2.1.13.2.1 无 MUST，3.3.5.3.13.2 无校验句）。
**"服务端不校验 / 规范未提出此要求"→ 不成立**。规范在 Set Error Info 的 `errorInfo` 枚举里**专门定义了两个只可能由 Confirm Active 校验失败产生的错误码**：

```
[BASH: python -X utf8 -c "... grep ERRINFO_CONFIRMACTIVE ..."]
2984   ROW: ERRINFO_CONFIRMACTIVEWRONGSHAREID0x000010D4 | A Confirm Active PDU (section 2.2.1.13.2) was received
       from the client with an invalid shareID field.
2985   ROW: ERRINFO_CONFIRMACTIVEWRONGORIGINATOR0x000010D5 | A Confirm Active PDU (section 2.2.1.13.2) was received
       from the client with an invalid originatorID field.
```

另外 `ERRINFO_BADCAPABILITIES0x000010EA`：`The capabilities received from the client in the Confirm Active PDU ... were not accepted by the server`（3000）。

**不回填 shareId 的后果**（任务要求判定）：服务端若校验，可发 `Set Error Info`（errorInfo=0x000010D4）后断链；客户端此时**已发出 Confirm Active，尚未收到 Font Map**，按文档 §12.2 仍停在 S3，会表现为"握手卡住后断链"，错误原因只能从 Set Error Info 读出——而文档**整篇 0 次提到 Set Error Info**（`grep 'Set Error Info' capabilities.md` → 0 命中），因此实现者拿不到这个诊断路径。这正是 J 项 D-12 的连带影响。

### H.3 H 项判定：**PARTIAL**

字段表本身**完全正确**（顺序/宽度/LE 全对，dump 双证），但：
- D-03：§5.5 行 822 的"服务端不校验"被 ERRINFO 表反证；
- D-04：U-13 降级表述"文字对、后果缺"；
- D-05：行 266 把 `pduSource MUST = User Channel ID` 的来源标成 S61（3.2.5.3.13.2），实际该 MUST 在 **3.2.5.1**（`bcgr.txt:7242`），3.2.5.3.13.2 全段无 pduSource 句；
- D-06：行 791 `PDUVersion = 0x1` 应为 MUST。

---

## I. 长度与畸形处理策略

### I.1 把文档 §6.1 的伪码原样实现，然后喂畸形输入（红证）

文档 §6.1 行 844-853 给出的遍历算法：

```
p = caps_start
for i in 0 .. numberCapabilities-1:
    type = LE16(p)
    len  = LE16(p+2)
    if len < 4: error
    process(type, p, len)
    p += len
assert p == caps_start + lengthCombinedCapabilities - 4
```

我把它逐字实现（`F:\rtsc\.tmp\auditb_red_i.py` / `auditb_red_i2.py`），喂 6 类畸形：

```
[BASH: python -X utf8 F:\rtsc\.tmp\auditb_red_i.py]
A lengthCapability>remaining  -> ('OOB-READ-BODY', [(1, 24)], 24)
B numberCapabilities too big  -> ('OOB-READ-HEADER', [(1, 24)], 24)
C numberCapabilities too small-> ('ASSERT-FAIL', [(1, 24)], 24)
D combined mismatch           -> ('ASSERT-FAIL', [(1, 24), (2, 28)], 52)
E duplicate type              -> ('ASSERT-PASS', [(1, 24), (1, 24)], 48)

[BASH: python -X utf8 F:\rtsc\.tmp\auditb_red_i2.py]
F numberCapabilities too small, combined consistent -> ('ASSERT-PASS', [('0x1', 24)], 24)  <- 第二个 set 被静默丢弃
G lengthCombinedCapabilities < 4                   -> ('ASSERT-FAIL', [('0x1', 24)], 24)  combined-4 若为无符号则下溢
H numberCapabilities == 0                          -> ('ASSERT-PASS', [], 0)
I lengthCapability == 0xFFFF                       -> ('OOB-BODY', [], 0)
J trailing garbage after last set                  -> ('ASSERT-PASS', [('0x1', 24)], 24)
```

### I.2 任务点名的 5 个场景 + 我补的 3 个，逐个判覆盖

| # | 畸形场景 | 文档是否覆盖 | 覆盖处 | 处置是否会导致静默接受 | 我的独立建议 |
|---|---|---|---|---|---|
| 1 | `numberCapabilities` 与实际 set 个数不符（多） | **否** | 仅 §17.2 行 2455 有**发送侧**"必须一致"；接收侧全无 | — | 遍历前先算 `caps_end = caps_start + lengthCombinedCapabilities - 4`，每个 set 要求 `p+4 <= caps_end` 且 `p+len <= caps_end`；越界即断链 |
| 2 | `numberCapabilities` 与实际个数不符（少） | **否** | 无 | **是**：红证 F 显示 `ASSERT-PASS`，多余 set 被静默忽略 | 遍历结束后额外要求 `p == caps_end`（不是 `combined-4` 的等价式，而是与 `caps_end` 比较），不等则告警并断链 |
| 3 | `lengthCombinedCapabilities` 与 Σ 不符 | **部分** | §6.1 行 852 的 `assert` | **是**：assert 在生产构建里通常被编译掉；且文档未写 assert 失败后做什么 | 显式策略：`Σ != combined-4` → 以 combined 为界定界（更可信，因为它同时被 totalLength 约束）+ 告警；`combined < 4` → 断链 |
| 4 | `capabilitySetType` 重复 | **是** | U-14 行 2379 | **是**：策略是"后者覆盖前者" | **反对"后者覆盖"**，见 I.3 |
| 5 | `lengthCapability` 大于剩余数据 | **否** | 只有 U-09 管 `< 4`、U-20 管"与规范固定值不符" | — | 必须 `p+len <= caps_end` 且 `<= 实际收到的字节数`，否则断链（红证 A 是真实越界读） |
| 6 | 同一 capability 两次且字段冲突 | **部分**（=#4） | U-14 | **是** | 见 I.3 |
| 7 | `lengthCombinedCapabilities < 4` | **否** | 无 | **是**：`combined - 4` 无符号下溢成 0xFFFD+ | 先判 `combined >= 4`，否则断链 |
| 8 | 末个 set 之后有多余字节 | **否** | 无 | **是**：红证 J `ASSERT-PASS` | 与 #2 同一修正：以 `caps_end` 严格等值收口 |

### I.3 为什么"后者覆盖前者"不安全（独立建议）

U-14 的建议是"最后一次出现生效"。反例（均为安全/正确性相关）：

- **General 重复**：第一份 `extraFlags=0x0400`（不含 `ENC_SALTED_CHECKSUM 0x0010`），第二份含 0x0010。若"后者覆盖"，客户端会按 **salted MAC** 计算 MAC，而服务端仍按标准 MAC 校验 → 之后**每个包 MAC 校验失败 → SHOULD 断链**（5.3.6 区段）。规范对此无仲裁规则，所以任何"覆盖"策略都可能单方面改变密码学参数。
- **Order 重复**：第一份 `orderSupport` 声明支持 MemBlt/Mem3Blt，第二份不声明。若"后者覆盖"，客户端会拒绝 MemBlt，但服务端已按第一份的意图发 MemBlt（若服务端取第一份）→ 订单无法解析。
- **BitmapCacheRev2 重复**：`NumCellCaches` 与 `CellInfo` 冲突 → 缓存槽索引错位 → **显示错误图像**（不是崩溃，是静默错误，最危险）。

**建议**：对同一个 `capabilitySetType` 的重复，按"**取交集 / 取更保守值**"合并（support 位 AND、`NumCellCaches` 取小、`MaxRequestSize` 取小、`extraFlags` 取 AND），并记告警；对无法安全合并的（如 `preferredBitsPerPixel` 不同）直接断链。至少**不能**无条件 last-wins。

### I.4 文档未覆盖的畸形（我补的清单）

1. `sourceDescriptor` 的 `lengthSourceDescriptor` 超出剩余数据（§4.3 只给偏移公式，无边界检查）——注意这与 #5 同源，但发生在 capability 遍历**之前**。
2. `totalLength` 与 `lengthCombinedCapabilities` 的**三方一致性**（`totalLength` / `combined` / `Σ`）。文档分别检查前两者（§4.4 第 5 条 + §6.1 assert），但**从不互相对照**；先做三方对照可以把 #1/#5 提前拦下。
3. `numberCapabilities` 与 `lengthCombinedCapabilities` 的**下界关系**：`combined - 4 >= numberCapabilities * 4`（每个 set 至少 4 字节）。文档无此不变量。
4. Fast-Path 侧：`length1` 声明长度大于实际收到字节（U-07 只讨论 >16383 的"应当"，未讨论"声明长度 vs 实收长度"）。

### I.5 I 项判定：**FAIL**

---

## J. 状态机完整性

### J.1 把文档 §12.2 迁移表（行 1886-1899）编码后探测

`F:\rtsc\.tmp\auditb_red_j.py` 把 14 条迁移原样编码，然后喂规范**允许**的事件：

```
[BASH: python -X utf8 F:\rtsc\.tmp\auditb_red_j.py]
state  event                next       note
S1     deactivate_all       UNDEFINED  server may start disconnect seq (1.3.1.4.2) before cap exchange
S2     deactivate_all       UNDEFINED  server-side disconnect may abort right after Confirm Active
S3     deactivate_all       UNDEFINED  server may abort during Connection Finalization
S2     monitor_layout       UNDEFINED  1.3.1.1: optional Monitor Layout PDU sent after Demand Active
S3     monitor_layout       UNDEFINED  late Monitor Layout (server batching)
S3     set_error_info       UNDEFINED  3.2.5.7.1: MUST store error code before disconnect
S4     set_error_info       UNDEFINED  server-initiated disconnect precursor
S1     set_error_info       UNDEFINED  authorization failure before Demand Active
S4     demand_active        UNDEFINED  duplicate/out-of-sequence Demand Active
S3     demand_active        UNDEFINED  out-of-sequence Demand Active
S2     ultimatum            S6         server drops before Sync
S3     ultimatum            S6         server drops mid-finalization
S5     confirm_active       UNDEFINED  n/a - client never receives Confirm Active
S4     deactivate_all_dup   UNDEFINED  second Deactivate All
S2     font_map             UNDEFINED  font map before finalization completes

undefined (state,event) pairs probed: 13
```

### J.2 逐项判定

| 任务问题 | 判定 | 证据 |
|---|---|---|
| **是否覆盖 Deactivation-Reactivation**（服务端发 Deactivate All 后重发 Demand Active）？ | **部分覆盖** | §12.2 有 `S4 + Deactivate All → S5`（1895）与 `S5 + 新 Demand Active → S2`（1896），且注明"不重跑 MCS/安全/Licensing"。**但只在 S4 有 Deactivate All 迁移**；规范 1.3.1.4.2 的服务端断开序列是"可选 Set Error Info → **可选 Deactivate All** → 可选 Ultimatum → 关闭"，Deactivate All 可在**任意时刻**发出。S1/S2/S3 收到 Deactivate All 全部 UNDEFINED（红证前 3 行） |
| **是否覆盖服务端主动断开（MCS Disconnect Provider Ultimatum）**？ | **覆盖** | §12.2 有 `任意 + Ultimatum → S6`（1899）与 `S5 + Ultimatum → S6`（1897）。**但漏了 reason 字段规则**：`Clients MAY use the value in the reason field ... If the reason code was not set to either rn-provider-initiated (1) or rn-user-requested (3), the client MUST ignore the reason code`（`bcgr.txt:6017`）。文档全篇未提 reason 码 |
| **迁移表是否遗漏"收到意外 PDU"的分支**？ | **是，大面积遗漏** | 只有 S1 一条（`pduType.type != 1 → 忽略`，1889）。规范为"意外 PDU"专门定义了两个错误码：`ERRINFO_CONTROLPDUSEQUENCE0x000010CD`（`An out-of-sequence Demand Active / Confirm Active / Deactivate All / Enhanced Security Server Redirection PDU has been received`，2977）与 `ERRINFO_DATAPDUSEQUENCE0x000010CB`（2976）。文档 0 次引用这两个码 |
| **U-03（Deactivation-Reactivation 后 bitmap cache 是否保留）的建议是否安全**？ | **不安全（需修正）** | 见 J.3 |

### J.3 U-03 的独立评估（任务点名）

U-03（2368 行）现状："规范未明示 → 保守：**清空** bitmap cache，等新 Confirm Active 后按新 capability 重建"。

**规范事实**：

1. `1.3.1.3`：`If a capability re-exchange is required, then the Capability Exchange and Connection Finalization phases of the connection sequence are re-executed`（`bcgr.txt:879`）——确实没提缓存。
2. `3.2.1.13 Bitmap Caches`：`A Bitmap Cache is a store that contains bitmap images that were sent to the client using the Cache Bitmap (Revision 2) Secondary Drawing Order`（7209）——未说生命周期。
3. **但** `3.2.1.14 Persistent Bitmap Caches`：`Unlike the Bitmap Caches described in section 3.2.1.13, Persistent Bitmap Caches are **not bound to the lifetime of a given RDP connection** and their contents are persisted even after the RDP connection is closed`（7211）。
4. `3.2.1.15 Persisted Bitmap Keys`：`The lifetime of this store is bound to the lifetime of the Persistent Bitmap Caches`（7213）。

**因此"清空 bitmap cache"这句话有两个问题**：

- **（致命）没有区分"标准 Bitmap Cache"与"Persistent Bitmap Cache"**。照字面实现会把持久缓存一并清空，直接违反 7211 的"不受连接生命周期约束"，并使 `PERSISTENT_KEYS_EXPECTED_FLAG`（2.2.7.1.4.2，3434 `k` 位：`If this bit is set, 64-bit keys MUST be sent by the server`）与 Persistent Key List 流程失去意义。→ **D-16**
- **（次要）没有写清代价**。清空后服务端仍可能按旧缓存引用发 `MemBlt`/`Mem3Blt`，客户端命中缺失 → 按 EGDI `The Bitmap Cache Error PDU SHOULD be sent to a server that has requested the rendering of a cached bitmap that is not available`（`egdi.txt:3754`）→ `BC_ERR_FLUSH_CACHE 0x01 | Indicates that the contents of the cache MUST be emptied`（2665）+ 黑图重绘。所以"清空"是**可用但会掉帧/黑闪**的选择，文档应写明。→ **D-17**

**我的建议**：改为"清空**标准** Bitmap Cache（3.2.1.13），**保留** Persistent Bitmap Cache（3.2.1.14）与 Persisted Bitmap Keys（3.2.1.15）；重建时以新 Rev2 的 `NumCellCaches`/`CellInfo` 为准；若服务端未重发 Rev2，则清空并停用缓存路径。**保留**旧标准缓存反而是不安全的那一侧：`CellInfo` 变了会导致槽位语义错位，命中旧槽位会画出**错误的图**（静默错误，无任何报错）。

### J.4 其他状态机缺口

| 缺口 | 规范依据 | 影响 |
|---|---|---|
| **Set Error Info PDU（2.2.5.1 / 3.2.5.7.1）全篇缺失** | `Once this PDU has been processed, the client MUST store the error code so that the reason for the server disconnect which will follow can be accurately reported to the user`（`bcgr.txt:7460`） | 客户端无法向用户报断开原因；1.3.1.4.2 的断开序列被建模成"Deactivate All → 关"，少了一跳 |
| **Monitor Layout PDU（2.2.12.1）未进状态机** | `The optional Monitor Layout PDU (section 2.2.12.1) is sent by the server after the Demand Active PDU`（858） | 文档 §2.2 行 304 只列了 `pduType2=0x37`，状态机无对应迁移；S1/S2 收到会走"未定义"分支 |
| **无任何定时器** | `The Client-Side Connection Sequence Timeout fires if more than 300 seconds have elapsed ... the client MAY terminate`（7633）；章节 3.2.6.1 | U-06 说"若服务端不发 Font Map，按超时处理"（2371）却不给时长与来源；§12 无 timer 定义 |
| **`S0` 的入口条件含糊** | `After sending the License Error (Valid Client) PDU, the server MUST send the Demand Active PDU`（7947） | 文档写"或直接进入"（1886），未说明"无 licensing 时"的判定依据；实际可直接以收到 Demand Active 为 S1 入口，建议明确 |

### J.5 J 项判定：**FAIL**

---

## K. Font List / Font Map 与 Deactivate All 的正确性

### K.1 Deactivate All 的正确章节号（任务要求独立验证）

`F:\rtsc\.tmp\toc.txt` 官方目录实测：

```
[BASH: Select-String toc.txt -Pattern "2\.2\.3|2\.2\.1\.13"]
2.2.3 Deactivation-Reactivation Sequence | 6879b907-27a4-4d5d-bd83-9e093394d90f
  2.2.3.1 Server Deactivate All PDU | 8a29971a-df3c-48da-add2-8ed9a05edc89
    2.2.3.1.1 Deactivate All PDU Data (TS_DEACTIVATE_ALL_PDU) | fc191c40-e688-4d5a-a550-6609cd5b8b59
  2.2.1.13 Mandatory Capability Exchange | 8be0074f-...
    2.2.1.13.1 Server Demand Active PDU
    2.2.1.13.1.1 Demand Active PDU Data
    2.2.1.13.1.1.1 Capability Set (TS_CAPS_SET)
    2.2.1.13.2 Client Confirm Active PDU
    2.2.1.13.2.1 Confirm Active PDU Data
```

**判定**：文档 §10.2/§10.3/§16 第 6 条说的 **2.2.3.1 / 2.2.3.1.1 正确**；任务提示的 2.2.1.13.3 **不存在**（`grep '2.2.1.13.3' bcgr.txt` → 0 命中，TOC 亦无）。→ **文档正确**。
（我如何验证：官方 `toc.txt` 的层级结构 + 对 `bcgr.txt` 全文做 `2.2.1.13.3` 字面检索，两者一致。）

### K.2 Deactivate All 结构

| 文档（行 1739-1749） | 规范（`bcgr.txt:2803-2806`） | 判定 |
|---|---|---|
| 无 `sessionId` | 字段表只有 shareControlHeader/shareID/lengthSourceDescriptor/sourceDescriptor | PASS |
| `pduType` = `PDUTYPE_DEACTIVATEALLPDU (6)`，线上 0x0016 | 2803 `MUST be set to PDUTYPE_DEACTIVATEALLPDU (6)`；`0x0010 | 0x6 = 0x0016` | PASS（推导正确，文档也标注"无 dump 佐证"，诚实） |
| `sourceDescriptor` SHOULD 为 0x00 | 2806 `This field SHOULD be set to 0x00` | PASS |
| 若取 0x00 则 `lengthSourceDescriptor=1`、`totalLength=13` | 由 6+4+2+1 = 13 推得 | PASS |

### K.3 Font List / Font Map 固定值

| 字段 | 文档声称（行） | 规范原文（`bcgr.txt`） | 判定 |
|---|---|---|---|
| Font List `numberFonts` | SHOULD = 0（1828） | 2581 `This field SHOULD be set to zero` | PASS |
| Font List `totalNumFonts` | SHOULD = 0（1829） | 2582 同 | PASS |
| Font List `listFlags` | SHOULD = 0x0003 = FONTLIST_FIRST(1)+LAST(2)（1830） | 2583 `SHOULD be set to 0x0003, which is the logical OR'd value of FONTLIST_FIRST (0x0001) and FONTLIST_LAST (0x0002)` | PASS |
| Font List `entrySize` | SHOULD = 0x0032（50）（1831） | 2584 `SHOULD be set to 0x0032 (50 bytes)` | PASS |
| Font Map `numberEntries` | SHOULD = 0（1842） | 2689 同 | PASS |
| Font Map `totalNumEntries` | SHOULD = 0（1843） | 2690 同 | PASS |
| Font Map `mapFlags` | SHOULD = 0x0003（1844） | 2691 `SHOULD be set to 0x0003 ... FONTMAP_FIRST (0x0001) and FONTMAP_LAST (0x0002)` | PASS |
| Font Map `entrySize` | SHOULD = 0x0004（1845） | 2692 `SHOULD be set to 0x0004 (4 bytes)` | PASS |
| 两者均 26 字节 | 1821/1835/2402 | 2564 `fontListPduData (26 bytes)`；2672 `fontMapPduData (26 bytes)` | PASS |
| `pduType2` = 0x27 / 0x28 | 1827/1841 | 2580 `PDUTYPE2_FONTLIST (39)`；2688 `PDUTYPE2_FONTMAP (40)` | PASS |

### K.4 官方 dump 逐字节核对

我把文档 §13.3 的十六进制块与规范 4.1.18/4.1.22 的解密明文做**字节级比较**：

```
[BASH: python -X utf8 F:\rtsc\.tmp\auditb_font.py]
FontList 26 26 True
FontMap 26 26 True
FontList fields: numberFonts=0 total=0 listFlags=0x0003 entrySize=50
FontMap fields: numberEntries=0 total=0 mapFlags=0x0003 entrySize=4
pduType2 FL=27 FM=28
```

→ **26/26 字节完全一致**，四个字段值全部命中。同时验证了文档 §13.3 行 2153 的观察：`pad1` 在 Font List 为 `00`、在 Font Map 为 `45`，而规范对 `pad1` 说 `Values in this field MUST be ignored`（`bcgr.txt:3840`）——该推断正确。

### K.5 处理规则

| 文档（行） | 规范 | 判定 |
|---|---|---|
| 客户端 MUST 忽略 Font Map 的 4 个字段（1851） | 7441 区段 `The contents of the numberEntries, totalNumEntries, mapFlags, and entrySize fields MUST be ignored`（7441 区段） | PASS |
| 服务端 MUST 忽略 Font List 的 4 个字段（1856） | 7977 `The contents of the numberFonts, totalNumFonts, listFlags, and entrySize fields MUST be ignored` | PASS |
| 服务端处理完 Font List 后 MUST 发 Font Map，失败 SHOULD 断链（1860） | 7979-7980 | PASS |
| 引用"3.2.5.3.22，S59 系列"（1849） | 3.2.5.3.22 是 `Processing Font Map PDU`，但 **S59 = 3.2.5.3.13**，且 3.2.5.3.22 的 guid `d246ad43-...` **不在 §0.2 的 S 表里** | **D-26（引用不精确/不可追溯）** |

### K.6 K 项判定：**PASS**

（K 是六项中唯一完全通过的一项；唯一瑕疵 D-26 属引用精度，不影响任何字节结论。）

---

## L. 文档内部一致性

### L.1 同一事实的跨章节矛盾

| # | 事实 | 一处表述 | 另一处表述 | 判定 |
|---|---|---|---|---|
| 1 | Confirm Active 18 个 capability 的长度合计 | §7.2 行 1020 `合计 492 = totalLength ✔` | §13.2 行 2099 `18 个 capability 合计 466 字节` | **矛盾**。我实测：`sum=466`（脚本 `auditb_sum.py` 逐行取 18 个 `lengthCapability` 相加）。492 是含 26 字节头的 `totalLength`，被误标成"合计"。→ **D-18** |
| 2 | VirtualChannel 固定总长 | §8.18 行 1425 `固定总长：12 字节` | §8.18 行 1429 表内 `8（无 VCChunkSize）或 12`；§13.1/§13.2 实测均为 8 | **自相矛盾**。规范 2.2.7.1.10 的 `VCChunkSize` 标注 `(optional)`（`bcgr.txt:3574`），故不存在"固定 12"。→ **D-19** |
| 3 | Deactivate All 的 pduType 确定性 | §15.1 行 2403 归入"已全部核实、**无不确定性**的项" | 同一行末尾 `**无 dump 佐证**（见 U-10）` | **自相矛盾**：既"无不确定性"又"无佐证"。→ **D-21** |
| 4 | 服务端是否校验 shareID/originatorID | §5.5 行 822 断言"不校验（规范未提出此要求）" | §15 U-13 行 2378 "部分未验证" | **正文断言 vs §15 不确定**（任务点名的反模式），且被 ERRINFO 反证。→ **D-03** |
| 5 | capability 的 `lengthCapability` 是否被规范固定 | §8 全部 27 节 + §17.2 均写 `MUST = 24/28/88/...` | 规范原文 **无任何** `lengthCapability MUST be set to` 句（我实测 0 命中） | **过度断言**：这些是"结构推导出的定长"，不是规范 MUST。→ **D-22**（连带 U-20 前提错误） |
| 6 | 编号表位置 | §16 第 3 条"编号表在 2.2.1.13.1.1.1；2.2.7.1.x 只到 2.2.7.1.11" | §6.2 标题确实引 2.2.1.13.1.1.1；TOC 实测 2.2.7.1 只到 `.11` | **一致，PASS**（此项为文档正确之处） |
| 7 | 状态机 PDU 序列 | §12.2 行 1891 用 `Server Synchronize` | §12.3 时序图行 1920-1929 把服务端 Sync 画在 Font List 之后 | **图与表不一致**（见 D-25） |
| 8 | Fast-Path dump 的线上密文 | §3.4 行 543 `26 18 5e 76 0e de 28` | §13.4 行 2162 `20 00 08 ab 02 6f 01`（实为解密后明文） | **同一 dump 两组字节**（见 D-28） |

### L.2 交叉引用抽查（≥10 处，实测 20 处）

用脚本抽出全部 179 个 `§x.y` 引用，过滤掉 `[T128]/[T125]/[X224]/[MS-*]` 前缀的外部引用，得到 **5 处内部断引用**（`auditb_refs.py`）：

| # | 位置 | 引用 | 目标是否存在的章节 | 内容是否匹配 | 判定 |
|---|---|---|---|---|---|
| 1 | 行 148 | "唯一例外是 Fast-Path 的 `length1`/`length2` 组合（**§2.3**）" | §2.3 存在，但它是 `TS_SECURITY_HEADER` | **不匹配**——fast-path 长度编码在 **§3.4** | **FAIL（D-20a）** |
| 2 | 行 1677 | "见 **§12** U-04" | §12 是"客户端能力交换状态机" | **不匹配**——U-04 在 **§15** | **FAIL（D-20b）** |
| 3 | 行 1688 | "见 **§12** U-05" | 同上 | **不匹配**——U-05 在 **§15** | **FAIL（D-20b）** |
| 4 | 行 961 | "`[MS-RDPRFX] §2.2.1.1 / §2.2.1.2`" | 后一个 `§2.2.1.2` 缺 spec 前缀，被解析成本文档内部引用（本文档 §2.2.1 不存在） | 语义可推知，属格式问题 | **PARTIAL** |
| 5 | 行 1971/2032/2159/2193 | "官方规范 **§4.1.12 / §4.1.13 / §4.7**" | 本文档无 §4.7 及 §4.1.x 编号（§4 只有 4.1-4.4） | 上下文已说明是"官方规范"，可接受 | **PASS（格式瑕疵）** |
| 6 | 行 1732 | "`securityHeader` 可选（规则同 **§2.3**）" | §2.3 = TS_SECURITY_HEADER，含"securityHeader 是否存在"规则（357-367 行） | **匹配** | PASS |
| 7 | 行 2443 | "Enhanced Security 下必须不存在（**§2.3**）" | 同上 | 匹配 | PASS |
| 8 | 行 2445 | "`flagsHi` 仅在 `SEC_FLAGSHI_VALID` 置位时有效（**§2.3**）" | §2.3 行 331 | 匹配 | PASS |
| 9 | 行 856 | "见 **§15 U-09**" | §15 有 U-09 | 匹配 | PASS |
| 10 | 行 895 | "见 **§15 U-01**" | §15 有 U-01 | 匹配 | PASS |
| 11 | 行 1032 | "**§15 U-02** 记录该缺口" | §15 有 U-02 | 匹配 | PASS |
| 12 | 行 1784 | "推论（B 级），见 **§15 U-03**" | §15 有 U-03 | 匹配 | PASS |
| 13 | 行 1864 | "见 **§15 U-06**" | §15 有 U-06 | 匹配 | PASS |
| 14 | 行 890 | "`0x001D` | **§6.4**（变长）" | §6.4 = Bitmap Codecs 变长 | 匹配 | PASS |
| 15 | 行 1943 | "（**§4.4**）" | §4.4 = 客户端处理规则，含"忽略 vs 断链" | 匹配 | PASS |
| 16 | 行 2299 | "Font 那 1 个是规范自述的服务端 bug，见 **§8.12**" | §8.12 行 1319 确有该说明 | 匹配 | PASS |
| 17 | 行 2469 | "按序发 Synchronize → ... → Font List（**§12.2**）" | §12.2 行 1890 | 匹配 | PASS |
| 18 | 行 2472 | "（**§10.4 / §12.2**）" | 两处均有 | 匹配 | PASS |
| 19 | 行 1125 | "索引表见 **§9.4**" | §9.4 = orderSupport 索引表 | 匹配 | PASS |
| 20 | 行 129 / 2328 | "见 **§14.3** 复现脚本" | §14.3 存在 | 匹配（但覆盖度问题见 D-23） | PASS/见 D-23 |

**统计**：20 处抽查中 **3 处 FAIL**（D-20a/b）、1 处 PARTIAL、16 处 PASS。

### L.3 §15 的 20 条不确定项 vs 正文断言（抽查全部 20 条）

| 编号 | 正文是否已断言该事实 | §15 是否说其不确定 | 是否矛盾 | 备注 |
|---|---|---|---|---|
| U-01 未分配 type | §6.2 行 895 只说"规范未定义" | 是 | 一致 | PASS |
| U-02 现代 mstsc | §7.2 行 1031 明确"不能声称" | 是 | 一致 | PASS |
| U-03 缓存保留 | §10.6 行 1784 标"推论（B 级）" | 是 | 一致（但建议不安全，见 J.3） | PARTIAL |
| U-04 VKPACKET 命名 | §9.5 行 1675 陈述"规范原文缺陷" | 是 | 一致 | PASS |
| U-05 PARTIAL/FULL | §9.6 行 1687 | 是 | 一致 | PASS |
| U-06 Font List 前置条件 | §11.4 行 1864 | 是 | 一致 | PASS |
| U-07 >16383 | §3.4 行 552 | 是 | 一致 | PASS |
| U-08 未分配 updateCode | §3.5 行 589 | 是 | 一致 | PASS |
| U-09 len<4 | §6.1 行 855 | 是 | 一致 | PASS |
| U-10 Deactivate All dump | §15.1 行 2403 同时说"无 dump 佐证" | 是 | **§15.1 内部矛盾** | **D-21** |
| U-11 sourceDescriptor 语义 | §4.3 行 714 直接写"内容为 source descriptor 字符串" | 是 | 轻微：正文断言了 §15 说"未取原文"的语义 | **D-27** |
| U-12 HEADER1 拆分 | §2.4/§2.6 行 440 | 是 | 一致 | PASS |
| U-13 shareID MUST | **§5.5 行 822 断言"服务端不校验"** | 是（"部分未验证"） | **矛盾 + 被 ERRINFO 反证** | **D-03** |
| U-14 重复 type | §6.1 未提，仅 §15 | 是 | 一致 | PASS |
| U-15 sessionId | §4.3 行 718 "被客户端忽略" | 是（"规范明示忽略"） | 一致 | PASS |
| U-16 extraFlags 未定义位 | §9.1 只列 5 位 | 是 | 一致 | PASS |
| U-17 preferredBitsPerPixel | §8.2 行 1103 写 SHOULD | 是 | 一致 | PASS |
| U-18 codecProperties | §6.4 行 954 只给指引 | 是 | 一致 | PASS |
| U-19 textFlags | §9.3 行 1141 写"MUST 被忽略" | 是 | 一致 | PASS |
| U-20 lengthCapability 不符 | **§8 全节断言 `MUST = N`** | 是（"各 capability 节都写 MUST be set to N"） | **§15 的前提本身事实错误**（规范 0 命中该句） | **D-22** |

**结论**：20 条中 **3 条与正文冲突**（U-10/U-13/U-20 关联的 §5.5、§15.1、§8），其中 U-13 与 U-20 是实质错误。

### L.4 §16 的 9 条订正是否在正文落实（全部 9 条实测）

| # | §16 声明 | 正文落实位置 | 落实判定 |
|---|---|---|---|
| 1 | Bitmap=0x0002 / Order=0x0003 / BitmapCache Rev1=0x0004, Rev2=0x0013 / Pointer=0x0008 / Input=0x000D / VC=0x0014 | §1.4 行 208-211 + §6.2 行 865-881 + §8 各节标题 | **已落实** |
| 2 | 不存在 ShareControl capability，Share=0x0009 | §1.4 行 212 + §8.8 行 1250 | **已落实** |
| 3 | 编号表在 2.2.1.13.1.1.1；2.2.7.1.x 只到 .11 | §6.2 行 858 标题引用正确；§6.3 用 2.2.7.1/2.2.7.2 划分 | **已落实** |
| 4 | `TS_FP_UPDATE_PDU` 在 2.2.9.1.2；2.2.9.1.2.1 是 `TS_FP_UPDATE` | §3.3 标题"（2.2.9.1.2）"；§3.5 标题"（2.2.9.1.2.1）" | **已落实** |
| 5 | `fpOutputHeader` 只含 action/reserved/flags；length1/2 独立 | §3.3 表行 487-492 + 位域表行 496-501 + 差异表行 505-511 | **已落实** |
| 6 | Deactivate All = 2.2.3.1 / 2.2.3.1.1；2.2.1.13.3 不存在 | §10 标题、§10.2 行 1725、§10.3 行 1735、§18 行 2490 | **已落实** |
| 7 | Font List=2.2.1.18；Font Map=2.2.1.22；2.2.1.19=Server Synchronize | §11.2 行 1817、§11.3 行 1833、§5.5 行 820 | **已落实** |
| 8 | 无 "Server Confirm"；服务端响应是 Server Synchronize | §12.2 行 1891-1893 用 Server Synchronize；§17.3 行 2470 复述 | **已落实**（但 §12.3 时序图与之不符，见 D-25） |
| 9 | 给出 4 个官方 dump | §13.1/§13.2/§13.3/§13.4 各一组；13.1/13.2/13.3 字节级校验通过（见下），**13.4 密文区有误** | **已落实（1 处字节错误，见 D-28）** |

**dump 真实性独立复核**（不重复甲的 A-F 项，只做"文档十六进制块 vs 规范十六进制块"的字节比对）：

```
[BASH: python -X utf8 F:\rtsc\.tmp\auditb_dump.py]
13.1 Demand Active doc bytes 359 official bytes 359 identical True
13.2 Confirm Active doc bytes 492 official bytes 492 identical True
```

（§13.3 Font List/Map 见 K.4，26/26 字节一致；§13.4 Fast-Path **发现一处真实不一致**，见 D-28。）

**§13.4 的逐字节复核（红证）**：

```
[BASH: python -X utf8 F:\rtsc\.tmp\auditb_fp3.py]
official wire bytes: c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28 len 17

[BASH: python -X utf8 F:\rtsc\.tmp\auditb_fp2.py]
doc : c4 11 30 35 6b 5b b5 34 c8 47 20 00 08 ab 02 6f 01
doc wire[10:] == doc decrypted ? True
```

即 §13.4 的"完整线上字节"块，偏移 10 起的 7 字节写的是**解密后的明文**（`20 00 08 ab 02 6f 01`），而规范 dump 的密文是 `26 18 5e 76 0e de 28`。文档自己在 **§3.4 行 543** 引用的正是正确密文 `26 18 5e 76 0e de 28`——**同一份官方 dump 在文档内被写成两种字节**。→ **D-28**

### L.5 L 项判定：**FAIL**

---

## 缺陷清单（28 条）

> 格式：**编号 / 文档位置 / 文档声称 / 规范原文 / 差异 / 建议修正**

### 严重（会导致实现错误或安全/正确性问题）

**D-03 [G/H] §5.5 行 822 — "服务端不校验 originatorID/shareID"**
- 文档声称：「服务端**不校验** `originatorID` / `shareID` 是否与自己的 Demand Active 一致（规范未提出此要求）。」
- 规范原文：`ERRINFO_CONFIRMACTIVEWRONGSHAREID0x000010D4 | A Confirm Active PDU ... was received from the client with an invalid shareID field`（`bcgr.txt:2984`）；`ERRINFO_CONFIRMACTIVEWRONGORIGINATOR0x000010D5`（2985）。
- 差异：3.3.5.3.13.2 的**处理步骤**确实没写校验，但规范在错误码表里为这两种校验失败定义了**专用码**，即协议明确预期实现会校验。文档把"某节没写"当成"规范没要求"，结论方向错误。
- 建议：改为「3.3.5.3.13.2 的处理步骤未要求校验；但 2.2.5.1 为 `shareID`/`originatorID` 非法分别定义了 `ERRINFO_CONFIRMACTIVEWRONGSHAREID (0x000010D4)` / `ERRINFO_CONFIRMACTIVEWRONGORIGINATOR (0x000010D5)`，说明实现可校验并据此断链。客户端必须按 0x03EA 填 originatorID、按收到的 shareID 回填。」

**D-07 [I] §6.1 行 844-853 — 遍历缺上界检查**
- 文档声称：伪码只有 `if len < 4: error`，然后 `p += len`。
- 规范原文：`lengthCapability (2 bytes) ... The length in bytes of the capability data, including the size of the capabilitySetType and lengthCapability fields`（`bcgr.txt:2335`）——未规定上界，故实现必须自证。
- 差异：红证 A：`lengthCapability=200` 而剩余仅 8 字节 → `OOB-READ-BODY`。伪码无任何检查能拦住。
- 建议：加 `caps_end = caps_start + lengthCombinedCapabilities - 4`，要求 `p + 4 <= caps_end` 且 `p + len <= caps_end` 且 `p + len <= recv_len`；任一不满足 → 断链。

**D-08 [I] — `numberCapabilities` 偏大无接收侧规则**
- 文档声称：无（仅 §17.2 行 2455 有发送侧"必须一致"）。
- 规范原文：`The number of capability sets is specified by the numberCapabilities field`（`bcgr.txt:2379`）。
- 差异：红证 B：`numberCapabilities=3` 而只有 1 个 set → `OOB-READ-HEADER`。规范未定义处置，实现必须有策略。
- 建议：遍历前先验证 `lengthCombinedCapabilities - 4 >= numberCapabilities * 4`；遍历中越界即断链（不要"尽力解析"）。

**D-16 [J] U-03 行 2368 — "清空 bitmap cache"未区分持久缓存**
- 文档声称：「保守：**清空** bitmap cache，等新 Confirm Active 后按新 capability 重建」。
- 规范原文：`Unlike the Bitmap Caches described in section 3.2.1.13, Persistent Bitmap Caches are not bound to the lifetime of a given RDP connection and their contents are persisted even after the RDP connection is closed`（`bcgr.txt:7211`）；`The lifetime of this store is bound to the lifetime of the Persistent Bitmap Caches`（7213）。
- 差异：照字面实现会清掉持久缓存，违反 7211，并使 `PERSISTENT_KEYS_EXPECTED_FLAG`（3434）与 Persistent Key List 流程失去意义。
- 建议：改为「清空 **标准** Bitmap Cache（3.2.1.13）；**保留** Persistent Bitmap Cache（3.2.1.14）与 Persisted Bitmap Keys（3.2.1.15）；重建以新 Rev2 的 `NumCellCaches`/`CellInfo` 为准。」

### 中等（表述/覆盖缺陷，会误导实现者）

**D-01 [G] §7.3 行 1038-1047 — "必须"表混装规范 MUST 与工程需要**
- 文档声称：General/Order/Pointer/Share/VirtualChannel/Font 均为"必须"。
- 规范原文：这些 set 只有 `This capability is sent by both client and server`（3155/3271/3436/3644/3569/3655），**无任何"必须发送"句**；Font 的 `fontSupportFlags` 是 SHOULD（3663）。
- 差异：与文档自己 §6.3 行 901"Mandatory ≠ 每次都必须发送"的表述冲突；只有 Bitmap 有"连接继续"级硬约束（3257）。
- 建议：拆成两张表——「规范 MUST 可推出的最小集合」（实质只有 Bitmap + 条件性的 Input/Order 字段）与「本项目功能所需的最小集合」（其余 7 个），每行标注 `规范 MUST / SHOULD / 工程需要`。

**D-02 [G] §7.3 — 遗漏 3 个服务端拒绝码**
- 文档声称：无（全文 0 次出现 `ERRINFO_BADCAPABILITIES` / `ERRINFO_NOCURSORCACHE` / `ERRINFO_CACHECAPNOTSET`）。
- 规范原文：`ERRINFO_BADCAPABILITIES0x000010EA | The capabilities received from the client in the Confirm Active PDU ... were not accepted by the server`（3000）；`ERRINFO_NOCURSORCACHE0x000010E9 | Both the colorPointerCacheSize and pointerCacheSize fields in the Pointer Capability Set ... are set to zero`（2999）；`ERRINFO_CACHECAPNOTSET0x000010F4 | The client sent a Persistent Key List PDU without including the prerequisite Revision 2 Bitmap Cache Capability Set`（3006）。
- 差异：这三个码是"最小集合是否安全"的**唯一规范级反馈机制**，缺失导致读者以为"少发几个 set 只是降带宽"。
- 建议：§7.3 增补"最小集合的风险面"小节，逐条给出三个码及触发条件；并在 §8.7（Pointer）明确"两个 cache size 都为 0 → 服务端可发 ERRINFO_NOCURSORCACHE"。

**D-04 [H] U-13 行 2378 — 降级表述不完整**
- 文档声称：「工程上必要，但规范未用 MUST 表述」。
- 规范原文：见 D-03。
- 差异：前半句正确，但缺"违反的后果"与"规范的检测机制"。
- 建议：补「若不回填，服务端可回 `ERRINFO_CONFIRMACTIVEWRONGSHAREID` 后断链；客户端此时尚未收到 Font Map，会表现为 S3 卡死后断链，原因只能从 Set Error Info 读取（见 §12 应补的 Set Error Info 处理）」。

**D-09 [I] §6.1 — `lengthCombinedCapabilities < 4` 未设防**
- 文档声称：伪码直接算 `lengthCombinedCapabilities - 4`。
- 规范原文：`The combined size in bytes of the numberCapabilities, pad2Octets and capabilitySets fields`（2375）——隐含 ≥ 4，但无显式下界条款。
- 差异：红证 G：combined=2 时 `combined-4` 若为无符号则下溢。
- 建议：先判 `combined >= 4`，否则断链；并对 `numberCapabilities == 0`（红证 H，`ASSERT-PASS`）明确"合法但无意义，应告警"。

**D-10 [I] §6.1 — assert 不是处置策略**
- 文档声称：`assert p == caps_start + lengthCombinedCapabilities - 4`。
- 规范原文：无对应条款。
- 差异：生产构建通常关闭 assert；文档未写校验失败后是断链、忽略剩余、还是按 combined 重新定界。
- 建议：改为显式分支：不等 → 以 `caps_end` 为界重新定位（更可信，因 combined 同时被 totalLength 约束）+ 告警 + 若 `p > caps_end` 则断链。

**D-11 [I] U-14 行 2379 — "后者覆盖前者"不安全**
- 文档声称：「保守：**后者覆盖前者**（最后一次出现生效），并记告警」。
- 规范原文：无重复条款；`The client and server do not violate any peer capabilities`（1026）。
- 差异：对 `General.extraFlags`（`ENC_SALTED_CHECKSUM 0x0010`，3213）、`Order.orderSupport`、`Rev2.NumCellCaches/CellInfo` 而言，last-wins 会单方面改变密码学参数/订单集合/缓存槽语义 → MAC 全失败、订单不可解析、或**画错图**。
- 建议：改为「按交集/更保守值合并（support 位 AND、NumCellCaches 取小、MaxRequestSize 取小）；无法安全合并的字段冲突 → 断链」，不要无条件 last-wins。

**D-12 [J] §12 全节 — Set Error Info PDU 缺失**
- 文档声称：无（全文 0 次）。
- 规范原文：`Once this PDU has been processed, the client MUST store the error code so that the reason for the server disconnect which will follow can be accurately reported to the user`（`bcgr.txt:7460`）；1.3.1.4.2 服务端断开序列为「可选 Set Error Info → 可选 Deactivate All → 可选 Ultimatum → 关闭」。
- 差异：状态机缺这一跳，且 D-03/D-04 的诊断路径依赖它。
- 建议：§12.1 增加 `S7 DISCONNECT_PENDING`（或说明为何不需要），§12.2 增加「任意状态 + Set Error Info → 记录 errorInfo → 继续等 Deactivate All/Ultimatum」；§17.3 增补对应检查项。

**D-13 [J] §12 — Monitor Layout PDU 缺失**
- 文档声称：仅 §2.2 行 304 列了 `pduType2=0x37`，状态机无对应迁移。
- 规范原文：`The optional Monitor Layout PDU (section 2.2.12.1) is sent by the server after the Demand Active PDU`（858）。
- 差异：S1/S2 收到 Monitor Layout 会落到"未定义"分支（红证）。
- 建议：在 S1（收到 Demand Active 之后）与 S2 增加「Monitor Layout → 记录显示器布局，状态不变」迁移；§17.1 增补解析检查项。

**D-14 [J] §12.2 — 缺通用"意外 PDU"分支**
- 文档声称：只有 `S1 + pduType.type != 1 → 忽略`（1889）。
- 规范原文：`ERRINFO_CONTROLPDUSEQUENCE0x000010CD | An out-of-sequence Demand Active PDU, Confirm Active PDU, Deactivate All PDU or Enhanced Security Server Redirection PDU has been received`（2977）；`ERRINFO_DATAPDUSEQUENCE0x000010CB`（2976）。
- 差异：红证中 13 个 `(state,event)` 对无迁移，包括 S4 收到重复 Demand Active、S3 收到 Deactivate All。
- 建议：增加兜底迁移「任意状态 + 与当前状态不符的 PDU → 忽略并告警（不改变状态）」；对 `PDUTYPE_DEMANDACTIVEPDU`/`CONFIRMACTIVEPDU`/`DEACTIVATEALLPDU` 的错序，明确"忽略"还是"断链"（规范只给了错误码，未强制，需自定并记录理由）。

**D-15 [J] §12 — 无定时器；U-06 的"按超时处理"无依据**
- 文档声称：U-06 行 2371「若服务端不发 Font Map，按超时处理」；§12 无 timer 定义。
- 规范原文：`The Client-Side Connection Sequence Timeout fires if more than 300 seconds have elapsed on the client-side Connection Sequence Timeout Timer ... the client MAY terminate the connection`（`bcgr.txt:7633`）；章节号 3.2.6.1。
- 差异：缺时长（300 s）、缺章节号、缺"MAY 而非 MUST"的强度。
- 建议：§12 增"12.5 定时器"小节，引用 3.2.6.1 / 3.2.2.1，写明 300 s 与 MAY；U-06 改为引用该小节。

**D-17 [J] U-03 — 未写"清空"的代价**
- 文档声称：仅"保守：清空"。
- 规范原文：`The Bitmap Cache Error PDU SHOULD be sent to a server that has requested the rendering of a cached bitmap that is not available in the client Bitmap Cache`（`egdi.txt:3754`）；`BC_ERR_FLUSH_CACHE0x01 | Indicates that the contents of the cache MUST be emptied`（2665）。
- 差异：清空会触发缓存错误 PDU + 黑图重绘（掉帧/黑闪），文档未提示。
- 建议：补「清空后服务端可能仍引用旧槽位 → 客户端按 EGDI 发 Bitmap Cache Error（`BC_ERR_FLUSH_CACHE`）并黑图重绘；这是可用但会掉帧的选择」。

### 轻微（一致性/引用/表述）

**D-05 [H] 行 266 — pduSource MUST 的来源标错**
- 文档声称：`这符合 3.2.5.3.13.2 "pduSource MUST be set to the User Channel ID"（S61）`。
- 规范原文：3.2.5.3.13.2 的 Sending 段（`bcgr.txt:7411-7419`）**全段无 pduSource 句**；该 MUST 在 3.2.5.1：`The pduSource field of the embedded Share Control Header ... MUST be set to the User Channel ID`（7242）。
- 建议：把 S61 改为 3.2.5.1（并在 §0.2 补该章节的 guid）。

**D-06 [H] 行 791 — PDUVersion 漏 MUST**
- 文档声称：`PDUVersion = 0x1 ⇒ 线上 0x0013`。
- 规范原文：`the PDUVersion subfield MUST be set to TS_PROTOCOL_VERSION (0x1)`（2371）。
- 建议：改为 `PDUVersion MUST = 0x1`。

**D-18 [L] §7.2 行 1020 — 合计 492 与 466 矛盾**
- 文档声称：表末 `**合计** | **492** = totalLength ✔`。
- 实测：18 个 `lengthCapability` 之和 = **466**（`auditb_sum.py`）；492 = 26（头）+ 466。§13.2 行 2099 自己也写"合计 466"。
- 建议：把该行改为「Σ lengthCapability = 466；+ 26 字节头 = 492 = totalLength」。

**D-19 [L] §8.18 行 1425 — VirtualChannel"固定总长 12"自相矛盾**
- 文档声称：`固定总长：12 字节`，但同行表内写 `lengthCapability | 8（无 VCChunkSize）或 12`，且 §13.1/§13.2 实测均为 8。
- 规范原文：`VCChunkSize (4 bytes)` 在结构图中标注 `(optional)`（`bcgr.txt:3574`）。
- 建议：改为「长度：8 或 12（`VCChunkSize` 可选）」，并删除行 1436 的"末字段结束 = 12 = 固定总长 12 ✔"。

**D-20 [L] 内部断引用 2 处**
- (a) 行 148：fast-path 长度编码引 `§2.3`（= 安全头），应为 **§3.4**。
- (b) 行 1677 / 1688：`§12 U-04` / `§12 U-05`，应为 **§15 U-04 / U-05**。
- 建议：直接改这三处编号。

**D-21 [L] §15.1 行 2403 — "无不确定性"表内含"无佐证"项**
- 文档声称：§15.1 标题「已全部核实、无不确定性的项」，但表内 Deactivate All 一行写 `**无 dump 佐证**（见 U-10）`。
- 建议：把该行移出 §15.1，或改写为「结构自洽（S41 表推导），但缺 dump 佐证 → 见 U-10」。

**D-22 [L] §8 全节 + U-20 — `lengthCapability MUST = N` 属过度断言**
- 文档声称：§8.1-§8.27 每节都写 `lengthCapability | MUST = 24/28/88/...`；U-20 前提写「各 capability 节都写 "MUST be set to N"」。
- 规范原文：实测 `lengthCapability[^.]*MUST be set to` 在 `bcgr.txt` 命中 **0** 次；全部 `lengthCapability` 定义均为 `The length in bytes of the capability data, including the size of the capabilitySetType and lengthCapability fields`（如 2335/3166/3243），**无值、无 MUST**。只有 `capabilitySetType` 才有 `MUST be set to CAPSTYPE_xxx`。
- 差异：这些定长值是"结构推导"（文档 §14.2 脚本也确实这么算），不是规范 MUST。U-20 的"原因"栏因此站不住（规范既没规定值，自然谈不上"未规定接收方校验义务"）。
- 建议：§8 统一改为 `lengthCapability | 定长 24（结构推导；规范未固定该值）`；U-20 改写为「规范未固定 `lengthCapability`，各节字段宽度决定期望值；接收侧按实际值定界，`len < 期望` 时缺失字段取 0 并告警」。

**D-23 [L] §0.2 行 129 / §14.3 行 2323-2332 — "85/85 覆盖每个章节"不成立**
- 文档声称：「上述 85 个 learn.microsoft.com 页面…85/85 返回 HTTP 200」「即本文件引用的**每个**章节号都能定位到实际页面」。
- 实测：
  ```
  [BASH: python -X utf8 F:\rtsc\.tmp\auditb_urls.py]
  rows 89 learn 87 docx 2
  distinct learn urls 87
  script urls 85
  in doc not script ['ms-rdpbcgr/7c61b54e-...', 'ms-rdpbcgr/8be0074f-...', 'ms-rdpbcgr/b61e1c76-...', 'ms-rdpbcgr/e0d4b29b-...']
  in script not doc ['ms-rdpbcgr/5073f4ed-...', 'ms-rdpegdi/745f2eee-...']
  ```
  即 §0.2 表有 **87** 个 learn URL，脚本只查 **85** 个，其中 **4 个被引用的页面从未被脚本验证**，另 2 个脚本查的页面不在表内。
- 补充：这 4 个 guid 我逐一在 `toc.txt` 中确认**存在**（`b61e1c76`/`8be0074f`/`7c61b54e`/`e0d4b29b` 均 True），并抽测 `745f2eee` 返回 HTTP 200。所以**内容没错，是证据覆盖面被夸大**。
- 建议：把脚本 URL 列表与 §0.2 表对齐（87 条），输出改为 `checked=87 ok=87 bad=0`；或把 §0.2 措辞改为"85 个已核验 + 2 个 DOCX 直链"。

**D-24 [K/L] 正文引用了未登记在 §0.2 的章节号**
- 实测：正文引用 `3.2.5.3.17`、`3.2.5.3.18`、`3.2.5.3.22`、`3.3.5.3.18`、`3.3.5.3.22`、`2.2.5.1`、`2.2.12.1`、`3.2.6.1`，但 §0.2 的 89 行 S 表中**这些章节号全部 ABSENT**（`auditb_sref.py` 输出）。
- 差异：违反文档自己的「所有事实性论断均标注来源章节号（`Sxx` 对应 §0.2 表）」承诺（行 2497）。
- 建议：补登 S90-S97（或改用已登记的 guid），特别是 2.2.5.1（Set Error Info，D-12 会用到）与 3.2.6.1（超时，D-15 会用到）。

**D-25 [L] §12.3 时序图与 1.3.1.1 不符**
- 文档声称：时序图（行 1920-1929）中客户端先发完 Sync/Coop/ReqCtrl/[PKL]/FontList，服务端再发 Sync/Coop/Granted/FontMap。
- 规范原文：`The Server Synchronize PDU (section 2.2.1.19) is sent in response to the Confirm Active PDU`（`bcgr.txt:866`）；`The client-to-server PDUs sent during this phase have no dependencies on any of the server-to-client PDUs; they can be sent as a single batch`（859）。
- 差异：服务端 Sync 应对 Confirm Active 立即响应，不必等 Font List。图与文档自己的 §12.4 第 4 条（1948-1949）也不一致。
- 建议：把服务端 Sync 画在 Confirm Active 之后（可加注"客户端 5 个 PDU 可整批发送，故实际观测顺序可能交错"）。

**D-26 [K] 行 1849 — `S59 系列` 引用不精确**
- 文档声称：`客户端（3.2.5.3.22，S59 系列）`。
- 实际：S59 = 3.2.5.3.13（§0.2 行 97）；3.2.5.3.22 的 guid 是 `d246ad43-d84e-4de8-a808-46e11035db56`，未登记。
- 建议：登记 3.2.5.3.22 为 S9x 并直接引用。

**D-27 [L] §15 U-11 与正文冲突**
- 文档 §15 称 `sourceDescriptor` 语义"未取原文"，但 §4.3 行 714 直接断言「内容为 source descriptor 字符串（dump 中为 `"RDP"`，含 NUL，长度 4）」，§5.3 行 797 断言 `"MSTSC"`。
- 差异：正文把 dump 观测当语义结论；§15 又说语义未验证。属"正文断言 vs §15 不确定"的轻度反模式。
- 建议：§4.3/§5.3 措辞改为「dump 实测内容为 ...；语义见 [T128] 8.4.1（未取证）」。

**D-28 [L/§13.4] 行 2162-2163 与 2171 — Fast-Path dump 的密文区写成了明文（同一 dump 在文档内两种字节）**
- 文档声称：§13.4 行 2162 标注"**完整线上字节**（17 字节，无 TPKT/X.224/MCS 封装）"，偏移 10 的 7 字节标为 `fpInputEvents（密文）` = `20 00 08 ab 02 6f 01`。
- 规范原文：`[MS-RDPBCGR] 4.7` 的线上字节为 `c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28`（`bcgr.txt:11568-11569`），**密文是 `26 18 5e 76 0e de 28`**；`20 00 08 ab 02 6f 01` 是该 PDU 的**解密后** `fpInputEvents`（`bcgr.txt:11582`）。
- 差异：
  ```
  [BASH: python -X utf8 F:\rtsc\.tmp\auditb_fp3.py]
  official wire bytes: c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28 len 17
  [BASH: python -X utf8 F:\rtsc\.tmp\auditb_fp2.py]
  doc : c4 11 30 35 6b 5b b5 34 c8 47 20 00 08 ab 02 6f 01
  doc wire[10:] == doc decrypted ? True
  ```
  即文档把"解密后明文"填进了"线上密文"位置。**并且文档自己在 §3.4 行 543 写的是正确密文 `26 18 5e 76 0e de 28`**——同一份 dump 在 §3.4 与 §13.4 给出**互相矛盾的两组字节**。
  危害：读者若照 §13.4 的"线上字节"实现 MAC 校验/解密自测，**永远无法复现**（密文对不上），且会误以为 `20 00 08 ab 02 6f 01` 是"加密后数据"从而把明文当密文送进解密器。
- 建议：§13.4 行 2162-2163 改为 `c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28`，行 2171 的字节改为 `26 18 5e 76 0e de 28`；保留现有"解密后的 fpInputEvents（7 字节）"块不动（该块正确）。同时把 §13.4 的标题从"完整线上字节"改为"线上字节 + 解密后载荷"，避免再次混淆。

---

## 我如何验证（方法学，供复核）

| 手段 | 具体做法 | 产物 |
|---|---|---|
| 规范原文定位 | 官方 DOCX 抽文本 `F:\rtsc\.tmp\bcgr.txt`（13226 行）/ `egdi.txt`，按字符串检索并记录**行号**；所有引用都给出 `bcgr.txt:NNNN` | 全文引用均带行号 |
| 章节号真伪 | 用官方 `toc.txt`（63120 字节）逐行比对 §0.2 的 87 个 learn URL 的 guid；`2.2.1.13.3` 做全文 0 命中确认 | 9 个非 BCGR 的 guid 在各自 TOC 中 FOUND；2.2.1.13.3 不存在 |
| dump 真实性 | 写脚本从文档 markdown 提取十六进制块、从 `bcgr.txt` 提取 `[Code]` 块，**逐字节比较**（不信任文档注解） | 13.1 = 359/359 一致；13.2 = 492/492 一致；13.3 = 26/26 ×2 一致；13.4 密文区不一致（D-28）。注：此项仅为 L 项"同一事实跨章节矛盾"的取证，不做甲负责的 dump 逐字节注解复核 |
| 字段偏移验证 | 按文档 §8 的偏移从 dump 里 `struct.unpack` 取值，再与文档 §13 注解对照 | orderFlags/textANSICodePage/Cache2CellInfo/Offscreen/NineGrid 全部命中 |
| 红证（可执行复现） | 把文档伪码逐字实现，喂构造的畸形输入，观察是否越界/静默通过 | I 项 9 例、J 项 15 例 |
| 交叉引用完整性 | 正则抽全部 `§x.y`，过滤外部 spec 前缀，检查目标章节是否存在 + 内容是否匹配 | 179 个引用 / 86 个 distinct；5 处内部断引用 |
| §16 落实检查 | 对 9 条订正逐条去正文找实际落地位置 | 9/9 已落实（1 条连带时序图不符） |
| 文档自证脚本 | 实跑 `verify_caps.py`（31/31 PASS）、`gen_caps_full.py`（caps=27 bytes=25034，assert 全过） | 两者可复现，输出与文档 §14 声称一致 |

---

## 我未覆盖的部分（显式声明）

1. **§8 各 capability 的字段宽度逐项复核**——按分工归甲。我只做了"文档 dump 字节块 == 规范 dump 字节块"的整体比对，未逐字段验证宽度（如 `GlyphCache` 52 字节的 40+4+2+2 分解）。
2. **位域读法（bit0 在左/右）**——归甲。我仅使用 §14.4 的既有结论（`0xC4` 反推），未独立复核。
3. **编号表 28 项的逐项真伪**——归甲。我只验证了"表内 28 行、§8 有 27 个小节、0x001D 单独在 §6.4"这一结构自洽性。
4. **错误策略（SHOULD 断链 vs 忽略）的规范性强度**——归甲。我只在 G/I/J 中因涉及"是否静默接受畸形"而引用。
5. **[MS-RDPERP] / [MS-RDPRFX] / [MS-RDPNSC] 的内部结构**——未取原文。§8.21/§8.22/§8.27 的字段宽度我只核对了 guid 存在性，未核对字段定义。
6. **[T128] 原文**——未获取（文档 U-11 也承认）。故 `sourceDescriptor` 语义、`TS_DEACTIVATE_ALL_PDU` 的 T.128 细节只能引用二手。
7. **现代 mstsc（10.x）的实际 capability 集合**——无抓包，无法验证。文档 U-02 已声明该缺口，我同意。
8. **真实服务端互操作**——未做。所有结论均为规范文本 + 官方 dump 层面；未在真实 RDP 服务端上验证 D-03/D-16 的实际触发。
9. **Fast-Path 2 字节长度（`length1` MSB 置位）的线上实例**——规范无 dump，我未构造。
10. **`deactivateAllPduData` 的 `totalLength=13` 实测**——无官方 dump，只能按结构推导（文档 U-10 同样标注）。

---

## 附：本报告用到的脚本清单（均在 `F:\rtsc\.tmp\`）

| 脚本 | 作用 |
|---|---|
| `auditb_dump.py` | 文档 hex 块 vs 规范 `[Code]` 块逐字节比对（13.1/13.2/13.4） |
| `auditb_font.py` | Font List / Font Map 26 字节比对 + 4 字段解包 |
| `auditb_fields.py` | 从 dump 按文档偏移解包 8 个 capability 的关键字段 |
| `auditb_red_i.py` / `auditb_red_i2.py` | I 项红证：文档 §6.1 伪码 + 9 类畸形输入 |
| `auditb_red_j.py` | J 项红证：文档 §12.2 迁移表 + 15 个规范允许的事件 |
| `auditb_refs.py` | 交叉引用完整性（179 引用 / 5 处断引用） |
| `auditb_urls.py` | §0.2 URL 表 vs `check_urls.ps1` 覆盖比对 |
| `auditb_toc.py` / `auditb_othertoc.py` | §0.2 guid 在官方 TOC 中的存在性 |
| `auditb_sref.py` | 正文 `Sxx` 引用 vs §0.2 表登记项 |
| `auditb_sum.py` | §7.2 18 个 lengthCapability 求和（466 vs 492） |
| `auditb_types.py` | dump 中出现的 capability 类型集合（21/28） |

---

*本报告为审计 AI 乙的独立结论，仅覆盖 G-L 六项；与审计甲（A-F）的结论应交叉验证后合并。*
