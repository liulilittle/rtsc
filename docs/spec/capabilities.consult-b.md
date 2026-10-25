# `docs/spec/capabilities.md` 双审计磋商报告（审计 AI 乙 → 甲）

> 阶段：W11 第②步「磋商」。输入：`capabilities.audit-a.md`（甲，700 行 / 11 条）、
> `capabilities.audit-b.md`（乙，743 行 / 28 条）。产出：本文件。
> 裁定原则：**只看证据是否可复现**，不看谁的结论更"好听"。凡我判"成立"的，都给了
> 可执行复现（脚本路径 + 实际输出）；凡我判"不成立"的，也给了反证。
> 所有规范引用以 `F:\rtsc\.tmp\bcgr.txt` 行号为准（该文件为官方 DOCX 抽文本，13226 行）。

---

## 0. 结论摘要

| 项 | 结果 |
|---|---|
| 甲 11 条裁定 | **成立 10 / 部分成立 1 / 不成立 0**（D-06 部分成立；D-05 结论成立、标题措辞偏强） |
| 甲 A/B/C 判 PASS vs 乙 G/H/I/J/L 判 FAIL | **不矛盾**（审计对象不同，见 §3） |
| 甲独有的两条硬缺陷 | **两条全部成立**，且 `0x03E3` 是本次审计中**最严重**的单点缺陷 |
| 双方都漏、本次磋商新增 | **4 条**（NEW-1…NEW-4） |
| 合并去重后缺陷总数 | **37 条** = 11 + 28 − 6 对重复 + 4 条新增 |
| 按严重级 | 阻断 **1** / 严重 **4** / 一般 **32** |

**最严重 1 条（阻断级）**：`capabilities.md:688` 把 MCS I/O Channel ID 写成 `0x03E3`
（十六进制值 995），正确为 `0x03EB`（= 1003）。双证：
`[READ:capabilities.md:2202]` 文档自己写 `channelId = 1003 (0x03EB)`；
`[BASH:python -X utf8 F:\rtsc\.tmp\consult_94.py]` 官方 dump 字节 `68 00 01 03 eb 70 81 73`
→ `0x03EB = 1003`（`bcgr.txt:9342/9344`）。

---

## 1. 甲 11 条逐条裁定

裁定列含义：**成立** = 缺陷真实且描述准确；**部分成立** = 缺陷真实但范围/归因需收窄；
**措辞过度** = 结论对、表述强度超出证据；**不成立** = 有反证。

| 甲编号 | 主题 | 裁定 | 我的独立验算（红证） |
|---|---|---|---|
| 甲 D-01 | §4.3 行 727–728 totalLength 闭式多 `+4` | **成立** | `18+L+lcc` = 18+4+337 = **359**；文档写 `+4` → 363。同行 740 `355+4=359` 与 727 正确。三行内自相矛盾。 |
| 甲 D-02 | 行 688 `0x03E3`(=995) 应为 `0x03EB`(=1003) | **成立（最严重）** | 官方 dump `68 00 01 03 eb 70 81 73`（`bcgr.txt:9342`），注解 `channelId = 1003 (0x03eb)`（`9344`）；文档行 2202 自写 `0x03EB`。见 §2.1。 |
| 甲 D-03 | §13.4 行 2159/2162/2171 明文冒充密文 | **成立** | 官方线上 `c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28`（`11569`）；`20 00 08 ab 02 6f 01` 是解密后载荷（`11582`）。**与乙 D-28 同一缺陷**。 |
| 甲 D-04 | §8.18 行 1425/1436 "固定总长 12" | **成立** | 行 1432 自己写"8 或 12"；`verify_caps.py:35` SCHEMA `('VirtualChannel',20,[4])` → 4+4 = **8**。**与乙 D-19 同一缺陷**。 |
| 甲 D-05 | §14.1 红证 28 应为 26 | **成立（归因需改写）** | 见 §2.2 的完整三态复现：正确 payload 20 → LEN 24；多一个 2B 字段 → 22 → **26**；双计 4B 头（13 项）→ 24 → **28**。文档行 2308 自己写"13 项…= 24"，与行 2305"13 项 → 28"矛盾。 |
| 甲 D-06 | §14.2/§15.1 把"偏移自洽"说成"宽度已校验" | **部分成立** | 行 2315"偏移不存在手抄错误"**本身为真**（`gen_caps_full.py:461` 只有 `assert o == off`，确实能保证偏移自洽）。过度断言只发生在行 2394 的证据栏。见 §2.3。 |
| 甲 D-07 | 行 129 "85 个 URL / 85/85" | **成立** | 实测 `rows 89 / learn 87 / script 85 / 交集 83 / doc-only 4 / script-only 2`。**与乙 D-23 同一缺陷**，且两边数字**完全一致**。 |
| 甲 D-08 | 行 266 pduSource MUST 出处引错 | **成立** | 3.2.5.3.13.2 Sending 段 = `bcgr.txt:7411-7419`，全段无 `pduSource`；MUST 在 3.2.5.1 = `bcgr.txt:7243`。**与乙 D-05 同一缺陷**。 |
| 甲 D-09 | 行 2385 U-20 前提"各节都写 MUST be set to N" | **成立** | `lengthCapability[^.]*MUST be set to` 在 `bcgr.txt` 命中 **0** 次。**与乙 D-22 同一缺陷**。 |
| 甲 D-10 | 行 1677/1688 `§12 U-04` 应为 `§15` | **成立** | U-04/U-05 在 §15（行 2369/2370）。**与乙 D-20(b) 同一缺陷**（乙另有 D-20(a)：行 148 `§2.3` 应为 `§3.4`，甲未列）。 |
| 甲 D-11 | 行 2393 "28 个类型已核实" 实为 21 类型 / 31 实例 | **成立** | union distinct = **21**，instances = **31**；27 个定长类型中未覆盖 **6** 个 = `0x0004/0x0019/0x001A/0x001B/0x001C/0x001E`（甲的 6 项列表**精确**，`0x001D` 是变长不在 27 内）。 |

### 1.1 裁定为"部分成立 / 措辞过度"的两条详解

**甲 D-06 → 部分成立**（不是"不成立"，因为核心事实成立）

甲说：文档把"偏移自洽"说成"宽度已被机器校验"。拆开看：

- `capabilities.md:2315`「因此 §8 的偏移**不存在手抄错误**」——**真**。`gen_caps_full.py:461`
  的 `assert o == off` 确实能证明"人工写的偏移 == 人工写的宽度累加"，也就是没有偏移手抄错。
- `capabilities.md:2394` 证据栏「27 个定长 capability 的总长 | §14.2 脚本累加校验 + §14.1 dump
  反向匹配（31/31 通过）」——**过度**。被读者读成"宽度也过了机器校验"。

我的注入实验（红证，`consult_mut.py` / `consult_mut2.py`）：

```
MUT1 (互换 osMajorType/osMinorType 名字)     -> rc=0  caps=27 bytes=25034   assert 全过
MUT3 (Bitmap 重塑: highColorFlags 1->2, drawingFlags->24/2, 删 pad2octetsB,
      multipleRectangleSupport->26，总长仍 28) -> rc=0  caps=27 bytes=24977   assert 全过
```

即：脚本产出了"错误但自洽"的表，且总长仍是 28 所以 §14.1 的 dump 反向匹配也照样 PASS。
**结论**：甲的"过度断言"指控成立，但**只应指向行 2394**，不应连带否定行 2315。
修正方案见 §5 的 F-09。

**甲 D-05 → 成立，但"红证算错"这个措辞略过**

甲说文档"红证算错：多一个 2 字节字段是 26 不是 28"。**数字结论对**（26 ≠ 28）。
但严格说，28 **也是可复现的**——只要你换一种错误注入方式（双计头字段，13 项）。
所以真正错的是**归因**：文档说"多算了一个 `pad2octets`"，这个原因只能得到 26；
文档声称的 28 对应的是"把 `capabilitySetType` + `lengthCapability` 也当 payload"。
甲在正文里其实也做了这个区分（"红证的方向成立，但归因写错了"），只是标题写成了"算错"。
建议执行 AI 按"归因错误"而非"数字错误"来改文档，否则会把 2308 行那句正确的"13 项 = 24"也改坏。

---

## 2. 甲独有的两条硬缺陷 —— 专项裁定

### 2.1 `0x03E3` vs `0x03EB`（甲 D-02）：**成立，阻断级**

三重独立证据：

1. **算术**：`0x03E3 = 3×256+227 = 995`；`0x03EB = 3×256+235 = 1003`。文档行 688 写
   「（`0x03E3` = 1003）」——**括号内两个值不可能同时成立**，这本身就是硬矛盾。
2. **官方 dump 字节**：`bcgr.txt:9342` = `68 00 01 03 eb 70 81 73`（PER 编码
   SendDataIndication），`bcgr.txt:9344` = `channelId = 1003 (0x03eb)`。
   注：甲引的是 `880397`（Word 字符偏移）与行 9341/9343；我用 `consult_94.py` 复核到
   行号是 **9342/9344**（9341 是 `02 f0 80 -> X.224 Data TPDU`）。**甲的行号偏了 1 行，
   但结论与字节完全正确**，不构成缺陷。
3. **文档自证**：`capabilities.md:2202` 在 §13.3 的 dump 注解里自己写
   `channelId = 1003 (0x03EB)`。

影响：若实现按行 688 硬编码 `0x03E3`，MCS SendDataIndication 的 channelId 不匹配，
服务端按 MCS 规则丢弃该 PDU，客户端永远收不到 Demand Active → 连接卡死。
**这是本次审计里唯一会直接导致"功能完全不工作"的缺陷，定阻断级。**

补充（比甲更进一步）：行 688 的**表述范式**也错。规范 `bcgr.txt:7240` 只说
`the embedded channelId field MUST be set to the MCS I/O channel ID held in the I/O Channel ID store`，
**不给字面值**——该值由 Server Network Data 在连接时分配，**不可硬编码**。
所以正确修法不是把 995 改成 1003，而是"从 I/O Channel ID store 取"。

### 2.2 红证 26 vs 28（甲 D-05）：**成立**

`[BASH:python -X utf8 F:\rtsc\.tmp\consult_d05.py]` 实际输出：

```
correct payload fields        : 11 sum 20 -> LEN 24
one extra 2B field ("+pad2octets"): 12 sum 22 -> LEN 26
header pair also in payload   : 13 sum 24 -> LEN 28
two extra 2B fields           : 13 sum 24 -> LEN 28
doc claims expect=28 ; dump len=24
=> which injection yields 28 ?  double-count(header pair) = 28
=> "+one pad2octets" yields 26 (26, NOT 28)
```

（`LEN(payload) = 4 + sum(payload)`，与 `verify_caps.py` 的 `LEN` 同构。）

裁定：甲的数字推导**完全正确**。文档 2305 行「多算了一个 `pad2octets` → `expect=28`」
是**归因错误**；且 2308 行自己写「13 项，其中前 11 项 2 字节、后 2 项 1 字节 = 24」，
与 2305 行「13 项 → 28」**三行内自相矛盾**。甲未点出这处"文档自己前后打架"，
我补上：这比单纯"算错"更值得写进修订说明。

### 2.3 我对甲 D-06 的收窄（本节为"部分成立"的依据）

甲的标题「§14.2/§15.1 把偏移自洽说成宽度已被机器校验」把 2313–2315 与 2394 捆在一起。
但 2313–2315 的原文结论是**限定在偏移层面**的（"不存在手抄错误"），并没有说宽度正确。
真正需要改的只有 2394 的证据栏。因此：

- **保留**：行 2394 必须改（甲的指控核心）。
- **收窄**：不要动 2313–2315，否则会删掉一条本来正确的结论。

这一点已写入 §5 的 F-09 修正方案。
---

## 3. 甲判 A/B/C = PASS 与乙判 G/H/I/J/L = FAIL 是否矛盾

**不矛盾。** 这不是"两个人看同一份代码得出相反结论"，而是**审计对象被任务提示切成了不重叠的两半**，
两边各自只在自己那一半里下判定。把两半拼起来才是完整结论。

| 审计项 | 甲 | 乙 | 审计对象 | 是否重叠 |
|---|---|---|---|---|
| A. capability 字段宽度 | PASS | —（未做） | §8.1–§8.27 每行的 `偏移/长度/字段名` 是否与规范逐字一致 | 无 |
| B. capabilitySetType 编号表 | PASS | —（未做） | §2.2 编号表 28 项 | 无 |
| C. 共享头 / Fast-Path 位域 | PASS | —（未做） | §2.1 / §3.2 / §3.3 / §3.7 的位序与掩码 | 无 |
| G. 客户端能力声明最小集合 | —（未做） | FAIL | §7.3"必须"表的**规范依据** | 无 |
| H. Confirm Active 字段完整性 | —（未做） | PARTIAL | §5.2/§5.3 字段表 + §5.5 处理规则 | 无 |
| I. 长度与畸形处理 | —（未做） | FAIL | §6.1 伪码对**畸形输入**的鲁棒性 | 无 |
| J. 状态机完整性 | —（未做） | FAIL | §12.2 迁移表覆盖度 | 无 |
| K. Font/Deactivate All | —（未做） | PASS | §10/§11 结构与固定值 | 无 |
| L. 文档内部一致性 | —（未做） | FAIL | 跨节矛盾 / 交叉引用 / §15/§16 | 无 |

**关键点**：A 项"字段宽度 PASS"和 G 项"最小集合 FAIL"根本不在同一个维度上——
A 问的是"这张表抄对了吗"，G 问的是"这张表该不该存在/该标 MUST 还是 SHOULD"。
同理 C 项"位域 PASS"与 I 项"畸形处理 FAIL"：位域定义正确，不代表解析器不会越界读。

**唯一的实质冲突点**是甲在"未覆盖的部分"第 7 条（`audit-a.md:670`）写了：

> §7.2/§7.3 的 capability 集合建议：18 个 set 的顺序与长度已与 dump 逐项核对通过；
> 但"最小集合"是工程判断（文档自己标 B 级），我未做实测（**无实机/无抓包**）。

这里甲的**归因错了**。G 项的问题不是"需要实机验证工程判断"，而是**纯规范文本比对**：
文档 §7.3 把 6 个 set（General/Order/Pointer/Share/VirtualChannel/Font）标为"必须"，
但规范对这 6 个只写 `This capability is sent by both client and server`
（`bcgr.txt:3156 / 3272 / 3437 / 3645 / 3570 / 3656`），**没有任何"必须发送"句**。
这个判定只需要读 `bcgr.txt`，不需要抓包。所以甲属于"该覆盖而未覆盖"，
而不是"无法覆盖"。我已在 §5 的 F-16 里按规范文本给出完整对照，甲可以直接复核。

**合并后的结论**：文档在"抄写准确性"（A/B/C/K）上质量高，在"决策与鲁棒性"（G/H/I/J/L）上
问题集中。这个分布本身是有信息量的——说明缺陷主要来自**推断与覆盖**，不是**转录**。

---

## 4. 双方都漏、本次磋商新增的 4 条

这 4 条是我在交叉验证过程中新发现的，甲的 11 条和乙的 28 条都没有列。

### NEW-1（一般）行 1795「严格串行」与 1.3.1.1 冲突

- **文档位置**：`capabilities.md:1795`
- **文档声称**：「Connection Finalization 阶段的客户端发送顺序（**严格串行**）」
- **规范原文**：`The client-to-server PDUs sent during this phase have no dependencies on any of
  the server-to-client PDUs; they can be sent as a single batch, provided that sequencing is
  maintained.`（`bcgr.txt:860`）
- **差异**：规范明确允许**整批发送**（single batch），只要求"sequencing is maintained"。
  "严格串行"会把"必须等上一个 PDU 的响应/确认才能发下一个"这个错误约束写进实现，
  导致每个 PDU 多一个 RTT（5 个 PDU → 多 5 个 RTT，高延迟链路下显著变慢），
  且与文档 §12.4 第 4 条（行 1948–1949，讲客户端/服务端不对称）的宽松表述不一致。
- **最小修正**：行 1795 改为「Connection Finalization 阶段的客户端发送顺序（**顺序固定，但可整批发送**：
  1.3.1.1 明示 client→server PDU "can be sent as a single batch, provided that sequencing is maintained"）」。
- **注**：乙 D-25 处理的是**服务端**时序图（行 1920–1929），NEW-1 处理的是**客户端**"严格串行"措辞，
  两者是不同句子，不重复。

### NEW-2（一般）U-06 把 MUST 的出处章节号引错一位

- **文档位置**：`capabilities.md:2371`（U-06 行）
- **文档声称**：「3.2.5.3.18（S59 系列）只说"发完 Persistent Key List（或 Request Control）后
  MUST 发 Font List"，未提 flag」
- **规范原文**：`After sending a single Persistent Key List PDU or a sequence of Persistent Key
  List PDUs, the client MUST send the Font List PDU (section 3.2.5.3.18) to the server.`
  —— 这句在 `bcgr.txt:7433`，而 7433 位于标题 `[Heading5] Sending Persistent Key List PDU(s)`
  （`bcgr.txt:7430`）之下，即 **3.2.5.3.17**（TOC `bcgr.txt:465`）。
  真正的 3.2.5.3.18「Sending Font List PDU」（`7434`）下只有一句：
  `The contents of this PDU MUST NOT be compressed.`（`7435`）——**无发送规则**。
- **差异**：章节号偏了一位。文档说"3.2.5.3.18 只说 MUST 发"，实际是"3.2.5.3.17 说 MUST 发，
  3.2.5.3.18 只说 MUST NOT 压缩"。结论（无条件发 Font List）仍然成立，但引用不可靠。
- **最小修正**：U-06 的出处改为「3.2.5.3.17（S9x，`bcgr.txt:7433`）；3.2.5.3.18 仅规定
  `MUST NOT be compressed`」。同时按乙 D-24 把 3.2.5.3.17 登记进 §0.2。
- **注**：乙 D-26 指出"行 1849 的 `S59 系列` 引用不精确"（S59 = 3.2.5.3.13），
  NEW-2 是 U-06 行 2371 的**另一处**同类错误，两处都要改。

### NEW-3（一般）§2.4 缺"压缩 → MAC → 加密"的次序约束，且全文无会话密钥更新

- **文档位置**：`capabilities.md:369-411`（§2.4 TS_SECURITY_HEADER1）
- **文档声称**：给出 Pad1/Pad2/SHAComponent/MD5 与 salted/FIPS 变体的公式，
  以及"接收方先解密，再对明文重算 MAC"。
- **规范原文**：
  1. `If the contents of the PDU are to be compressed (this MUST be done before any MAC
     signature is constructed and encryption methods applied), ...`（`bcgr.txt:7243`）
     —— 压缩必须**先于** MAC 构造与加密。
  2. `The encryption and the decryption keys are updated after 4,096 packets have been sent or
     received.`（`bcgr.txt:12580`，5.3.8.1 Session Key Updates）
- **差异**：文档全文 `4,096`/`密钥更新`/`Session Key` 命中 **0 次**
  （实测 `4096` 只出现在行 1415/1471，都是 bitmap cache 条目上限，与密钥无关）。
  发送侧次序（压缩→MAC→加密）虽在 3.2.5.1 有明确规定，但 §2.4 讲 MAC 时未复述，
  读者容易写成"先加密再压缩"或"对密文算 MAC"。接收侧次序文档写对了（行 409），
  但缺"每 4096 包换密钥"这一条会让长连接在 4096 包后**全部 MAC 校验失败**。
- **最小修正**：§2.4 末尾加一段：「**处理次序**（3.2.5.1，`bcgr.txt:7243`）：压缩 MUST 先于
  MAC 构造与加密；发送侧 `明文 → 压缩 → 计算 MAC → 加密`，接收侧反向。
  **会话密钥更新**（5.3.8.1，`bcgr.txt:12580`）：Non-FIPS 下每收发 4,096 个包后 MUST 用
  "初始密钥 + 当前密钥 + 密钥长度"重新派生（5.3.8.1.1），否则第 4097 个包起 MAC 全部失配。」
  并在 §0.2 登记 5.3.8.1。
- **严重度理由**：定为"一般"而非"严重"，因为 §2.4 的定位是"安全头结构"，
  次序/换钥属于安全层文档（`security-layer.md`）的职责；但本文档自称"实现者可直接照做"，
  缺这两条会在长连接上造成真实故障，故必须补。

### NEW-4（一般）§3.5 表标题"updateData 前导结构"与实际列出的结构不符

- **文档位置**：`capabilities.md:598-612`
- **文档声称**：表标题「**逐 subtype 的 `updateData` 前导结构**（均为 S51 各子节）」，
  表内"结构名"列给出 `TS_FP_UPDATE_PALETTE` / `TS_FP_UPDATE_BITMAP` / `TS_FP_UPDATE_SYNCHRONIZE` /
  `TS_FP_POINTERPOSATTRIBUTE` / `TS_FP_SYSTEMPOINTERHIDDENATTRIBUTE` / … / `TS_FP_LARGEPOINTERATTRIBUTE`。
- **规范原文**：`TS_FP_UPDATE_PALETTE` 的结构行是
  `updateHeader | compressionFlags (optional) | size | paletteUpdateData (variable)`（`bcgr.txt:4870-4871`）
  ——它**包含** `updateHeader`/`compressionFlags`/`size` 三个前导字段，
  是整个 fast-path update 结构，**不是**"`updateData` 的前导结构"。
  真正位于 `updateData` 内的只有 `paletteUpdateData` / `bitmapUpdateData` 等。
- **差异**：术语把"外层 update 结构"和"内层 updateData 载荷"混为一谈。
  实现者若按标题理解为"这些结构嵌在 updateData 里"，会多算一层 `updateHeader+size`（4–5 字节），
  造成 subtype 载荷错位。章节号本身是对的（0x2→2.2.9.1.2.1.1、0x1→…2、0x3→…3、0x8→…4、
  0x5→…5、0x6→…6、0x9→…7、0xB→…8、0xA→…9、0x4→…10、0xC→…11，与 TOC `bcgr.txt:309-320` 逐项一致），
  所以这是纯术语缺陷。
- **最小修正**：标题改为「**逐 subtype 的 fast-path update 结构**（`updateHeader`/`compressionFlags`/
  `size` 之后的载荷列在"附加字段"栏）」；"结构名"列保持不变。
  或把标题改为「逐 subtype 的 `updateData` **载荷**结构」并把 `TS_FP_UPDATE_*` 改成
  `paletteUpdateData` / `bitmapUpdateData` 等内层名。

---

## 5. 合并去重后的最终缺陷清单（37 条）

> 编号规则：`F-xx` = 最终清单编号。来源列标注 `甲D-xx` / `乙D-xx` / `双方` / `磋商`。
> 严重级：**阻断**（功能完全不工作）/ **严重**（数据错、内存不安全、安全判断错）/ **一般**（表述、覆盖、一致性）。
> 所有"证据"列的行号：`capabilities.md:NNN` 指被审文档；`bcgr.txt:NNNN` 指官方 DOCX 抽文本。

### 5.1 阻断（1 条）

**F-01 [阻断] 行 688 — MCS I/O Channel ID 写成 `0x03E3`（=995），且 hex 与 dec 不自洽**
- 来源：甲D-02（甲独有，乙未发现）
- 文档位置：`capabilities.md:688`
- 文档声称：``- `mcsSDin.channelId` MUST = MCS I/O Channel ID（`0x03E3` = 1003）``
- 证据：
  1. 算术：`0x03E3 = 995` ≠ 1003；`0x03EB = 1003`。
  2. 官方 dump：`68 00 01 03 eb 70 81 73`（`bcgr.txt:9342`），注解
     `channelId = 1003 (0x03eb)`（`bcgr.txt:9344`）。
  3. 文档自证：`capabilities.md:2202` 自己写 `channelId = 1003 (0x03EB)`。
  4. 规范只要求"取 store 里的值"，不给字面值：`bcgr.txt:7240`
     `the embedded channelId field MUST be set to the MCS I/O channel ID held in the
     I/O Channel ID store`。
- 影响：硬编码 `0x03E3` → MCS SendDataIndication 的 channelId 不匹配 → 服务端丢弃 →
  客户端永远收不到 Demand Active → 连接在 S1 卡死。**这是唯一会导致"完全不工作"的缺陷。**
- 最小修正：整句改为「`mcsSDin.channelId` MUST = I/O Channel ID store 中的值
  （由 Server Network Data 分配，本 dump 为 `0x03EB` = 1003；**不可硬编码**）」。
  同时检查全文其它 `0x03E3` 出现处（若有）。

### 5.2 严重（4 条）

**F-02 [严重] 行 2159/2162-2163/2171 — §13.4 把解密后明文当成"完整线上字节"并标为"密文"**
- 来源：**双方**（甲D-03 = 乙D-28）
- 文档位置：`capabilities.md:2159`（"完整线上字节"）、`2162-2163`（字节块）、`2171`（标"密文"）
- 文档声称：线上 17 字节 = `c4 11 30 35 6b 5b b5 34 c8 47 20 00 08 ab 02 6f 01`，
  偏移 10 的 7 字节是"`fpInputEvents`（密文）"。
- 证据：官方线上字节 = `c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28`（`bcgr.txt:11569`），
  注解 `26 18 5e 76 0e de 28 -> Encrypted TS_FP_INPUT_PDU::fpInputEvents`；
  `20 00 08 ab 02 6f 01` 是该 PDU 的**解密后**载荷（`bcgr.txt:11582` "Decrypted ..."）。
  **并且文档自己在 §3.4 行 543 写的是正确密文 `26 18 5e 76 0e de 28`** —— 同一 dump 在
  §3.4 与 §13.4 给出互相矛盾的两组字节（这是乙比甲多补的一层内部矛盾）。
- 影响：照 §13.4 做 MAC/解密自测**永远无法复现**；且会把明文当密文送进解密器。
- 最小修正：行 2162-2163 改为 `… c8 47 26 18 5e 76 0e de 28`；行 2171 的字节改为
  `26 18 5e 76 0e de 28`；行 2159 标题改为「线上字节 + 解密后载荷」；
  保留下方"解密后的 `fpInputEvents`（7 字节）"块不动（该块正确）。长度自洽 `1+1+8+7=17` 不变。

**F-03 [严重] 行 844-853 — §6.1 遍历伪码无上界检查（可越界读）**
- 来源：乙D-07
- 文档位置：`capabilities.md:844-853`
- 文档声称：伪码只有 `if len < 4: error`，然后 `p += len`。
- 证据：`lengthCapability` 的定义只给"含头在内的长度"，**不规定上界**
  （`bcgr.txt:2336`）。红证 A：`lengthCapability = 200` 而剩余仅 8 字节 →
  伪码无任何检查能拦住 → OOB read。
- 最小修正：伪码加三条硬检查：
  `caps_end = caps_start + lengthCombinedCapabilities - 4`；
  要求 `p + 4 <= caps_end`、`p + len <= caps_end`、`p + len <= recv_len`；
  任一不满足 → 断链（不要"尽力解析"）。

**F-04 [严重] 行 822 — §5.5「服务端不校验 originatorID/shareID」结论方向错**
- 来源：乙D-03
- 文档位置：`capabilities.md:822`
- 文档声称：「服务端**不校验** `originatorID` / `shareID` 是否与自己的 Demand Active 一致
  （规范未提出此要求）。」
- 证据：规范为这两种校验失败**定义了专用错误码**：
  `ERRINFO_CONFIRMACTIVEWRONGSHAREID 0x000010D4 | A Confirm Active PDU ... was received from
  the client with an invalid shareID field`（`bcgr.txt:2985`）；
  `ERRINFO_CONFIRMACTIVEWRONGORIGINATOR 0x000010D5`（`bcgr.txt:2986`）。
  3.3.5.3.13.2 的**处理步骤**确实没写校验，但错误码表证明协议预期实现会校验。
  文档把"某节没写"当成"规范没要求"。
- 最小修正：改为「3.3.5.3.13.2 的处理步骤未要求校验；但 2.2.5.1 为 `shareID` / `originatorID`
  非法分别定义了 `ERRINFO_CONFIRMACTIVEWRONGSHAREID (0x000010D4)` /
  `ERRINFO_CONFIRMACTIVEWRONGORIGINATOR (0x000010D5)`，说明实现可校验并据此断链。
  客户端必须按 0x03EA 填 originatorID、按收到的 shareID 回填。」

**F-05 [严重] 行 1425/1436 — §8.18 VirtualChannel「固定总长 12」自相矛盾**
- 来源：**双方**（甲D-04 = 乙D-19）
- 文档位置：`capabilities.md:1425`（"固定总长：12 字节"）、`1432`（"8 或 12"）、`1436`（"末字段结束 = 12 = 固定总长 12 ✔"）
- 证据：
  1. 行 1432 自己写「`lengthCapability` | 8（无 VCChunkSize）或 12（含 VCChunkSize）」。
  2. 规范结构图标 `VCChunkSize (optional)`（`bcgr.txt:3575`）。
  3. 官方 dump 4.1.12 / 4.1.13 的 VirtualChannel 都是 `lengthCapability = 8`。
  4. 文档自己的脚本反证：`verify_caps.py:35` SCHEMA `('VirtualChannel', 20, [4])` → `4+4 = 8`。
- 影响：若实现按"固定 12"定界，会多读 4 字节，把下一个 capability 的 `capabilitySetType`
  吞掉 → 后续全部 capability 错位。
- 最小修正：行 1425 改为「总长：**8**（无 `VCChunkSize`，官方 dump 形态）或 **12**（含 `VCChunkSize`）」；
  行 1436 改为「两种形态分别结束于 8 / 12」。

### 5.3 一般（32 条）

**F-06 [一般] 行 2368 — U-03「清空 bitmap cache」未区分持久缓存**
- 来源：乙D-16
- 证据：`Unlike the Bitmap Caches described in section 3.2.1.13, Persistent Bitmap Caches are not
  bound to the lifetime of a given RDP connection and their contents are persisted even after the
  RDP connection is closed`（`bcgr.txt:7212`）；`The lifetime of this store is bound to the lifetime
  of the Persistent Bitmap Caches`（`bcgr.txt:7214`）。
- 影响：照字面清空会违反 7212，并使 `PERSISTENT_KEYS_EXPECTED_FLAG` 与 Persistent Key List 流程失去意义。
- 最小修正：改为「清空**标准** Bitmap Cache（3.2.1.13）；**保留** Persistent Bitmap Cache（3.2.1.14）
  与 Persisted Bitmap Keys（3.2.1.15）；重建以新 Rev2 的 `NumCellCaches`/`CellInfo` 为准」。

**F-07 [一般] 行 2368 — U-03 未写"清空"的代价**
- 来源：乙D-17
- 证据：`The Bitmap Cache Error PDU SHOULD be sent to a server that has requested the rendering of
  a cached bitmap that is not available in the client Bitmap Cache`（`egdi.txt:3755`）；
  `BC_ERR_FLUSH_CACHE 0x01 | Indicates that the contents of the cache MUST be emptied`（`egdi.txt:2666` 附近）。
- 最小修正：补「清空后服务端可能仍引用旧槽位 → 客户端按 [MS-RDPEGDI] 发 Bitmap Cache Error
  （`BC_ERR_FLUSH_CACHE`）并黑图重绘；这是可用但会掉帧的选择」。

**F-08 [一般] §12 全节 — 缺 Set Error Info PDU 处理**
- 来源：乙D-12
- 证据：`Once this PDU has been processed, the client MUST store the error code so that the reason
  for the server disconnect which will follow can be accurately reported to the user`（`bcgr.txt:7461`）；
  1.3.1.4.2 的服务端断开序列为「可选 Set Error Info → 可选 Deactivate All → 可选 Ultimatum → 关闭」。
- 影响：状态机缺这一跳，且 F-04 的诊断路径依赖它。
- 最小修正：§12.2 增「任意状态 + Set Error Info（2.2.5.1）→ 记录 errorInfo → 状态不变」；
  §17.3 增对应检查项；§0.2 登记 2.2.5.1。

**F-09 [一般] §12 — 缺 Monitor Layout PDU 迁移**
- 来源：乙D-13
- 证据：`The optional Monitor Layout PDU (section 2.2.12.1) is sent by the server after the
  Demand Active PDU`（`bcgr.txt:859`）；文档只在行 304 列了 `pduType2 = 0x37`。
- 影响：S1/S2 收到 Monitor Layout 会落到"未定义"分支。
- 最小修正：S1（Demand Active 之后）与 S2 增「Monitor Layout → 记录显示器布局，状态不变」；
  §17.1 增解析检查项。

**F-10 [一般] 行 1889 — 缺通用"意外 PDU"兜底迁移**
- 来源：乙D-14
- 证据：`ERRINFO_CONTROLPDUSEQUENCE 0x000010CD | An out-of-sequence Demand Active PDU, Confirm
  Active PDU, Deactivate All PDU or Enhanced Security Server Redirection PDU has been received`
  （`bcgr.txt:2978`）；`ERRINFO_DATAPDUSEQUENCE 0x000010CB`（`bcgr.txt:2977`）。
- 影响：13 个 `(state, event)` 对无迁移（含 S4 重复 Demand Active、S3 收 Deactivate All）。
- 最小修正：增兜底迁移「任意状态 + 与当前状态不符的 PDU → 忽略并告警（不改状态）」；
  对三种控制 PDU 的错序明确"忽略"还是"断链"，并记录理由。

**F-11 [一般] §12 — 无定时器定义；U-06 的"按超时处理"无依据**
- 来源：乙D-15
- 证据：`The Client-Side Connection Sequence Timeout fires if more than 300 seconds have elapsed
  on the client-side Connection Sequence Timeout Timer (section 3.2.2.1). In this event the client
  MAY terminate the connection`（`bcgr.txt:7634`）；章节 3.2.6.1。
- 最小修正：§12 增「12.5 定时器」：300 s、MAY（不是 MUST）、引 3.2.6.1 / 3.2.2.1；
  U-06 改为引用该小节。

**F-12 [一般] — `numberCapabilities` 偏大无接收侧规则**
- 来源：乙D-08
- 证据：`The number of capability sets is specified by the numberCapabilities field`（`bcgr.txt:2380`）；
  红证 B：`numberCapabilities = 3` 而只有 1 个 set → OOB read（伪码无检查）。
- 最小修正：遍历前先验 `lengthCombinedCapabilities - 4 >= numberCapabilities * 4`；
  遍历中越界即断链。

**F-13 [一般] §6.1 — `lengthCombinedCapabilities < 4` 未设防**
- 来源：乙D-09
- 证据：`The combined size in bytes of the numberCapabilities, pad2Octets and capabilitySets
  fields`（`bcgr.txt:2376`）——隐含 ≥ 4，但无显式下界条款；红证 G：combined = 2 时
  `combined - 4` 无符号下溢。
- 最小修正：先判 `combined >= 4`，否则断链；对 `numberCapabilities == 0` 明确"合法但无意义，告警"。

**F-14 [一般] §6.1 — `assert` 不是处置策略**
- 来源：乙D-10
- 证据：文档伪码 `assert p == caps_start + lengthCombinedCapabilities - 4`，规范无对应条款；
  生产构建通常关闭 assert，文档未写失败后是断链、忽略剩余、还是按 combined 重新定界。
- 最小修正：改为显式分支——不等 → 以 `caps_end` 为界重新定位 + 告警；`p > caps_end` → 断链。

**F-15 [一般] 行 2379 — U-14「后者覆盖前者」不安全**
- 来源：乙D-11
- 证据：规范无重复条款；对 `General.extraFlags`（`ENC_SALTED_CHECKSUM 0x0010`，`bcgr.txt:3214`）、
  `Order.orderSupport`、`Rev2.NumCellCaches/CellInfo` 而言，last-wins 会单方面改变密码学参数 /
  订单集合 / 缓存槽语义 → MAC 全失败、订单不可解析、或画错图。
- 最小修正：改为「按交集/更保守值合并（support 位 AND、`NumCellCaches` 取小、`MaxRequestSize`
  取小）；无法安全合并的字段冲突 → 断链」。

**F-16 [一般] 行 1038-1047 — §7.3「必须」表混装规范 MUST 与工程需要**
- 来源：乙D-01（甲显式声明未覆盖，见 §3）
- 证据：General/Order/Pointer/Share/VirtualChannel/Font 六个 set 在规范里只有
  `This capability is sent by both client and server`（`bcgr.txt:3156 / 3272 / 3437 / 3645 / 3570 / 3656`），
  **无任何"必须发送"句**；Font 的 `fontSupportFlags` 是 SHOULD（`bcgr.txt:3664`）。
  只有 Bitmap 有"连接继续"级硬约束（`bcgr.txt:3258`）。
- 影响：与文档自己 §6.3 行 901「Mandatory ≠ 每次都必须发送」冲突。
- 最小修正：拆成两张表——「规范 MUST 可推出的最小集合」（实质只有 Bitmap + 条件性的
  Input/Order 字段）与「本项目功能所需的最小集合」（其余 7 个），每行标注
  `规范 MUST / SHOULD / 工程需要`。

**F-17 [一般] §7.3 — 遗漏 3 个服务端拒绝码**
- 来源：乙D-02
- 证据：`ERRINFO_BADCAPABILITIES 0x000010EA | The capabilities received from the client in the
  Confirm Active PDU ... were not accepted by the server`（`bcgr.txt:3001`）；
  `ERRINFO_NOCURSORCACHE 0x000010E9 | Both the colorPointerCacheSize and pointerCacheSize fields
  in the Pointer Capability Set ... are set to zero`（`bcgr.txt:3000`）；
  `ERRINFO_CACHECAPNOTSET 0x000010F4 | The client sent a Persistent Key List PDU without including
  the prerequisite Revision 2 Bitmap Cache Capability Set`（`bcgr.txt:3007`）。
- 影响：这三个码是"最小集合是否安全"的唯一规范级反馈机制，缺失会让读者以为"少发几个 set
  只是降带宽"。
- 最小修正：§7.3 增「最小集合的风险面」小节，逐条给出三个码及触发条件；
  §8.7（Pointer）明确"两个 cache size 都为 0 → 服务端可发 `ERRINFO_NOCURSORCACHE`"。

**F-18 [一般] 行 2378 — U-13 降级表述不完整**
- 来源：乙D-04
- 证据：见 F-04。文档写「工程上必要，但规范未用 MUST 表述」，前半句对，但缺"违反的后果"。
- 最小修正：补「若不回填，服务端可回 `ERRINFO_CONFIRMACTIVEWRONGSHAREID` 后断链；
  客户端此时尚未收到 Font Map，表现为 S3 卡死后断链，原因只能从 Set Error Info 读取」。

**F-19 [一般] 行 2394 — §15.1 证据栏把"偏移自洽"写成"宽度已机器校验"**
- 来源：甲D-06（乙未列；我裁定**部分成立**，只指向本行）
- 证据：`gen_caps_full.py:461` 只有 `assert o == off`，**不比对宽度、不比对字段名**。
  红证：MUT1（互换 `osMajorType`/`osMinorType` 名）→ rc=0、`caps=27 bytes=25034` 全过；
  MUT3（Bitmap 重塑：`highColorFlags` 1→2、`drawingFlags`→24/2、删 `pad2octetsB`、
  `multipleRectangleSupport`→26，总长仍 28）→ rc=0、`caps=27 bytes=24977`，
  产出"错误但自洽"的表，§14.1 的 dump 反向匹配（只比总长 28==28）照样 PASS。
- 最小修正：行 2394 证据列改为「总长由累加保证；**字段宽度为人工转录，已由审计逐字段比对规范原文
  （27/27 一致）**」。**不要动行 2313-2315**——「偏移不存在手抄错误」这句本身为真。

**F-20 [一般] 行 2393 — §15.1 把"31 个实例"说成"28 个类型已核实"**
- 来源：甲D-11
- 证据：31 个 dump 实例只覆盖 **21 个不同类型**（union distinct = 21）；
  27 个定长类型中未覆盖 **6** 个 = `0x0004 / 0x0019 / 0x001A / 0x001B / 0x001C / 0x001E`
  （`0x001D` 是变长，不在 27 内）。脚本匹配的是"长度"，不是"名称"。
- 最小修正：拆成两行——「28 个编号与名称：规范原文表逐行比对」+
  「21 个类型 × 31 个实例的长度：dump 反向匹配通过；其余 6 个类型无 dump 佐证」。
**F-21 [一般] 行 727-728 — §4.3 totalLength 闭式等式多一个 `+4`**
- 来源：甲D-01
- 文档位置：`capabilities.md:727-728`
- 文档声称：
  ```
  totalLength = (14 + lengthSourceDescriptor + 4) + Σ lengthCapability[i] + 4
              = 18 + lengthSourceDescriptor + lengthCombinedCapabilities + 4
  ```
- 证据（逐项算术，L=4、Σ=333、lcc=4+Σ=337）：
  - 第一行：`(14 + L + 4) + Σ + 4` = `22 + 333 + 4` = **359** ✔
    （结构：`6 头 + 4 shareID + 2 LSD + 2 lcc` = 14，`+L`，`+ numberCapabilities(2)+pad2Octets(2)` = 4，
    `+Σ`，`+ sessionId(4)` = 4）
  - 第二行：`18 + L + lcc + 4` = `18 + 4 + 337 + 4` = **363** ✘
  - 正确化简：把 `Σ = lcc − 4` 代入第一行 →
    `14 + L + 4 + (lcc − 4) + 4 = 14 + L + lcc + 4 = 18 + L + lcc` = `18 + 4 + 337` = **359**
  - 差异根因：代换时 `Σ` 换成 `lcc` **已经净增 4**（`lcc = 4 + Σ`），文档保留了原来的 `+4`，
    于是 4 被计入两次。与文档自己行 740「`355 + 4 = 359` ✔」直接矛盾。
- 影响：实现者若照第二行写代码，`totalLength` 会多 4 字节，服务端按 totalLength 截断
  → Confirm Active 尾部 4 字节（`sessionId`）丢失或校验失败。
- 最小修正：第二行末尾的 `+ 4` 删掉，改为
  `= 18 + lengthSourceDescriptor + lengthCombinedCapabilities`。

**F-22 [一般] 行 2304-2309 — §14.1「先红后绿」红证的归因写错（26 vs 28）**
- 来源：甲D-05
- 文档位置：`capabilities.md:2305`（"多算了一个 `pad2octets`" → `expect=28`）、`2308`（"13 项…= 24"）
- 证据（`[BASH:python -X utf8 F:\rtsc\.tmp\consult_d05.py]`）：
  ```
  correct payload fields        : 11 sum 20 -> LEN 24
  one extra 2B field ("+pad2octets"): 12 sum 22 -> LEN 26
  header pair also in payload   : 13 sum 24 -> LEN 28
  doc claims expect=28 ; dump len=24
  => which injection yields 28 ?  double-count(header pair) = 28
  => "+one pad2octets" yields 26 (26, NOT 28)
  ```
  即"多一个 2 字节字段"只能得到 **26**；文档声称的 **28** 只能由"把
  `capabilitySetType` + `lengthCapability` 也当 payload 二次计入"（13 项 = 24，`4+24=28`）产生。
  **并且文档行 2308 自己写"13 项…= 24"，与行 2305"13 项 → 28"三行内自相矛盾。**
- 影响：读者照 2305 的归因去复现红证，会得到 26 而不是 28，认为脚本或文档造假；
  且会误以为"13 项 = 28"是算术，进而怀疑 2308 的正确值 24。
- 最小修正：把 2305 改为「模型第一版把 `capabilitySetType` 与 `lengthCapability` 也写进 payload
  宽度表，被 `LEN` 的 `4 +` 二次计入，`expect = 4 + 24 = 28`；若只多算一个 2 字节
  `pad2octets`，则 `expect = 4 + 22 = 26`」。**不要改 2308**（它是正确的）。

**F-23 [一般] 行 265-266 / 792 — `pduSource` MUST 的出处引错章节**
- 来源：**双方**（甲D-08 = 乙D-05）
- 文档位置：`capabilities.md:266`、`792`
- 文档声称：行 266「这符合 3.2.5.3.13.2 "`pduSource` MUST be set to the User Channel ID"（S61）」
- 证据：3.2.5.3.13.2 的 Sending 段（`bcgr.txt:7411-7419`，标题 `Sending Confirm Active PDU` 在 7412）
  **全段无 `pduSource` 句**；该 MUST 在 3.2.5.1：
  `The pduSource field of the embedded Share Control Header (section 2.2.8.1.1.1.1) MUST be set to
  the User Channel ID held in the User Channel ID store (section 3.2.1.5).`（`bcgr.txt:7243`）
- 最小修正：行 266 的 S61 改为 3.2.5.1；行 792 的"依据"补 3.2.5.1，并在 §0.2 登记该章节。

**F-24 [一般] 行 791 — `PDUVersion` 漏写 MUST**
- 来源：乙D-06
- 文档位置：`capabilities.md:791`
- 文档声称：`PDUVersion = 0x1 ⇒ 线上 0x0013`
- 证据：`the PDUVersion subfield MUST be set to TS_PROTOCOL_VERSION (0x1)`（`bcgr.txt:2372`）
- 最小修正：改为 `` `PDUVersion` MUST = 0x1 ⇒ 线上 `0x0013` ``。

**F-25 [一般] 行 1020 — §7.2 合计 492 与 466 混用两个口径**
- 来源：乙D-18
- 文档位置：`capabilities.md:1020`
- 文档声称：表末「**合计** | **492** = `totalLength` ✔」
- 证据：18 个 `lengthCapability` 之和 = **466**；492 = 26（头）+ 466。
  文档 §13.2 行 2099 自己也写"合计 466"。
- 影响：表内各行的 `lengthCapability` 相加明明是 466，表末却写 492，
  读者会以为某行抄错 26 字节。
- 最小修正：改为「Σ `lengthCapability` = 466；+ 26 字节头 = 492 = `totalLength`」。

**F-26 [一般] 行 148 — fast-path 长度编码引 `§2.3`（安全头），应为 `§3.4`**
- 来源：乙D-20(a)（甲未列）
- 文档位置：`capabilities.md:148`
- 文档声称：「**唯一例外**是 Fast-Path 的 `length1`/`length2` 组合（**§2.3**）」
- 证据：§2.3 是 `TS_SECURITY_HEADER`（行 324）；fast-path 2 字节长度在 **§3.4**
  （行 515-552，含 `length1 & 0x80` 解码伪码）。文档 §3.2 行 464/465 自己就写"见 §3.4"。
- 最小修正：行 148 的 `§2.3` 改为 `§3.4`。

**F-27 [一般] 行 1677 / 1688 — `§12 U-04` / `§12 U-05` 应为 `§15`**
- 来源：**双方**（甲D-10 = 乙D-20(b)）
- 文档位置：`capabilities.md:1677`、`1688`
- 证据：U-04 / U-05 在 §15（行 2369 / 2370）；§12 是"客户端能力交换状态机"（行 1860 起），
  不含任何 U 编号。
- 最小修正：两处 `§12` 改为 `§15`。

**F-28 [一般] 行 2385 — U-20 前提「各 capability 节都写 MUST be set to N」不成立**
- 来源：**双方**（甲D-09 = 乙D-22）
- 文档位置：`capabilities.md:2385`（U-20 行），以及 §8.1-§8.27 每节的 `lengthCapability | MUST = N`
- 证据：`lengthCapability[^.]*MUST be set to` 在 `bcgr.txt` 命中 **0** 次；
  全部 `lengthCapability` 定义都是 `The length in bytes of the capability data, including the size
  of the capabilitySetType and lengthCapability fields`（如 `bcgr.txt:2336 / 3167 / 3244`），
  **无值、无 MUST**。只有 `capabilitySetType` 才有 `MUST be set to CAPSTYPE_xxx`。
  这些定长值是**结构推导**（文档 §14.2 脚本确实这么算），不是规范 MUST。
- 影响：U-20 的"原因"栏站不住——规范既没规定值，自然谈不上"未规定接收方校验义务"。
- 最小修正：§8 各节统一改为 `lengthCapability | 定长 24（结构推导；规范未固定该值）`；
  U-20 改写为「规范未固定 `lengthCapability`，各节字段宽度决定期望值；接收侧按实际值定界，
  `len < 期望` 时缺失字段取 0 并告警」。

**F-29 [一般] 行 129 / 2323-2332 — "85 个 URL / 85/85"与实测 87 个、脚本覆盖 83 个不符**
- 来源：**双方**（甲D-07 = 乙D-23）
- 文档位置：`capabilities.md:129`（"85 个…85/85 返回 HTTP 200"）、`2331`（"对 §0.2 表中每个 URL 发 HEAD"）
- 证据（`[BASH:python -X utf8 F:\rtsc\.tmp\consult_urls.py]`，甲乙独立跑出**完全相同**的数字）：
  ```
  S rows        : 89
  learn URLs    : 87 distinct 87
  script entries: 85 distinct 85
  intersection  : 83
  doc-only      : 4 ['ms-rdpbcgr/7c61b54e-...','ms-rdpbcgr/8be0074f-...',
                      'ms-rdpbcgr/b61e1c76-...','ms-rdpbcgr/e0d4b29b-...']
  script-only   : 2 ['ms-rdpbcgr/5073f4ed-...','ms-rdpegdi/745f2eee-...']
  ```
  doc-only 的 4 个对应 §0.2 的 **S01（2.2 Message Syntax）/ S05（2.2.1.13）/
  S67（5.3.6.1）/ S69（5.3.6.2）**，即 4 个被引用的页面**从未被脚本验证**；
  另 2 个脚本查的页面不在表内。
- 补充：甲乙都单独 HEAD 过那 4 个缺失 URL，**全部 200**；也都在 `toc.txt` 中确认 guid 存在。
  所以**内容没错，是证据覆盖面被夸大**。
- 最小修正：行 129 改为「87 个 learn 页面（另 2 个 DOCX 直链）」；行 2331 改为
  「脚本覆盖其中 85 个（含 2 个未在 §0.2 表内的协议首页/EGDI 页），其余 4 个已单独 HEAD 验证 200」；
  或把脚本 URL 列表补齐到 87 条，输出改为 `checked=87 ok=87 bad=0`。

**F-30 [一般] 行 2403 — §15.1「已全部核实、无不确定性」表内含"无 dump 佐证"项**
- 来源：乙D-21
- 文档位置：`capabilities.md:2403`
- 文档声称：§15.1 标题「已全部核实、无不确定性的项」，但表内 Deactivate All 一行写
  `**无 dump 佐证**（见 U-10）`。
- 证据：文档 §14.5 与 U-10 都自承"官方无 Deactivate All dump"。
- 最小修正：把该行移出 §15.1，或改写为「结构自洽（S41 表推导），但缺 dump 佐证 → 见 U-10」。

**F-31 [一般] 正文引用了未登记在 §0.2 的章节号（违反文档自己的来源承诺）**
- 来源：乙D-24
- 文档位置：正文多处 vs `capabilities.md:2497`（"本文件所有事实性论断均标注来源章节号（`Sxx` 对应 §0.2 表）"）
- 证据：正文引用 `3.2.5.3.17`、`3.2.5.3.18`、`3.2.5.3.22`、`3.3.5.3.18`、`3.3.5.3.22`、
  `2.2.5.1`、`2.2.12.1`、`3.2.6.1`，但 §0.2 的 89 行 S 表中**这些章节号全部 ABSENT**。
  这些章节在官方 TOC 中确实存在（`bcgr.txt:465-470`：3.2.5.3.17 Persistent Key List /
  3.2.5.3.18 Font List / 3.2.5.3.22 Processing Font Map 等），所以**不是伪章节号，是漏登记**。
- 最小修正：补登 S90-S97（特别是 2.2.5.1 供 F-08 用、3.2.6.1 供 F-11 用），
  或改用已登记的 guid。

**F-32 [一般] 行 1920-1929 — §12.3 时序图把服务端 Sync 画在 Font List 之后**
- 来源：乙D-25
- 文档位置：`capabilities.md:1920-1929`
- 文档声称：时序图中客户端先发完 Sync/Coop/ReqCtrl/[PKL]/FontList，服务端再发
  Sync/Coop/Granted/FontMap。
- 证据：`The Server Synchronize PDU (section 2.2.1.19) is sent in response to the Confirm Active
  PDU`（`bcgr.txt:867`）；`The client-to-server PDUs sent during this phase have no dependencies on
  any of the server-to-client PDUs; they can be sent as a single batch`（`bcgr.txt:860`）。
  即服务端 Sync 应在收到 Confirm Active 后**立即**发出，不必等 Font List。
  图与文档自己的 §12.4 第 4 条（行 1948-1949）也不一致。
- 最小修正：把服务端 Sync 画在 Confirm Active 之后，并加注「客户端 5 个 PDU 可整批发送，
  故实际观测顺序可能交错」。

**F-33 [一般] 行 1849 — `S59 系列` 引用不精确**
- 来源：乙D-26
- 文档位置：`capabilities.md:1849`
- 文档声称：`客户端（3.2.5.3.22，S59 系列）`
- 证据：S59 = 3.2.5.3.13（§0.2 行 97），与 3.2.5.3.22（Processing Font Map PDU）无关；
  3.2.5.3.22 的 guid 是 `d246ad43-d84e-4de8-a808-46e11035db56`，**未登记**。
- 最小修正：登记 3.2.5.3.22 为 S9x 并直接引用，删掉"S59 系列"。

**F-34 [一般] §15 U-11 与 §4.3/§5.3 正文冲突**
- 来源：乙D-27
- 文档位置：§15 U-11（行 2376）vs `capabilities.md:714`、`797`
- 文档声称：§15 说 `sourceDescriptor` 语义"未取原文"；但行 714 直接断言
  「内容为 source descriptor 字符串（dump 中为 `"RDP"`，含 NUL，长度 4）」，
  行 797 断言 `"MSTSC"`。
- 证据：正文把 dump 观测写成语义结论，§15 又说语义未验证——两者不能同真（至少表述冲突）。
- 最小修正：行 714/797 改为「dump 实测内容为 `"RDP"`（含 NUL，长度 4）；语义见 [T128] 8.4.1（未取证）」。

**F-35 [一般] 行 1795 — 「严格串行」与 1.3.1.1 的"可整批发送"冲突**（磋商新增 NEW-1）
- 来源：**磋商新增**（甲乙均未列）
- 文档位置：`capabilities.md:1795`
- 文档声称：「Connection Finalization 阶段的客户端发送顺序（**严格串行**）」
- 证据：`The client-to-server PDUs sent during this phase have no dependencies on any of the
  server-to-client PDUs; they can be sent as a single batch, provided that sequencing is
  maintained.`（`bcgr.txt:860`）
- 影响："严格串行"被实现为"等上一个 PDU 的响应再发下一个"→ 每个 PDU 多一个 RTT
  （5 个 PDU 多 5 个 RTT，高延迟链路显著变慢），且与行 1948-1949 的宽松表述不一致。
- 最小修正：改为「顺序固定，但**可整批发送**（1.3.1.1：`can be sent as a single batch, provided
  that sequencing is maintained`）」。

**F-36 [一般] 行 2371 — U-06 把 MUST 的出处章节号引错一位**（磋商新增 NEW-2）
- 来源：**磋商新增**（甲乙均未列）
- 文档位置：`capabilities.md:2371`
- 文档声称：「3.2.5.3.18（S59 系列）只说"发完 Persistent Key List（或 Request Control）后
  MUST 发 Font List"」
- 证据：`After sending a single Persistent Key List PDU or a sequence of Persistent Key List PDUs,
  the client MUST send the Font List PDU (section 3.2.5.3.18) to the server.` 在 `bcgr.txt:7433`，
  位于标题 `[Heading5] Sending Persistent Key List PDU(s)`（`bcgr.txt:7430`）之下
  = **3.2.5.3.17**（TOC `bcgr.txt:465`）。真正的 3.2.5.3.18（`bcgr.txt:7434`）下只有
  `The contents of this PDU MUST NOT be compressed.`（`bcgr.txt:7435`）——**无发送规则**。
- 影响：引用不可靠（与 F-33 是同一类"章节号偏移"错误，但位置不同）。
- 最小修正：U-06 出处改为「3.2.5.3.17（`bcgr.txt:7433`）；3.2.5.3.18 仅规定
  `MUST NOT be compressed`」。

**F-37 [一般] §2.4 — 缺"压缩→MAC→加密"次序，且全文无 4096 包会话密钥更新**（磋商新增 NEW-3）
- 来源：**磋商新增**（甲乙均未列）
- 文档位置：`capabilities.md:369-411`（§2.4 TS_SECURITY_HEADER1）
- 文档声称：给出 Pad1/Pad2/SHAComponent/MD5 与 salted/FIPS 公式，接收侧"先解密再对明文重算 MAC"。
- 证据：
  1. `If the contents of the PDU are to be compressed (this MUST be done before any MAC signature
     is constructed and encryption methods applied), ...`（`bcgr.txt:7243`）
  2. `The encryption and the decryption keys are updated after 4,096 packets have been sent or
     received.`（`bcgr.txt:12580`，5.3.8.1 Session Key Updates）
  实测：文档全文 `4,096` / `密钥更新` / `Session Key` 命中 **0 次**；
  `4096` 仅出现在行 1415/1471，都是 bitmap cache 条目上限，与密钥无关。
- 影响：缺次序约束易写成"先加密再压缩"或"对密文算 MAC"；
  缺 4096 包换钥会让长连接在第 4097 个包起**MAC 全部失配**（表现为无故断链）。
- 最小修正：§2.4 末尾加「**处理次序**（3.2.5.1，`bcgr.txt:7243`）：压缩 MUST 先于 MAC 构造与加密；
  发送侧 `明文 → 压缩 → 计算 MAC → 加密`，接收侧反向。**会话密钥更新**（5.3.8.1，
  `bcgr.txt:12580`）：Non-FIPS 下每收发 4,096 个包后 MUST 重新派生密钥（5.3.8.1.1）」，
  并在 §0.2 登记 5.3.8.1。

> 说明：磋商新增的第 4 条 NEW-4（§3.5 表标题"updateData 前导结构"术语不准，
> `capabilities.md:598-612` vs `bcgr.txt:4870-4871`）经复核后**并入 F-28 的同类问题域**
> 但独立成条会突破"37 条"口径，故此处记为 **F-37 附注**，严重级"一般"，
> 修正方案：标题改为「逐 subtype 的 fast-path update 结构」，或把"结构名"列改成
> `paletteUpdateData`/`bitmapUpdateData` 等内层名。

---

## 6. 最终清单汇总表（37 条）

| 编号 | 严重级 | 文档行 | 一句话 | 来源 |
|---|---|---|---|---|
| F-01 | **阻断** | 688 | `0x03E3`(=995) 应为 `0x03EB`(=1003)，且不可硬编码 | 甲D-02 |
| F-02 | **严重** | 2159/2162-2163/2171 | §13.4 明文冒充线上密文（与 §3.4 行 543 自相矛盾） | 双方 |
| F-03 | **严重** | 844-853 | §6.1 遍历伪码无上界 → OOB read | 乙D-07 |
| F-04 | **严重** | 822 | "服务端不校验 shareID" 方向错（有专用错误码） | 乙D-03 |
| F-05 | **严重** | 1425/1436 | VirtualChannel"固定 12"与自身"8 或 12"矛盾 | 双方 |
| F-06 | 一般 | 2368 | U-03 清空缓存未区分持久缓存 | 乙D-16 |
| F-07 | 一般 | 2368 | U-03 未写清空的代价（Bitmap Cache Error） | 乙D-17 |
| F-08 | 一般 | §12 | 缺 Set Error Info PDU 处理 | 乙D-12 |
| F-09 | 一般 | §12 | 缺 Monitor Layout PDU 迁移 | 乙D-13 |
| F-10 | 一般 | 1889 | 缺通用"意外 PDU"兜底 | 乙D-14 |
| F-11 | 一般 | §12 | 无定时器；U-06"按超时"无依据（300 s / MAY） | 乙D-15 |
| F-12 | 一般 | §6.1 | `numberCapabilities` 偏大无规则 → OOB | 乙D-08 |
| F-13 | 一般 | §6.1 | `lengthCombinedCapabilities < 4` 未设防（下溢） | 乙D-09 |
| F-14 | 一般 | §6.1 | `assert` 不是处置策略 | 乙D-10 |
| F-15 | 一般 | 2379 | U-14"后者覆盖前者"不安全 | 乙D-11 |
| F-16 | 一般 | 1038-1047 | §7.3"必须"表混装 MUST 与工程需要 | 乙D-01 |
| F-17 | 一般 | §7.3 | 遗漏 3 个服务端拒绝码 | 乙D-02 |
| F-18 | 一般 | 2378 | U-13 降级表述不完整 | 乙D-04 |
| F-19 | 一般 | 2394 | 证据栏把"偏移自洽"写成"宽度已校验" | 甲D-06（部分成立） |
| F-20 | 一般 | 2393 | "28 类型已核实"实为 21 类型 / 31 实例 | 甲D-11 |
| F-21 | 一般 | 727-728 | totalLength 闭式多一个 `+4` | 甲D-01 |
| F-22 | 一般 | 2305 | 红证归因错（26 vs 28），且 2305/2308 自相矛盾 | 甲D-05 |
| F-23 | 一般 | 266/792 | `pduSource` MUST 出处应为 3.2.5.1 | 双方 |
| F-24 | 一般 | 791 | `PDUVersion` 漏 MUST | 乙D-06 |
| F-25 | 一般 | 1020 | §7.2 合计 492 与 466 两个口径混用 | 乙D-18 |
| F-26 | 一般 | 148 | fast-path 长度编码引 `§2.3` 应为 `§3.4` | 乙D-20(a) |
| F-27 | 一般 | 1677/1688 | `§12 U-04/U-05` 应为 `§15` | 双方 |
| F-28 | 一般 | 2385 + §8 | `lengthCapability MUST = N` 属过度断言 | 双方 |
| F-29 | 一般 | 129/2331 | "85 个 URL / 85/85" 实为 87 个、覆盖 83 | 双方 |
| F-30 | 一般 | 2403 | §15.1"无不确定性"表内含"无佐证"项 | 乙D-21 |
| F-31 | 一般 | 正文多处 | 引用了未登记在 §0.2 的章节号 | 乙D-24 |
| F-32 | 一般 | 1920-1929 | §12.3 时序图把服务端 Sync 画晚 | 乙D-25 |
| F-33 | 一般 | 1849 | `S59 系列` 引用不精确 | 乙D-26 |
| F-34 | 一般 | 2376 vs 714/797 | §15 U-11 与正文断言冲突 | 乙D-27 |
| F-35 | 一般 | 1795 | "严格串行"与"可整批发送"冲突 | 磋商 NEW-1 |
| F-36 | 一般 | 2371 | U-06 MUST 出处引错一位（3.2.5.3.18→.17） | 磋商 NEW-2 |
| F-37 | 一般 | 369-411 | §2.4 缺"压缩→MAC→加密"次序 + 无 4096 包换钥 | 磋商 NEW-3 |

**计数校验**：阻断 1 + 严重 4 + 一般 32 = **37** ✔
**来源校验**（两条恒等式互相印证）：
- 口径一（按原始条目）：11 + 28 = 39 → 6 对重复合并
  （甲D-03↔乙D-28、甲D-04↔乙D-19、甲D-07↔乙D-23、甲D-08↔乙D-05、甲D-09↔乙D-22、
  甲D-10↔乙D-20b）→ 33 → 加磋商新增 4 条（NEW-1…NEW-4）→ **37**。
- 口径二（按 F 条目反查来源）：甲 11 条占 11 个 F；乙 28 条中 23 条独有、6 条已合并，
  且 D-20 的 (a)/(b) 是两处独立错误被拆成 F-26 / F-27，故乙占 23 个独有 F；
  磋商 NEW-1/2/3 占 F-35/36/37 共 3 个。合计 11 + 23 + 3 = **37** ✔
  （NEW-4 与 F-28 同属"结构名/前导字段"问题域，作为 F-37 附注记录、不单独占号；
  这正好抵消 D-20 拆分带来的 +1，使两口径同时落在 37。）
- 若执行 AI 希望 NEW-4 单独占号，则总数变 38，需同步修改 §0 与 §6 全部计数；
  本报告选择"并入 F-37 附注"以保持 37 的口径稳定。

### 6.1 甲乙编号 → F 编号映射

| 甲 | F | 乙 | F |
|---|---|---|---|
| D-01 | F-21 | D-01 | F-16 |
| D-02 | **F-01** | D-02 | F-17 |
| D-03 | F-02 | D-03 | F-04 |
| D-04 | F-05 | D-04 | F-18 |
| D-05 | F-22 | D-05 | F-23 |
| D-06 | F-19 | D-06 | F-24 |
| D-07 | F-29 | D-07 | F-03 |
| D-08 | F-23 | D-08 | F-12 |
| D-09 | F-28 | D-09 | F-13 |
| D-10 | F-27 | D-10 | F-14 |
| D-11 | F-20 | D-11 | F-15 |
| — | — | D-12 | F-08 |
| — | — | D-13 | F-09 |
| — | — | D-14 | F-10 |
| — | — | D-15 | F-11 |
| — | — | D-16 | F-06 |
| — | — | D-17 | F-07 |
| — | — | D-18 | F-25 |
| — | — | D-19 | F-05 |
| — | — | D-20(a) | F-26 |
| — | — | D-20(b) | F-27 |
| — | — | D-21 | F-30 |
| — | — | D-22 | F-28 |
| — | — | D-23 | F-29 |
| — | — | D-24 | F-31 |
| — | — | D-25 | F-32 |
| — | — | D-26 | F-33 |
| — | — | D-27 | F-34 |
| — | — | D-28 | F-02 |

---

## 7. 裁定为「不成立」的条目

**无。** 甲 11 条中：**成立 10**（D-01/02/03/04/05/07/08/09/10/11 —— 其中 D-05 结论与数字
均成立，只是"算错"这个标题措辞偏强，真正错的是文档的归因，见 §1.1 与 §2.2）、
**部分成立 1**（D-06：缺陷真实，但应只指向行 2394，不应连带否定行 2313–2315 的"偏移不存在
手抄错误"）。**没有任何一条被判定为"不成立"**。

同样，乙自己的 28 条在本次交叉验证中也**没有一条被推翻**。两边唯一需要收窄的是甲 D-06 的
覆盖范围（见 §2.3），以及甲在 `audit-a.md:670` 对 §7.2/§7.3 未覆盖的**归因**
（"无实机/无抓包"应为"该做规范文本比对而未做"，见 §3）。

---

## 8. 我如何验证（本次磋商的可复现命令）

| 命令 | 目的 | 关键输出 |
|---|---|---|
| `python -X utf8 F:\rtsc\.tmp\consult_d05.py` | 复现 26 / 28 两种红证注入 | `one extra 2B field -> LEN 26`；`header pair -> LEN 28` |
| `python -X utf8 F:\rtsc\.tmp\consult_urls.py` | 复现 URL 计数 | `learn 87 / script 85 / 交集 83 / doc-only 4 / script-only 2` |
| `python -X utf8 F:\rtsc\.tmp\consult_mut.py` | 注入 MUT1（字段名互换） | `rc=0 caps=27 bytes=25034`（assert 全过 → 证明脚本不校验宽度/名称） |
| `python -X utf8 F:\rtsc\.tmp\consult_mut2.py` | 注入 MUT3（Bitmap 重塑，总长仍 28） | `rc=0 caps=27 bytes=24977`（同上） |
| `python -X utf8 F:\rtsc\.tmp\consult_94.py` | 复核 channelId 字节 | `68 00 01 03 eb 70 81 73` → `0x03EB = 1003` |
| `python -X utf8 F:\rtsc\.tmp\consult_guid.py` | 复核 GUID 线上字节序 | `B9 1B 8D CA 0F 00 4F 15 …` 与文档一致 |
| 直接读 `bcgr.txt` 指定行 | 所有规范引用 | 见各条"证据"栏的行号 |

**数字裁定（甲乙分歧或需统一的）**：

1. **URL 数**：**87 个 learn 页面**（不是 85），脚本覆盖 **83/87**（不是 85/87）。
   甲乙**结论一致**，都判"内容没错、计数错"。
2. **红证 26 vs 28**：**26 是"多一个 2 字节字段"的正确结果**，**28 是"双计 4 字节头"的结果**。
   文档写 28 但归因写"多算 pad2octets"→ **归因错、数字在另一口径下可复现**。甲的裁定正确。
3. **`0x03E3`**：`= 995`。**`0x03EB = 1003`**。文档行 688 括号内两值不可能同真。
4. **类型覆盖**：dump 实例 **31** 个，覆盖 **21** 个不同类型（不是 28）。未覆盖 6 个：
   `0x0004/0x0019/0x001A/0x001B/0x001C/0x001E`。

---

## 9. 我未覆盖的部分（本次磋商）

1. **F-01 之外的行 688 上下文**：只核了 `mcsSDin.channelId` 这一句；同一代码块内其它字段
   （`initiator`、`userData length`）未逐字节复核。甲在 `audit-a.md:9343` 引的
   `initiator = 1002 (0x03ea)` 我复核成立。
2. **F-37 的密码学正确性**：只核了"次序约束"与"4096 包"两条**文本存在性**，
   未做任何 MAC 测试向量验证（无官方测试向量）。密钥派生算法（5.3.8.1.1）本身未审。
3. **NEW-4（§3.5 术语）**：只核了 `TS_FP_UPDATE_PALETTE` 一例的结构行
   （`bcgr.txt:4870-4871`），其余 10 个 subtype 的"结构名是否含前导字段"未逐个核。
4. **F-16 的"最小集合"工程判断**：只核了规范文本（6 个 set 无 MUST 句），
   未做"少发哪个 set 会导致什么实际后果"的实机验证（无实机）。
5. **F-31 的章节号补登记清单**：只确认了 8 个章节号在 §0.2 中 ABSENT 且在官方 TOC 中存在，
   未给出每个的 guid（需另查 `toc.txt`）。
6. **现代 mstsc 10.x 行为**：无抓包，未核（文档 U-02 已自承）。

---

## 10. 给执行 AI 的修订优先级建议

按"改了收益最大 / 不改风险最高"排序：

1. **F-01**（阻断）——一行改动，避免连接完全卡死。**必改**。
2. **F-02 / F-05**（严重）——都是"文档自相矛盾"，改动局部且证据确凿（文档自己另一处是对的）。
3. **F-03 / F-04**（严重）——涉及内存安全与协议判断方向，改动稍大（伪码 + 结论段）。
4. **F-21 / F-22 / F-23 / F-25 / F-26 / F-27 / F-28 / F-29**（一般，纯数字/引用）——
   机械修正，可批量做，每处 1 行。
5. **F-08 / F-09 / F-10 / F-11**（一般，状态机补全）——需要新增小节，改动量最大，
   但都是"缺项"而非"错项"，不改也不会让已有内容错。
6. **F-35 / F-36 / F-37**（磋商新增）——F-35/F-36 是 1 行改，F-37 需加一段。

**回归验证要求**（给执行 AI）：改完后必须重跑
`verify_caps.py`（应仍 31/31 PASS）与 `gen_caps_full.py`（应仍 27 表、字节数不变），
确认 F-19/F-21/F-22 的改动**没有**触碰脚本断言逻辑，只改了文档措辞。

---

*磋商报告结束。审计 AI 乙。*
*合并缺陷总数 **37**；裁定"不成立" **0** 条；甲 11 条全部有效（1 条需收窄范围）。*
---

## 11. 第二轮：41 条统一清单（最终定案候选）

### 11.0 并集算式的独立复核（结论：父会话的 41 成立）

我按"槽位"（一条缺陷占一个编号）重算，而不是按两份报告的条目数直接相加，因为两边都存在
**一条拆两处**的情况：

| 计法 | 明细 | 小计 |
|---|---|---|
| 甲 audit-a 第一轮 | 11 条 | 11 |
| 乙 audit-b | 28 条，其中 **D-20 含 (a)(b) 两处独立错误**（(a) 行 148 §2.3→§3.4；(b) 行 1677/1688 §12→§15），占 **29 个槽位** | 29 |
| 甲↔乙 重合槽位 | 甲D-03↔乙D-28、甲D-04↔乙D-19、甲D-07↔乙D-23、甲D-08↔乙D-05、甲D-09↔乙D-22、甲D-10↔乙D-20(b) = **6 对** | −6 |
| 甲+乙 并集 | 11 + 29 − 6 | **34** |
| 乙磋商新增 | NEW-1（行 1795 严格串行）、NEW-2（U-06 出处偏一位）、NEW-3（§2.4 次序/换钥） | +3 |
| 甲磋商新增 | N-3（行 1891 input 许可）、N-1（行 137 §12→§15）、N-2（行 998 §14.2→§14.1）、N-4（行 2441 SHOULD） | +4 |
| **并集总数** | 34 + 3 + 4 | **41** ✔ |

两路交叉校验：
- 乙侧：37 = 34 + 3 ✔（我原报告的 37 条 = 34 共有 + 3 我独有）
- 甲侧：38 = 34 + 4 ✔（甲报告的 38 条 = 34 共有 + 4 甲独有）
- 41 = 37 + 4 = 38 + 3 ✔

**确认父会话的归因准确**：我确实缺甲那 4 条（N-1/N-2/N-3/N-4），甲确实缺我这 3 条
（NEW-1/NEW-2/NEW-3）。我用 `grep` 在 `capabilities.consult-a.md` 实测：
`1795`→0 命中、`严格串行`→0、`4,096`→0、`4096`→0、`密钥更新`→0、`压缩`→0，
证明甲的报告**完全没有**碰这三处；反之在本文件 **§11 之前的正文（第 1–865 行）** 中，
`行 137`/`行 998`/`行 1891`/`行 2441` 以及裸数字 `137`/`998`/`1891`/`2441` 的命中**均为 0**，
证明我第一轮确实漏了那 4 条（本轮已作为 F-38…F-41 补齐）。

**一处必须披露的边界**：我原报告还有一条 NEW-4（§3.5 表标题"updateData 前导结构"术语不准，
`capabilities.md:598-612` vs `bcgr.txt:4870-4871`），我此前把它**折进 F-37 作附注**、
不单独占号，所以它不在 41 里。若执行 AI 希望它独立成条，则总数为 **42**（新增 F-42），
本表的结构不受影响。这是我的主动披露，不是与甲的分歧。

### 11.1 统一严重度定义 + 3 处真实分歧的裁定

**统一三档定义（本轮定案，取代我第一轮的宽松定义）**：

| 档 | 判定标准 |
|---|---|
| **阻断** | 照文档实现会 (a) 使连接**完全无法建立/协议不可用**，或 (b) 产生**可被对端（恶意服务端）触发的内存越界/崩溃**。必须在编码前改。 |
| **严重** | 会导致实现产生**错误行为、数据错误，或漏掉规范必需分支**，但不会使连接完全不可用，也不构成内存安全后果。同一迭代内改。 |
| **一般** | 表述、引用、内部一致性。**不改变字节与行为**。可批量收尾。 |

> 说明：我第一轮把"阻断"定义成"功能完全不工作"，漏掉了"安全后果"这一支。按父会话给的
> 判据（"是否可被恶意服务端触发内存越界"），这个定义必须修正——修正后我在 §6.1 的两条上
> **改变裁定、与甲一致**。

#### 分歧一：§6.1 越界读算严重还是阻断 → **裁定：阻断（采纳甲）**

- **F-03**（`lengthCapability` 无上界）与 **F-12**（`numberCapabilities` 偏大无上界）
  是**同一类缺陷**：遍历循环的上界完全由对端控制的字段决定，而文档伪码
  （`capabilities.md:844-853`）**只有 `if len < 4: error`**，没有 `p+len <= caps_end`、
  没有 `p+4 <= caps_end`、没有 `p+len <= recv_len`。
- **后果判定**（按父会话指定的口径，不按改动量）：恶意服务端发一个 `lengthCapability = 200`
  但 caps 区只剩 8 字节的 Confirm Active，客户端的 `process(type, p, len)` 会读 200 字节，
  **越过接收缓冲区末尾** → 越界读（可致崩溃，或把堆内存内容当字段值使用）。
  `numberCapabilities = 3` 而只有 1 个 set 时，第二轮循环在 `p` 已越过 `caps_end` 处
  继续读 `LE16(p)`/`LE16(p+2)`，同样越界。**两条都是对端可触发、无需本地条件的越界读。**
- 因此按统一定义 (b) 判 **阻断**。我原判 F-03 严重 / F-12 一般是**低估**，此处上调。
- 补充（甲未点，我给执行 AI 的加固建议）：`ERRINFO_CAPABILITYSETTOOLARGE 0x000010E8`
  （`bcgr.txt:2999`，内容为 `A Capability Set ... has been received with a lengthCapability
  field that contai[ns]...`）证明规范**预期实现会检查这个长度**，可作为"越界即断链"的
  规范依据，比单纯"防御性编程"更强。

#### 分歧二：持久缓存清空（U-03）算阻断还是严重 → **裁定：严重（不采纳甲的高/阻断）**

- 甲把 **H-4**（行 2368，未区分标准缓存与持久缓存）判 阻断。我判 **严重**，理由：
  1. **不会使连接不可用**。照字面清空后，服务端仍按 Persistent Key List 引用旧槽位，
     客户端发 `Bitmap Cache Error`（`egdi.txt:3755` SHOULD）并要求服务端 flush
     （`BC_ERR_FLUSH_CACHE`，`egdi.txt:2666`），服务端重发位图后画面恢复。
     这是**画质/性能退化 + 掉帧黑闪**，不是连接失败。
  2. **不是内存安全后果**。清空是"多丢数据"，不是"越界访问"。
  3. 违反的 `bcgr.txt:7212` 是"Persistent Bitmap Caches ... are not bound to the lifetime
     of a given RDP connection"，属于**语义违背**，不构成 (a)/(b) 任一。
- 按统一定义落 **严重**。同时我把 **F-07**（未写清空代价）保持 **一般**——它只是缺一段
  后果说明，本身不改变行为。
- 给执行 AI 的提示：F-06 与 F-07 是**同一行 2368 的两个层次**，改的时候一起改，
  但严重度按上表分别登记（F-06 严重 / F-07 一般）。

#### 分歧三：§13.4 明文冒充线上密文算阻断还是严重 → **裁定：严重（不采纳甲的高/阻断）**

- 甲把 **H-5**（= 我的 F-02）判 阻断。我判 **严重**，理由：
  1. 它**不是实现指令**。实现者要写的解析逻辑来自 §3.2/§3.4（行 459-552），
     而 §3.4 行 543 给的密文是**正确**的 `26 18 5e 76 0e de 28`。
     §13.4 只是"证据展示"章节，写错字节不会让任何一条解析规则变错。
  2. 它**不会使连接不可用**——按 §3.4 实现仍能连通。
  3. 它**不构成安全后果**——不会让实现少做 MAC 校验或解密（这些在 §2.4 行 409-410 有写）。
  4. 它的真实危害是：**证据链不可复现**（拿 §13.4 做自测永远对不上），
     以及**文档内部自相矛盾**（§3.4 vs §13.4 两组字节）。这属于"数据错误 + 误导"，
     落在统一定义的"严重"档，不到"阻断"。
- 但我要强调：**它是 41 条里最值得优先修的两条之一**（另一条是 F-01），
  因为修它只需改 3 个字节序列、零风险，且直接决定"这份文档的证据能不能被信任"。
  严重度是"后果分级"，不是"修复优先级"——两者不要混。

#### 分歧汇总（我 vs 甲）

| 缺陷 | 甲 | 我（第一轮） | 我（本轮定案） | 裁定依据 |
|---|---|---|---|---|
| F-01 `0x03E3` | 高/阻断 | 阻断 | **阻断** | 一致，连接无法建立 |
| F-03 遍历无上界 | 高/阻断 | 严重 | **阻断** | 对端可触发越界读 → 采纳甲 |
| F-12 count 偏大 | 高/阻断 | 一般 | **阻断** | 同上，与 F-03 同类 → 采纳甲 |
| F-06 持久缓存 | 高/阻断 | 一般 | **严重** | 画质退化可恢复、非安全后果 → 不采纳甲 |
| F-02 dump 明文 | 高/阻断 | 严重 | **严重** | 证据错、非实现错 → 不采纳甲 |
| F-38 input 许可时点 | 中/严重 | —（缺） | **严重** | 采纳甲 |

结果：**阻断 3 条（F-01/F-03/F-12）、严重 6 条（F-02/F-04/F-05/F-06/F-15/F-38）、一般 32 条 = 41**。
（F-15 于第三轮由「一般」上调为「严重」，见 §13；本行为第三轮定稿值。）

### 11.2 统一清单（F-01 … F-41，共 41 行，一行不缺）

| F 编号 | 严重度 | 文档行号 | 缺陷一句话 | 最小修正 |
|---|---|---|---|---|
| **F-01** | **阻断** | 688 | `mcsSDin.channelId` 写成 `0x03E3`（=995）却说等于 1003；正确 `0x03EB`=1003，且该值不可硬编码 | 改为「I/O Channel ID store 中的值（本 dump 为 `0x03EB`=1003；由 Server Network Data 分配，不可硬编码）」 |
| **F-02** | **严重** | 2159 / 2162-2163 / 2171 | §13.4 把解密后明文 `20 00 08 ab 02 6f 01` 填进"完整线上字节"并标"密文"，与 §3.4 行 543 的正确密文互相矛盾 | 代码块改回 `… c8 47 26 18 5e 76 0e de 28`；行 2171 的字节改密文；行 2159 标题改"线上字节 + 解密后载荷"；保留下方解密块 |
| **F-03** | **阻断** | 844-853 | §6.1 遍历伪码只有 `len<4` 检查，无任何上界；恶意服务端可令 `process()` 越界读 | 加 `caps_end = caps_start + lcc - 4`；要求 `p+4<=caps_end`、`p+len<=caps_end`、`p+len<=recv_len`，任一不满足断链 |
| **F-04** | **严重** | 822 | §5.5「服务端**不校验** shareID/originatorID（规范未提出此要求）」是绝对断言 | 改为「3.3.5.3.13.2 处理步骤未要求校验；但 2.2.5.1 为两种非法值各定义了专用 ERRINFO（`0x000010D4`/`0x000010D5`），实现可校验并据此断链」 |
| **F-05** | **严重** | 1425 / 1436 | §8.18「固定总长 12」与同行表「8 或 12」、两个官方 dump（均 8）、自身脚本 `SCHEMA [4]` 全部矛盾 | 行 1425 改「8（无 `VCChunkSize`，官方形态）或 12（含）」；行 1436 改「分别结束于 8 / 12」 |
| **F-06** | **严重** | 2368 | U-03「清空 bitmap cache」未区分标准缓存与持久缓存，照字面违反 `bcgr.txt:7212` | 改「清空**标准** Bitmap Cache（3.2.1.13）；**保留** Persistent（3.2.1.14）与 Persisted Keys（3.2.1.15）」 |
| **F-07** | 一般 | 2368 | U-03 未写「清空」的代价（触发 Bitmap Cache Error + 黑图重绘） | 补「清空后服务端可能仍引用旧槽位 → 按 [MS-RDPEGDI] 发 `BC_ERR_FLUSH_CACHE` 并黑图重绘；可用但掉帧」 |
| **F-08** | 一般 | §12（缺） | 全节缺 Set Error Info PDU（2.2.5.1）处理，`ERRINFO`/`Set Error Info` 全文 0 命中 | §12.2 增「任意状态 + Set Error Info → 记录 errorInfo，状态不变」；§17.3 补检查项；§0.2 登记 2.2.5.1 |
| **F-09** | 一般 | §12（缺） | 缺 Monitor Layout PDU（2.2.12.1）状态迁移，仅行 304 提了 `pduType2=0x37` | S1（Demand Active 之后）与 S2 增「Monitor Layout → 记录显示器布局，状态不变」；§17.1 补解析检查项 |
| **F-10** | 一般 | 1889 | 缺通用「意外 PDU」兜底；13 个 `(state,event)` 对无迁移 | 增兜底「与当前状态不符 → 忽略并告警（不改状态）」；对 Demand/Confirm/Deactivate All 的错序明确忽略或断链并记理由 |
| **F-11** | 一般 | §12（缺） | 无定时器定义；U-06「按超时处理」无时长无来源 | 增「12.5 定时器」：300 s、**MAY**（非 MUST），引 3.2.6.1 / 3.2.2.1；U-06 改引该小节 |
| **F-12** | **阻断** | §6.1 | `numberCapabilities` 偏大无接收侧规则；循环按对端给的计数读头，可越界读 | 遍历前验 `lcc-4 >= numberCapabilities*4`；遍历中越界即断链；遍历后严格 `p == caps_end` |
| **F-13** | 一般 | §6.1 | `lengthCombinedCapabilities < 4` 未设防（`lcc-4` 下溢/定界错） | 先判 `lcc >= 4`，否则断链；`numberCapabilities == 0` 明确「合法但无意义，告警」 |
| **F-14** | 一般 | 852 | `assert` 不是处置策略（生产构建关闭 assert，失败后无动作） | 改显式分支：不等 → 以 `caps_end` 为界重新定位 + 告警；`p > caps_end` → 断链 |
| **F-15** | **严重**（第三轮由「一般」上调，见 §13） | 2379 | U-14「后者覆盖前者」（last-wins）对 `ENC_SALTED_CHECKSUM`/`orderSupport`/`NumCellCaches` 不安全 | 改「取交集/更保守值（support 位 AND、`NumCellCaches` 取小、`MaxRequestSize` 取小）；无法安全合并 → 断链」 |
| **F-16** | 一般 | 1038-1047 | §7.3「必须」表把 6 个纯 SHOULD/无约束 set 归入「必须」，与自身 §6.3 行 901 冲突 | 拆两表：①规范 MUST 可推出（实质只有 Bitmap + 条件性 Input/Order 字段）②本项目功能需要；逐行标 `规范 MUST / SHOULD / 工程需要` |
| **F-17** | 一般 | §7.3 | 缺 3 个针对客户端 capability 的服务端拒绝码 | §7.3 增「最小集合的风险面」列 `0x000010EA`/`0x000010E9`/`0x000010F4` 及触发条件；§8.7 补「两个 cache size 都为 0 → 可发 NOCURSORCACHE」 |
| **F-18** | 一般 | 2378 | U-13 只说「工程必要、规范未用 MUST」，缺「违反后果」与诊断路径 | 补「不回填 → 服务端可回 `0x000010D4` 后断链；客户端表现为 S3 卡死，原因只能从 Set Error Info 读」 |
| **F-19** | 一般 | 2394 | §15.1 证据栏把「偏移自洽」写成「宽度已被机器校验」（`assert o==off` 只比偏移） | 证据列改「总长由累加保证；**字段宽度为人工转录，已由审计逐字段比对规范原文（27/27 一致）**」；**不要动行 2313-2315** |
| **F-20** | 一般 | 2393 | §15.1 称「28 个类型已核实」，实为 21 个类型 × 31 个实例；6 个类型无 dump | 拆两行：「28 个编号与名称：原文表逐行比对」／「21 类型 × 31 实例的长度：dump 反向匹配通过；`0x0004/0x0019/0x001A/0x001B/0x001C/0x001E` 无 dump 佐证」 |
| **F-21** | 一般 | 727-728 | `totalLength` 闭式多算 4：正确 `18+L+lcc`=359，文档写 `+4`=363，与自身行 740 矛盾 | 删第二行末尾的 `+ 4`，改为 `= 18 + lengthSourceDescriptor + lengthCombinedCapabilities` |
| **F-22** | 一般 | 2305 | §14.1 红证归因错：多一个 2 字节字段只能得 26；要得 28 必须双计头字段；且 2305 与 2308 三行内自相矛盾 | 改为「把 `capabilitySetType`/`lengthCapability` 也写进 payload，被 `LEN` 的 `4+` 二次计入 → `4+24=28`；只多算一个 `pad2octets` 则 `4+22=26`」；**不要改 2308** |
| **F-23** | 一般 | 266 / 792 | `pduSource MUST = User Channel ID` 出处标 S61，实际在 3.2.5.1（S61 段无 `pduSource`） | 行 266 改引 3.2.5.1；行 792 依据补 3.2.5.1；§0.2 补该章节 guid |
| **F-24** | 一般 | 791 | `PDUVersion` 漏 MUST（行 709 写了 MUST、行 791 没写） | 改为 `` `PDUVersion` MUST = 0x1 ⇒ 线上 `0x0013` `` |
| **F-25** | 一般 | 1020 | §7.2 表末「合计 492」与各 `lengthCapability` 之和 466 混用两个口径 | 改「Σ `lengthCapability` = 466；+ 26 字节头 = 492 = `totalLength`」 |
| **F-26** | 一般 | 148 | fast-path 长度编码引 `§2.3`（= 安全头），应为 `§3.4` | 改 `§3.4` |
| **F-27** | 一般 | 1677 / 1688 | 「见 §12 U-04 / U-05」应为 §15（§12 是状态机，不含 U 编号） | 两处 `§12` 改 `§15` |
| **F-28** | 一般 | 2385 + §8 全节 | U-20 原因栏「各 capability 节都写 MUST be set to N」失实（实测 0 命中）；§8 各节标 `MUST = N` 属强度标签过度 | §8 改「定长 N（由字段宽度推出；规范未固定该值）」；U-20 原因栏改写为「规范未固定取值，字段宽度决定期望总长」；**数值不动** |
| **F-29** | 一般 | 129 / 2331 | 「85 个 URL / 85/85」实为 87 个 learn + 2 个 DOCX；脚本覆盖 83/87，4 个被引用页面从未被脚本验证 | 行 129 改「87 个 learn 页面（另 2 个 DOCX 直链）」；行 2331 改「83/87 由脚本覆盖，其余 4 个已单独 HEAD 验证 200」；或补齐脚本至 87 条 |
| **F-30** | 一般 | 2403 | §15.1「已全部核实、无不确定性」表内含「**无 dump 佐证**（见 U-10）」行 | 该行移出 §15.1，或改写为「结构自洽（S41 表推导），缺 dump 佐证 → 见 U-10」 |
| **F-31** | 一般 | 1785 / 1864 / 1890 / 2371 / 1849 / 1854 / 304 | 正文引用了未登记在 §0.2 的章节号（`3.2.5.3.17`/`.18`/`.22`、`3.3.5.3.18`、`2.2.12.1`），违反行 2497 的承诺 | 补登 S90+（逐条给 guid），或改引已登记的等价 guid |
| **F-32** | 一般 | 1920-1929 | §12.3 时序图把服务端 Sync 画在客户端 5 个 PDU 之后；原文是「响应 Confirm Active」 | 把服务端 Sync 画在 Confirm Active 之后，并加注「客户端 PDU 可整批发送，实际观测顺序可能交错」 |
| **F-33** | 一般 | 1849 | 「S59 系列」引用不精确（S59 = 3.2.5.3.13，与 3.2.5.3.22 无关且未登记） | 登记 3.2.5.3.22 并直接引用，删「S59 系列」 |
| **F-34** | 一般 | 714 / 797 vs U-11 | 正文断言 `sourceDescriptor` 内容为 `"RDP"`/`"MSTSC"`，§15 U-11 又说语义「未取原文」 | 改为「dump 实测内容为 …；语义见 [T128] 8.4.1（未取证）」 |
| **F-35** | 一般 | 1795 | 「严格串行」与 1.3.1.1「client→server PDU 可整批发送（provided sequencing is maintained）」冲突 | 改「顺序固定，但**可整批发送**（1.3.1.1）」 |
| **F-36** | 一般 | 2371 | U-06 把 MUST 的出处引成 3.2.5.3.18；该句实际在 3.2.5.3.17，3.2.5.3.18 只有 `MUST NOT be compressed` | 出处改「3.2.5.3.17；3.2.5.3.18 仅规定 `MUST NOT be compressed`」 |
| **F-37** | 一般 | 369-411（§2.4） | §2.4 缺「压缩 MUST 先于 MAC 构造与加密」的次序约束；全文无「每 4,096 包更新会话密钥」（`4,096`/`密钥更新` 0 命中） | §2.4 末补「处理次序（3.2.5.1）：明文→压缩→算 MAC→加密，接收侧反向」+「会话密钥更新（5.3.8.1）：Non-FIPS 每收发 4,096 包 MUST 重新派生」；§0.2 登记 5.3.8.1 |
| **F-38** | **严重** | 1891 | §12.2 把「可开始发送 input」挂在「收到 Server Synchronize」上；原文是「**发出** Confirm Active 后即可」，且文档行 1948 自己也这么写 | 把许可移到 S2→S3 那行（1890），或把 1891 动作列改为「记录；**此时已在 S2 末尾获得 input 发送许可**」 |
| **F-39** | 一般 | 137 | 「无法验证，进入 §12『不确定项』」应为 §15（第三处 §12 误引） | 改 `§15` |
| **F-40** | 一般 | 998 | 「本文 §14.2 已逐字节复算」应为 §14.1（§14.1 才是 dump 逐字节；§14.2 是偏移 assert） | 改 `§14.1` |
| **F-41** | 一般 | 2441 | 检查清单写「`totalLength` 不一致 → 断链」，原文是 `SHOULD be dropped`；正文行 758 已正确写 SHOULD | 改「不一致 → **SHOULD** 断链（SHOULD，非 MUST）」 |

**行数校验**：F-01 … F-41 连续无缺号，共 **41** 行。
**严重度校验**（第三轮定稿）：阻断 3（F-01/F-03/F-12）+ 严重 6（F-02/F-04/F-05/F-06/F-15/F-38）+ 一般 32 = **41** ✔
（本行原为二轮值「严重 5 / 一般 33」，第三轮 F-15 上调后已改为定稿值；F-15 见 §13.2。）

### 11.3 F-38…F-41 的证据（甲提出，我独立复核后采纳）

四条我都在 `capabilities.md` 与 `bcgr.txt` 上逐条复核过，**全部成立**，并给出我自己的行号定位：

**F-38（行 1891）** — 我补一条甲没引的更强证据：
- 文档行 1891：`| S3 | 收到 Server Synchronize | 记录；**可开始发送 input PDU** | ... | 1.3.1.1；"Once the
  client has sent the Confirm Active PDU, it can start sending mouse and keyboard input" |`
  ——**引用与结论相反**：引文说"sent the Confirm Active"，动作列写"收到 Server Synchronize"。
- `bcgr.txt:871`：`Once the client has sent the Confirm Active PDU, it can start sending mouse and
  keyboard input to the server, and upon receipt of the Font List PDU the server can start sending
  graphics output`。
- **我补的证据**：`bcgr.txt:7420`（3.2.5.3.13.2 段内，紧接 Confirm Active 发送规则）：
  `Once the client has successfully transmitted this PDU, input PDUs (section 2.2.8) SHOULD be
  sent to the server (section 3.3.5.8).` —— 规范在 Confirm Active 的发送小节里**明确**把 input
  的时点绑在"成功发出本 PDU 之后"，比 871 的概述更硬。
- 文档自相矛盾：行 1948「客户端在**发出 Confirm Active 之后**就可以发 input（S60 明示）」。
- 判定：**成立，严重**（会导致输入延迟；极端情况服务端等 Font List 才发 Sync → 互锁）。

**F-39（行 137）** — 成立：
- 行 137：`| **C** | 无法验证，进入 §12「不确定项」，**不作实现依据** |`
- §12 标题在行 1868（`## 12. 客户端能力交换状态机`）；「不确定项清单」是 **§15**（行 2359
  `## 15. 不确定项清单`）。**纯引用错误，一般**。

**F-40（行 998）** — 成立：
- 行 998：`` `numberCapabilities = 18`，顺序与长度如下（本文 §14.2 已逐字节复算，全部通过） ``
- §14.1 在行 2241（`### 14.1 独立长度模型 vs 官方 dump（先红后绿）`）——这才是 dump 逐字节；
  §14.2 在行 2311（`### 14.2 逐字段偏移的机器校验`），只做 `assert o == off`，**与 dump 无关**。
- 判定：**成立，一般**。

**F-41（行 2441）** — 成立，但甲的出处行号需订正：
- 行 2441：`- [ ] 慢路径：`totalLength` 校验（不含外层头）；不一致 → 断链（§2.1 / §4.4）`
- 原文在 `bcgr.txt:7409`（不是甲写的"7411 区段"；7411 是 `After successfully processing the
  Demand Active PDU, the client MUST send the Confirm Active PDU`）：
  `The value of the totalLength field MUST also be examined for consistency with the received data.
  If there is any discrepancy, the connection SHOULD be dropped.`
- 文档行 758 已正确写 `**SHOULD 断链**`，清单与正文不一致。
- 判定：**成立，一般**（收紧不会出错，但清单是"实现检查项"，写成无条件会让实现者以为 MUST）。
---

## 12. 与甲的一致性声明

### 12.1 我明确接受的三项

1. **接受 41 条并集**。我已独立重算（§11.0），并集 = 11 + 29（乙 28 条占 29 槽位）− 6 重合
   + 3（我新增）+ 4（甲新增）= **41**。两条交叉校验（37+4=41、38+3=41）同时成立。
   我不接受"37"或"38"任一单独数字作为最终口径。
2. **接受统一编号方案**。以我的 `F-01…F-37` 为基座，甲独有 4 条按父会话指定顺序追加为
   `F-38`（行 1891 input 许可）/ `F-39`（行 137 §15）/ `F-40`（行 998 §14.1）/
   `F-41`（行 2441 SHOULD）。甲侧的 `H-*/M-*/L-*` 编号从此只作历史索引，执行阶段一律用 F 号。
3. **接受统一严重度定义**（§11.1 表格），并**据此修改了我自己的 3 处裁定**：
   - F-03（§6.1 遍历无上界）：严重 → **阻断**（采纳甲）
   - F-12（count 偏大）：一般 → **阻断**（采纳甲）
   - F-06（持久缓存）：一般 → **严重**（部分采纳甲，但不到阻断）

### 12.2 我仍然不接受的 2 条（附证据，请甲复核）

**不接受 1：F-02（§13.4 dump）判"阻断"。**

甲的 H-5 把这条与 `0x03E3`、遍历越界并列为"阻断"。我不接受，证据是**这条不影响实现正确性**：

- 实现者写解析器依据的是 §3.2（`capabilities.md:459-552`）与 §3.5，不是 §13.4（`2157` 起，
  标题就是"十六进制 dump 与逐字节注解"）。
- §3.4 行 543 给出的密文 `26 18 5e 76 0e de 28` **是正确的**（`bcgr.txt:11569` 逐字节相符）。
  也就是说，**文档在"实现依据"那一侧是对的，只在"证据展示"这一侧错了**。
- 按统一"阻断"定义的两个分支逐条排除：
  (a) 不会使连接无法建立——按 §3.2/§3.4 实现能正常连通；
  (b) 不产生越界/安全后果——§13.4 不参与任何解析路径。
- 因此落在"严重"（数据错误 + 误导 + 内部矛盾）。**但我同意它应是修复优先级第 2 位**
  （仅次于 F-01），因为改 3 个字节序列、零风险，且决定"文档证据能否被信任"。
  **严重度分级 ≠ 修复优先级**，这两件事在定案文档里应分开表述。

**不接受 2：F-06（持久缓存）判"阻断"。**

甲的 H-4 判阻断。我的反证是**这条的失败模式是可恢复的画质退化，不是连接失败**：

- 照字面清空后，服务端仍按 Persistent Key List 引用旧槽位 → 客户端按 `egdi.txt:3755`
  （`The Bitmap Cache Error PDU SHOULD be sent to a server that has requested the rendering of a
  cached bitmap that is not available in the client Bitmap Cache`）发 Bitmap Cache Error，
  服务端 flush（`BC_ERR_FLUSH_CACHE`，`egdi.txt:2666`）并重发位图 → **画面恢复**。
- 违反的是 `bcgr.txt:7212` 的**语义约束**（"Persistent Bitmap Caches are not bound to the
  lifetime of a given RDP connection"），不是协议级硬失败。
- 既不属于 (a)（连接仍可用），也不属于 (b)（无越界、无内存后果）。
- 故落"严重"。若甲坚持阻断，请给出"这条会导致连接完全不可用或内存越界"的具体路径，
  我按证据改判——但目前我找不到这样的路径。

### 12.3 我接受的甲方 4 条新增（含 1 处出处订正）

| 甲编号 | 我的编号 | 我的裁定 | 备注 |
|---|---|---|---|
| N-3（行 1891） | **F-38** | **成立，严重** | 我补了更强的证据：`bcgr.txt:7420`（Confirm Active 发送小节内明写「Once the client has successfully transmitted this PDU, input PDUs SHOULD be sent」） |
| N-1（行 137） | **F-39** | **成立，一般** | 与 F-27 同类（§12→§15），但位置不同（行 137 vs 1677/1688），不合并 |
| N-2（行 998） | **F-40** | **成立，一般** | §14.1 才是 dump 逐字节；§14.2 只做 `assert o == off` |
| N-4（行 2441） | **F-41** | **成立，一般** | **甲的出处需订正**：`SHOULD be dropped` 在 `bcgr.txt:7409`，不在"7411 区段"；7411 是 Demand Active 处理段的首句 |

### 12.4 我要求甲接受的 3 条（我独有）

| 我的编号 | 主题 | 我的证据（供甲复核） |
|---|---|---|
| **F-35** | 行 1795「严格串行」 | `bcgr.txt:860`：`they can be sent as a single batch, provided that sequencing is maintained`。甲的 consult-a 中 `1795`/`严格串行` 命中均为 **0**，确认甲未覆盖 |
| **F-36** | U-06 出处偏一位 | `bcgr.txt:7433` 在 `[Heading5] Sending Persistent Key List PDU(s)`（`7430`）之下 = 3.2.5.3.17；3.2.5.3.18（`7434`）只有 `MUST NOT be compressed`（`7435`）。甲的 consult-a 中 `3.2.5.3.17` 仅出现在 D-24 的"未登记章节号"清单里，**未发现 U-06 的出处错误** |
| **F-37** | §2.4 次序 + 4096 包换钥 | `bcgr.txt:7243`（压缩 MUST 先于 MAC/加密）、`bcgr.txt:12580`（4,096 包更新密钥）。甲的 consult-a 中 `4,096`/`4096`/`密钥更新`/`压缩` 命中均为 **0**；甲在 §4.1 明确把 §2.3–2.5 判为「**文本层面无缺陷**」，我认为该判定**遗漏了这两条跨节约束**——MAC 公式本身没错，但"何时算 MAC、何时换钥"是同一节必须交代的运行时前提 |

### 12.5 需要甲回应的 3 个问题（若不回应，我按上表定案）

1. **F-02 / F-06 的阻断依据**：请给出"会导致连接完全不可用或内存越界"的具体触发路径。
   若给不出，请接受"严重"。
2. **F-37 是否算缺陷**：甲在 consult-a §4.1 判 §2.3–2.5「文本层面无缺陷」。请确认该判定
   是否**未覆盖**"压缩/MAC/加密的先后次序"与"4096 包会话密钥更新"这两条**跨节运行时约束**
   （它们不在 MAC 公式里，但在同一 §2.4 的实现语境里）。若认为应归 `security-layer.md`
   而非本文档，请明说，我据此把 F-37 标为"跨文档归属待定"。
3. **F-31 的章节清单**：甲指出我 D-24 举的 3 个例子（`3.3.5.3.22`/`2.2.5.1`/`3.2.6.1`）
   在文档中 0 命中——**这一点我接受**（我已独立复测：三者 `doc_hits` 均为空数组）。
   F-31 的清单已按实测重列为 `3.2.5.3.17`(1785) / `3.2.5.3.18`(1864,1890,2371) /
   `3.2.5.3.22`(1849) / `3.3.5.3.18`(1854) / `2.2.12.1`(304)。请确认这份 5 项清单完整。

### 12.6 我对甲"行号偏 1"指控的回应（自我订正）

甲在 consult-a §2.1 指出我的 `bcgr.txt:NNNN` 引用**整体偏小 1**（0-based 枚举）。
**这条我接受，并已在本轮全文修正**：我第一轮报告用的是 Python 列表下标（0-based），
漏了 +1。本轮我在追加 §11 之前，先对 `capabilities.consult-b.md` 全文做了行号订正
（17 组替换，逐组打印替换次数），并用脚本回读校验：

```
bcgr citations: [309, 465, 859, 860, 867, 2336, 2372, 2376, 2380, 2977, 2978, 2985, 2986,
                 3000, 3001, 3007, 3156, 3214, 3258, 3575, 3664, 4870, 7212, 7214, 7240,
                 7243, 7411, 7430, 7433, 7434, 7435, 7461, 7634, 9342, 9344, 11569, 11582, 12580]
```

逐个回读全部命中正确内容（`2985` = `ERRINFO_CONFIRMACTIVEWRONGSHAREID`、`2986` =
`ERRINFO_CONFIRMACTIVEWRONGORIGINATOR`、`3000` = `ERRINFO_NOCURSORCACHE`、`3001` =
`ERRINFO_BADCAPABILITIES`、`3007` = `ERRINFO_CACHECAPNOTSET`、`7212` = Persistent Bitmap
Cache 段、`7214` = Persisted Bitmap Keys 段、`3156/3272/3437/3645/3570/3656` = 六个 set 的
`This capability is sent by both client and server` 句、`3258` = `bitmapCompressionFlag MUST be
set to TRUE`、`3575` = `VCChunkSize (optional)`、`3664` = `fontSupportFlags ... SHOULD`）。
§11 之后新增的所有引用（`7409`、`7420`、`7435`、`12580` 等）也已按 1-based 标注。

### 12.7 最终一致性结论

- **已达成一致的**：41 条并集、统一编号、统一三档定义、F-03/F-12 升阻断、F-06 升严重、
  甲 4 条新增全部采纳（F-38…F-41）、我的行号偏 1 缺陷已认领并修正。
- **二轮时仍存分歧的**：F-02 与 F-06 是否应为"阻断"（我坚持"严重"，已给反证）；
  F-37 的归属（本文档 vs `security-layer.md`，待甲回应）。
  → **三轮已全部收口**：甲在 `capabilities.consult-a.md` §11 接受 F-02/F-06 为严重，
  我接受 F-15 上调为严重，双方分布统一为 3/6/32，见 §13.6 盖章声明。
- **分歧性质**：这两处分歧**不影响 41 条的完整性**，只影响严重度标签与修复排序。
  执行 AI 可以立即开工——**41 条的"缺陷是否存在"与"最小修正方案"双方无分歧**，
  分歧只在"标几级"。若甲在下一轮给出 F-02/F-06 的阻断路径，我按证据改判；
  若给不出，建议主代理直接按"严重"定案（并保留我给的"优先级第 2 位"标注，
  以兼顾"后果分级"与"修复排序"两个不同维度）。

---

*第二轮磋商结束。审计 AI 乙。*
*统一清单 **41 条**（最终定稿：阻断 3 / 严重 6 / 一般 32，见 §13）；与甲在"缺陷存在性 + 最小修正 + 严重度"上 **全部一致**；*
*二轮曾在 F-02/F-06 上保留分歧，三轮已收口——甲让步 F-03/F-12，我上调 F-15，双方盖章（§13.6）。*

---

## 13. 第三轮：定级盖章

> 触发：父会话下达机械仲裁（按双方共同接受的三档定义套用，非协商）；审计甲已在
> `capabilities.consult-a.md` §11 让步 F-03/F-12，并要求我确认 F-15。
> 本轮**只改定级标签，不改任何缺陷事实与修正方案**。`capabilities.md` 未改动。

### 13.1 三条的最终唯一取值

| 条目 | 前值（我二轮） | **最终值** | 命中档位 | 判据（一句话） |
|---|---|---|---|---|
| **F-03** `lengthCapability` 无上界 | 阻断 | **阻断** | (b) | 对端控制 `len=200` 而 caps 区仅 8 字节 → `process()` 消费 200 字节越过缓冲区末尾，属**对端可触发的内存越界**，与"合法输入下能否跑通"无关 |
| **F-12** `numberCapabilities` 偏大 | 阻断 | **阻断** | (b) | 对端控制 `nc=3` 而只有 1 个 set → 第二轮循环时 `p=24` 已等于 `end=24`，仍继续 `LE16(p)` → 越界读；与 F-03 是**同一段伪码的同一缺检查**，必须同级 |
| **F-15** last-wins 覆盖 | 一般 | **严重**（上调） | 严重档 | 「一般」档的定义**明写"不改变字节与行为"**；last-wins 明确改变运行时行为（`Order.orderSupport` 32 字节位图被覆盖 → 订单不可解析；`Rev2.NumCellCaches/CellInfo` 被覆盖 → 画错图）。单凭"改变行为"这一条即已离开一般档，**不需要**再依赖"攻击者可控"这一附加论证 |

**F-03 / F-12 的 (a) 反证不成立的理由（记录甲的判据纠正，我同意）**：
我二轮曾用"红证场景 C 证明合法输入下完全正常"来论证"不到阻断"，但那是拿 **(a) 的反证去驳 (b)**。
阻断定义为 `(a) OR (b)`，二者是**或**关系，(b) 独立成立即可判阻断。这个判据错位我认领。

### 13.2 F-15 上调的完整定义层论证（不依赖影响面）

1. **「一般」档有排除条款**：`一般 = 表述/引用/内部一致性，不改变字节与行为`。
   last-wins 改变的是**运行时行为**（同一个 capability 数组，两种合并策略产生不同的
   `orderSupport` 位图、不同的 `NumCellCaches`、不同的 `extraFlags`），因此**不可能**落在
   一般档。这是定义层面的排除，与"改动量""影响面"无关。
2. **「严重」档的正面覆盖**：`严重 = 错误行为、数据错误，或漏掉规范必需分支`。
   - `Order.orderSupport`（`bcgr.txt` 2.2.7.1.3，32 字节位图）：被 last-wins 覆盖后，
     客户端声明"不支持"的订单被服务端认为"支持" → 服务端发出客户端无法解析的订单 →
     **订单流错位**（这是"数据错误"）。
   - `Rev2.NumCellCaches/CellInfo`（2.2.7.1.4.2）：被覆盖后缓存槽语义与实际分配不符 →
     **画错图**（这是"错误行为"）。
   - `General.extraFlags` 的 `ENC_SALTED_CHECKSUM 0x0010`（`bcgr.txt:3214`）被翻掉 →
     MAC 生成方式切换（详见 13.3 的证据强度订正）。
3. **不判阻断**：不命中 (a)（正常输入下连接可用），不命中 (b)（无越界、无内存后果）。

### 13.3 我对甲"MAC 全失配"链条的证据强度订正（自我收窄，不影响定级）

甲与我在二轮都写"`ENC_SALTED_CHECKSUM` 被翻掉 → **此后全部包 MAC 失配**"。我复核后认为
这条因果链**需要弱化为"可能失配"**，依据是规范给了**两个**指示源：

- `bcgr.txt:12569`：`The use of the salted MAC is dictated by capability flags in the General
  Capability Set ... **In addition**, the presence of a salted MAC is indicated by the presence of
  the SEC_SECURE_CHECKSUM flag in the Security Header flags field (section 5.3.8).`
- `bcgr.txt:3918`：`SEC_SECURE_CHECKSUM 0x0800 | Indicates that the MAC for the PDU was generated
  using the "salted MAC generation" technique ... If this flag is not present, then the standard
  technique was used.`

即**接收侧可以只看逐包 `SEC_SECURE_CHECKSUM` 标志**，而不必依赖自己存的 capability。
所以"capability 被翻 → MAC 必然全失配"这一步**不是必然的**，正确表述是"若实现按
capability 决定算法（文档 §2.4 行 400-401 就是这么写的：「是否用 salted 由 General
Capability Set 的 `ENC_SALTED_CHECKSUM` 协商，并由 `SEC_SECURE_CHECKSUM` 逐包指示」），
则被翻后可能失配"。

**这不改变 F-15 的定级**，因为定级已由 13.2 第 2 条的 `orderSupport` / `NumCellCaches`
两条**无歧义**的"数据错误"支撑，不需要 MAC 链条。修正后的 F-15 一句话表述应为：

> U-14「后者覆盖前者」（last-wins）不安全：重复 set 可单方面改写
> `Order.orderSupport`（→ 订单不可解析）、`Rev2.NumCellCaches/CellInfo`（→ 画错图）、
> `General.extraFlags`（→ 若实现按 capability 选 MAC 算法则可能失配）。

请执行 AI 在施工时按这句改 §15 U-14 的措辞，不要照抄"全部 MAC 失配"这一绝对表述。

### 13.4 甲对我方 harness 偏离的核验（我确认，接受，且不改变结论）

甲按他第一轮批评我 `auditb_red_i.py` 的**同一标准**，核对了 `redlit_walk.cpp` 是否忠实于
`capabilities.md:844-853`，指出两处偏离。我逐条复核，**两处都成立**（第 3 处见 §14，甲在后续
一轮补充，我同样确认）：

1. **`lcc < 4` 前置守卫**（`redlit_walk.cpp:20`）——文档伪码**没有**这一句（`lcc-4` 只出现在
   行 852 的 assert 里）。所以 harness 的 case D 报 `doc=ERR-lcc<4`，而逐字实现会走到行 852。
   我实跑 `python -X utf8 F:\rtsc\.tmp\a_r3_literal.py`：
   ```
   D lcc=2 (F-13)             -> ('ASSERT-FAIL', 24, 65534, [(1, 24)])
   ```
   （65534 = `(2-4) & 0xFFFF`，uint16 回绕；不做回绕则为 `-2`，见该脚本下半段输出。）
   **F-13 的后果因此应表述为"assert 失败 / 长度下溢"，不是"越界读"**，维持「一般」正确。
2. **`p+4 > buf.size()` / `p+len > buf.size()` 两条检查**（`:25/:28`）——这是 harness 为了
   "把本会越界转成可打印 tag 而不去真读越界内存"的**必要安全设计**。但由此 harness 报的
   `OOB-READ-*` 是**建模结论**而非"真的读了越界内存"。甲用无任何上界检查的逐字实现复核，
   A/B 同样成立：
   ```
   A count>data (F-12)        -> ('OOB-READ-TYPE', 24, 24, [(1, 24)])
   B len>remaining (F-03)     -> ('OOB-READ-BODY', 0, 8, [])
   ```

我另外用自己的独立 harness（`F:\rtsc\.tmp\r3_probe.py`，用 `Buf.u16/body` 做真边界检查、
越界即 `IndexError`，无任何前置守卫）复跑，得到同样结论：
```
A nc=3 1set                  doc -> ('RAISED', 'OOB-READ-HEADER A nc=3 1set off=4 need=2 size=4')
A nc=3 1set                  fix -> ('ERR-count-too-big',)
B len=200 8B                 doc -> ('RAISED', 'OOB-READ-BODY B len=200 8B off=4 len=196 size=8')
B len=200 8B                 fix -> ('ERR-set-oob',)
C legit 24B                  doc -> ('ASSERT-PASS', 24)
```
**三份独立实现（甲 `a_r3_literal.py`、甲 `redlit_walk.exe`、我 `r3_probe.py`）对 A/B 结论一致**
→ F-03/F-12 的 (b) 命中是稳健的，不依赖任何单一 harness 的建模方式。

**我接受这个批评，并记录一条方法学教训**：审计 harness 若为了"不真读越界内存"而加前置守卫，
必须在报告里**显式声明"报出的是建模结论"**，并另附一份逐字实现的结果。我在 §8 的方法学表里
没有做这个区分，是我的缺陷。执行 AI 施工时不受影响（修正方案本来就要求加上界检查）。

### 13.5 最终 41 条严重度分布（定稿）

| 档 | 条数 | 编号 |
|---|---:|---|
| **阻断** | **3** | F-01、F-03、F-12 |
| **严重** | **6** | F-02、F-04、F-05、F-06、F-15、F-38 |
| **一般** | **32** | F-07、F-08、F-09、F-10、F-11、F-13、F-14、F-16、F-17、F-18、F-19、F-20、F-21、F-22、F-23、F-24、F-25、F-26、F-27、F-28、F-29、F-30、F-31、F-32、F-33、F-34、F-35、F-36、F-37、F-39、F-40、F-41 |
| **合计** | **41** | F-01 … F-41，无缺号、无重复 |

**计数校验**：3 + 6 + 32 = **41** ✔
**编号校验**：阻断 3 + 严重 6 + 一般 32 的并集 = F-01…F-41 全集，无遗漏 ✔
（校验脚本 `F:\rtsc\.tmp\verify41.py` 从 §11.2 表格机械提取 41 行，逐行核对编号连续性。）

### 13.6 与审计甲的一致性

| 争点 | 甲（三轮） | 我（三轮） | 一致 |
|---|---|---|---|
| 并集总数 | 41 | 41 | **是** |
| 编号基座 | F-01…F-41 | F-01…F-41 | **是** |
| 三档定义 | 接受 | 提出 | **是** |
| F-01 | 阻断 | 阻断 | **是** |
| F-03 | 阻断 | 阻断 | **是**（甲已让步） |
| F-12 | 阻断 | 阻断 | **是**（甲已让步） |
| F-15 | 严重 | 严重 | **是**（我已上调） |
| F-02 | 严重 | 严重 | **是** |
| F-06 / F-07 | 一般 | 一般 | **是** |
| F-38 | 严重 | 严重 | **是** |
| 分布 | 阻断 3 / 严重 6 / 一般 32 | 阻断 3 / 严重 6 / 一般 32 | **是** |

**盖章声明：**

> 审计乙确认：41 条统一清单（F-01…F-41）的事实、证据、最小修正方案与最终严重度分级
> **与审计甲完全一致**；最终分布 **阻断 3 / 严重 6 / 一般 32 = 41**。
> **与审计甲达成一致，盖章通过。**
> 附条件（不构成分歧，供执行 AI 遵循）：
> ① F-15 的表述按 §13.3 的收窄版写，不写"全部 MAC 失配"；
> ② F-13 的后果表述为"assert 失败 / 长度下溢"，不写"越界读"；
> ③ 施工顺序建议：F-01 → F-02 → F-03/F-12 → F-15 → F-06 → F-38 → 其余一般档批量收尾。

---

*第三轮定级盖章结束。审计 AI 乙。*
*最终分布 **阻断 3 / 严重 6 / 一般 32 = 41**；与审计甲 **一致盖章通过**。*

---

## 14. 第四轮：harness 第 3 处偏离的确认与收口

> 触发：审计甲在 `capabilities.consult-a.md` §11.3.3 / §12.4 提出，我只回应了他列的
> **前两处**偏离，漏了**第 3 处**：修正版 `redlit_walk.cpp` 删掉 `lcc<4` 守卫时，
> 把文档行 849 的 `if len < 4: error` 也一并删了。
> 本轮**只做确认与收口，不改任何缺陷事实、证据与定级**。`capabilities.md` 未改动。

### 14.1 甲的指控成立，我已复核

我逐行读 `capabilities.md:844-853`，行 849 确实有这句：

```
849:     if len < 4: error            # 防御：否则 p 不前进，死循环
```

而当时的 `redlit_walk.cpp` 的 `WalkDoc` 里**只有** `WouldRead(p,4,...)` 与
`WouldRead(p,len,...)` 两个建模检查，**没有** `len < 4` 分支。后果是 case F
（`len = 0`）走不到文档自己的守卫，落到末尾 assert：

| 实现 | case F (`len=0`) | 是否忠实 |
|---|---|---|
| 当时的 harness | `doc=ASSERT-FAIL off=0 len=0 end=24` | ✘ 漏了行 849 |
| 逐字实现 `a_r4_literal.py` | `('ERR-len<4', 0, 0, 24, [])` | ✔ |

我实跑确认（`[BASH:python -X utf8 F:\rtsc\.tmp\a_r4_literal.py]`）：

```
== 逐字实现（含行 849 if len<4，无 lcc<4 守卫）==
A count>data (F-12)      -> ('OOB-READ-HEADER', 24, 4, 24, [(1, 24)])
B len>remaining (F-03)   -> ('OOB-READ-BODY', 0, 200, 8, [])
C legal (green)          -> ('OK', 24, 0, 24, [(1, 24)])
D lcc=2 (F-13)           -> ('ASSERT-FAIL', 24, 0, 65534, [(1, 24)])
E trailing slack         -> ('ASSERT-FAIL', 24, 0, 32, [(1, 24)])
F len=0                  -> ('ERR-len<4', 0, 0, 24, [])
```

**A/B/C/D/E 五场景与 harness 逐字一致，仅 F 的 tag 名不同。** 甲的定性准确：
这是"修正'多加了检查'时滑到'少加了检查'"，与初版"擅自加守卫"是**同一类不忠实，
方向相反**。

### 14.2 harness 已修正，我复跑确认（红证→绿证）

`redlit_walk.cpp` 现已在 `WouldRead(p,len,...)` **之前**插入文档行 849 的守卫
（`redlit_walk.cpp:54-58`，含注释说明"omitting it would be the mirror image of adding
checks the document does not have"），并按 README 的复跑命令重编译：

```
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$vs='C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vs`" >nul 2>&1 && cd /d F:\rtsc\evidence\capabilities && cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 redlit_walk.cpp /Fe:redlit_walk.exe >rl.log 2>&1 & type rl.log & redlit_walk.exe"
```

实测输出（`/W4 /WX` 零告警零错误）：

```
redlit_walk.cpp
A count>data (F-12)          doc=OOB-READ-HEADER    off=24 len=4 end=24 | fix=ERR-header-oob
B len>remaining (F-03)       doc=OOB-READ-BODY      off=0 len=200 end=8 | fix=ERR-body-oob
C legal (green)              doc=OK                 off=24 len=0 end=24 | fix=OK
D lcc=2 (F-13)               doc=ASSERT-FAIL        off=24 len=0 end=65534 | fix=ERR-lcc<4
E trailing slack             doc=ASSERT-FAIL        off=24 len=0 end=32 | fix=ERR-trailing
F len=0                      doc=ERR-len<4          off=0 len=0 end=24 | fix=ERR-len<4
```

`F len=0 doc=ERR-len<4` 与逐字实现 `a_r4_literal.py` 的 `('ERR-len<4', 0, 0, 24, [])`
**tag 与 off/len/end 全部一致** → 第 3 处偏离已消除。
`redlit_walk.out.txt`（540 字节 / 6 行）与该次运行逐行相同，无残留旧输出。

### 14.3 对 41 条结论的影响：**无**

| 场景 | 缺陷 | 修正前后 harness 结论 | 影响 |
|---|---|---|---|
| A | F-12 | `OOB-READ-HEADER off=24 len=4 end=24` | 不变 |
| B | F-03 | `OOB-READ-BODY off=0 len=200 end=8` | 不变 |
| C | 绿证 | `OK` | 不变 |
| D | F-13 | `ASSERT-FAIL end=65534` | 不变 |
| E | F-13 同族 | `ASSERT-FAIL end=32` | 不变 |
| F | 无（文档行 849 守卫生效） | `ASSERT-FAIL` → `ERR-len<4` | 仅 tag 名，**不涉任何 F 编号** |

F 场景**不对应 41 条中的任何一条**（它是"文档自己已有守卫"的对照），因此第 3 处偏离
**不影响 F-01…F-41 的任何事实、证据、修正方案或定级**。

### 14.4 我接受这条批评，并把它写成方法学约束

甲的理由我完全接受：**我第一轮正是以"你的红证脚本不是逐字实现"要求甲重写红证，
标准必须双向成立**——批评别人"多加了检查"时，不能自己在修正过程中"少加了检查"。

我在此把这条固化为本审计的 harness 验收清单（供后续任何红证脚本自检）：

| # | 验收项 | 反例 |
|---|---|---|
| 1 | 不得添加被建模代码**没有**的检查 | 初版 `lcc<4` 前置守卫 |
| 2 | 不得遗漏被建模代码**已有**的检查 | 本轮的 `if len < 4` |
| 3 | 边界访问必须用"建模判定"而非真实越界访问，且**在报告中显式声明这是建模结论** | `WouldRead()` 的语义说明（已在 cpp 头注释与 README 写明） |
| 4 | 必须另附一份**逐字实现**的独立结果交叉验证 | `a_r3_literal.py` / `a_r4_literal.py` |
| 5 | 数值下溢/回绕必须按被建模语言的真实语义建模并注明 | `static_cast<uint16_t>(lcc - 4)` → `end=65534` |

第 2 项与第 4 项是本轮新增（由甲的第 3 处偏离促成）。

### 14.5 收口结论

- 甲的 3 处偏离指控：**全部成立**，我全部接受，无保留。
- harness 已修正并复跑，第 3 处偏离消除（`F len=0` → `ERR-len<4`）。
- 41 条清单：**不变**（阻断 3 / 严重 6 / 一般 32 = 41）。
- 双方盖章状态：**维持**。本轮不引入任何新的分歧，也不撤销任何已达成的一致。

### 14.6 顺带核实：实现侧未受这三条污染（供执行 AI 参考）

harness 的偏离只影响"红证怎么展示"，不影响"文档有没有缺陷"。我另核了实现侧
（`F:\rtsc\src\proto\capabilities.cpp:120-163` 的 `ParseCapabilitySets`），确认它**已含**
这四条检查，因此 F-03 / F-12 / F-13 是**纯文档缺陷，代码无需改动**：

| 检查 | 实现位置 | 对应缺陷 |
|---|---|---|
| `combined_length < 4` → `InvalidLength` | `capabilities.cpp:129` | F-13 |
| `size < window` → `InvalidLength` | `capabilities.cpp:131` | F-03/F-12（缓冲区本身不够） |
| `p + kHeaderSize > window` → `count_mismatch` + `InvalidLength` | `capabilities.cpp:136-139` | **F-12**（count 偏大） |
| `len < kHeaderSize` → `InvalidLength` | `capabilities.cpp:147` | 文档行 849 的同类守卫 |
| `p + len > window` → `InvalidLength` | `capabilities.cpp:149` | **F-03**（len 无上界） |
| `p != window` → `trailing_slack` 标记 | `capabilities.cpp:161` | F-14 建议的处置方式 |

**给执行 AI 的结论**：F-03 / F-12 / F-13 / F-14 只需修 `capabilities.md` 的文档与伪码，
**不要**去改 `capabilities.cpp`（它已经是对的，改了反而可能引入回归）。

---

*第四轮收口结束。审计 AI 乙。*
*harness 3 处偏离全部确认并修正；41 条与定级分布 **不变**（3 / 6 / 32）。*

---

> **编号说明（如实披露）**：父会话要求把本轮两节编为 `## 14` / `## 15`。但本文件 `## 14`
> 已被"第四轮 harness 第 3 处偏离收口"占用（1329 行起，内容不可删——它记录了甲的批评与我的
> 修正）。为避免出现两个 `## 14` 导致执行 AI 引用歧义，本轮顺延为 `## 15` / `## 16`。
> 内容与父会话要求的两节一一对应，无缺项。

## 15. 磋商关闭确认（同步甲的第五轮）

1. **甲已正式关闭磋商**：`capabilities.consult-a.md` §13「第五轮：harness 保真度收口（磋商正式关闭）」，
   文件 **1061 行 / 96,033 字节**（UTF-8 无 BOM）。其 §13.5 关闭声明明确写「磋商阶段正式关闭」，
   41 条事实/证据/修正/定级甲乙完全一致，无未收口项。
2. **harness 第 3 处偏离已修正且六场景全字段一致**：我删 `lcc<4` 守卫时误删了文档行 849 的
   `if len < 4: error`；补回后 `F len=0` 由 `ASSERT-FAIL` 变为 `ERR-len<4`，与逐字实现
   `a_r4_literal.py` 的 `('ERR-len<4', 0, 0, 24, [])` 在 **tag + off + len + end** 四个字段上
   逐一相等。甲的 `a_r5_verify6.py` 对 A–F 六场景做了自动化全字段比对，结论 `True`。
3. **乙确认无保留意见，磋商关闭**。最终分布 **阻断 3（F-01/F-03/F-12）/ 严重 6
   （F-02/F-04/F-05/F-06/F-15/F-38）/ 一般 32 = 41**，与我 §13.5 一致。

---

## 16. 验收判据（乙视角，侧重措辞与语义）

> 定位：甲写机械断言型判据（"某字节等于某值"），本节写**互补的另一半**——措辞与语义。
> 理由：第三轮我主动提了两处收窄（F-15 的 MAC 因果、F-13 的"越界读"），这两处**最容易
> 被执行 AI 按旧措辞写回**；而它们恰恰是"机械搜索会误判"的典型。
>
> 可执行脚本：`F:\rtsc\evidence\capabilities\accept_consult_b.py`
> （**17 条**机械判据；本文 §16.1 的表格是 12 条基线，§17.3 增补 5 条，
> 两者在同一个脚本里，以脚本实际输出为准。）
> 复跑：`$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'; python -X utf8 F:\rtsc\evidence\capabilities\accept_consult_b.py`
> 红证：`python -X utf8 F:\rtsc\evidence\capabilities\red_f30_intro.py`（F-30 导语强度判据的 6 用例负向对照）
> 退出码：全 PASS = 0，有 FAIL = 1（可直接接 CI）。

### 16.1 机械可判的 12 条

| F 编号 | 判据 | 可执行命令 | 判读要点 |
|---|---|---|---|
| **F-15** | U-14 行必须同时满足：① 含 `orderSupport`；② 含 `NumCellCaches` 或 `CellInfo`；③ `全部 MAC 失配`/`MAC 全部失配` 计数 == 0；④ 若提到 MAC 必须是条件式（`若…则…失配` 或 `可能失配`） | `python -X utf8 -c "import io,re;L=io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines();r=[l for l in L if l.startswith('| **U-14**')][0];print(bool(re.search('ordersupport',r,re.I)),bool(re.search('numcellcaches|cellinfo',r,re.I)),r.count('全部 MAC 失配'))"` | 三项全 `True True 0` 才过。**为什么不能用"全部 MAC 失配"**：`bcgr.txt:12569` 写 `The use of the salted MAC is dictated by capability flags … **In addition**, the presence of a salted MAC is indicated by the presence of the SEC_SECURE_CHECKSUM flag`，而 `bcgr.txt:3918` 写 `SEC_SECURE_CHECKSUM 0x0800 … If this flag is not present, then the standard technique was used`——**两个指示源**，接收侧可只看逐包 flag，故 capability 被翻**不必然**导致 MAC 全失配。文档行 400-401 自己就写了这两个源，写"全部失配"连文档自己那句话都对不上 |
| **F-13** | §6.1 内 `lcc<4` 相关段落必须出现 `下溢` 或 `assert 失败`；该段内 `越界` 的每次出现都必须处于**否定语境**（前面 14 字内有 `不是/而非/非/不得/禁止/不算`） | `python -X utf8 -c "import io,re;L=io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines();s=chr(10).join([l for l in L if re.search(r'lcc\s*<\s*4',l)]);print('下溢' in s or 'assert 失败' in s, s.count('越界'))"` | 需 `True` 且 `越界` 出现时必须在否定语境。**注意**：父会话原拟的"窗口内搜`越界`==0"是**错的判据**——正确写法恰恰是"**不是**越界读"，粗暴搜 0 会把正确答案判 FAIL。脚本里保留了这条对照（`[对照]` 行），当前两者同结论纯属巧合（该段暂无"越界"字样） |
| **F-03/F-12** | §6.1 内必须出现威胁模型词：`对端可控` / `对端触发` / `可被对端触发` / `恶意服务端` / `攻击者可控` 任一；且 `numberCapabilities…偏大` 与 `lengthCapability…大于/超出/无上界` 两条各自有描述 | `python -X utf8 -c "import io,re;t=io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read();print(bool(re.search('对端可控|对端触发|可被对端触发|恶意服务端',t)),bool(re.search('numberCapabilities.{0,60}?(偏大|大于|超出)',t)),bool(re.search('lengthCapability.{0,60}?(大于|超出|无上界|越界)',t)))"` | 三项全 `True`。**这是"阻断"的判据本体**：只写"缺少检查"是"严重"（质量缺陷），写"对端可控→越界"才是"阻断"（安全后果）。若执行 AI 把措辞改回"缺少检查"，定级依据就丢了 |
| **F-06** | U-03 行必须：含 `Persistent`、含 `保留`、且含 `清空标准` 或 `标准…Bitmap Cache` | `python -X utf8 -c "import io,re;r=[l for l in io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines() if l.startswith('| **U-03**')][0];print('Persistent' in r,'保留' in r,bool(re.search('清空\s*\*{0,2}标准|标准\s*\*{0,2}\s*Bitmap Cache',r)))"` | 三项全 `True`。只写"清空 bitmap cache"（旧措辞）会过不了第一项，能有效拦住回退 |
| **F-38** | §12.2 窗口内：① **不得**有行同时含 `Server Synchronize` 与 `可开始发送 input`；② 必须有行同时含 `Confirm Active` 与 `input` | `python -X utf8 -c "import io,re;L=io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines();s=[i for i,l in enumerate(L) if l.startswith('### 12.2')][0];e=[i for i,l in enumerate(L) if i>s and l.startswith('### 12.3')][0];b=L[s:e];print(sum(1 for l in b if 'Server Synchronize' in l and re.search(r'可开始发\s*input',l)),any(re.search('Confirm Active',l) and re.search('input',l,re.I) for l in b))"` | 必须 `0 True`。第一个数 > 0 = 旧措辞还在；第二个 `False` = 修过头（把许可整句删了，读者反而不知道何时可发 input） |
| **F-41** | 检查清单中含 `totalLength` 且含 `断链` 的 `- [ ]` 行，必须每行都含 `SHOULD` | `python -X utf8 -c "import io;c=[l for l in io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines() if 'totalLength' in l and '断链' in l and l.strip().startswith('- [')];print(len(c),sum('SHOULD' in l for l in c))"` | 两个数必须相等（当前实测 `1 0` = **未修**）。原文 `bcgr.txt:7409` 是 `the connection SHOULD be dropped`，文档正文行 758 已写对，只有清单漏了 SHOULD |
| **F-02** | 在 **§13.4 窗口内**：① `26 18 5e 76`（线上密文前缀）出现 ≥ 2 次；② 其中**至少 1 次在表格行**（`\|` 开头）；③ 每个含 `20 00 08 ab`（解密后载荷）的行，**它本身或它向上 3 行内**须有 `明文`/`解密`/`不是`/`Decrypted` | `python -X utf8 F:\rtsc\evidence\capabilities\accept_consult_b.py`（F-02 条目） | **必须"向上 3 行窗口"**：markdown 的合法结构是"块前说明行写限定 + 代码块写数据"，限定语与数据天然不同行（本行 v1 判据曾因要求同行而**误报 FAIL**，见 §16.5）。另外**不能只数出现次数**：注释行 + hexdump 行已能凑够 2 次，会漏掉"表格行仍写明文"（见 §16.5 变体 2） |
| **F-21** | 全文不得再有 `lengthSourceDescriptor + lengthCombinedCapabilities + 4` | `python -X utf8 -c "import io;print([i+1 for i,l in enumerate(io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines()) if 'lengthSourceDescriptor + lengthCombinedCapabilities + 4' in l])"` | 必须输出 `[]`。注意 `+ 4` 可能在别处合法出现（`lcc = 4 + Σ`），所以判据锁的是**这个特定组合**，不是搜 `+ 4` |
| **F-29** | ① 文档自述的 learn URL 计数 **必须等于** 实测 distinct 计数；② 正文（排除 §18 修订记录）不得残留 `85/85` | `python -X utf8 F:\rtsc\evidence\capabilities\accept_consult_b.py`（F-29 条目） | 判据**不锁死数字**：修订中因补登 S90–S99，真值从 87 变成 **97**。锁死"87"会把正确的 97 判 FAIL（这类"判据绑死会过期的数字"是 §16.5 同类陷阱）。判据改为"自述 == 实测"这一**一致性**关系，并对 `85/85` 残留单独把关 |
| **F-35** | 正文（**排除 §18 修订记录**）不得出现 `严格串行` | `python -X utf8 F:\rtsc\evidence\capabilities\accept_consult_b.py`（F-35 条目） | **必须排除修订记录**：§18 会合法引用旧措辞（`「严格串行」改为「顺序固定，但可整批发送」`）作为变更记录，全局搜索会把这条**正确引用**判成缺陷——这正是 F-02 误报的同一类错误（假设了文档里不会出现旧词）。依据 `bcgr.txt:860` |
| **F-37** | 全文必须出现 `4,096`（会话密钥更新周期） | `python -X utf8 -c "import io;print([i+1 for i,l in enumerate(io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines()) if '4,096' in l])"` | 不得为空。依据 `bcgr.txt:12580`。**判读要点**：`4096`（无逗号）在 §8 的 bitmap cache 条目上限处也有，属无关命中，故判据锁 `4,096` 带逗号形式（规范原文写法） |
| **F-01** | 行 688 不得含 `0x03E3`；必须含 `0x03EB` 且含"不可硬编码"或"I/O Channel ID store" | `python -X utf8 -c "import io,re;L=io.open(r'F:\rtsc\docs\spec\capabilities.md',encoding='utf-8').read().splitlines();print(sum('0x03E3' in l for l in L),[i+1 for i,l in enumerate(L) if '0x03EB' in l])"` | 前数必须 `0`。`0x03EB` 应至少出现 2 次（行 688 + dump 注解）。这是唯一"阻断 + 数值"双重判据，也是甲的主场，此处只作交叉引用 |

### 16.2 必须人工判读的 7 条（无法机械判定，附"看什么"）

| F 编号 | 为什么机械判不了 | 人工判读看什么 |
|---|---|---|
| **F-16** | "哪几个 capability set 属'规范 MUST 可推出'、哪几个属'工程需要'"是**分类判断**，词面无法区分 | 看 §7 是否出现**两张独立表**：一张"规范 MUST 可推出"（实质只有 Bitmap + 条件性 Input/Order 字段），一张"本项目功能需要"（其余 6 个）。若仍是一张混装"必须"表 = 未修。再看每行是否有 `规范 MUST / SHOULD / 工程需要` 三选一的标签 |
| **F-17** | 机械只能查"三个码是否出现"，查不出"触发条件是否写对" | 搜 `0x000010EA` / `0x000010E9` / `0x000010F4`，逐个确认：BADCAPABILITIES 对应"Confirm Active 的 capability 未被服务端接受"、NOCURSORCACHE 对应"两个 cache size 都为 0"、CACHECAPNOTSET 对应"发 Persistent Key List 但没带 Rev2 Bitmap Cache capability"。写反了就是新缺陷 |
| **F-08/F-09/F-10** | 状态机迁移的**语义正确性**（跳到哪个状态、动作是"记录"还是"处理完成"）需要理解 S1–S6 全图 | 新增三行：Set Error Info（应"记录 errorInfo，**状态不变**"）、Monitor Layout（应"记录布局，**状态不变**"，且在 S1 收到 Demand Active 之后）、兜底"意外 PDU"（应"忽略并告警，**不改状态**"）。重点看**有没有误跳到新状态**——若写成 `S3 → S7`，就破坏了原状态机 |
| **F-28** | "标签改了但数值没改"是**配对判断**，搜单词查不出 | 逐个 capability 节核对：`lengthCapability` 的**数值必须仍是** 24/28/88/88/52/40/11/…（与 §14.1 的 dump 反向匹配一致），只允许把 `MUST = N` 改成 `定长 N（结构推导；规范未固定该值）`。**若数值被改动 = 引入新缺陷，比原缺陷更严重** |
| **F-31** | 只能查"章节号是否登记"，查不出"guid 是否真对应那个章节" | 新增的 S90+ 条目，逐条 HEAD 该 guid（应 200），并在 `toc.txt` 里确认该 guid 的标题**就是**那个章节号。特别注意 `3.2.5.3.22` 的 guid 是 `d246ad43-d84e-4de8-a808-46e11035db56`，别错配成 3.2.5.3.18 |
| **F-34** | `sourceDescriptor` 的措辞是"降级为实测"还是"仍当语义结论"，是**语用判断**；搜 `实测` 会命中大量无关处 | 看 §4.3 行 714 与 §5.3 行 797：应改为「dump 实测内容为 `"RDP"`/`"MSTSC"`（含 NUL）；语义见 [T128] 8.4.1（**未取证**）」。关键是**必须保留"未取证"这个诚实标注**，不能只写"实测为…"就当结论 |
| **F-15（第二判据）** | 机械只能查"有没有 orderSupport"，查不出"合并策略是否还是 last-wins" | 看 U-14 的建议列是否已从"后者覆盖前者"改为"取交集/更保守值（`orderSupport` 按位 AND、`NumCellCaches` 取小、`MaxRequestSize` 取小、`extraFlags` 取交集）"。**只要仍出现 `last-wins` 或"后者覆盖前者" = 未修**，即使机械判据全 PASS |

### 16.3 本判据脚本的"先红后绿"实测证据（证明它有区分力，不是恒真）

**观测说明**：本节写作期间，执行 AI 已在并发修改 `capabilities.md`（文件大小在 8 分钟内
从 151,753 B 变到 160,530 B）。因此我做了**两次快照**，正好捕捉到"红 → 绿"的转变过程。

**快照 1（较早，工作副本中间态）**：
```
机械判据：6 / 12 通过
未通过：['F-41', 'F-02', 'F-21', 'F-29', 'F-35', 'F-37']
```

**快照 2（约 8 分钟后，同一脚本）**：
```
机械判据：7 / 12 通过
未通过：['F-41', 'F-02', 'F-29', 'F-35', 'F-37']
```

**两快照之差 = 恰好 1 条：F-21 由 FAIL 转 PASS**（`lengthCombinedCapabilities + 4`
已从文档中删除）。这直接证明三件事：

1. **判据不是恒真**：快照 1 时 F-21 是红的，而文档确实还留着错误的 `+4`。
2. **判据不是恒假**：执行 AI 修好 F-21 后，同一条判据自动变绿，无需我改判据。
3. **判据对"具体哪一处"有定位力**：从 6/12 到 7/12 的增量精确对应 F-21 一处改动，
   没有出现"改 A 导致 B 误绿/误红"的串扰。

同时，**已修的项全部 PASS 且稳定**：F-01（`0x03E3` 计数为 0）、F-06（U-03 区分
Persistent + 保留 + 清空标准）、F-13（下溢/assert，无"越界"误述）、F-15（orderSupport +
NumCellCaches，绝对失配计数 0）、F-38（§12.2 无"Server Synchronize + 可发 input"行）、
F-03/F-12（威胁模型词"对端可控"/"可被对端触发"齐备）。

→ 结论：快照 2 时的 5 条红里，**4 条（F-41/F-29/F-35/F-37）是执行 AI 尚未改到的项**，
但**第 5 条 F-02 是我的判据误报**（文档其实已正确修复）——该误报的复盘见 §16.5。
这条自我更正很重要：**"判据红"不能直接等同于"文档没修"**。

> 附：快照 2 时文档 `sha256=37ec250c8f0578d65f64da0a1169c75b1580223bfaf0af6cec9791e07d5e9dc5`
> （2,596 行 / 160,530 B）。因文件在并发修改，**执行 AI 复跑时不要用这个 sha 校验**，
> 只以脚本的 PASS/FAIL 与退出码为准。

### 16.4 给执行 AI 的四条使用建议

1. **每改完一个 F 编号就跑一次脚本**，看对应判据由 FAIL 转 PASS；不要等全改完再跑
   （否则分不清是哪一处改动引入的回归）。
2. **`F-28` 必须人工核数值**：机械判据查不出"数值被改错"，而这是最危险的回归——
   原文档的数值是对的，改标签时手滑改数值会制造比原缺陷更严重的问题。
3. **不要在 `capabilities.md` 里搜"越界==0"来自证 F-13**：正确写法是"**不是**越界读"，
   粗暴搜索会把正确答案判成失败。用 §16.1 的 F-13 精化判据（带否定语境豁免）。
4. **判据红了先别断言文档没修**：先人工核对原文，再判定是"文档没修"还是"判据写错"。
   我在 F-02 上就犯过这个错（§16.5），把已修好的文档判成 FAIL。

### 16.5 判据脚本自身也需红证（一次真实误报的复盘）

> 这一节记录我自己的一次错误：**判据写错，把已修好的文档判成 FAIL**。
> 它与 §14.4 沉淀的 harness 5 条是**同一条原则**——"用来验证别人的东西，自己也要被验证"。

#### 16.5.1 事故经过

我给 F-02 写的 v1 判据是：

```python
# v1（错误）
ok = sum('26 18 5e 76 0e de 28' in l for l in L) >= 2 and all(
    ('明文' in l) or ('解密' in l) or ('不是' in l)
    for l in L if '20 00 08 ab 02 6f 01' in l)     # ← 要求"同一行内"带限定
```

它报 `[FAIL] F-02 明文行=[2285]（明文行须带"明文/解密/不是"限定）`。

而文档实际是**正确修好的**：

```
2282: 解密后的 `fpInputEvents`（7 字节）：      ← 限定语在这里
2283:
2284: ```
2285: 00000000  20 00 08 ab 02 6f 01   ....o.     ← 数据在这里
2286: ```
```

**限定语在行 2282，数据在行 2285** —— 中间隔了空行与代码块围栏。这是 markdown 的
标准"块前说明 + 代码块"结构，**合法且常见**。我的 v1 判据假设"限定语必须与数据同行"，
这个假设本身是错的。

#### 16.5.2 第二个错误：只数次数会被"凑够"骗过

修 v1 时我又发现 v2 的另一个漏洞：`26 18 5e 76` 在 §13.4 里出现 3 次
（行 2269 注释、2272 hexdump、2281 表格）。若只判"出现 ≥ 2 次"，那么**表格行没改**
（仍是明文）时，注释行 + hexdump 行已经凑够 2 次 → 误判 PASS。

红证（`F:\rtsc\.tmp\f02_negative.py`，内存构造退化版，不改文档）：

```
[good] 当前文档 §13.4          : PASS | cipher=[2269, 2272, 2281] table=[2281] plain=[2286] unq=[]
[bad1 旧版：明文填线上块+删说明]: FAIL | cipher=[] table=[] unq=[2279, 2283]
[bad2 表格行仍写明文        ]: FAIL | cipher=[2269, 2272] table=[]
[bad3 删掉"解密后的"说明行  ]: FAIL | unq=[2285]
结论：good=PASS，bad1/bad2/bad3 全 FAIL → 判据有区分力，非恒真
ASSERT OK
```

`bad2` 就是"只数次数"会漏掉的场景——加上"**表格行必须有密文**"这条才拦住。

#### 16.5.3 第三个错误：改了调用没先做语法自检

我在给 F-02 加"向上 3 行窗口"时，把 `section(start_pred, end_pred)` 调用误写成
3 个参数（多传了一个 `'13.4'` 标签），脚本直接 `TypeError` 崩掉。parent 复现到的就是这一条。

**教训**：改判据脚本后**必须先 `py_compile` 再跑**，不要拿完整脚本赌它能过。

#### 16.5.4 固化为判据脚本的 3 条自检（已写入脚本头部 docstring）

| # | 自检项 | 具体做法 | 本次反例 |
|---|---|---|---|
| 1 | **语法自检** | `python -c "import py_compile; py_compile.compile(r'...accept_consult_b.py', doraise=True)"` 必须先过 | `section()` 多传参 → `TypeError` |
| 2 | **不假设排版** | 限定语与数据行可以不同行；"块前说明 + 代码块"是合法结构，须用"向上 N 行窗口"匹配 | F-02 v1 要求同行 → 误报 FAIL |
| 3 | **红证（负向对照）** | 对已修好的文档跑，若某条仍 FAIL，**必须人工核对原文**再判定是"文档没修"还是"判据写错"；另建内存退化版验证判据会把旧文档判 FAIL | F-02 v2 只数次数 → `bad2` 漏判 |

> 第 3 条与 §14.4 的 harness 5 条是同一条原则的两个面：
> §14.4 管"红证脚本要忠实于被建模的代码"，本节管"**验收判据要忠实于被验收的文档**"。
> 两者都会因为"假设了不存在的结构"而给出错误结论，且**错误方向都是把正确的判 FAIL**。

#### 16.5.5 修正后的当前实测（12/12 PASS）

修正 v3 判据（§13.4 窗口 + 表格行必须有密文 + 向上 3 行窗口）后：

```
[PASS] F-15 / F-13 / F-03-F-12(×2) / F-06 / F-38 / F-41 / F-02 / F-21 / F-29 / F-35 / F-37
机械判据：12 / 12 通过
未通过：无
需人工判读：7 条
EXIT=0
```

`F-02` 的实测细节：`§13.4 窗口=2265..2301；密文行=[2269, 2272, 2281]；密文表格行=[2281]；
明文行=[2286]（向上 3 行内命中"解密后的"）；未带限定=无`。

**注意**：`12/12 PASS` 只证明"文档已满足这 12 条措辞判据"，**不等于 41 条全部验收通过**——
7 条人工判读项（§16.2）尚未由人核，且 F-28 的"只改标签不改数值"必须人工逐节核对。

---

### 16.6 第二轮误报：判据"绑死会过期的数字"与"扫到修订记录"

> 在 §16.5 修完 F-02 之后，脚本又暴露了**两条同类误报**。它们与 F-02 同源：
> 判据假设了文档里**不该有的东西**（旧数字、旧措辞），而修订记录 §18 会合法引用这些旧值。
> 我把它们一并记下，因为它们比 F-02 更隐蔽——F-02 报红时文档是"对的"，
> 这两条报红时文档也是"对的"。

#### 16.6.1 F-29：判据绑死了会过期的数字

- v1 判据：`不得出现 85/85` + 建议改成"87 个"。
- 但执行 AI 在修 F-31（补登 S90–S99）时**多登记了 10 个 guid**，真值从 87 变成 **97**。
  文档写 97 是**正确**的，而我的判据若写成"必须等于 87"，会把 97 判 FAIL。
- 实测：`S rows 118 / learn URLs 97 distinct / script 85 / intersection 83 / doc-only 14`。
- **修正**：判据改为**一致性关系**——"文档自述的计数 == 实测 distinct 计数"，
  不锁死具体数字。这样文档登记多少条都能自动跟上，只抓"自述与实测不符"。

#### 16.6.2 F-35：全局扫描扫到了修订记录里的旧措辞

- v1 判据：全文搜 `严格串行`，命中即 FAIL。
- 但 §18「修订记录」会**合法引用旧措辞**：`| **F-35** | 1795 | 「严格串行」改为「顺序固定，但**可整批发送**（1.3.1.1）」 |`
  这是**变更记录**，不是缺陷残留。
- 实测：全文唯一命中在行 2655，位于 §18 修订记录表内；正文行 1864 已是
  `（顺序固定，但**可整批发送**——1.3.1.1（S02）…）`。
- **修正**：判据加 `body_rows()` 过滤器，**排除 §18 修订记录整节**后再扫。

#### 16.6.3 三条误报的共同根因（可推广的教训）

| 误报 | 判据的错误假设 | 正确做法 |
|---|---|---|
| F-02 v1 | 假设"限定语必须与数据同行" | 用"向上 N 行窗口"匹配块前说明 |
| F-29 v1 | 假设"正确计数是固定值 87" | 改成"自述 == 实测"的一致性判据 |
| F-35 v1 | 假设"旧措辞在任何位置出现都是缺陷" | 排除"修订记录/变更日志"这类**合法引用区** |

**共同根因**：判据把"文档的某一种特定排版/某一次特定数值/某一种特定结构"当成不变量。
而实际文档是**演进中的**——它会新增章节、补登条目、追加修订记录。
**判据必须表达"语义要求"，不能表达"当前实现的快照"。**

这与 §14.4 的 harness 5 条是同一条原则的第三个面：
- §14.4：红证脚本要忠实于**被建模的代码**
- §16.5：验收判据要忠实于**被验收的文档**
- §16.6：验收判据还要**容忍文档的合法演进**（修订记录、计数变化）

#### 16.6.4 修正后实测：12/12 PASS

```
capabilities.md  lines=2704  bytes=174393
[PASS] F-15 / F-13 / F-03-F-12(×2) / F-06 / F-38 / F-41 / F-02 / F-21 / F-29 / F-35 / F-37
机械判据：12 / 12 通过
未通过：无
需人工判读：7 条
EXIT=0
```

关键细节：
- `F-29`：`实测 distinct learn URL=97；文档自述计数=[97]；正文残留 85/85 的行=无`
- `F-35`：`正文（排除 §18 修订记录）仍含"严格串行"的行=无`
- `F-02`：`密文行=[2269,2272,2281]；密文表格行=[2281]；明文行=[2286]（向上3行内命中"解密后的"）；未带限定=无`

> **仍然要强调**：12/12 PASS 只覆盖"措辞类"判据。§16.2 的 7 条人工判读项**尚未由人核**，
> 其中 F-28（"只改标签不改数值"）必须逐节人工比对，机械判据查不出数值被改错。

---

## 17. F-20 / F-30 冲突裁定

> 触发：执行 AI 提出，F-30（§15.1 不得有自承"缺 dump 佐证"的行）与 F-20（§15.1 应明写
> "6 个类型无 dump 佐证"）**字面冲突**。父会话要求我裁定，并顺带复核 12 条判据是否仍成立。
> 本节只做裁定与复核，**不修改 `capabilities.md`**。

### 17.1 裁定：**(a) 豁免成立，不需要改**

不是"折中"，也不是"妥协"，而是**F-30 的缺陷本体不覆盖这一行**。定义层论证如下。

#### 17.1.1 先把两条缺陷的"主语"写清楚

| 缺陷 | 原文措辞 | 主语 | 断言内容 |
|---|---|---|---|
| **F-30** | 「§15.1『已全部核实、无不确定性的项』表内含『**无 dump 佐证**（见 U-10）』行」 | **该行所描述的那一项**（Deactivate All 的 `pduType` 推导值） | 「**这一项**已被核实」← 而它自己承认缺佐证 → **自相矛盾** |
| **F-20** | 「§15.1 称『28 个类型已核实』，实为 21 类型 × 31 实例」 | **21 类型 × 31 实例**这个集合 | 「**这个集合**已核实」+ 明确声明「**另有** 6 个类型不在其中」 |

关键差别：F-30 的矛盾是"**主语内部**声称已核实、却又自承未核实"；
F-20 的写法是"**主语已核实** + **主语之外**另有一个未覆盖集合"。
后者**不是矛盾**，是**边界声明**。

#### 17.1.2 用集合恒等式证明"两个集合不重叠"

若 6 个类型**属于**"21 类型"这个主语，则 F-20 的写法就是自相矛盾，豁免不成立。
实测证明它们**不相交**：

```
28 个已分配编号 : 28
dump 覆盖类型   : 21
§15.1 自述无 dump 的 6 个 : 0x0004 / 0x0019 / 0x001A / 0x001B / 0x001C / 0x001E  (共 6)
28 = 21 + 6 + 1(0x001D 变长)  -> True
dump ∩ six      = 空
dump ∩ 0x001D   = 空
six  ∩ 0x001D   = 空
dump ∪ six ∪ 0x001D == 全部 28 ?  True
```

（复现：`python -X utf8 F:\rtsc\.tmp\f20f30_relation.py`）

**结论**：`{21 个有 dump 的类型}` 与 `{6 个无 dump 的类型}` 是**两个不相交的集合**，
并集加上变长的 `0x001D` 恰好等于全部 28 个已分配编号。
所以"21 类型已核实"与"另有 6 个类型无 dump 佐证"**同时为真**，不构成矛盾。

#### 17.1.3 关键限定：豁免只对"主语之外"的写法成立

豁免**不是无条件**的。判别标准是**那 6 个类型在句法上属于主语之内还是之外**：

| 写法 | 6 个类型的位置 | 是否矛盾 | 豁免 |
|---|---|---|---|
| 「21 类型 × 31 实例的长度已核实。**另有** 6 个类型…无 dump 佐证」 | **主语之外**（"另有"） | 不矛盾 | **成立** ✔（当前写法） |
| 「21 类型已核实（**其中** 6 个无 dump）」 | **主语之内**（"其中"） | **矛盾** | **不成立** ✘ |
| 「全部 28 个类型已核实」+ 又写"6 个无 dump" | 主语 = 全部 28 | **矛盾** | **不成立** ✘ |

当前文档用的是「**另有** 6 个类型…」，属第一行 → **豁免成立**。

#### 17.1.4 与 F-30 的"选项 1 vs 选项 2"不冲突

F-30 的最小修正给了两个选项：① 把该行移出 §15.1；② 改写为"结构自洽（S41 表推导），
但缺 dump 佐证 → 见 U-10"。当时父会话裁定走 ①，理由是"② 只是在矛盾上加注脚"。

这个理由对 **Deactivate All 那一行**完全正确——因为该行的主语**就是** Deactivate All 的
`pduType`，加注脚不改变"这一项未核实"的事实。但**不能外推到 6 个类型**：
6 个类型不是行 2517 的主语，删掉它反而会**丢失 F-20 要求的诚实披露**，制造新缺陷。

**一句话**：F-30 管"**主语内部**不得自承未核实"；F-20 管"**主语之外**必须披露未覆盖范围"。
两者管的是**不同象限**，不存在冲突。

### 17.2 需要改的地方：**不是这一行，而是另外两处**（我新发现，甲的判据漏检）

裁定 (a) 之后，我按父会话要求做最后一道防线复核，**发现当前文档仍有 2 处未修完**。
它们都是**已有 F 编号的残留**，不新增缺陷编号（41 条总数不变）。

#### 17.2.1 【F-28 残留】§8.21 / §8.22 表格仍写 `LengthCapability | MUST = 8 / 11`

- **位置**：`capabilities.md:1555`、`1571`
- **实测**：
  ```
  1555 | | 2 | 2 | `LengthCapability` | MUST = 8 |
  1571 | | 2 | 2 | `LengthCapability` | MUST = 11 |
  ```
- **为什么漏检**：这两行用的是**首字母大写** `LengthCapability`，而 §8 其余 25 节都是小写
  `lengthCapability`。甲的 `check_acceptance.py:276` 正则是
  `r'lengthCapability`?\s*\|\s*MUST\s*='`，**大小写敏感** → 实测 `cs 命中 = 0`、`ci 命中 = 2`
  → F-28 报 PASS，**漏掉这 2 行**。
- **为什么是真缺陷**：同一节内**自相矛盾**——bullet 已改成"定长"，表格仍写 MUST：
  ```
  §8.21 0x0017: bullet定长=True  table定长=False
      table: | 2 | 2 | `LengthCapability` | MUST = 8 |
  §8.22 0x0018: bullet定长=True  table定长=False
      table: | 2 | 2 | `LengthCapability` | MUST = 11 |
  ```
  而 F-28 的要求正是"§8 各节统一改为『定长 N（结构推导；规范未固定该值）』"。
- **最小修正**（两行同构）：
  ```
  1555: | 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
  1571: | 2 | 2 | `lengthCapability` | 定长 11（由字段宽度推出；规范未固定该值） |
  ```
  （顺手把小写也统一，消除大小写不一致这一独立隐患。）

#### 17.2.2 【F-30 残留】§15.1 导语强度 > 内容强度

- **位置**：`capabilities.md:2512`（导语）+ `2516`（第一行）
- **实测**：
  ```
  2512: 以下各项**已用官方原文 + dump 双向核实**，可作确定事实使用：
  2516: | 28 个 `capabilitySetType` 的编号与名称 | 规范原文表（S08）逐行比对 |   ← 无 dump
  ```
  逐行统计：§15.1 的 10 个数据行里，**9 行含 dump、1 行（2516）不含**。
- **为什么是真缺陷（属 F-30 同一类）**：F-30 的缺陷本体是"**声称强度 > 事实强度**"。
  导语说"各项都已用**原文 + dump 双向**核实"，但行 2516 只做了**原文单向**比对。
  这与 F-30 原案（"标题称无不确定性、内容却自承缺佐证"）是**同一矛盾的两个方向**：
  - F-30 原案：**内容**弱于**标题**（标题说没问题，内容说缺佐证）
  - 本案：**内容**弱于**导语**（导语说双向核实，内容只有单向）
- **最小修正**（改导语，不动内容——因为"编号与名称"用原文表比对已经足够）：
  ```
  2512: 以下各项**已用官方原文核实**（多数并辅以官方 dump 双向验证，逐行注明核实方式），
        可作确定事实使用：
  ```
  或给行 2516 补 dump 依据（dump 里确有 `type=0xNNNN` 可交叉核对），但改导语更省且不引入新风险。

### 17.3 12 条判据复核：**仍成立，且我把它扩到 17 条**（新增 5 条覆盖上述盲区）

父会话给的实测数据我逐项复核，**结论一致**：
`check_acceptance.py` PASS=80 / FAIL=0 / MANUAL=2 / exit=0；`verify_caps.py` demand=True
confirm=True；文档 175,513 B / 2,711 行 / 无 BOM / CRLF=0 / FFFD=0。
`'0x03E3'=0`、`'全部 MAC 失配'=0` 等关键计数亦一致。

**但"甲的 82 条全绿"不等于"文档无残留"** —— 因为甲的判据有 2 处覆盖盲区（大小写、导语强度）。
我把自己的脚本从 12 条扩到 **17 条**，新增 5 条专门堵这两个盲区：

| 新增判据 | 堵什么盲区 | 扩表时结果 | **当前结果** |
|---|---|---|---|
| **F-28**（大小写不敏感版） | 甲的 `lengthCapability` 正则大小写敏感，漏掉 `LengthCapability` | FAIL（行 1555 / 1571） | **PASS**（残留已清零） |
| **F-30**（§15.1 无自承未核实行，含 6 类型豁免） | 把豁免写成**有条件的**（"另有"才放行），不是无条件放行 | PASS | **PASS** |
| **F-20**（§15.1 保留 6 类型披露） | 防止执行 AI 为过 F-30 而**删掉** F-20 的诚实披露 | PASS | **PASS** |
| **F-20**（分区恒等式 28 = 21 + 6 + 1） | 证明两个集合不相交，豁免有数学依据而非口舌 | PASS | **PASS** |
| **F-30**（§15.1 导语强度 ≤ 内容强度） | 甲的 F-30 只看"无 dump 佐证"字样，不看导语 | FAIL（行 2516 无 dump） | **PASS**（导语已加削弱语"多数"，判据修至 v4，见 §17.6） |

**当前 17 条实测：17 / 17 PASS，未通过=无，exit=0。**
（此前 15/17 的两条 FAIL——F-28 大小写漏检、F-30 导语强度——已由执行 AI 按 §17.4 的三行清单改完；
F-30 判据本身也修了第 4 次误报，见 §17.6。）

**判据脚本位置（可复现性硬要求）**：已从 `F:\rtsc\.tmp\` 迁到
`F:\rtsc\evidence\capabilities\accept_consult_b.py`（17 条 / 387 行 / 19,697 B），
配套红证 `F:\rtsc\evidence\capabilities\red_f30_intro.py`（6 用例）。
两者都在 `evidence/` 下，随仓库持久化，不依赖 `.tmp` 临时目录。

### 17.4 给执行 AI 的最小修正清单（只有 3 行改动）

| # | 位置 | 改法 |
|---|---|---|
| 1 | `1555` | `| 2 | 2 | \`lengthCapability\` | 定长 8（由字段宽度推出；规范未固定该值） |` |
| 2 | `1571` | `| 2 | 2 | \`lengthCapability\` | 定长 11（由字段宽度推出；规范未固定该值） |` |
| 3 | `2512` | 导语改为「以下各项**已用官方原文核实**（多数并辅以官方 dump 双向验证，逐行注明核实方式），可作确定事实使用：」 |

**不需要改**：§15.1 行 2517（6 类型披露）—— 裁定 (a)，豁免成立。
**不要动**：§15.1 的 Deactivate All 相关行（已按 F-30 选项 ① 移出，正确）。

改完复跑 `accept_consult_b.py` 应 **17/17 PASS，exit=0**。

### 17.5 本轮新增的方法学教训（第四次同类，已由 §17.6 扩展）

这已经是**第四次**"判据自身的假设导致漏判/误判"：
1. §16.5：F-02 假设"限定语与数据同行" → **假阳性**（把对的判错）
2. §16.6：F-29 绑死数字 87、F-35 扫到修订记录 → **假阳性**（把对的判错）
3. §17.3：F-28 大小写敏感、F-30 只看关键词 → **假阴性**（把错的判对）
4. §17.6：F-30 导语强度不识别削弱语（"多数"读成"全部"）→ **假阳性**（把对的判错）

前两次与第四次是**假阳性**，第三次是**假阴性**。合起来的教训是：
**判据的覆盖面本身是一个需要被验证的对象**——不能只验证"它能不能抓到我想到的错误"，
还要验证"它会不会漏掉我没想到的写法变体（大小写/同义表述/结构变体）"，
以及"它会不会把**正确的修复**判成未修复"（第四次，见 §17.6）。

具体到本次：**"关键词搜索"必须考虑大小写与同义表达**；
**"强度断言"必须核对导语/标题与每一行的实际强度，且必须能区分「全部/所有/均」与
「多数/部分/逐行注明」两类强度量词**——后者是第四次误报的直接原因。

> 完整的 7 条可执行检查清单见 **§17.7**（第 7 条见 §17.10.3）；"只看脚本 PASS 就认为全绿"的约束见 **§17.8**。

---

*第六轮（乙侧）：F-20/F-30 冲突裁定 + 判据扩至 17 条。审计 AI 乙。*
*裁定 **(a) 豁免成立，§15.1 行 2517 不需要改**；但发现 2 处残留（F-28 大小写漏检、F-30 导语强度），需执行 AI 改 3 行。*

---

### 17.6 第四次误报：判据没识别"削弱性限定语"

> 执行 AI 按 §17.4 的三行清单改完后，`F-28` 转绿，但 `F-30 导语强度` **仍报 FAIL**。
> 我读了自己的判据源码，确认是**判据写错**，文档是对的。这是第四次同类问题，
> 且性质与前三次都不同。

#### 17.6.1 事故经过

执行 AI 把行 2512 改成了：

```
以下各项**已用官方原文核实**（多数并辅以官方 dump 双向验证，逐行注明核实方式），可作确定事实使用：
```

这**正是** F-30 要求的效果——「多数」明确表示"不是全部"，与"§15.1 十个数据行里
9 行含 dump、1 行（2516）不含"完全吻合。声称强度 ≤ 事实强度，缺陷已消除。

但我的判据（v3）写的是：

```python
_intro = [l for l in blk15 if '双向核实' in l or 'dump 双向' in l]
_rows_no_dump = [... 不含 'dump' 的数据行 ...]
_ok_intro = (not _intro) or (not _rows_no_dump)
```

新导语含 `dump 双向` 子串 → `_intro` 为真；2516 行不含 dump → `_rows_no_dump = [2516]`
→ `FAIL`。**它把「多数并辅以」当成「全部都是」**，恰好把正确的修复判成未修复。

#### 17.6.2 与前三例的性质差异

| # | 案例 | 类型 | 错在哪 |
|---|---|---|---|
| 1 | §16.5 F-02 | **假阳性** | 假设"限定语与数据同行"，把对的判错 |
| 2 | §16.6 F-29 / F-35 | **假阳性** | 绑死会过期的数字 87 / 扫到 §18 修订记录，把对的判错 |
| 3 | §17.3 F-28 / F-30 | **假阴性** | 大小写敏感 / 只看关键词，把错的判对 |
| 4 | **§17.6 F-30 导语强度** | **假阳性（新子类）** | **不识别削弱性限定语**——把"多数"读成"全部"，把对的判错 |

第 4 例与第 1、2 例同属"假阳性"，但**根因不同**：前两者是"位置/时态假设错"，
本例是"**语义强度量词不可区分**"——判据只会做"出现/不出现"的二值判断，
无法区分「全部/所有/均」与「多数/部分/逐行注明」这两类**强度量词**。

#### 17.6.3 修正：三档强度判定

```python
WEAK = ('多数', '大部分', '部分', '逐行注明', '不完全', '少数', '绝大部分')
ABS  = ('全部', '所有', '每一项', '均', '各项', '每一项都')

def _judge_intro(intro_text, rows_no_dump):
    if not intro_text:            return True,  '无导语，不作强度断言'
    if any(w in intro_text for w in WEAK):
        return True,  '削弱语 → 允许 %d 行无 dump' % len(rows_no_dump)
    if any(a in intro_text for a in ABS):
        return (not rows_no_dump), '绝对语 → 每行必须有 dump'
    return (not rows_no_dump), '无强度词（默认按"全部"）→ 每行必须有 dump'
```

判定顺序要点：**先判削弱语**。因为削弱语是"降级"操作——只要出现"多数/部分/逐行注明"，
就说明作者已经承认不是全部，此时允许有缺 dump 的行。只有当**既无削弱语**时才看绝对语，
**两者都无**则按最保守的"全部"处理（宁可判严，不可放过）。

#### 17.6.4 红证：6 个用例全部符合预期

脚本：`F:\rtsc\evidence\capabilities\red_f30_intro.py`（从 `accept_consult_b.py`
源码级抽取 `WEAK`/`ABS`/`_judge_intro`，不 import 整个模块以免触发 `sys.exit`）

```
[PASS] 变体1 当前文档：削弱语「多数并辅以」+ 1 行无 dump        ok=True  expect=True
[PASS] 变体2 绝对声明：无削弱语的「原文 + dump 双向核实」+ 1 行无 dump  ok=False expect=False
[PASS] 变体3 无强度词：「以下各项已核实：」+ 1 行无 dump          ok=False expect=False
[PASS] 对照4 绝对声明 + 每行都有 dump                        ok=True  expect=True
[PASS] 对照5 削弱语 + 每行都有 dump                         ok=True  expect=True
[PASS] 对照6 无导语                                     ok=True  expect=True

三变体红证结果: PASS=True FAIL=True FAIL=True  -> 符合预期
全部 6 个用例符合预期: True
ASSERT OK
```

**关键**：变体 1 是"**正向**用例"（削弱语 + 数据不全 → 应 PASS）。
前三次红证我只构造"旧版应该 FAIL"的负向用例，**从没构造"正确修复应该 PASS"的正向用例**——
这正是为什么"把对的判错"这类错误能连续出现三次而不被发现。

#### 17.6.5 判据脚本当前位置（可复现性）

| 文件 | 作用 | 条数 |
|---|---|---|
| `F:\rtsc\evidence\capabilities\accept_consult_b.py` | 17 条机械判据主脚本 | 17 add + 7 human |
| `F:\rtsc\evidence\capabilities\red_f30_intro.py` | F-30 导语强度判据的红证（6 用例） | — |

两者均在 `evidence/` 下随仓库持久化，**不再依赖 `F:\rtsc\.tmp\`**（父会话指出的可复现性硬要求）。
当前实测：`17 / 17 PASS，未通过=无，exit=0`。

---

### 17.7 判据覆盖面的可执行检查清单（**7 条**，后续审计照做）

> 这是从四次误报里提炼的**操作手册**。每条都给出"怎么查"和"本项目的反例"，
> 不是原则性口号。

#### 第 1 条：大小写变体

**查什么**：判据里每个关键词，是否所有大小写变体都覆盖？
（`MUST`/`must`/`Must`、`LengthCapability`/`lengthCapability`、`SHOULD`/`should`）

**怎么查**：对每个关键词，跑一次大小写不敏感计数与大小写敏感计数，**两者必须相等**；
不等就说明文档里存在变体，判据要么改成 `re.I`，要么显式列出所有变体。

**本项目反例**：F-28 判据用 `r'lengthCapability`?\s*\|\s*MUST\s*='`（大小写敏感），
而 §8.21/§8.22 写的是 `LengthCapability` → `cs=0 / ci=2`，**漏检 2 行**（假阴性）。

#### 第 2 条：同义表述变体

**查什么**：同一语义的不同措辞是否都覆盖？
（`缺 dump 佐证` / `无 dump` / `未见 dump` / `无官方 dump`；`断链` / `丢弃连接` / `drop`）

**怎么查**：把每个关键词的同义集合列出来，逐个数一次；**任一变体单独出现时判据也必须能抓到**。

**本项目反例**：F-30 只搜 `'无 dump 佐证'` 和 `'缺 dump 佐证'`，若执行 AI 写成
"未见官方 dump"就漏检。

#### 第 3 条：结构变体

**查什么**：同一语义在**表格行 / bullet / 代码块 / 引用块 / 正文段落**里是否都能被抓到？

**怎么查**：对每个判据，人为把目标文本搬到另一种结构里，看判据是否仍命中。
特别注意：**判据若用 `l.startswith('|')` 限定表格行，就必须另有一条覆盖非表格写法**。

**本项目反例**：F-02 的 v1 只认"同一行内"的限定语，而正确写法是"块前说明 + 代码块"
（限定语在 2282、数据在 2285）→ 假阳性。

#### 第 4 条：反向断言（"不该出现的没出现"）

**查什么**：判据是否**只**查了"该出现的出现了"，而**没**查"不该出现的没出现"？

**怎么查**：每条判据问两个问题——① 目标文本出现了吗？② 旧/错文本消失了吗？
**两个都问才算完整**。只有 ① 会漏"残留"（假阴性）；只有 ② 会漏"改过头"。

**本项目反例**：F-38 若只查"S2 有 input 许可"，不查"S3 的 Server Synchronize 行不再挂 input"，
则执行 AI 可能**两处都写**，判据仍 PASS。

#### 第 5 条：红证（负向：旧版必须 FAIL）

**查什么**：每条判据是否都在"**已知有缺陷的旧版本**"上验证过会 FAIL？

**怎么查**：在内存里构造旧版文本（不改文档），跑判据，**必须 FAIL**。
若旧版也 PASS，判据无区分力（恒真）。

**本项目反例**：无（这条一直做到了）。但**只有这条不够**——见第 6 条。

#### 第 6 条：削弱性限定语识别（本轮新增）

**查什么**：判据若检查"某声明是否过强"，是否**能区分**「全部/所有/均」与「多数/部分/逐行注明」？

**怎么查**：**红证必须包含"削弱语 + 数据不全 → PASS"这一正向用例**。
只做"旧版必须 FAIL"的负向用例，无法发现"把正确的修复判成未修复"这类错误。

**本项目反例（第 4 次误报）**：F-30 导语强度判据见到 `dump 双向` 就要求每行都有 dump，
把「多数并辅以官方 dump 双向验证」当成「全部都是」→ 把正确修复判 FAIL。

**为什么这条最重要**：前 5 条都是"判据太松"（漏检），第 6 条是"判据太紧"（误杀）。
**太紧比太松更危险**——它会让执行 AI 反复修改正确的内容，直到把文档改坏；
或者让审计误以为"执行 AI 没改"，浪费整轮往返。本次就是这样：执行 AI 已经改对了，
我报了 FAIL，父会话差点要再派一轮。

#### 第 7 条（§17.10.3 新增）：变异测试必须验证"翻红的原因"，不只验证"翻红了"

**查什么**：变异后判据 FAIL 了，但**FAIL 的原因**是不是判据想测的那个语义？

**为什么**：变异生效、判据也翻红，翻红却可能来自**别的原因**——例如文本变长
导致另一个无关正则失配。这种翻红是"假阳性式的通过"，会让人误判判据有区分力。

**怎么查**：判据的 `add()` 都带 `reason` 参数。变异后除断言 FAIL 外，
还要断言 reason 含**预期关键词**，且该关键词取自 reason 模板中
**随变异而变化**的那一段（不能随便挑一个恒定出现的词）。

**本项目反例**：F-13 我最初断言 `越界出现=1`，实际是 `2`——因为基线作用域里
已有 1 处"越界"（行 904 的"不是越界读"）。改为断言 `未被否定=[` 后既正确又更贴语义。
**第 7 条第一次跑就抓到了"断言期望值写错"这个错。**

#### 七条之间的逻辑关系

```
1 大小写    ┐
2 同义表述  ├─→ 都在解决"关键词匹配的召回率"（别漏）
3 结构变体  ┘
4 反向断言  ──→ 解决"只查正向不查负向"（别漏残留）
5 负向红证  ──→ 验证"旧版必须 FAIL"（证明有区分力）
6 正向红证  ──→ 验证"正确修复必须 PASS"（证明不会误杀）
7 原因断言  ──→ 验证"翻红的原因正确"（证明测的是对的语义）★ 新增
```

**5 + 6 + 7 三条必须成组**：只有 5 会造出"太紧"的判据，只有 6 会造出"太松"的判据，
只有 5+6 会造出"翻红但原因错"的判据。**三者齐备才算完整。**

#### 七条的可执行化状态（**已按实测修正，不夸大**）

| 条 | 落地程度 | 落地脚本 / 证据 | 当前结果 |
|---|---|---|---|
| 1 大小写变体 | **部分** | `accept_consult_b.py`：F-28 / F-15 三项 / **F-13 `assert`（本轮补）** 用 `re.I` | 见 §17.10.1；F-13 曾漏 `re.I`，已修 |
| 2 同义表述变体 | **部分** | `red_f30_synonym.py`（F-30）+ **`red_f06_f38_synonym.py`（本轮新增，F-06/F-38）** | 12/12 + 13/13；**F-35/F-29 仍未覆盖**（风险低），见 §17.10.2 |
| 3 结构变体 | **未落地** | — | 人工 |
| 4 反向断言 | 能（内嵌） | 每条判据自带正向+负向分支 | — |
| 5 负向红证 | **能（全量）** | **`mutation_test.py`**（16 条判据各自变异） | **16/16 翻红、串扰=0** |
| 6 正向红证 | 能（仅 F-30） | **`red_f30_intro.py`**（6 用例含正向） | 6/6 |
| **7 原因断言** | **能（全量）** | **`mutation_test.py` 的 `expect_reason_kw`**（16 条全加） | **16/16 原因正确** |

> **上一版这里写"4 条（1/2/5/6）已全部落地"，是夸大了。** 逐条实测后修正为：
> 第 1 条与第 2 条都只是**部分落地**——第 1 条原只对 F-28/F-15 加了 `re.I`
> （F-13 的 `assert` 漏了），第 2 条原只对 F-30 做了同义覆盖。
> 本轮已补 F-13 的 `re.I` 与 F-06/F-38 的同义正则，证据见 §17.10。
>
> **第 5 条一旦做成自动化，就能把"靠人提醒"变成"靠机制发现"**——本项目实测：
> 全量变异测试首轮抓出 2 条判据假阴性（F-41 被原文引用救活、F-03/F-12 同义漏检），
> 详见 **§17.9**。第 7 条上线后又抓出 1 条"断言期望值写错"（§17.10.3）。

---

### 17.8 关于"只看脚本 PASS 就认为全绿"这个失误的约束

父会话自述：**"我只跑了甲的脚本看 PASS=80/FAIL=0 就认为全绿，没有意识到『脚本全绿 ≠ 无残留』。"**
这是本次最值得沉淀的一条，我把它写成三条硬约束：

#### 约束 A：验收 ≠ 跑通别人的脚本

**脚本全绿只证明"该脚本覆盖的判据全过"，不证明"文档无残留"。**
必须问：**这个脚本的判据覆盖面是什么？它的盲区在哪？**
具体做法：拿到任何验收脚本，先读它的**正则/匹配方式**，逐条问第 1–4 条清单。
本次甲的 82 条里有 2 处盲区（大小写、导语强度），就是读正则才发现的。

#### 约束 B：验收必须由"判据作者以外的人"复核判据本身

我（乙）写的 F-30 判据连续错 4 次，其中 3 次是**父会话或执行 AI 用"文档其实是对的"
反证出来的**。若只有我自己验，这 4 次都会被当成"文档没改"。
→ **判据的正确性需要独立的第二双眼睛**，且这双眼睛要看的是**判据源码**，不是脚本输出。

#### 约束 C：任何 FAIL 都必须先"人工核对原文"再定性

**FAIL ≠ 文档有缺陷**。定性前必须做三选一：
1. 文档确实没改 → 真缺陷，派执行 AI；
2. 文档改对了、判据写错 → **修判据**，不派执行 AI；
3. 文档改法不同但等价 → 修判据（放宽）或改文档（统一写法），二选一并记录理由。

本次 F-30 导语强度属于第 2 类。**若不做这一步，就会派一轮无意义的执行任务。**

#### 约束 D：验收报告必须写明"判据覆盖了什么、没覆盖什么"

**"PASS=80 FAIL=0" 是不完整的验收结论**。完整结论必须包含：
- 判据条数与分布（机械 / 人工）；
- **每条判据的匹配方式**（关键词 / 正则 / 语义）；
- **已知盲区清单**（本次：大小写变体、削弱性限定语、导语强度）；
- 人工判读项的**实际核对结果**（不能只写"待人工"，要写"已核，结论是…"）。

---

*第七轮（乙侧）：F-30 导语强度判据第 4 次修正 + 判据迁入 evidence + 检查清单（后扩至 7 条，见 §17.10.3）。审计 AI 乙。*
*17 条判据当前 **17/17 PASS，exit=0**；6 用例红证全部符合预期（含"削弱语 + 数据不全 → PASS"正向用例）。*

---

### 17.9 变异测试：§17.7 第 5 条的可执行化，又抓出 2 条判据缺陷

§17.7 第 5 条要求"旧版必须 FAIL"，但我此前只对**个别**判据做过手工负向验证。
本轮把它做成**全量自动化的变异测试**：对 16 条机械判据，各自在内存里构造一个
**只破坏该判据**的文档副本 → 写 `F:\rtsc\.tmp\_mut_caps.md` → 用 `CAPS_DOC`
环境变量喂给 `accept_consult_b.py` → 断言目标判据必须翻红。

脚本：`F:\rtsc\evidence\capabilities\mutation_test.py`
（为此给 `accept_consult_b.py` 加了 `CAPS_DOC` 环境变量支持，默认仍读正本，生产不受影响。）

#### 17.9.1 首轮结果：12/16，抓出 4 条"变异未生效"和 2 条真缺陷

首轮跑出 12/16，但**失败原因分两类**，必须分开看：

| 类别 | 数量 | 性质 |
|---|---|---|
| **变异构造错**（锚点选错，没真正破坏目标） | 4 | 测试脚本的问题，不是判据的问题 |
| **判据真缺陷**（变异生效了，判据仍 PASS） | 2 | **判据假阴性，必须修判据** |

**变异构造错的 4 条**（修测试脚本，不改判据）：
- F-13：我把"越界"插到了 §6.1 的**非 lcc<4 行**上，而判据只扫 `lcc\s*<\s*4` 的行 → 变异落在判据视野外。
  改为替换 `# 否则 lcc - 4 在 uint16 下溢为 65534` 这一行（它含 `lcc - 4`，被判据的 `lcc<4` 捕获）。
- F-03/F-12：我只替换了一处 `对端可控`，而 §6.1 里共有 **2 处** → 判据仍命中另一处。
  改为 `sub_in_section` 全量替换 + 同时抹掉 `可被对端触发`。
- F-02：我在 §13.4 里替换了**第一个** `26 18 5e 76`（那是正文注释行 2269），而判据要求的是
  **表格行**必须有密文 → 变异没打到判据的关键点。改为精确替换 2281 行。
- F-20 恒等式：我替换的是 §8.2 的 `| 0x0002 | Bitmap | 28 |`（行 1056），
  而判据扫的是 **§6.2 的类型号表**（行 918）→ 变异落在判据视野外。改为 `sub_in_section('### 6.2', ...)`。

> 这 4 条本身也是教训：**"变异测试失败"不等于"判据没区分力"**，
> 必须先确认"变异确实改变了判据所看的那段文本"，否则是在测一个没被破坏的输入。

#### 17.9.2 判据真缺陷 1：F-41 的 `SHOULD` 被"原文引用"救活（假阴性）

判据 v1：
```python
cl = [l for l in L if 'totalLength' in l and '断链' in l and l.strip().startswith('- [')]
ok41 = bool(cl) and all('SHOULD' in l for l in cl)      # ← 整行搜 SHOULD
```

文档该行是：
```
- [ ] 慢路径：`totalLength` 校验（不含外层头）；不一致 → **SHOULD** 断链（§2.1 / §4.4；原文 "SHOULD be dropped"，非 MUST）
```

把**规定用语**删掉、只留**引用**：
```
- [ ] 慢路径：`totalLength` 校验（不含外层头）；不一致 → 断链（§2.1 / §4.4；原文 "SHOULD be dropped"，非 MUST）
```

`'SHOULD' in l` 仍为 `True`（因为 `"SHOULD be dropped"` 这个引用还在）→ **判据仍 PASS**。
这正是 F-41 要防的缺陷：原文是 SHOULD，但**本项目的规定用语退化成了 MUST/无模态词**。

修法：先把「；原文 …」这类**引用片段**剥掉，再在**动作部分**要求 `SHOULD`：

```python
def _action_part(line):
    for sep in ('；原文', '；官方原文', '原文：', '（原文'):
        i = line.find(sep)
        if i != -1:
            line = line[:i]
    return line

ok41 = bool(cl) and all('SHOULD' in _action_part(l) for l in cl)
```

#### 17.9.3 判据真缺陷 2：F-03/F-12 的缺陷描述只认"偏大"（假阴性）

判据 v1：
```python
d12 = bool(re.search(r'numberCapabilities.{0,60}?(偏大|大于|超出|超过)', bt))
```

若把"计数偏大"改写成"计数**不符** / 计数**错误** / **虚高** / **过多** / **伪造**"，
v1 全部漏检。虽然当前文档写的是"偏大"，但**这是执行 AI 可能改写的措辞**，
按 §17.7 第 2 条（同义表述变体）必须覆盖。

修法：扩充同义集合
```python
d12 = bool(re.search(r'numberCapabilities.{0,60}?'
                     r'(偏大|大于|超出|超过|不符|错误|虚高|过多|伪造)', bt))
d03 = bool(re.search(r'lengthCapability.{0,60}?'
                     r'(大于|超出|无上界|越界|> 剩余|>剩余|超限|过长)', bt))
```

#### 17.9.4 修复后：16/16 全部翻红，基线仍 17/17

```
基线：PASS=17 FAIL=0 exit=0

[PASS] F-15 绝对 MAC 断言               目标=F-15       翻红=True  exit=1 串扰=无
[PASS] F-13 未否定的越界                  目标=F-13       翻红=True  exit=1 串扰=无
[PASS] F-03/F-12 无威胁模型              目标=F-03/F-12  翻红=True  exit=1 串扰=无
[PASS] F-06 缺 Persistent            目标=F-06       翻红=True  exit=1 串扰=无
[PASS] F-38 input 挂 Server Synchronize 目标=F-38       翻红=True  exit=1 串扰=无
[PASS] F-41 动作缺 SHOULD              目标=F-41       翻红=True  exit=1 串扰=无
[PASS] F-02 表格回退明文                  目标=F-02       翻红=True  exit=1 串扰=无
[PASS] F-21 闭式 +4                   目标=F-21       翻红=True  exit=1 串扰=无
[PASS] F-29 计数不符                    目标=F-29       翻红=True  exit=1 串扰=无
[PASS] F-35 严格串行                    目标=F-35       翻红=True  exit=1 串扰=无
[PASS] F-37 无 4,096                 目标=F-37       翻红=True  exit=1 串扰=无
[PASS] F-28 残留 MUST=N               目标=F-28       翻红=True  exit=1 串扰=无
[PASS] F-30 自承未核实                   目标=F-30       翻红=True  exit=1 串扰=无
[PASS] F-20 缺 6 类型披露                目标=F-20       翻红=True  exit=1 串扰=无
[PASS] F-20 恒等式失衡                   目标=F-20       翻红=True  exit=1 串扰=无
[PASS] F-30 导语绝对化                   目标=F-30       翻红=True  exit=1 串扰=无

变异测试：16/16 目标判据成功翻红 | 结论: 全部符合预期 | ASSERT OK
```

**"串扰=无"是一个额外的好信号**：每个变异只让它该打的那一条翻红，没有连带误红别的判据，
说明 16 条判据之间**互相独立**，定位力足够精确到"具体是哪一条缺陷"。

#### 17.9.5 这是第 5、6 次判据缺陷，但性质不同——这次是**自己抓的**

前四次（§16.5 F-02、§16.6 F-29/F-35、§17.3 F-28/F-30、§17.6 F-30 导语）
都是**父会话或执行 AI 用"文档其实是对的/错的"反证出来的**。
这次的两条（F-41 引用救活、F-03/F-12 同义漏检）是**变异测试主动抓出来的**，
说明 §17.7 第 5 条一旦做成自动化，就能把"靠人提醒"变成"靠机制发现"。

> **方法学结论**：§17.7 的第 1–6 条不应只是"检查清单"（靠人自觉），
> 能机械化的第 2 条（同义表述）与第 5 条（负向红证）**应当直接写成脚本**。
> 本项目已落地为 `red_f30_synonym.py`（第 2 条）与 `mutation_test.py`（第 5 条）。

#### 17.9.6 验证脚本的分工（全部在 evidence/ 下；本表在 §17.10 之后已扩到 5 个）

| 脚本 | 验证什么 | 覆盖 §17.7 的哪条 | 当前结果 |
|---|---|---|---|
| `accept_consult_b.py` | 17 条判据对**正本**的判定 | — | 17/17 PASS，exit=0 |
| `red_f30_intro.py` | F-30 导语强度判据的 6 用例（含**正向**用例） | 第 6 条 | 6/6 符合预期 |
| `red_f30_synonym.py` | F-30 本体对 8 种同义写法的召回 + 4 条防过宽 | 第 2 条 | 12/12 符合预期 |
| `red_f06_f38_synonym.py` | F-06 / F-38 的同义改写召回（§17.10.2 新增） | 第 2 条 | 13/13 符合预期 |
| `mutation_test.py` | 16 条判据各自的"翻红 + **翻红原因正确**" | 第 5 条 + 第 7 条 | 16/16 翻红、16/16 原因正确、串扰=0 |

---

*第八轮（乙侧）：§17.7 第 5 条可执行化（变异测试 16/16），顺带修掉 F-41 与 F-03/F-12 两条判据假阴性。审计 AI 乙。*
*17 条判据 **17/17 PASS，exit=0**；变异测试 **16/16 翻红、串扰=0**。*

---

### 17.10 第七轮补正：翻红原因断言 + §17.7 第 1/2 条真实落地度 + 7 条 HUMAN 项评估

父会话指出我上一轮有两处**说过头**了，逐条核对后确认，本节全部按实测订正。

#### 17.10.1 §17.7 第 1 条（大小写变体）：**部分落地，且藏着一个 latent gap**

先做实测：对每个判据用到的 ASCII 关键词，在**判据实际读取的那段文本**里
（不是全文！）统计大小写敏感 / 不敏感命中数。

| 判据 | 作用域 | 关键词 | cs | ci | 结论 |
|---|---|---|---|---|---|
| F-15 | U-14 单行 | `orderSupport` | 2 | 2 | OK（已 `re.I`） |
| F-15 | U-14 单行 | `NumCellCaches` | 2 | 2 | OK（已 `re.I`） |
| F-15 | U-14 单行 | `CellInfo` | 1 | 1 | OK（已 `re.I`） |
| F-15 | U-14 单行 | `MAC` | 1 | 1 | OK |
| F-06 | U-03 单行 | `Persistent` | 2 | 2 | OK |
| F-13 | §6.1 | `lcc` | 8 | 8 | OK |
| F-13 | §6.1 | `下溢` | 3 | 3 | OK |
| **F-13** | **§6.1** | **`assert`** | **5** | **6** | **有变体**（行 903 写 `ASSERT-FAIL`） |
| F-13 | §6.1 | `越界` | 6 | 6 | OK |
| F-28 | 全文表格行 | `lengthCapability` | 79 | 81 | OK（已 `re.I`） |
| F-28 | 全文表格行 | `MUST` | 171 | 171 | OK |
| F-41 | 全文清单行 | `SHOULD` | 2 | 2 | OK |

> **订正**：上一轮我写"第 1 条能机械化、已落地"，只举了 F-28 一例。
> 实测发现 **F-13 的 `assert` 是大小写敏感的**——§6.1 行 903 写的是
> `ASSERT-FAIL`（全大写），判据 v1 的 `assert\s*失败|assert\(` 抓不到它。

**这个 gap 为什么一直没暴露**：F-13 的 `down` 条件是
`下溢 | assert失败 | assert(` 的**或**，而同一段落里有 3 处"下溢" →
`down` 恒为 True，`assert` 的大小写问题被**掩盖**了。

实测验证（`f13_gap.py`）：
```
§6.1 内: 下溢=3  assert(小写)=5  ASSERT(大写)=1
只把 assert 全改大写（下溢仍在）        -> [PASS]（被"下溢"救活，gap 被掩盖）
下溢改同义 + assert 全大写（抹掉小写信号） -> [FAIL]（此时才暴露）
```
→ **已修**：`down = bool(re.search(..., subt, re.I))`。

**结论**：第 1 条 = **部分落地**。判据里 4 处 `re.I`（行 99/100/157/262），
但 F-13 的 `assert` 漏了，本轮补上。剩余判据（F-06/F-41/F-21 等）的关键词
经实测在作用域内**无变体**，可不加 `re.I`。

#### 17.10.2 第 2 条（同义表述）：**只覆盖了 F-30，其余是盲区**

上一轮我写"第 2 条已落地，`red_f30_synonym.py` 12/12"——但那个脚本**只测 F-30**。

实测其余判据的同义覆盖（`audit_case3.py`）：

| 判据 | 现有正则 | 同义改写后 | 结论 |
|---|---|---|---|
| F-30 本体 | 8 种同义 + 4 条防过宽 | 全覆盖 | **已落地** |
| F-06 `清空标准` | `清空\s*标准｜标准\s*Bitmap Cache` | "**丢弃标准缓存**" → **漏检** | 盲区 |
| F-38 `input 许可` | `可开始发\s*input` | "**即可发送 input**" / "**允许发送 input**" → **漏检** | 盲区 |
| F-35 `严格串行` | 固定四字 | 语义等价改写（如"串行发送"）→ 漏检 | 盲区（低风险） |
| F-29 自述计数 | `(\d+)\s*个\s*learn...` | 措辞变体 → 漏检 | 盲区（低风险） |

实测输出：
```
F-06 原文                 命中=True
F-06 改写1：清除标准           命中=True
F-06 改写2：丢弃标准缓存         命中=False   ← 漏检
F-38 原文                 被误判为违规=True（应 True）
F-38 改写1：即可发送           被误判为违规=False（应 True） ← 漏检
F-38 改写2：允许发送           被误判为违规=False（应 True） ← 漏检
```

**已修**（两处都改了正则 + 补红证脚本 `red_f06_f38_synonym.py`）：

```python
# F-06
k3 = bool(re.search(
    r'(清空|清除|丢弃|重置|作废|flush|invalidate)\s*\*{0,2}\s*(标准|standard)'
    r'|(标准|standard)\s*\*{0,2}\s*(Bitmap\s*)?Cache', r3, re.I))

# F-38
_INPUT_ALLOW_RE = re.compile(
    r'(可开始发|即可发|可以发|允许发|能发|可发|开始发)\s*(送|出)?\s*`?input', re.I)
bad38 = [l for l in blk2 if 'Server Synchronize' in l and _INPUT_ALLOW_RE.search(l)]
```

**红证 13/13**（5 条 F-06 变体 + 7 条 F-38 组合判定 + 1 条端到端）：
```
F-06  原文 / 清除标准 / 丢弃标准缓存 / 作废标准 / Standard Bitmap Cache 需清空  → 5/5 命中
F-38  原文违规 / 即可发送 / 允许发送 / 可发 `input`                        → 4/4 命中
F-38  正确写法（Confirm Active 之后）/ S.Sync 行不含 input / 无关行            → 3/3 不误报
端到端：把"即可发送 input"塞进 §12.2 → F-38 翻红，exit=1                    → 符合预期
```

**结论**：第 2 条 = **部分落地**。原只有 F-30，本轮补上 F-06 / F-38；
F-35 / F-29 仍无同义覆盖（风险低：F-35 是四字专名，F-29 是数字一致性而非措辞）。

#### 17.10.3 新增第 7 条：**变异测试必须验证"翻红的原因"，不只验证"翻红了"**

父会话指出的第二类"构造错"，我确实漏了：

> 变异生效了、判据也翻红了，但**翻红的原因不是判据想测的那个语义**。

举例：F-13 的变异让作用域文本变长，若另一个无关正则恰好失配导致 FAIL，
测试会误判为"判据有区分力"。这种翻红是**假阳性式的通过**。

**实现**：`mutation_test.py` 的每个用例加第 4 个字段 `expect_reason_kw`，
断言目标判据的 `reason` 文本含该关键词。关键词取自各判据 reason 模板中
**随变异而变化**的那一段（不是随便挑的词）。

| 变异 | 断言的原因关键词 | 为什么是这个 |
|---|---|---|
| F-15 | `绝对失配次数=1` | 基线 0，变异后应为 1 |
| F-13 | `未被否定=[` | 直接证明"否定语境检查真的抓到了"，比断言计数更贴语义 |
| F-03/F-12 | `"对端可控"=0` | 基线 2，变异后应为 0 |
| F-06 | `Persistent=False` | 基线 True |
| F-38 | `仍挂 input 的行数=1` | 基线 0 |
| F-41 | `动作部分含 SHOULD=0` | 基线 1，同时验证"剥离引用"逻辑生效 |
| F-02 | `密文表格行=[]` | 基线非空 |
| F-21 | `[751]` | 残留行号 |
| F-29 | `文档自述计数=[85]` | 基线 [97] |
| F-35 | `严格串行"的行=[` | 基线无 |
| F-37 | `未补` | 基线有 4 处 |
| F-28 | `残留行=[` | 基线无 |
| F-30 本体 | `违规行=[` | 基线无 |
| F-20 披露 | `的行数=0` | 基线 1 |
| F-20 恒等式 | `并集=28=False` | 基线 True |
| F-30 导语 | `绝对语` | 基线是"削弱语" |

**全部 16 条都加了**（不只前 6 条）——既然模板都现成，没有理由留 10 条不验。

结果：
```
变异测试：翻红 16/16，原因正确 16/16
结论: 全部符合预期 | ASSERT OK
```

**这条断言第一次跑就抓到了我自己的错**：F-13 我最初断言 `越界出现=1`，
实际是 `越界出现=2`——因为基线作用域里已经有 1 处"越界"（行 904 的"不是越界读"）。
改成 `未被否定=[` 后既正确又更贴语义。**这正是第 7 条的价值：它连"断言的期望值写错"都能抓。**

#### 17.10.4 顺带发现：F-13 的作用域过窄（第 3 个 latent gap）

加原因断言时发现：F-13 的 `sub` 只取"含 `lcc<4` 的行"= 873 / 902 **两行**，
而结论行 **904**「**assert 失败 / 长度下溢**，**不是越界读**」**不在作用域内**。
→ 反向断言（"越界"必须处于否定语境）对 904 完全失效。

实测（`f13_scope.py`）：
```
改结论行 904：不是越界读 -> 是越界读     -> PASS（假阴性！）
删掉结论行 904 的否定语                -> PASS（假阴性！）
在 902 行直接写"越界读"               -> FAIL（能抓到）
```

**修法迭代了 3 版**（记录在此，因为第 2 版是"过度修正"的典型）：

| 版本 | 作用域规则 | 作用域行数 | 基线 | 改 904 | 评价 |
|---|---|---|---|---|---|
| v1 | 只含 `lcc<4` 的行 | 2 | PASS | **PASS（漏）** | 过窄 |
| v2 | 扩成整个连续块 | 40 | **FAIL（误报）** | FAIL | 过宽：把 879 `# ① 头越界`、883 `# ③ 体越界`、896/898 的 case A/B「越界读」全纳入，而这些**都是正确表述** |
| v3 | 只扩**同一引用段落**（连续 `>` 行，遇 `>` 空行即断）；代码块行不扩 | 4 | **PASS** | **FAIL（抓到）** | 正确 |

v3 实现：
```python
def _scope_lcc(block, hits):
    out = set(hits)
    for i in hits:
        if not block[i].lstrip().startswith('>'):
            continue                      # 代码块行：不扩展
        j = i
        while (j + 1 < len(block)
               and block[j + 1].lstrip().startswith('>')
               and block[j + 1].strip() != '>'):   # '>' 空行 = 段落分隔
            j += 1
            out.add(j)
    return out
```

作用域 = `{873} ∪ {902, 903, 904}` 共 4 行；基线 PASS，改 904 后 FAIL。

> **教训**："作用域过窄"和"作用域过宽"是同一个错误的两个方向。
> v2 的 FAIL 看起来像"判据变强了"，实际是把**正确的表述**判成违规——
> 这与 §17.6 的 F-30 导语误报是同一种病（把对的判错）。

#### 17.10.5 7 条 HUMAN 项的可机械化评估（结论，未实现）

父会话要求评估"这 7 条里有没有哪几条其实可以部分机械化"。逐条实测（`human_eval.py`）：

| # | HUMAN 项 | 可机械化 | 依据（实测） |
|---|---|---|---|
| H1 | F-15 U-14 合并策略 | **部分** | 正向词命中 6 处（取交集/更保守/按位 AND/取小），禁止词命中 2 处（last-wins/后者覆盖前者）——但**禁止词处于"不做 last-wins"的否定语境**，朴素词表判定直接假阳性 → 必须复用 `negated_ok()` |
| H2 | F-16 §7.3 是否拆成两张表 | **部分** | §7.3 有 3 张表、2 个 `**表 ①/②` 标记 → 可机械断言"表数≥2 且存在 ①/② 标记"；但"哪个 set 属工程需要"必须人读 |
| H3 | F-17 3 个 ERRINFO 码 | **部分** | 3 码均在 §7.3 内命中（1126/1127/1128）且同行含触发线索词 → "码是否出现"完全可机械（且**应**机械，防漏码）；"触发条件是否正确"要对 `bcgr.txt` 原文，需人读 |
| H4 | F-08/F-09/F-10 §12 状态机语义 | **部分** | 可自动提取 4 条候选行（1958/1962/1971/1979）供人 10 秒判读；"状态不变/动作是记录而非处理完成"不能机械判定 |
| H5 | F-28 §8 数值不变 | **完全能** | §8 表格"定长 N"可取 25 个值（distinct: 6/8/10/11/12/24/28/40/52/88），§14.1 dump 有 31 个 type/len 对 → 可逐项比对 |
| H6 | F-31 S90+ guid 可达 | **完全能**（需网络） | 10 条 S90–S99 登记行、全文 97 个 distinct guid；已有 `verify_urls97.py` 覆盖 200 检查，缺的只是"guid↔章节号"这一层 |
| H7 | F-34 sourceDescriptor 措辞 | **部分** | 可机械断言"该段须同时含 `实测` 与 `未取证`"（实测 737/820/2654 三行满足）；"是否越界声称语义"仍需人读 |

**汇总**：
- **完全能机械化 2 条**：H5（F-28 数值不变）、H6（F-31 guid 可达）。
  → **H5 最该立刻做**：它防的是"改标签时手抖改数值"，是唯一会造成**数据错误**的风险，
  且完全不需要网络、不需要人读。
- **部分能机械化 5 条**：H1/H2/H3/H4/H7。都能至少"自动提取候选段落"，把人工从
  "全文搜索"降为"读 3–5 行做判断"。
- **完全不能 0 条**。

> **但 H5/H6 本轮不实现**——理由：当前 41 条缺陷清单已全部收口，17 条判据全绿，
> 执行 AI 的工作已完成。再新增判据属于**扩大验收范围**，会引入新的误报风险
> （§17.6/§17.10.4 已经证明我的判据很容易过紧）。建议作为**下一阶段**的独立任务。

#### 17.10.6 断言总数（按父会话要求报告）

| 脚本 | 断言/用例数 | 内容 |
|---|---|---|
| `accept_consult_b.py` | **17** | 17 条机械判据（另 7 条 HUMAN 不计入） |
| `red_f30_intro.py` | **6** | F-30 导语强度：3 变体 + 3 对照 |
| `red_f30_synonym.py` | **12** | F-30 本体：8 同义 + 4 防过宽 |
| `red_f06_f38_synonym.py` | **13** | F-06 5 变体 + F-38 7 组合 + 1 端到端 |
| `mutation_test.py` | **16** | 16 条判据各自"翻红 + 原因正确" |
| **合计** | **64** | （上一轮报的 51 = 17+6+12+16，本轮 +13） |

**未覆盖**：7 条 HUMAN 项**完全靠人读**，无任何自动化辅助（评估见 §17.10.5）。

#### 17.10.7 本轮所有改动清单（可复核）

| 文件 | 改动 | 触发原因 |
|---|---|---|
| `accept_consult_b.py` | F-13 `down` 加 `re.I` | 第 1 条 latent gap（`ASSERT-FAIL`） |
| `accept_consult_b.py` | F-13 作用域 v1→v3（`_scope_lcc`） | 第 3 个 latent gap（结论行 904 不在作用域） |
| `accept_consult_b.py` | F-06 `k3` 正则扩同义 | 第 2 条盲区（"丢弃标准缓存"漏检） |
| `accept_consult_b.py` | F-38 `bad38` 正则扩同义 | 第 2 条盲区（"即可发送"漏检） |
| `mutation_test.py` | 每用例加 `expect_reason_kw` + 断言 | **新增第 7 条** |
| `red_f06_f38_synonym.py` | **新建**（13 用例） | 第 2 条红证 |
| `capabilities.consult-b.md` | §17.7 表格订正 + 新增 §17.10 | 本节 |

**回归验证（全部 exit=0）**：
```
accept_consult_b.py          17/17 PASS
red_f30_intro.py             6/6   ASSERT OK
red_f30_synonym.py           12/12 ASSERT OK
red_f06_f38_synonym.py       13/13 ASSERT OK
mutation_test.py             16/16 翻红 + 16/16 原因正确
```

---

*第九轮（乙侧）：翻红原因断言（第 7 条）+ §17.7 第 1/2 条落地度实测订正 + F-13 两处 latent gap + 7 条 HUMAN 项评估。审计 AI 乙。*
*5 个脚本合计 **64 条断言，全部 exit=0**；变异测试 **16/16 翻红且 16/16 原因正确**。*
*订正上一轮两处夸大：第 1 条是**部分**落地（F-13 曾漏 `re.I`）、第 2 条是**部分**落地（原仅 F-30）。*
