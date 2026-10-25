# MCS / GCC 连接层字段规格（T.125 Connect Initial / Connect Response + T.124 GCC Conference Create）

本文件是 RTSC 项目 MCS/GCC 连接层的实现依据，逐字段、逐字节可追溯。

**来源等级约定**

| 等级 | 含义 |
|---|---|
| A | 微软官方规范原文（[MS-RDPBCGR] 网页 markdown / 官方 PDF） |
| B | ITU-T 官方规范原文（T.124 / T.125 官方 PDF，由 MS-RDPBCGR 1.2.1 规范引用指定版本） |
| C | 由 A/B 原文推导（本文明确标注"推断"） |

**重要结论（先读）**

- RDP 使用的 MCS 版本为 **Version 2 编码规则**：Connect MCSPDU 用 **BER**（definite length），后续 Domain MCSPDU 用 **PER aligned**（[MS-RDPBCGR] 2.2，A 级）。
- GCC 层（T.124）外层 `ConnectData`/`ConferenceCreate*` 用 **PER aligned**，内层 PDU 单独 PER 编码后放入 OCTET STRING（T.124 §9.6，B 级）。
- 所有多字节整数字段（除 BER/PER 内部编码外）为 **little-endian**（[MS-RDPBCGR] 2.2，A 级）。
- `h221NonStandard` 客户端键在线上是 **4 字节 `44 75 63 61`（"Duca"）**，前面 1 字节 `0x00` 是 PER 长度决定因子（length-4）。**不存在 8 字节键**（详见 §4.3 与 §10.1）。
- 规范中**没有** `convMode` / `convCreate` 字段（详见 §10.2）；对应语义由 `lockedConference` / `listedConference` / `conductibleConference` / `terminationMethod` 及可选扩展 `conferenceMode` 承担。
- [MS-RDPBCGR] **没有** "Server Monitor Data" / "Server Monitor Extended Data" 小节（详见 §10.3）。

---

## 0. 规范来源清单（全部实际抓取，HTTP 200）

| 编号 | 标题 | URL | 等级 |
|---|---|---|---|
| S1 | 2.2 Message Syntax | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b61e1c76-5d7c-4285-b61a-b69f85e4a0e2 | A |
| S2 | 2.2.1.3 Client MCS Connect Initial PDU with GCC Conference Create Request | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db6713ee-1c0e-4064-a3b3-0fac30b4037b | A |
| S3 | 2.2.1.3.1 User Data Header (TS_UD_HEADER) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8a36630c-9c8e-4864-9382-2ec9d6f368ca | A |
| S4 | 2.2.1.3.2 Client Core Data (TS_UD_CS_CORE) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73 | A |
| S5 | 2.2.1.3.3 Client Security Data (TS_UD_CS_SEC) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6b58e11e-a32b-4903-b736-339f3cfe46ec | A |
| S6 | 2.2.1.3.4 Client Network Data (TS_UD_CS_NET) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/49f99e00-caf1-4786-b43c-d425de29a03f | A |
| S7 | 2.2.1.3.4.1 Channel Definition Structure (CHANNEL_DEF) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a9b9dc4a-6ae4-4b04-a6f5-87e5ed6fd7e7 | A |
| S8 | 2.2.1.3.5 Client Cluster Data (TS_UD_CS_CLUSTER) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d68c629f-36a1-4a40-afd0-8b3e56d29aac | A |
| S9 | 2.2.1.3.6 Client Monitor Data (TS_UD_CS_MONITOR) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a8029f8e-01e1-4f19-af67-bcad5bdef624 | A |
| S10 | 2.2.1.3.6.1 Monitor Definition (TS_MONITOR_DEF) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/c3964b39-3d54-4ae1-a84a-ceaed311e0f6 | A |
| S11 | 2.2.1.3.7 Client Message Channel Data (TS_UD_CS_MCS_MSGCHANNEL) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f50e791c-de03-4b25-b17e-e914c9020bc3 | A |
| S12 | 2.2.1.3.8 Client Multitransport Channel Data (TS_UD_CS_MULTITRANSPORT) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3801236b-b5ba-4b6e-bf0d-afbde1fe391c | A |
| S13 | 2.2.1.3.10 Client Monitor Extended Data (TS_UD_CS_MONITOR_EX) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfaf8842-c20c-4626-bd3b-8b7d0463bc0f | A |
| S14 | 2.2.1.3.10.1 Monitor Attributes (TS_MONITOR_ATTRIBUTES) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8fb3a83c-f3e2-4a81-8824-8173af03b6bc | A |
| S15 | 2.2.1.4 Server MCS Connect Response PDU with GCC Conference Create Response | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/927de44c-7fe8-4206-a14f-e5517dc24b1c | A |
| S16 | 2.2.1.4.2 Server Core Data (TS_UD_SC_CORE) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/379a020e-9925-4b4f-98f3-7d634e10b411 | A |
| S17 | 2.2.1.4.3 Server Security Data (TS_UD_SC_SEC1) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e86b68d-3e2e-4433-b486-878875778f4b | A |
| S18 | 2.2.1.4.4 Server Network Data (TS_UD_SC_NET) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/89fa11de-5275-4106-9cf1-e5aa7709436c | A |
| S19 | 2.2.1.4.5 Server Message Channel Data (TS_UD_SC_MCS_MSGCHANNEL) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9269d58a-3d85-48a2-942a-bb0bbe5a55aa | A |
| S20 | 2.2.1.4.6 Server Multitransport Channel Data (TS_UD_SC_MULTITRANSPORT) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/bf7201d4-9ed9-4dfe-9f6f-f2d68a7367ed | A |
| S21 | 2.2.1.4.3.1.1 Server Proprietary Certificate | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a37d449a-73ac-4f00-9b9d-56cefc954634 | A |
| S22 | 2.2.1.4.3.1.1.1 RSA Public Key | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/fe93545c-772a-4ade-9d02-ad1e0d81b6af | A |
| S23 | 3.2.5.3.3 Sending MCS Connect Initial PDU（客户端 SHOULD 取值表） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/c1bea8bd-069c-4437-9769-db5d27935225 | A |
| S24 | 3.3.5.3.3 Processing MCS Connect Initial PDU（服务端合并/校验规则） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7617f746-95c9-4a6e-808d-e2f642471e86 | A |
| S25 | 3.3.5.3.4 Sending MCS Connect Response PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3a2b869f-5096-439b-bfc5-55a4ccfa10f8 | A |
| S26 | 4.1.3 Annotated dump: Connect Initial | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2610fcc7-3df4-4166-85bb-2c7ae21f6151 | A |
| S27 | 4.1.4 Annotated dump: Connect Response | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d23f7725-876c-48d4-9e41-8288896a19d3 | A |
| S28 | 1.3.1.1 Connection Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee | A |
| S29 | [MS-RDPBCGR] 官方 PDF（v20260309，444 页） | https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RDPBCGR/%5bMS-RDPBCGR%5d.pdf | A |
| S30 | T.125 (02/98) 官方 PDF | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.125-199802-I!!PDF-E&type=items | B |
| S31 | T.124 (01/2007) 官方 PDF | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.124-200701-I!!PDF-E&type=items | B |
| S32 | T.124 (02/98) 官方 PDF | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.124-199802-S!!PDF-E&type=items | B |
| S33 | X.691 (07/2002) 官方 PDF（PER 长度决定因子 §10.9.3） | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.691-200207-S!!PDF-E&type=items | B |

> 注：任务给出的 `9cde84cd-5055-475a-acb0-9a0f8d9c1c4c` 是 **2.2.1.10 Security Exchange PDU** 的 GUID，不是 2.2.1.3，直接访问返回 404。正确入口为 S2。本表所有 URL 均实测 HTTP 200。

---

## 1. 顶层封装链

客户端 → 服务端（Connect Initial），共 5 层：

```
+-------------------------------------------------------------+
| TPKT Header                        4 bytes   (offset 0)     |
+-------------------------------------------------------------+
| X.224 Class 0 Data TPDU            3 bytes   (offset 4)     |
+-------------------------------------------------------------+
| MCS Connect-Initial (BER)          8+ bytes  (offset 7)     |
|   0x7F 0x65 | BER length | value                            |
|   value = SEQUENCE {                                        |
|       callingDomainSelector  OCTET STRING                   |
|       calledDomainSelector   OCTET STRING                   |
|       upwardFlag             BOOLEAN                        |
|       targetParameters       DomainParameters               |
|       minimumParameters      DomainParameters               |
|       maximumParameters      DomainParameters               |
|       userData               OCTET STRING  <-- GCC 层       |
|   }                                                         |
+-------------------------------------------------------------+
| GCC ConnectData (PER aligned)      variable                 |
|   t124Identifier Key | connectPDU OCTET STRING              |
+-------------------------------------------------------------+
| ConnectGCCPDU (PER aligned)        variable                 |
|   conferenceCreateRequest / conferenceCreateResponse        |
+-------------------------------------------------------------+
| RDP 用户数据块序列                  variable                 |
|   TS_UD_HEADER + payload, 反复拼接                          |
+-------------------------------------------------------------+
```

来源：[MS-RDPBCGR] 2.2.1.3（S2）、2.2.1.4（S15）、T.125 §7 Part 2（S30 第 15–16 页）、T.124 §8.7/§9.5/§9.6（S31 第 167/187/193–194 页）。

### 1.1 各层字节偏移（以 [MS-RDPBCGR] 4.1.3 官方 dump 为准，416 字节）

| 层 | 偏移 | 长度 | 内容 | 来源 |
|---|---|---|---|---|
| TPKT Header | 0 | 4 | `03 00 01 A0`（version=3, reserved=0, length=0x01A0=416） | S26 / [T123] §8 |
| X.224 Data TPDU | 4 | 3 | `02 F0 80`（LI=2, code=0xF0 Data, EOT=0x80） | S26 / [X224] §13.7 |
| MCS 应用标签 | 7 | 2 | `7F 65` = APPLICATION 101 (Connect-Initial) | S26 / T.125 §7 |
| BER 长度 | 9 | 3 | `82 01 94` = 404（长形式，2 个长度字节） | S26 |
| Connect-Initial value | 12 | 404 | 见 §3 | S26 |
| → callingDomainSelector | 12 | 3 | `04 01 01` | S26 |
| → calledDomainSelector | 15 | 3 | `04 01 01` | S26 |
| → upwardFlag | 18 | 3 | `01 01 FF` | S26 |
| → targetParameters | 21 | 27 | `30 19` + 25 字节 | S26 |
| → minimumParameters | 48 | 27 | `30 19` + 25 字节 | S26 |
| → maximumParameters | 75 | 30 | `30 1C` + 28 字节 | S26 |
| → userData (GCC) | 105 | 311 | `04 82 01 33` + 307 字节 | S26 |
| GCC t124Identifier | 109 | 7 | `00 05 00 14 7C 00 01`（OID 0.0.20.124.0.1） | S26 |
| GCC connectPDU 长度 | 116 | 2 | `81 2A` = 298 | S26 |
| CCrq PER 头（8B）+ h221 键 | 118 | 12 | `00 08 00 10 00 01 C0 00` + `44 75 63 61` | S26 |
| CCrq userData 长度 | 130 | 2 | `81 1C` = 284 | S26 |
| 第 1 个数据块 CS_CORE | 132 | 216 | `01 C0 D8 00` + 212 字节 | S26 / S4 |
| CS_CLUSTER | 348 | 12 | `04 C0 0C 00` + 8 字节 | S26 / S8 |
| CS_SECURITY | 360 | 12 | `02 C0 0C 00` + 8 字节 | S26 / S5 |
| CS_NET | 372 | 44 | `03 C0 2C 00` + 40 字节 | S26 / S6 |

服务端 → 客户端（Connect Response），337 字节：

| 层 | 偏移 | 长度 | 内容 | 来源 |
|---|---|---|---|---|
| TPKT Header | 0 | 4 | `03 00 01 51`（337） | S27 |
| X.224 Data TPDU | 4 | 3 | `02 F0 80` | S27 |
| MCS 应用标签 | 7 | 2 | `7F 66` = APPLICATION 102 (Connect-Response) | S27 / T.125 §7 |
| BER 长度 | 9 | 3 | `82 01 45` = 325 | S27 |
| → result | 12 | 3 | `0A 01 00`（ENUMERATED, rt-successful=0） | S27 / T.125 §7 |
| → calledConnectId | 15 | 3 | `02 01 00` | S27 |
| → domainParameters | 18 | 28 | `30 1A` + 26 字节 | S27 |
| → userData (GCC) | 46 | 291 | `04 82 01 1F` + 287 字节 | S27 |
| GCC t124Identifier | 50 | 7 | `00 05 00 14 7C 00 01` | S27 |
| GCC connectPDU 长度 | 57 | 1 | `2A`（短形式，声明 42，**客户端忽略**） | S27 / S25 |
| CCrsp PER 头 | 58 | 9 | `14 76 0A 01 01 00 01 C0 00` | S27 |
| h221 键 McDn | 67 | 4 | `4D 63 44 6E` | S27 |
| CCrsp userData 长度 | 71 | 2 | `81 08` = 264 | S27 |
| SC_CORE | 73 | 12 | `01 0C 0C 00` + 8 字节 | S27 / S16 |
| SC_NET | 85 | 16 | `03 0C 10 00` + 12 字节 | S27 / S18 |
| SC_SECURITY | 101 | 236 | `02 0C EC 00` + 232 字节 | S27 / S17 |

### 1.2 长度上限约束（A 级）

- Connect-Initial `userData`（GCC 层）：未协商 Extended Client Data Blocks 时 ≤ **1024** 字节；服务端通告 `EXTENDED_CLIENT_DATA_SUPPORTED (0x01)` 时 ≤ **4096** 字节（S2、S24）。
- TPKT `length` 必须与实际数据一致，不一致 SHOULD/MUST 断链（S2、S24）。
- MCS Domain MCSPDU 长度受 `maxMCSPDUsize` 约束；RDP 侧 Send Data 结构须 ≤ 16383 字节以避免 PER 扩展长度决定因子（S1）。

---

## 2. Connect Initial 的 ASN.1 定义（T.125 §7 Part 2，B 级原文）

T.125 (02/98) 第 15–16 页原文（S30）：

```asn1
-- Part 2: Connect provider
Connect-Initial  ::=  [APPLICATION 101] IMPLICIT SEQUENCE {
  callingDomainSelector  OCTET STRING,
  calledDomainSelector   OCTET STRING,
  upwardFlag             BOOLEAN,
        --  TRUE if called provider is higher
  targetParameters       DomainParameters,
  minimumParameters      DomainParameters,
  maximumParameters      DomainParameters,
  userData               OCTET STRING
}

Connect-Response  ::=  [APPLICATION 102] IMPLICIT SEQUENCE {
  result                 Result,
  calledConnectId        INTEGER (0..MAX),
        --  assigned by the called provider
        --  to identify additional TCs of the same MCS connection
  domainParameters       DomainParameters,
  userData               OCTET STRING
}

DomainParameters  ::=  SEQUENCE {
  maxChannelIds   INTEGER (0..MAX),   -- a limit on channel ids in use
  maxUserIds      INTEGER (0..MAX),   -- a sublimit on user id channels alone
  maxTokenIds     INTEGER (0..MAX),   -- a limit on token ids in use
  numPriorities   INTEGER (0..MAX),   -- the number of TCs in an MCS connection
  minThroughput   INTEGER (0..MAX),   -- the enforced number of octets per second
  maxHeight       INTEGER (0..MAX),   -- a limit on the height of a provider
  maxMCSPDUsize   INTEGER (0..MAX),   -- an octet limit on domain MCSPDUs
  protocolVersion INTEGER (0..MAX)
}

Result  ::=  ENUMERATED
--  in Connect, response, confirm
{  rt-successful (0), rt-domain-merging (1), rt-domain-not-hierarchical (2),
   rt-no-such-channel (3), rt-no-such-domain (4), rt-no-such-user (5),
   rt-not-admitted (6), rt-other-user-id (7), rt-parameters-unacceptable (8),
   rt-token-not-available (9), rt-token-not-possessed (10),
   rt-too-many-channels (11), rt-too-many-tokens (12), rt-too-many-users (13),
   rt-unspecified-failure (14), rt-user-rejected (15) }
```

> T.125 版本 3 定义（第 8 章）中 `Result`/`Reason` 改为 CHOICE（无值域编码），RDP 使用版本 2，即上表 ENUMERATED 形式（S30 第 33–35 页）。

编码规则（T.125 §9，B 级）：

- Version 2 = Connect MCSPDU 用 **BER**（X.690），后续 Domain MCSPDU 用 **PER aligned**（X.691 ALIGNED BASIC-PER）。
- Connect MCSPDU 尺寸不限；Domain MCSPDU 受 `maxMCSPDUsize` 限制。

---

## 3. Connect Initial 的 BER 骨架（逐字段）

| 字段 | BER tag | 长度（字节） | 线上字节 | 值来源 | 规范章节 |
|---|---|---|---|---|---|
| 应用标签 | `0x7F 0x65` | 2 | `7F 65` | APPLICATION 101 = Connect-Initial；多字节 tag：`CC=01`(APPLICATION)+`F=1`(constructed)，第二字节 `0TTTTTTT`，T=0x65 | S26；T.125 §7 |
| 整体长度 | `0x82` | 3 | `82 01 94` | 长形式：首字节低 7 位=长度字节数=2，值 `0x0194`=404 | S26 |
| `callingDomainSelector` | `0x04` OCTET STRING | 3 | `04 01 01` | 客户端 SHOULD 置 `0x01` | S23；S26 |
| `calledDomainSelector` | `0x04` OCTET STRING | 3 | `04 01 01` | 客户端 SHOULD 置 `0x01` | S23；S26 |
| `upwardFlag` | `0x01` BOOLEAN | 3 | `01 01 FF` | TRUE（0xFF）；含义"called provider is higher" | S23；S26；T.125 §11.1 |
| `targetParameters` | `0x30` SEQUENCE | 27 | `30 19` + 25B | 见 §3.1 | S23；S26 |
| `minimumParameters` | `0x30` SEQUENCE | 27 | `30 19` + 25B | 见 §3.1 | S23；S26 |
| `maximumParameters` | `0x30` SEQUENCE | 30 | `30 1C` + 28B | 见 §3.1 | S23；S26 |
| `userData` | `0x04` OCTET STRING | 311 | `04 82 01 33` + 307B | GCC Conference Create Request（§4） | S2；S26 |

BER 细节（S26 原文注解）：

- 多字节 tag 布局：`| C C F 1 1 1 1 1 | 1 T T T T T T T | ... | 0 T T T T T T T |`；此处 CC=01（APPLICATION）、F=1（constructed）、单字节类型值 0x65。
- 长形式长度布局：`| 1 (0<n<127) | L L ... L |`；`0x82` ⇒ 后续 2 字节为长度。
- 全部使用 **definite length**；RDP 对端不使用 indefinite length。

### 3.1 DomainParameters 逐字段（三个参数组）

字段顺序固定为 8 个 INTEGER，每个为 `02 <len> <value>`（大端二进制补码，最小字节数，不补 0x00 前缀）。

| # | 字段 | 类型 | targetParameters（客户端 SHOULD） | minimumParameters | maximumParameters | 4.1.3 dump 实际字节 |
|---|---|---|---|---|---|---|
| 1 | `maxChannelIds` | INTEGER (0..MAX) | 34 | 1 | 65535 | `02 01 22` / `02 01 01` / `02 02 FF FF` |
| 2 | `maxUserIds` | INTEGER (0..MAX) | 2 | 1 | 65535（表）/ **64535（dump）** | `02 01 02` / `02 01 01` / `02 02 FC 17` |
| 3 | `maxTokenIds` | INTEGER (0..MAX) | 0 | 1 | 65535 | `02 01 00` / `02 01 01` / `02 02 FF FF` |
| 4 | `numPriorities` | INTEGER (0..MAX) | 1 | 1 | 1 | `02 01 01` / `02 01 01` / `02 01 01` |
| 5 | `minThroughput` | INTEGER (0..MAX) | 0 | 0 | 0 | `02 01 00` / `02 01 00` / `02 01 00` |
| 6 | `maxHeight` | INTEGER (0..MAX) | 1 | 1 | 1 | `02 01 01` / `02 01 01` / `02 01 01` |
| 7 | `maxMCSPDUsize` | INTEGER (0..MAX) | 65535 | 1056 | 65535 | `02 02 FF FF` / `02 02 04 20` / `02 02 FF FF` |
| 8 | `protocolVersion` | INTEGER (0..MAX) | 2 | 2 | 2 | `02 01 02` / `02 01 02` / `02 01 02` |

来源：取值表 S23（3.2.5.3.3）；实际字节 S26（4.1.3）。

> **差异（重要）**：S23 表格规定 `maximumParameters.maxUserIds = 65535`，但 S26 的真实 Windows 客户端 dump 为 `0xFC17 = 64535`（= 65535 − 1000）。S26 的 dump 是逐字节权威测试向量；实现若做字节级回归应允许两者，或按 dump 生成。详见 §10.4。

服务端合并/校验规则（S24 3.3.5.3.3 伪码，摘要）：

- `maxChannelIds`：target ≥ 4 取 target；否则 maximum ≥ 4 取 4；否则失败。
- `maxUserIds`：target ≥ 3 取 target；否则 maximum ≥ 3 取 3；否则失败。
- `maxTokenIds`：直接取 target。
- `numPriorities`：minimum ≤ 1 取 1；否则失败。
- `minThroughput`：取 target。
- `maxHeight`：target == 1 或 minimum ≤ 1 取 1；否则失败。
- `maxMCSPDUsize`：target ∈ [124, 65528] 取 target；target > 65528 且 minimum ∈ [124, 65528] 取 65528；否则回退 maximum（≥124）；否则失败。
- `protocolVersion`：target == 2，或 minimum ≤ 2 ≤ maximum ⇒ 2；否则失败。

---

## 4. GCC Conference Create Request（T.124，PER aligned）

### 4.1 T.124 ASN.1 原文（B 级）

T.124 (01/2007) §8.7 第 167/175–177/187 页（S31）；(02/98) 对应第 171/181–183/191 页（S32）：

```asn1
H221NonStandardIdentifier ::= OCTET STRING (SIZE (4..255))
        -- First four octets shall be country code and Manufacturer code,
        -- assigned as specified in Annex A/H.221 for NS-cap and NS-comm

Key ::= CHOICE {
  object           OBJECT IDENTIFIER,
  h221NonStandard  H221NonStandardIdentifier }

UserData ::= SET OF SEQUENCE {
  key    Key,
  value  OCTET STRING OPTIONAL }

ConferenceName ::= SEQUENCE {
  numeric      SimpleNumericString,
  text         SimpleTextString OPTIONAL,
  ...,
  unicodeText  TextString OPTIONAL }

SimpleNumericString ::= NumericString (SIZE (1..255)) (FROM ("0123456789"))

TerminationMethod ::= ENUMERATED { automatic (0), manual (1), ... }

ConferenceMode ::= CHOICE {
  conventional-only NULL, counted-only NULL, anonymous-only NULL,
  conventional-control NULL, unrestricted-mode NULL,
  non-standard-mode NonStandardParameter, ... }

ConferenceCreateRequest ::= SEQUENCE {
  -- MCS-Connect-Provider request user data
  conferenceName           ConferenceName,
  convenerPassword         Password OPTIONAL,
  password                 Password OPTIONAL,
  lockedConference         BOOLEAN,
  listedConference         BOOLEAN,
  conductibleConference    BOOLEAN,
  terminationMethod        TerminationMethod,
  conductorPrivileges      SET OF Privilege OPTIONAL,
  conductedPrivileges      SET OF Privilege OPTIONAL,
  nonConductedPrivileges   SET OF Privilege OPTIONAL,
  conferenceDescription    TextString OPTIONAL,
  callerIdentifier         TextString OPTIONAL,
  userData                 UserData OPTIONAL,
  ...,
  conferencePriority       ConferencePriority OPTIONAL,
  conferenceMode           ConferenceMode OPTIONAL }

ConferenceCreateResponse ::= SEQUENCE {
  -- MCS-Connect-Provider response user data
  nodeID    UserID,     -- Node ID of the sending node
  tag       INTEGER,
  result    ENUMERATED { success (0), userRejected (1), resourcesNotAvailable (2),
                         rejectedForSymmetryBreaking (3),
                         lockedConferenceNotSupported (4), ... },
  userData  UserData OPTIONAL,
  ... }

ConnectData ::= SEQUENCE {
  t124Identifier  Key,
        -- This shall be set to the value {itu-t recommendation t 124 version(0) 1}
  connectPDU      OCTET STRING }

ConnectGCCPDU ::= CHOICE {
  conferenceCreateRequest   ConferenceCreateRequest,
  conferenceCreateResponse  ConferenceCreateResponse,
  conferenceQueryRequest    ConferenceQueryRequest,
  conferenceQueryResponse   ConferenceQueryResponse,
  conferenceJoinRequest     ConferenceJoinRequest,
  conferenceJoinResponse    ConferenceJoinResponse,
  conferenceInviteRequest   ConferenceInviteRequest,
  conferenceInviteResponse  ConferenceInviteResponse,
  ... }
```

编码规则（T.124 §9.5/§9.6 原文摘要，B 级）：

- MCS-Connect-Provider 的 User Data 不是直接把 PDU 放进去，而是包在 `ConnectData` 里；整体用 **PER（Aligned variant）**。
- 标准控制器时 `t124Identifier` 取 **object** 分支，值 `{itu-t recommendation t 124 version(0) 1}`。
- `connectPDU` 是 OCTET STRING，其内容**单独**用 PER（Aligned）编码，按每字节"高位在前"填装。

### 4.2 ConnectData 字节布局（客户端，307 字节 userData）

| 偏移（userData 相对） | 绝对偏移 | 长度 | 内容 | 说明 |
|---|---|---|---|---|
| 0 | 109 | 7 | `00 05 00 14 7C 00 01` | PER 编码的 `Key::object`：首字节 `0x00` = CHOICE 扩展位 0 + 索引 0（object）；随后 `0x05` = OID 长度 5；`00 14 7C 00 01` = OID 0.0.20.124.0.1 |
| 7 | 116 | 2 | `81 2A` | `connectPDU` 长度决定因子（X.691 §10.9.3.7 两字节形式），值 298；详见 §4.6 |
| 9 | 118 | 8 | `00 08 00 10 00 01 C0 00` | ConnectGCCPDU + ConferenceCreateRequest + ConferenceName + UserData 头的 PER 位域 |
| 17 | 126 | 4 | `44 75 63 61` | `h221NonStandard` = "Duca"（ASCII） |
| 21 | 130 | 2 | `81 1C` | `UserData::value` 长度决定因子，值 284 |
| 23 | 132 | 284 | 数据块序列 | 见 §5 |

OID 解码（S26 原文注解）：`{ 0 0 20 124 0 1 }` = `{itu-t(0) recommendation(0) t(20) t124(124) version(0) 1}`，即 ITU-T T.124 (Feb 1998) 第 1 版。

### 4.3 客户端 PER 位域逐位（S26 原文注解 + 本仓库重编码验证）

> 若只需要实现用的常量与逐字节归属，直接看 §4.5（8 字节 PER 头逐字节表）。本节给出逐位依据。

字节 `00`（ConnectGCCPDU / ConferenceCreateRequest 头）：

| 位 | 含义 | 值 |
|---|---|---|
| b7 | ConnectGCCPDU extension bit | 0 |
| b6..b4 | CHOICE 索引（8 个 root 分支 ⇒ 3 位），`conferenceCreateRequest` = 0 | 000 |
| b3 | ConferenceCreateRequest extension bit | 0 |
| b2 | `convenerPassword` present | 0（不使用） |
| b1 | `password` present | 0（不使用） |
| b0 | `conductorPrivileges` present | 0（不使用） |

字节 `08`：

| 位 | 含义 | 值 |
|---|---|---|
| b7 | `conductedPrivileges` present | 0 |
| b6 | `nonConductedPrivileges` present | 0 |
| b5 | `conferenceDescription` present | 0 |
| b4 | `callerIdentifier` present | 0 |
| b3 | `userData` present | **1** |
| b2 | ConferenceName extension bit | 0 |
| b1 | `ConferenceName.text` present | 0 |
| b0 | padding（对齐） | 0 |

字节 `00`（ConferenceName.numeric 长度决定因子，octet 对齐后）：长度 − 1 = 0 ⇒ 1 个数字。

字节 `10`：

| 位 | 含义 | 值 |
|---|---|---|
| b7 | NumericString 首位（BCD，0..9 用 4 位） | 0 |
| b6..b3 | 数字 `1` = 0001 | 0001 |
| b2 | `lockedConference` | 0 (FALSE) |
| b1 | `listedConference` | 0 (FALSE) |
| b0 | `conductibleConference` | 0 (FALSE) |

字节 `00`：`TerminationMethod` extension bit=0，随后 `automatic(0)` 占 1 位，余 7 位 padding。
字节 `01`：`UserData` 为 `SET OF`，size = 1。
字节 `C0`：

| 位 | 含义 | 值 |
|---|---|---|
| b7 | `UserData` 元素的 `value` present | **1** |
| b6 | `Key` CHOICE 扩展位 | **1**（h221NonStandard 为扩展分支） |
| b5..b0 | padding | 0 |

字节 `00`：`H221NonStandardIdentifier` 长度 − 4 = 0 ⇒ 4 字节。
随后 `44 75 63 61` = "Duca"。

> **审计提示**：S26 的文字注解把 CHOICE 写成 2 位并在字节 0 末尾留 1 位 padding。按 X.691，`ConnectGCCPDU` 有 8 个 root 分支 ⇒ 索引应为 **3 位**，此时字节 0 恰好填满 8 位（1+3+1+3），无需 padding，且产出的字节与 dump 完全一致（本仓库已用重编码验证，见 §9）。两种解读在"全 0 位"下字节相同，实现应使用 3 位索引（更符合 ASN.1 定义），并以 §9 的逐字节回归为准。

### 4.4 服务端 PER 位域（S27 原文注解）

字节 `14`（`0x14` = 0001 0100）：

| 位 | 含义 | 值 |
|---|---|---|
| b7 | ConnectGCCPDU extension bit | 0 |
| b6..b4 | CHOICE 索引 `conferenceCreateResponse` = 1 | 001 |
| b3 | ConferenceCreateResponse extension bit | 0 |
| b2 | `userData` present | **1** |
| b1..b0 | padding | 00 |

随后 `nodeID`（UserID = DynamicChannelId 1001..65535）编码为 16 位：`76 0A` ⇒ 0x760A + 1001 = **31219**（S27 注解、S25 规定 1001..65536）。
随后 `tag` = INTEGER，长度 1，值 1（`01 01`）。
随后 `result` = ENUMERATED，extension bit 0 + 索引 000（success=0），4 位 padding ⇒ 字节 `00`。
随后 `UserData` size = 1（`01`），`value` present = 1、`Key` = h221NonStandard = 1、6 位 padding ⇒ 字节 `C0`。
随后 h221 长度 − 4 = 0（`00`），`4D 63 44 6E` = "McDn"。
随后 `UserData::value` 长度 `81 08` = 264。

---

### 4.5 8 字节 PER 头 `00 08 00 10 00 01 C0 00` 的逐字节归属

这是客户端 Connect Initial 中**唯一一段"无长度字段的纯位域"**，实现时必须逐字节常量填充（全部为常量，与运行期参数无关）。逐字节归属如下（0-based 索引）：

| 字节序号 | 值 | 归属 | 位分解（b7..b0） |
|---|---|---|---|
| 0 | `00` | **ConnectGCCPDU 头 + ConferenceCreateRequest 头** | `0` ConnectGCCPDU ext；`000` CHOICE 索引（conferenceCreateRequest=0，3 位）；`0` CCreq ext；`0` convenerPassword absent；`0` password absent；`0` conductorPrivileges absent |
| 1 | `08` | **ConferenceCreateRequest 可选位图续 + ConferenceName 头** | `0` conductedPrivileges absent；`0` nonConductedPrivileges absent；`0` conferenceDescription absent；`0` callerIdentifier absent；`1` **userData present**；`0` ConferenceName ext；`0` ConferenceName.text absent；`0` padding |
| 2 | `00` | **ConferenceName.numeric 长度决定因子** | 8 位无符号 = `len − 1` = 0 ⇒ 1 个数字字符 |
| 3 | `10` | **ConferenceName.numeric 内容 + 三个会议布尔** | `0000`+`1` = 4 位 BCD 数字 `1`；`0` lockedConference；`0` listedConference；`0` conductibleConference |
| 4 | `00` | **TerminationMethod** | `0` TerminationMethod ext；`0` automatic(0)；`000000` padding（对齐到 octet） |
| 5 | `01` | **UserData ::= SET OF 的 size** | 8 位无符号 = 1（1 个元素） |
| 6 | `C0` | **UserData 元素内 Key/value 位域** | `1` value present；`1` Key CHOICE ext（选 h221NonStandard）；`000000` padding |
| 7 | `00` | **H221NonStandardIdentifier 长度决定因子** | 8 位无符号 = `len − 4` = 0 ⇒ 4 字节 |

第 7 字节（即第 8 个字节）`00` 之后紧接 4 字节 `44 75 63 61`（"Duca"）。这与父会话在 `mstscax.dll FUN_180161ce0` 观察到的常量序列完全一致：`00 08 00 10 00 01 C0 00` + `44 75 63 61`，其中第 8 字节 `00` 就是 h221 长度决定因子。

字节 0/1 的"可选位图跨字节"这一点容易写错：`userData present` 位落在**第 1 字节的 b3**，不在第 0 字节。实现建议直接使用这 8 字节常量，并附 §9 的回归测试，不要逐位重算。

### 4.6 PER 长度决定因子（X.691 §10.9.3，B 级）

来源：X.691 (07/2002) §10.9.3.6 / §10.9.3.7 / §10.9.3.8（S33，第 13–15 页）。

| 条件 | 编码 | 线上形式 |
|---|---|---|
| `n ≤ 127` | 1 octet，bit8=0，bits7..1 = n | `0x00..0x7F` |
| `127 < n < 16384`（< 16K） | 2 octets，bit8(octet1)=1，bit7(octet1)=0，bits6..1(octet1) = n 的高 6 位，octet2 = n 的低 8 位 | `0x80..0xBF` + 1 octet |
| `n ≥ 16384`（≥ 16K） | 1 octet（bit8=1，bit7=1，bits6..1 = 分片倍数）+ 分片内容，可重复 | `0xC0..0xFF` + 分片 |

**为什么 `connectPDU` 长度是 `81 2A` 而不是 `82 01 2A`**：

- `n = 298 = 0x12A`，落在 `127 < n < 16384` 区间 ⇒ 必须用 **2 字节形式**。
- 高 6 位 = `0x12A >> 8 = 0x01`；octet1 = `0x80 | 0x01 = 0x81`；octet2 = `0x2A` ⇒ **`81 2A`**。解码校验：`((0x81 & 0x3F) << 8) | 0x2A = 0x12A = 298` ✔
- `82 01 2A` 的 `0x82` 按 X.691 解析为 bit8=1、bit7=0、bits6..1=`0b000010`=2 ⇒ 声明的长度是 `(2 << 8) | 0x01 = 513`，`0x2A` 变成多余的悬挂字节 ⇒ **语义错误**。
- 3 字节形式只用于 `n ≥ 16384`，其首字节 bit8=1 **且 bit7=1**（即 `0xC0..0xFF`），与 `0x82`（bit7=0）不同。所以 `0x82` 永远不是"三字节形式的首字节"。
- 与父会话观察到的实现一致：`mstscax.dll FUN_180161ce0` 用 `(byte)(len >> 8) | 0x80` 作首字节、`(byte)len` 作次字节，正是 X.691 的 2 字节形式。

> **实现注意（发现的越界缺口）**：`FUN_180161ce0` 的守卫是 `len > 0xFFFF` 才返回 `E_FAIL`，但 2 字节形式的**合法上限是 16383**（`0x3FFF`）。当 `len ∈ [16384, 65535]` 时，`(len >> 8) | 0x80` 的高 6 位会溢出到 bit7/bit8（例如 `len = 0x4000` ⇒ 首字节 `0xC0`），按 X.691 会被解析成"分片"形式且分片倍数为 0，属非法编码。因此实现必须把上限收紧到 **16383**（`len > 0x3FFF` 即拒绝/分片），不能照抄 `0xFFFF`。这与 [MS-RDPBCGR] 2.2 的约束一致：Send Data 结构 MUST ≤ 16383 字节以避开 PER 扩展长度决定因子（S1）。

---

## 5. 客户端数据块（GCC userData 内）

### 5.1 通用块头 TS_UD_HEADER（4 字节）

| 偏移 | 字段 | 类型 | 说明 | 来源 |
|---|---|---|---|---|
| 0 | `type` | LE16 | 块类型，见下表 | S3 |
| 2 | `length` | LE16 | **含本 4 字节头**的块总长 | S3 |

`type` 取值（S3）：

| 值 | 名称 | 载荷章节 |
|---|---|---|
| `0xC001` | CS_CORE | 2.2.1.3.2 |
| `0xC002` | CS_SECURITY | 2.2.1.3.3 |
| `0xC003` | CS_NET | 2.2.1.3.4 |
| `0xC004` | CS_CLUSTER | 2.2.1.3.5 |
| `0xC005` | CS_MONITOR | 2.2.1.3.6 |
| `0xC006` | CS_MCS_MSGCHANNEL | 2.2.1.3.7 |
| `0xC008` | CS_MONITOR_EX | 2.2.1.3.10 |
| `0xC00A` | CS_MULTITRANSPORT | 2.2.1.3.8 |
| `0xC00C` | CS_UNUSED1 | 2.2.1.3.9 |
| `0x0C01` | SC_CORE | 2.2.1.4.2 |
| `0x0C02` | SC_SECURITY | 2.2.1.4.3 |
| `0x0C03` | SC_NET | 2.2.1.4.4 |
| `0x0C04` | SC_MCS_MSGCHANNEL | 2.2.1.4.5 |
| `0x0C08` | SC_MULTITRANSPORT | 2.2.1.4.6 |

块顺序：[MS-RDPBCGR] 2.2.1.3 明确"数据块顺序允许与图中不同，因为每块由 User Data Header 标识"（S2）。服务端只强制要求 CS_CORE..CS_CLUSTER 存在（S24）。

### 5.2 Client Core Data（TS_UD_CS_CORE，`0xC001`）

总长 = 4（头）+ 212 = 216 字节（S26 实测）。**全部多字节字段 little-endian**（S1）。

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC001 | S3/S4 |
| 4 | `version` | LE32 | 4 | 高 2 字节主版本，低 2 字节次版本；`0x00080001`=RDP 4.0；`0x00080004`=RDP 5.0/5.1/5.2/6.0/6.1/7.0/7.1/8.0/8.1；`0x00080005`..`0x00080011` = RDP 10.0..10.12 | S4 |
| 8 | `desktopWidth` | LE16 | 2 | 请求的桌面宽（像素）；超过服务端上限按上限处理 | S4/S24 |
| 10 | `desktopHeight` | LE16 | 2 | 请求的桌面高（像素） | S4/S24 |
| 12 | `colorDepth` | LE16 | 2 | `0xCA00`=4bpp，`0xCA01`=8bpp；**若 `postBeta2ColorDepth` 存在则本字段 MUST 被忽略** | S4 |
| 14 | `SASSequence` | LE16 | 2 | SHOULD 为 `RNS_UD_SAS_DEL (0xAA03)` | S4 |
| 16 | `keyboardLayout` | LE32 | 4 | 活动输入区域标识（HKL），如 `0x00000409`=US；为 0 时服务端用账户默认值 | S4 |
| 20 | `clientBuild` | LE32 | 4 | 客户端 build 号 | S4 |
| 24 | `clientName` | UTF-16LE | 32 | 最多 15 个 Unicode 字符 + NUL（16 个 UTF-16 单元） | S4 |
| 56 | `keyboardType` | LE32 | 4 | 1=IBM PC/XT 83 键；2=Olivetti ICO 102 键；3=IBM PC/AT 84 键；4=IBM 增强 101/102 键；5=Nokia 1050；6=Nokia 9140；7=Japanese；8=Korean | S4 |
| 60 | `keyboardSubType` | LE32 | 4 | OEM 相关 | S4 |
| 64 | `keyboardFunctionKey` | LE32 | 4 | 功能键数量 | S4 |
| 68 | `imeFileName` | UTF-16LE | 64 | 最多 31 个 Unicode 字符 + NUL | S4 |
| 132 | `postBeta2ColorDepth` | LE16 | 2 | `0xCA00`/`0xCA01`/`0xCA02`(15bpp 555)/`0xCA03`(16bpp 565)/`0xCA04`(24bpp)；若 `highColorDepth` 存在则 MUST 被忽略；**若本字段缺失，其后所有字段 MUST NOT 出现** | S4 |
| 134 | `clientProductId` | LE16 | 2 | SHOULD 为 1；存在则 `postBeta2ColorDepth` 必须存在 | S4 |
| 136 | `serialNumber` | LE32 | 4 | SHOULD 为 0；存在则 `clientProductId` 必须存在 | S4 |
| 140 | `highColorDepth` | LE16 | 2 | `0x0004`/`0x0008`/`0x000F`(15bpp 555)/`0x0010`(16bpp 565)/`0x0018`(24bpp)；存在则 `serialNumber` 必须存在 | S4 |
| 142 | `supportedColorDepths` | LE16 | 2 | 位标志：`0x0001`=24bpp，`0x0002`=16bpp，`0x0004`=15bpp，`0x0008`=32bpp；存在则 `highColorDepth` 必须存在 | S4 |
| 144 | `earlyCapabilityFlags` | LE16 | 2 | 位标志（见 §5.2.1）；存在则 `supportedColorDepths` 必须存在 | S4 |
| 146 | `clientDigProductId` | UTF-16LE | 64 | 唯一标识客户端的字符串；存在则 `earlyCapabilityFlags` 必须存在 | S4 |
| 210 | `connectionType` | u8 | 1 | 仅当 `RNS_UD_CS_VALID_CONNECTION_TYPE (0x0020)` 置位时有效：1=Modem，2=低带宽宽带，3=卫星，4=高带宽宽带，5=WAN，6=LAN，7=自动检测 | S4 |
| 211 | `pad1octet` | u8 | 1 | 对齐 `serverSelectedProtocol` 用 padding | S4 |
| 212 | `serverSelectedProtocol` | LE32 | 4 | 必须等于服务端 RDP Negotiation Response 的 `selectedProtocol`；未收到时为 `PROTOCOL_RDP (0)`；若发送过 Negotiation Request 则必须存在 | S4/S24 |
| 216 | `desktopPhysicalWidth` | LE32 | 4 | 物理宽（mm）；<10 或 >10000 时忽略；存在则 `serverSelectedProtocol` 与 `desktopPhysicalHeight` 必须存在 | S4 |
| 220 | `desktopPhysicalHeight` | LE32 | 4 | 物理高（mm）；同上 | S4 |
| 224 | `desktopOrientation` | LE16 | 2 | 0=横屏，90=竖屏，180=横屏翻转，270=竖屏翻转；非法值忽略 | S4 |
| 226 | `desktopScaleFactor` | LE32 | 4 | 百分比；<100 或 >500 或 `deviceScaleFactor` 非 100/140/180 时忽略 | S4 |
| 230 | `deviceScaleFactor` | LE32 | 4 | 必须为 100/140/180（百分比） | S4 |

**长度分段**：偏移 4..131（`version` 至 `imeFileName` 末尾）为**无条件必选段 128 字节**，即块最小长度 = 4 + 128 = **132 字节**。从偏移 132 的 `postBeta2ColorDepth` 起全部为条件可选段，且存在"若某字段缺失，其后所有字段 MUST NOT 出现"的链式依赖（S4）。S26 实测块长 216 = 4 头 + 212 载荷，覆盖到 `serverSelectedProtocol` 为止（不含物理尺寸/缩放字段）。

#### 5.2.1 `earlyCapabilityFlags` 位定义（S4）

| 值 | 名称 | 含义 |
|---|---|---|
| `0x0001` | RNS_UD_CS_SUPPORT_ERRINFO_PDU | 支持 Set Error Info PDU (2.2.5.1) |
| `0x0002` | RNS_UD_CS_WANT_32BPP_SESSION | 请求 32bpp 会话（`highColorDepth` 应置 24 作为回退） |
| `0x0004` | RNS_UD_CS_SUPPORT_STATUSINFO_PDU | 支持 Server Status Info PDU (2.2.5.2) |
| `0x0008` | RNS_UD_CS_STRONG_ASYMMETRIC_KEYS | 支持 >512 位非对称密钥 |
| `0x0010` | RNS_UD_CS_RELATIVE_MOUSE_INPUT | 支持相对鼠标模式（`version` ≥ 0x00080011 才有效） |
| `0x0020` | RNS_UD_CS_VALID_CONNECTION_TYPE | `connectionType` 有效 |
| `0x0040` | RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU | 支持 Monitor Layout PDU (2.2.12.1) |
| `0x0080` | RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT | 支持网络特征检测 (2.2.14) |
| `0x0100` | RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL | 支持 EGFX；置位需同时支持 2.2.1.4 的网络检测 |
| `0x0200` | RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE | 支持 Dynamic DST |
| `0x0400` | RNS_UD_CS_SUPPORT_HEARTBEAT_PDU | 支持 Heartbeat PDU (2.2.16.1) |
| `0x0800` | RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN | 支持跳过 Channel Join Request/Confirm |

### 5.3 Client Security Data（TS_UD_CS_SEC，`0xC002`）

固定 12 字节（S26 实测）。

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC002 | S3/S5 |
| 4 | `encryptionMethods` | LE32 | 4 | 位标志：`0x00000001` 40BIT，`0x00000002` 128BIT，`0x00000008` 56BIT，`0x00000010` FIPS；至少置一位 | S5 |
| 8 | `extEncryptionMethods` | LE32 | 4 | 仅法语区客户端使用：法语区 `encryptionMethods` MUST 为 0、本字段承载实际值；其他区域 MUST 为 0 | S5 |

S26 dump 实际值：`encryptionMethods = 0x0000001B`（= 40BIT|128BIT|56BIT|FIPS），`extEncryptionMethods = 0`。

### 5.4 Client Network Data（TS_UD_CS_NET，`0xC003`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC003 | S3/S6 |
| 4 | `channelCount` | LE32 | 4 | 请求的静态虚拟通道数，**最大 31** | S6 |
| 8 | `channelDefArray` | CHANNEL_DEF[] | 12 × channelCount | 见 §5.4.1 | S6/S7 |

块总长 = 8 + 12 × channelCount（S26：3 通道 ⇒ 44）。

#### 5.4.1 CHANNEL_DEF（12 字节，S7）

| 偏移 | 字段 | 类型 | 字节 | 说明 |
|---|---|---|---|---|
| 0 | `name` | ANSI char[8] | 8 | 7 个 ANSI 字符 + NUL |
| 8 | `options` | LE32 | 4 | 通道选项标志 |

`options` 位（S7）：

| 值 | 名称 | 说明 |
|---|---|---|
| `0x80000000` | CHANNEL_OPTION_INITIALIZED | 未使用，服务端 MUST 忽略 |
| `0x40000000` | CHANNEL_OPTION_ENCRYPT_RDP | 未使用，MUST 忽略 |
| `0x20000000` | CHANNEL_OPTION_ENCRYPT_SC | 未使用，MUST 忽略 |
| `0x10000000` | CHANNEL_OPTION_ENCRYPT_CS | 未使用，MUST 忽略 |
| `0x08000000` | CHANNEL_OPTION_PRI_HIGH | 高 MCS 优先级 |
| `0x04000000` | CHANNEL_OPTION_PRI_MED | 中优先级 |
| `0x02000000` | CHANNEL_OPTION_PRI_LOW | 低优先级 |
| `0x00800000` | CHANNEL_OPTION_COMPRESS_RDP | RDP 数据压缩时压缩通道数据 |
| `0x00400000` | CHANNEL_OPTION_COMPRESS | 始终压缩 |
| `0x00200000` | CHANNEL_OPTION_SHOW_PROTOCOL | 服务端 MUST 忽略 |
| `0x00100000` | REMOTE_CONTROL_PERSISTENT | 跨远程控制事务持久 |

S26 dump 实际三通道：`rdpdr` options `0x80800000`、`cliprdr` `0xC0A00000`、`rdpsnd` `0xC0000000`。

### 5.5 Client Cluster Data（TS_UD_CS_CLUSTER，`0xC004`）

固定 12 字节（S26 实测）。

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC004 | S3/S8 |
| 4 | `Flags` | LE32 | 4 | 见下 | S8 |
| 8 | `RedirectedSessionID` | LE32 | 4 | 仅当 `REDIRECTED_SESSIONID_FIELD_VALID` 置位时有效 | S8 |

`Flags` 位（S8）：

| 值 | 名称 | 说明 |
|---|---|---|
| `0x00000001` | REDIRECTION_SUPPORTED | 可接收会话重定向；置位时 `ServerSessionRedirectionVersionMask` 必须给出支持版本 |
| `0x0000003C` | ServerSessionRedirectionVersionMask | 4 位版本枚举，见下 |
| `0x00000002` | REDIRECTED_SESSIONID_FIELD_VALID | `RedirectedSessionID` 有效 |
| `0x00000040` | REDIRECTED_SMARTCARD | 客户端用智能卡登录 |

版本枚举（位于 `Flags` 的 bit2..bit5，即值 << 2）：`0x00`=V1，`0x01`=V2，`0x02`=V3，`0x03`=V4，`0x04`=V5，`0x05`=V6；不可组合。

S26 dump 实际值：`Flags = 0x0000000D`（`0x03 << 2 | 0x01` = REDIRECTION_VERSION4 | REDIRECTION_SUPPORTED），`RedirectedSessionID = 0`。

### 5.6 Client Monitor Data（TS_UD_CS_MONITOR，`0xC005`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC005 | S3/S9 |
| 4 | `flags` | LE32 | 4 | 保留，MUST 为 0 | S9 |
| 8 | `monitorCount` | LE32 | 4 | 显示器数，**最大 16** | S9 |
| 12 | `monitorDefArray` | TS_MONITOR_DEF[] | 20 × monitorCount | 见 §5.6.1 | S9/S10 |

约束（S9）：虚拟桌面并集宽/高 MUST NOT 超过 32766 像素；最小 200×200。本块属 Extended Client Data Block，未协商 `EXTENDED_CLIENT_DATA_SUPPORTED (0x01)` 时 MUST NOT 发送。

#### 5.6.1 TS_MONITOR_DEF（20 字节，S10）

| 偏移 | 字段 | 类型 | 字节 | 说明 |
|---|---|---|---|---|
| 0 | `left` | LE32 **signed** | 4 | 左上角 x，相对主显示器左上角 (0,0) |
| 4 | `top` | LE32 **signed** | 4 | 左上角 y |
| 8 | `right` | LE32 **signed** | 4 | 右下角 x（含） |
| 12 | `bottom` | LE32 **signed** | 4 | 右下角 y（含） |
| 16 | `flags` | LE32 | 4 | `0x00000001` = TS_MONITOR_PRIMARY |

### 5.7 Client Message Channel Data（TS_UD_CS_MCS_MSGCHANNEL，`0xC006`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC006 | S3/S11 |
| 4 | `flags` | LE32 | 4 | 保留，MUST 为 0 | S11 |

固定 8 字节。属 Extended Client Data Block。

### 5.8 Client Monitor Extended Data（TS_UD_CS_MONITOR_EX，`0xC008`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC008 | S3/S13 |
| 4 | `flags` | LE32 | 4 | 保留，MUST 为 0 | S13 |
| 8 | `monitorAttributeSize` | LE32 | 4 | MUST 为 20（TS_MONITOR_ATTRIBUTES 大小） | S13 |
| 12 | `monitorCount` | LE32 | 4 | MUST 与 CS_MONITOR 的 `monitorCount` 相同 | S13 |
| 16 | `monitorAttributesArray` | TS_MONITOR_ATTRIBUTES[] | 20 × monitorCount | 见下 | S13/S14 |

TS_MONITOR_ATTRIBUTES（20 字节，S14）：`physicalWidth` LE32（mm）、`physicalHeight` LE32（mm）、`orientation` LE32（0/90/180/270）、`desktopScaleFactor` LE32（%）、`deviceScaleFactor` LE32（100/140/180）。

### 5.9 Client Multitransport Channel Data（TS_UD_CS_MULTITRANSPORT，`0xC00A`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0xC00A | S3/S12 |
| 4 | `flags` | LE32 | 4 | `0x01` UDPFECR；`0x04` UDPFECL；`0x100` UDP_PREFERRED；`0x200` SOFTSYNC_TCP_TO_UDP | S12 |

---

## 6. Connect Response 结构

### 6.1 ASN.1（T.125 §7 Part 2）

见 §2 的 `Connect-Response` 定义。BER 骨架：

| 字段 | tag | 长度 | 线上字节（S27） | 说明 |
|---|---|---|---|---|
| 应用标签 | `0x7F 0x66` | 2 | `7F 66` | APPLICATION 102 = Connect-Response |
| 整体长度 | `0x82` | 3 | `82 01 45` | 325 |
| `result` | `0x0A` ENUMERATED | 3 | `0A 01 00` | rt-successful (0) |
| `calledConnectId` | `0x02` INTEGER | 3 | `02 01 00` | SHOULD 为 0（S25） |
| `domainParameters` | `0x30` SEQUENCE | 28 | `30 1A` + 26B | 见下 |
| `userData` | `0x04` OCTET STRING | 291 | `04 82 01 1F` + 287B | GCC Conference Create Response |

响应侧 `domainParameters`（S27 实测）：`maxChannelIds=34`、`maxUserIds=3`、`maxTokenIds=0`、`numPriorities=1`、`minThroughput=0`、`maxHeight=1`、`maxMCSPDUsize=**65528**`（`02 03 00 FF F8`，注意 3 字节整数，带前导 0x00）、`protocolVersion=2`。

服务端行为约束（S25）：`result` MUST 为 rt-successful(0)；`calledConnectId` SHOULD 为 0；`domainParameters` MUST 为按 S24 规则合并所得。客户端处理（S24/3.2.5.3.4）：**忽略** `calledConnectId` 与 `domainParameters`；`result == 0` 则继续 Erect Domain Request。

### 6.2 GCC Conference Create Response 字节布局（287 字节 userData）

| 偏移（userData 相对） | 绝对 | 长度 | 内容 |
|---|---|---|---|
| 0 | 50 | 7 | `00 05 00 14 7C 00 01`（同 §4.2 的 OID） |
| 7 | 57 | 1 | `2A`：`connectPDU` 长度决定因子（短形式），声明 42。**规范注明该长度被客户端忽略**（S27），实际后续 279 字节 |
| 8 | 58 | 1 | `14` = 扩展位 0 + CHOICE 001(conferenceCreateResponse) + 扩展位 0 + userData present 1 + 2 位 padding |
| 9 | 59 | 2 | `76 0A` = nodeID − 1001 ⇒ 31219 |
| 11 | 61 | 2 | `01 01` = tag（INTEGER 长度 1，值 1） |
| 13 | 63 | 1 | `00` = result success(0) + padding |
| 14 | 64 | 1 | `01` = UserData SET OF size = 1 |
| 15 | 65 | 1 | `C0` = value present 1 + h221NonStandard 1 + 6 位 padding |
| 16 | 66 | 1 | `00` = h221 长度 − 4 = 0 |
| 17 | 67 | 4 | `4D 63 44 6E` = "McDn" |
| 21 | 71 | 2 | `81 08` = UserData::value 长度 264 |
| 23 | 73 | 264 | 数据块序列 |

`tag` 与 `result` 取值表（S25）：`tag` = 1（长度 1 字节）、`result` = success(0)、`userData` = 基本服务端数据块。

---

## 7. 服务端数据块

### 7.1 Server Core Data（TS_UD_SC_CORE，`0x0C01`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0x0C01 | S3/S16 |
| 4 | `version` | LE32 | 4 | 同客户端 version 表（`0x00080001`/`0x00080004`/`0x00080005`..`0x00080011`）；≥ `0x00080004` 时必须支持 Info Packet 的 `UserName` 512 字节 | S16 |
| 8 | `clientRequestedProtocols` | LE32 | 4 | 回显客户端 RDP Negotiation Request 的 `requestedProtocols`；未收到时为 `PROTOCOL_RDP (0)`；缺失则其后字段 MUST NOT 存在 | S16 |
| 12 | `earlyCapabilityFlags` | LE32 | 4 | `0x00000001` EDGE_ACTIONS_SUPPORTED_V1；`0x00000002` DYNAMIC_DST_SUPPORTED；`0x00000004` EDGE_ACTIONS_SUPPORTED_V2；`0x00000008` SKIP_CHANNELJOIN_SUPPORTED | S16 |

S27 实测：`version = 0x00080004`，`clientRequestedProtocols = 0`，无 `earlyCapabilityFlags`（块长 12）。

### 7.2 Server Security Data（TS_UD_SC_SEC1，`0x0C02`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0x0C02 | S3/S17 |
| 4 | `encryptionMethod` | LE32 | 4 | `0x00` NONE、`0x01` 40BIT、`0x02` 128BIT、`0x08` 56BIT、`0x10` FIPS；Enhanced RDP Security 时 MUST 为 NONE | S17 |
| 8 | `encryptionLevel` | LE32 | 4 | `0x00` NONE、`0x01` LOW、`0x02` CLIENT_COMPATIBLE、`0x03` HIGH、`0x04` FIPS；Enhanced RDP Security 时 MUST 为 NONE | S17 |
| 12 | `serverRandomLen` | LE32 | 4 | 可选；`encryptionMethod`/`encryptionLevel` 均 0 时 MUST NOT 存在；任一非 0 时 MUST 为 `0x00000020` | S17 |
| 16 | `serverCertLen` | LE32 | 4 | 可选；两者均 0 时 MUST NOT 存在；否则为 `serverCertificate` 字节数 | S17 |
| 20 | `serverRandom` | bytes | serverRandomLen | 会话密钥派生用随机数；两者均 0 时 MUST NOT 存在 | S17 |
| 20+serverRandomLen | `serverCertificate` | SERVER_CERTIFICATE | serverCertLen | 见 §7.2.1 | S17/S21 |

S27 实测：`encryptionMethod=2`(128BIT)、`encryptionLevel=2`(CLIENT_COMPATIBLE)、`serverRandomLen=32`、`serverCertLen=184`。

#### 7.2.1 Server Certificate（PROPRIETARYSERVERCERTIFICATE，S21）

| 偏移 | 字段 | 类型 | 字节 | 取值 |
|---|---|---|---|---|
| 0 | `dwVersion` | LE32 | 4 | MUST `0x00000001` (CERT_CHAIN_VERSION_1) |
| 4 | `dwSigAlgId` | LE32 | 4 | MUST `0x00000001` (SIGNATURE_ALG_RSA) |
| 8 | `dwKeyAlgId` | LE32 | 4 | MUST `0x00000001` (KEY_EXCHANGE_ALG_RSA) |
| 12 | `wPublicKeyBlobType` | LE16 | 2 | MUST `0x0006` (BB_RSA_KEY_BLOB) |
| 14 | `wPublicKeyBlobLen` | LE16 | 2 | `PublicKeyBlob` 字节数 |
| 16 | `PublicKeyBlob` | RSA_PUBLIC_KEY | wPublicKeyBlobLen | 见下 |
| 16+blobLen | `wSignatureBlobType` | LE16 | 2 | `0x0008` (BB_RSA_SIGNATURE_BLOB) |
| 18+blobLen | `wSignatureBlobLen` | LE16 | 2 | 签名字节数 |
| 20+blobLen | `SignatureBlob` | bytes | wSignatureBlobLen | 用 Terminal Services 签名私钥生成 |

RSA_PUBLIC_KEY（S22）：

| 偏移 | 字段 | 类型 | 字节 | 取值 |
|---|---|---|---|---|
| 0 | `magic` | LE32 | 4 | MUST `0x31415352`（线上字节 `52 53 41 31` = "RSA1"） |
| 4 | `keylen` | LE32 | 4 | MUST `(bitlen/8) + 8` |
| 8 | `bitlen` | LE32 | 4 | 模数位数 |
| 12 | `datalen` | LE32 | 4 | MUST `(bitlen/8) - 1` |
| 16 | `pubExp` | LE32 | 4 | 公钥指数 |
| 20 | `modulus` | bytes | keylen | `bitlen/8` 字节模数 + 8 字节零填充 |

S27 实测：`dwVersion=1`、`dwSigAlgId=1`、`dwKeyAlgId=1`、`wPublicKeyBlobType=6`、`wPublicKeyBlobLen=0x5C=92`；`magic="RSA1"`、`keylen=72`、`bitlen=512`、`datalen=63`、`pubExp=0x00010001`；`wSignatureBlobType=8`、`wSignatureBlobLen=72`。

### 7.3 Server Network Data（TS_UD_SC_NET，`0x0C03`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0x0C03 | S3/S18 |
| 4 | `MCSChannelId` | LE16 | 2 | I/O 通道的 MCS 通道号 | S18 |
| 6 | `channelCount` | LE16 | 2 | `channelIdArray` 中 16 位通道号个数 | S18 |
| 8 | `channelIdArray` | LE16[] | 2 × channelCount | 与客户端请求的静态通道按位置一一对应 | S18 |
| 8 + 2×count | `Pad` | LE16 | 2（可选） | 仅当 `channelCount` 为奇数时存在，使整块长度为 4 的倍数；值 MUST 被忽略 | S18 |

S27 实测：`MCSChannelId=0x03EB=1003`、`channelCount=3`、`channelIdArray=[0x03EC,0x03ED,0x03EE]`（1004/1005/1006）、`Pad=0x0000`（3 为奇数 ⇒ 存在）。

### 7.4 Server Message Channel Data（TS_UD_SC_MCS_MSGCHANNEL，`0x0C04`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0x0C04 | S3/S19 |
| 4 | `MCSChannelID` | LE16 | 2 | MCS 消息通道号；为 0 时该通道 MUST NOT 被 join | S19 |

固定 6 字节（S15 明确 "serverMessageChannelData (6 bytes)"）。

### 7.5 Server Multitransport Channel Data（TS_UD_SC_MULTITRANSPORT，`0x0C08`）

| 块内偏移 | 字段 | 类型 | 字节 | 取值约束 | 规范 |
|---|---|---|---|---|---|
| 0 | `header` | TS_UD_HEADER | 4 | type = 0x0C08 | S3/S20 |
| 4 | `flags` | LE32 | 4 | `0x01` UDPFECR；`0x04` UDPFECL；`0x100` UDP_PREFERRED；`0x200` SOFTSYNC_TCP_TO_UDP | S20 |

固定 8 字节。仅当客户端发送了 `clientMultitransportChannelData` 时才出现（S15）。

---

## 8. 编解码实现要点（汇总）

| 项 | 规则 | 来源 |
|---|---|---|
| 字节序 | 所有多字节字段 little-endian（BER/PER 内部编码除外） | S1 |
| MCS 编码规则 | Version 2：Connect MCSPDU 用 BER，Domain MCSPDU 用 PER aligned | S1、T.125 §9 |
| BER 长度 | definite only；短形式 `<0x80`；长形式 `0x8n` + n 字节 | S26 |
| BER 整数 | 最小字节数、大端、二进制补码；0 编码为 `02 01 00` | S26 |
| BER BOOLEAN | `01 01 FF` = TRUE | S26 |
| 多字节 tag | `7F 65` / `7F 66`，规则见 §3 | S26/S27 |
| PER 长度决定因子 | `<0x80` 单字节；`0x80..0xBF` 两字节（14 位，上限 16383）；`0xC0..0xFF` 一般/分片形式（≥16K）；RDP 不使用分片 | S33 §10.9.3.6–10.9.3.8；S27 |
| PER 长度上限 | 两字节形式仅覆盖 `n ≤ 16383`；`n > 0x3FFF` MUST 走分片或拒绝（不能按 `0xFFFF` 守卫） | S33 §10.9.3.7–10.9.3.8；S1 |
| PER 对齐 | Aligned variant，按 octet 边界对齐后再编码长度决定因子 | T.124 §9.6 |
| OID 编码 | `Key::object` = `00 05 00 14 7C 00 01`（CHOICE 索引 0 + 长度 5 + OID） | S26 |
| h221 键 | 客户端 "Duca" = `44 75 63 61`；服务端 "McDn" = `4D 63 44 6E`；PER 长度字段为 `len-4` | S23/S25、S26/S27 |
| 块遍历 | 读 LE16 type + LE16 length，`length` 含 4 字节头，按 length 步进，直到 userData 用尽 | S3 |
| 长度校验 | 所有 BER/PER 长度 MUST 与实际数据一致，不一致断链 | S2/S24 |

---

## 9. 可执行验证（红/绿证据）

以下验证脚本使用 §1.1 的字节布局独立重编码，并与官方 dump 逐字节比对。

**[GREEN-1]** 用本文件的字段定义重编码 Connect Initial，与 [MS-RDPBCGR] 4.1.3 dump 逐字节相等：

```
[GREEN-1] Connect Initial re-encode == spec 4.1.3 dump: True (416/416 bytes)
[GREEN-2] Connect Response re-encode == spec 4.1.4 dump: True (337/337 bytes)
```

**[RED-1]** 把 `callingDomainSelector` 改成 `0x00`（错误值）后重编码，不再相等，首个差异落在偏移 14：

```
[RED-1] 用 callingDomainSelector=0x00 重编码:
   equal? False | 首个差异偏移 14 | 本版 00 vs 规范 01
```

**[RED-2]** 把 `h221NonStandard` 长度误写成 8 字节（在 "Duca" 后补 4 个 0）后重编码，长度与内容均错：

```
[RED-2] 用 h221NonStandard 长度=8 (Duca 后补 0) 重编码:
   equal? False | 长度 420 vs 416
```

**[DECODE]** 对官方 dump 做独立解码，确认字段值与 §3/§5/§7 表格一致：

```
=== Connect Initial (MS-RDPBCGR 4.1.3 annotated dump, 416 bytes) ===
  Connect-Initial value: len=404 @12
  callingDomainSelector  tag=0x04 len=1 value=0x01
  calledDomainSelector   tag=0x04 len=1 value=0x01
  upwardFlag             tag=0x01 len=1 value=0xff
  targetParameters       tag=0x30 len=25 [34, 2, 0, 1, 0, 1, 65535, 2]
  minimumParameters      tag=0x30 len=25 [1, 1, 1, 1, 0, 1, 1056, 2]
  maximumParameters      tag=0x30 len=28 [65535, 64535, 65535, 1, 0, 1, 65535, 2]
  userData               tag=0x04 len=307
  [GCC] t124Identifier  = 00 05 00 14 7c 00 01
  [GCC] connectPDU len  = 298 (declared) actual 298
  [GCC] CCrq prefix     = 00 08 00 10 00 01 c0 00
  [GCC] h221NonStandard = 44 75 63 61 = Duca
  [GCC] userData len    = 284 (declared)
  [GCC] blocks @abs     = 132 total 284
    type=0xc001 len=216 abs=132
    type=0xc004 len= 12 abs=348
    type=0xc002 len= 12 abs=360
    type=0xc003 len= 44 abs=372

=== Connect Response (MS-RDPBCGR 4.1.4 annotated dump, 337 bytes) ===
  Connect-Response value: len=325 @12
  result                 tag=0x0a value=0 (rt-successful)
  calledConnectId        value=0
  domainParameters       len=26 [34, 3, 0, 1, 0, 1, 65528, 2]
  userData               tag=0x04 len=287
  [GCC] t124Identifier  = 00 05 00 14 7c 00 01
  [GCC] connectPDU len  = 42 (declared, client ignores); actual 279
  [GCC] CCrsp prefix    = 14 76 0a 01 01 00 01 c0 00 4d 63 44 6e
  [GCC] nodeID          = 0x760a + 1001 = 31219
  [GCC] tag             = 1
  [GCC] result          = 0 (success)
  [GCC] UserData count  = 1
  [GCC] bits pdu[7]     = 11000000
  [GCC] h221NonStandard = 4d 63 44 6e = McDn
  [GCC] userData len    = 264 (declared)
  [GCC] blocks @abs     = 73 total 264
    type=0x0c01 len= 12 abs=73
    type=0x0c03 len= 16 abs=85
    type=0x0c02 len=236 abs=101
```

### 9.1 官方测试向量（可直接做单测固定输入）

Connect Initial（416 字节，[MS-RDPBCGR] 4.1.3，完整无省略）：

```
03 00 01 a0 02 f0 80 7f 65 82 01 94 04 01 01 04
01 01 01 01 ff 30 19 02 01 22 02 01 02 02 01 00
02 01 01 02 01 00 02 01 01 02 02 ff ff 02 01 02
30 19 02 01 01 02 01 01 02 01 01 02 01 01 02 01
00 02 01 01 02 02 04 20 02 01 02 30 1c 02 02 ff
ff 02 02 fc 17 02 02 ff ff 02 01 01 02 01 00 02
01 01 02 02 ff ff 02 01 02 04 82 01 33 00 05 00
14 7c 00 01 81 2a 00 08 00 10 00 01 c0 00 44 75
63 61 81 1c 01 c0 d8 00 04 00 08 00 00 05 00 04
01 ca 03 aa 09 04 00 00 ce 0e 00 00 45 00 4c 00
54 00 4f 00 4e 00 53 00 2d 00 44 00 45 00 56 00
32 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00
00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 01 ca 01 00 00 00 00 00
18 00 07 00 01 00 36 00 39 00 37 00 31 00 32 00
2d 00 37 00 38 00 33 00 2d 00 30 00 33 00 35 00
37 00 39 00 37 00 34 00 2d 00 34 00 32 00 37 00
31 00 34 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 04 c0 0c 00
0d 00 00 00 00 00 00 00 02 c0 0c 00 1b 00 00 00
00 00 00 00 03 c0 2c 00 03 00 00 00 72 64 70 64
72 00 00 00 00 00 80 80 63 6c 69 70 72 64 72 00
00 00 a0 c0 72 64 70 73 6e 64 00 00 00 00 00 c0
```

字节数核对：25 行 × 16 = 400，末行 16 字节 = 416。偏移 0x00–0x1A0。

Connect Response（337 字节，[MS-RDPBCGR] 4.1.4）：

```
03 00 01 51 02 f0 80 7f 66 82 01 45 0a 01 00 02
01 00 30 1a 02 01 22 02 01 03 02 01 00 02 01 01
02 01 00 02 01 01 02 03 00 ff f8 02 01 02 04 82
01 1f 00 05 00 14 7c 00 01 2a 14 76 0a 01 01 00
01 c0 00 4d 63 44 6e 81 08 01 0c 0c 00 04 00 08
00 00 00 00 00 03 0c 10 00 eb 03 03 00 ec 03 ed
03 ee 03 00 00 02 0c ec 00 02 00 00 00 02 00 00
00 20 00 00 00 b8 00 00 00 10 11 77 20 30 61 0a
12 e4 34 a1 1e f2 c3 9f 31 7d a4 5f 01 89 34 96
e0 ff 11 08 69 7f 1a c3 d2 01 00 00 00 01 00 00
00 01 00 00 00 06 00 5c 00 52 53 41 31 48 00 00
00 00 02 00 00 3f 00 00 00 01 00 01 00 cb 81 fe
ba 6d 61 c3 55 05 d5 5f 2e 87 f8 71 94 d6 f1 a5
cb f1 5f 0c 3d f8 70 02 96 c4 fb 9b c8 3c 2d 55
ae e8 ff 32 75 ea 68 79 e5 a2 01 fd 31 a0 b1 1f
55 a6 1f c1 f6 d1 83 88 63 26 56 12 bc 00 00 00
00 00 00 00 00 08 00 48 00 e9 e1 d6 28 46 8b 4e
f5 0a df fd ee 21 99 ac b4 e1 8f 5f 81 57 82 ef
9d 96 52 63 27 18 29 db b3 4a fd 9a da 42 ad b5
69 21 89 0e 1d c0 4c 1a a8 aa 71 3e 0f 54 b9 9a
e4 99 68 3f 6c d6 76 84 61 00 00 00 00 00 00 00
00
```

---

## 10. 未验证项与规范差异

### 10.1 `h221NonStandard` 的"8 字节"说法不成立（已核实）

- 任务描述要求"h221NonStandard key 的 8 字节（给出精确值）"。
- 官方原文：`H221NonStandardIdentifier ::= OCTET STRING (SIZE (4..255))`（T.124 §8.7，S31 第 167 页 / S32 第 171 页）。
- RDP 实际使用 **4 字节 ASCII**：客户端 `44 75 63 61`（"Duca"），服务端 `4D 63 44 6E`（"McDn"）（S23、S25、S26、S27）。
- 线上该键之前的 1 字节 `0x00` 是 PER 长度决定因子（`len - 4 = 0`），不是键的一部分。
- 因此**精确实现参数**为：`static const uint8_t kH221KeyClient[4] = {0x44,0x75,0x63,0x61};` 与 `kH221KeyServer[4] = {0x4D,0x63,0x44,0x6E};`，编码时前置 `(len-4)` 单字节。
- 未核实：T.124 称前 4 字节"shall be country code and Manufacturer code, assigned as specified in Annex A/H.221"。**未获取** H.221 Annex A 原文来确认 "Duca"/"McDn" 对应的国家码/厂商码分配；微软规范只要求"ANSI 字符串 Duca/McDn"，未给出 H.221 分配依据。此项标注为**未验证**。

### 10.2 `convMode` / `convCreate` 字段不存在（已核实）

- 在以下原文中检索 `convMode`、`convCreate`、`ConvMode`、`ConvCreate`：**0 次命中**。
  - [MS-RDPBCGR] 官方 PDF v20260309（S29，444 页全文）
  - T.124 (01/2007) 官方 PDF（S31）
  - T.124 (02/98) 官方 PDF（S32）
  - T.125 (02/98) 官方 PDF（S30）
- 实际存在的字段是：`conferenceName`、`convenerPassword`、`password`、`lockedConference`、`listedConference`、`conductibleConference`、`terminationMethod`、`conductorPrivileges`、`conductedPrivileges`、`nonConductedPrivileges`、`conferenceDescription`、`callerIdentifier`、`userData`，以及扩展 `conferencePriority`、`conferenceMode`（S31 第 175–176 页）。
- 结论：`convMode`/`convCreate` 不是 T.124/T.125 的字段名，可能是其他实现（如 FreeRDP 结构体/旧文档）的命名。本文件按官方 ASN.1 字段名描述。若后续实现需要与该命名对齐，应做映射层而非改字段语义。

### 10.3 章节号与任务描述不一致（已核实）

| 任务描述 | 实际官方标题 | 结论 |
|---|---|---|
| 2.2.1.3.1 Client Core Data | 2.2.1.3.1 **User Data Header (TS_UD_HEADER)** | 编号偏移；Client Core Data 是 2.2.1.3.2 |
| 2.2.1.4.5 Server Monitor Data | 2.2.1.4.5 **Server Message Channel Data (TS_UD_SC_MCS_MSGCHANNEL)** | 该标题不存在 |
| 2.2.1.4.6 Server Monitor Extended Data | 2.2.1.4.6 **Server Multitransport Channel Data (TS_UD_SC_MULTITRANSPORT)** | 该标题不存在 |
| 2.2.1.3 入口 GUID `9cde84cd-...` | 实为 2.2.1.10 Security Exchange PDU | 404；正确入口为 `db6713ee-...` |

- 服务端**没有** Monitor / MonitorExtended 数据块：显示器布局由服务端通过 **Monitor Layout PDU**（2.2.12.1，S 列表外，已抓取 200）下发，而非 GCC Connect Response。本文件 §7 因此按真实存在的 SC_CORE / SC_SECURITY / SC_NET / SC_MCS_MSGCHANNEL / SC_MULTITRANSPORT 给出字段表。

### 10.4 `maximumParameters.maxUserIds` 规范表与 dump 不一致（已核实）

- S23（3.2.5.3.3）表格：`maximumParameters.maxUserIds = 65535`。
- S26（4.1.3）真实 Windows 客户端 dump：`02 02 FC 17` = **64535**。
- 二者均为官方原文，属"规范 SHOULD 值"与"示例实现实际值"的差异。**未获取**解释该差异的官方说明。实现建议：生成时按 S23 表（65535）或按 dump（64535）均可被服务端接受（S24 合并规则只用 `maximumParameters.maxUserIds >= 3`）；做字节级回归测试时须与所选基准一致。

### 10.5 其他未验证项

| 项 | 状态 | 说明 / 尝试过的来源 |
|---|---|---|
| T.125 §7 的 `Connect-Initial` 在第 7 章（版本 1）与第 8 章（版本 3）的完整原文对照 | 部分核实 | 已获取 §7 Part 2 与 §8 的 ASN.1 定义（S30 第 15–16、24–26 页）；第 8 章扩展参数部分（ExtendedParameters）未逐字段整理，RDP 不使用 |
| T.124 `ConferenceCreateRequest` 的 PER 位域是否官方逐位给出 | 未获取 | T.124 未给出位级注解；本文 §4.3/§4.4 的位域来自 [MS-RDPBCGR] 4.1.3/4.1.4 注解 + 本仓库重编码验证（C 级推导，已验证字节一致） |
| `ConnectGCCPDU` CHOICE 索引位宽（2 位 vs 3 位） | 存在文档矛盾 | S26 注解写 2 位 + padding；按 ASN.1（8 个 root 分支）应为 3 位。两种编码在"全 0 索引"下字节相同（已重编码验证）。本文按 3 位实现，标注为待与微软文档确认 |
| `ConferenceCreateResponse` 的 `connectPDU` 长度（dump 声明 42，实际 279） | 已核实为规范允许 | S27 明确"该长度被客户端忽略"；实现 MUST NOT 用它做边界检查，应以 OCTET STRING 实际长度为准 |
| `conferenceName` 的 `numeric` 长度决定因子位置（octet 对齐时机） | 已通过重编码验证 | 位流在 ConferenceName.text 存在位之后按 octet 对齐，再写长度决定因子；与 dump 一致 |
| T.123 §8（TPKT）与 X.224 §13.7（Data TPDU）原文 | 未获取 | 本次只抓取 MS-RDPBCGR 对这两层的引用描述（S2、S26）；TPKT/X.224 细节见项目 `docs/spec/connection-initiation.md` |
| 服务端数据块顺序是否允许任意排列 | 未获取明确语句 | 客户端侧 S2 明确允许；服务端侧 S15 仅列顺序，未写"可任意"。实现应按"读头步进"解析以兼容两种 |

---

## 11. 与其他文档的关系

- 前置层（TPKT / X.224 / RDP Negotiation）：`docs/spec/connection-initiation.md`。
- 后续层（Erect Domain / Attach User / Channel Join）：[MS-RDPBCGR] 2.2.1.5–2.2.1.9（本次未落盘）。
- 本文件覆盖：Connect Initial（2.2.1.3）、Connect Response（2.2.1.4）及其全部 GCC 用户数据块。
