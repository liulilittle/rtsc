# 共享 PDU 头 + Fast-Path + 连接最终化 规格（P4）

本文件是 RTSC 项目 P4 阶段的实现依据，覆盖三条主线：

1. **Slow-Path（T.128 共享）头**：`TS_SHARECONTROLHEADER`、`TS_SHAREDATAHEADER`、安全头三态。
2. **Fast-Path**：输入 PDU、输出（更新）PDU、事件/更新枚举、分片重组。
3. **Connection Finalization**：客户端与服务端在连接最终化阶段交换的全部 PDU 与完整时序。

全部事实性论断均标注 `[MS-RDPBCGR]` 章节号。凡属推导（规范未直接给出字节序/位序结论）一律显式标注 **【推导】**，并给出推导依据。凡属本项目建议（规范未强制）一律标注 **【建议】**。

**证据等级约定**

| 等级 | 含义 |
|---|---|
| A | `[MS-RDPBCGR]` 网页正文原文（learn.microsoft.com openspecs 页面，本次实际抓取，HTTP 200） |
| A-dump | `[MS-RDPBCGR]` 第 4 章官方 annotated dump（逐字节注解原文） |
| D | 由 A / A-dump 推导（本文标注【推导】） |
| R | 本文建议（规范未强制，标注【建议】） |

**阅读顺序建议**：实现者先读 §1（封装与位序约定），再按需读 §2 / §3 / §4；§5 是可直接用于单元测试的十六进制向量；§6 是必须实现的校验与错误路径；§8 列出全部规范空洞与待确认点。

---

## 0. 规范来源清单（本次实际抓取）

| 编号 | 章节 | 标题 | GUID | 等级 |
|---|---|---|---|---|
| S01 | 2.2.8.1.1.1.1 | Share Control Header (TS_SHARECONTROLHEADER) | 73d01865-2eae-407f-9b2c-87e31daac471 | A |
| S02 | 2.2.8.1.1.1.2 | Share Data Header (TS_SHAREDATAHEADER) | 4b5d4c0d-a657-41e9-9c69-d58632f46d31 | A |
| S03 | 2.2.8.1.1.2 | Security Headers（容器页） | 9865e0ce-a540-4eab-9409-2a25937c38d2 | A |
| S04 | 2.2.8.1.1.2.1 | Basic (TS_SECURITY_HEADER) | e13405c5-668b-4716-94b2-1c2654ca1ad4 | A |
| S05 | 2.2.8.1.1.2.2 | Non-FIPS (TS_SECURITY_HEADER1) | 768e12c4-7748-4005-b91d-790847e47025 | A |
| S06 | 2.2.8.1.1.2.3 | FIPS (TS_SECURITY_HEADER2) | 463bd2eb-c3b1-4986-86b0-a240819d9088 | A |
| S07 | 2.2.8.1.1.3 | Client Input Event PDU (TS_INPUT_PDU) | d93d0cc5-5f56-4b80-83fd-3e919ae7d750 | A |
| S08 | 2.2.8.1.1.3.1 | Client Input Event PDU Data (TS_INPUT_PDU_DATA) | ff7f06f8-0dcf-4c8d-be1f-596ae60c4396 | A |
| S09 | 2.2.8.1.1.3.1.1 | Slow-Path Input Event (TS_INPUT_EVENT) | a9a26b3d-84a2-495f-83fc-9edd6601f33b | A |
| S10 | 2.2.8.1.2 | Client Fast-Path Input Event PDU (TS_FP_INPUT_PDU) | b8e7c588-51cb-455b-bb73-92d480903133 | A |
| S11 | 2.2.8.1.2.1 | Fast-Path FIPS Information (TS_FP_FIPS_INFO) | a641797e-3179-4212-8447-fa2a39e19c7b | A |
| S12 | 2.2.8.1.2.2 | Fast-Path Input Event (TS_FP_INPUT_EVENT) | 76c4dd59-7ba0-445d-a03c-885212ab80f6 | A |
| S13 | 2.2.8.1.2.2.1 | Fast-Path Keyboard Event (TS_FP_KEYBOARD_EVENT) | 089d362b-31eb-4a1a-b6fa-92fe61bb5dbf | A |
| S14 | 2.2.8.1.2.2.2 | Fast-Path Unicode Keyboard Event | e7b13e98-d800-42bb-9a1d-6948537d2317 | A |
| S15 | 2.2.8.1.2.2.3 | Fast-Path Mouse Event (TS_FP_POINTER_EVENT) | 16a96ded-b3d3-4468-b993-9c7a51297510 | A |
| S16 | 2.2.8.1.2.2.4 | Fast-Path Extended Mouse Event | c1d16633-3633-4868-b8ab-2b7e5f6d002a | A |
| S17 | 2.2.8.1.2.2.5 | Fast-Path Synchronize Event | 26d44af0-7eb2-4e7d-8a94-c05b9fa4a98e | A |
| S18 | 2.2.8.1.2.2.6 | Fast-Path QoE Timestamp Event | 4b1d972e-4435-4b27-84c7-63a36994e8e0 | A |
| S19 | 2.2.8.1.2.2.7 | Fast-Path Relative Mouse Event | 3b4ee59e-6049-45a9-9fcb-2e308defa3eb | A |
| S20 | 2.2.9.1.2 | Server Fast-Path Update PDU (TS_FP_UPDATE_PDU) | 68b5ee54-d0d5-4d65-8d81-e1c4025f7597 | A |
| S21 | 2.2.9.1.2.1 | Fast-Path Update (TS_FP_UPDATE) | a1c4caa8-00ed-45bb-a06e-5177473766d3 | A |
| S22 | 2.2.9.1.2.1.1 | Fast-Path Palette Update | 75eafb5c-40b2-4ffa-864f-5461a3329a28 | A |
| S23 | 2.2.9.1.2.1.2 | Fast-Path Bitmap Update | 0ae3c114-1439-4465-8d3f-6585227eff7d | A |
| S24 | 2.2.9.1.2.1.3 | Fast-Path Synchronize Update | 406dc477-c516-41cb-a8a0-ab4cc7119621 | A |
| S25 | 2.2.9.1.2.1.4 | Fast-Path Pointer Position Update | d50e2da8-c830-466e-8866-2d8871d0caaf | A |
| S26 | 2.2.9.1.2.1.5 | Fast-Path System Pointer Hidden Update | 129a003f-ddf4-4500-929d-c8b1cb214857 | A |
| S27 | 2.2.9.1.2.1.6 | Fast-Path System Pointer Default Update | 601801eb-ce9e-4073-803b-aea6deb1e457 | A |
| S28 | 2.2.9.1.2.1.7 | Fast-Path Color Pointer Update | c1fcf9dd-9762-4d73-9073-1f3f63ecc679 | A |
| S29 | 2.2.9.1.2.1.8 | Fast-Path New Pointer Update | c4490937-74aa-497c-94e4-17a78015e1a0 | A |
| S30 | 2.2.9.1.2.1.9 | Fast-Path Cached Pointer Update | 2a0a690b-6065-4d24-ac3a-4edc061dad99 | A |
| S31 | 2.2.9.1.2.1.10 | Fast-Path Surface Commands Update | cc14f53d-8303-4f0b-b0dc-5c865410c381 | A |
| S32 | 2.2.9.1.2.1.11 | Fast-Path Large Pointer Update | 037f4d6c-5753-4627-ba5e-ce1b8e9bc0cd | A |
| S33 | 2.2.1.14 / .14.1 | Client Synchronize PDU / TS_SYNCHRONIZE_PDU | e0027486-f99a-4f0f-991c-eda3963521c2 / 3fb4c95e-ad2d-43d1-a46f-5bd49418da49 | A |
| S34 | 2.2.1.15 / .15.1 | Client Control PDU - Cooperate / TS_CONTROL_PDU | 9d1e1e21-d8b4-4bfd-9caf-4b72ee91a713 / 0448f397-aa11-455d-81b1-f1265085239d | A |
| S35 | 2.2.1.16 | Client Control PDU - Request Control | 4f94e123-970b-4242-8cf6-39820d8e3d35 | A |
| S36 | 2.2.1.17 / .17.1 / .17.1.1 | Persistent Key List PDU / DATA / ENTRY | 2d122191-af10-4e36-a781-381e91c182b7 / a6218d19-5505-445d-acea-1b3f5b0097dc / 84737de7-76a1-47d7-bdc1-a26c3abf9997 | A |
| S37 | 2.2.1.18 / .18.1 | Client Font List PDU / TS_FONT_LIST_PDU | 7067da0d-e318-4464-88e8-b11509cf0bd9 / e373575a-01e2-43a7-a6d8-e1952b83e787 | A |
| S38 | 2.2.1.19 | Server Synchronize PDU | 5186005a-36f5-4f5d-8c06-968f28e2d992 | A |
| S39 | 2.2.1.20 | Server Control PDU - Cooperate | 43296a04-6324-4cbf-93d1-8e056e969082 | A |
| S40 | 2.2.1.21 | Server Control PDU - Granted Control | ff7bae0e-cd13-4776-83b2-ef1f45e1fc41 | A |
| S41 | 2.2.1.22 / .22.1 | Server Font Map PDU / TS_FONT_MAP_PDU | 7ba6ba81-e4f4-46a7-9062-2d57a821be26 / b4e557f3-7540-46fc-815d-0c12299cf1ee | A |
| S42 | 2.2.10.1 / .10.1.1 | Server Save Session Info PDU / DATA | 885c1879-e0c8-4e2d-80c4-81acea9b51fb / d892bc5b-aecd-4aee-99b6-5f43b5a63d75 | A |
| S43 | 1.3.1.1 | Connection Sequence（含 Connection Finalization 正文） | 023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee | A |
| S44 | 3.2.5.1 | Constructing a Client-to-Server Slow-Path PDU | b27f8935-ac1f-47f7-b87b-32b92875b869 | A |
| S45 | 3.2.5.2 | Processing a Server-to-Client Slow-Path PDU | dac03011-f059-44d3-a30b-26f238ad21aa | A |
| S46 | 3.3.5.2 | Processing a Client-to-Server Slow-Path PDU | 3608c816-fb97-4b75-b925-7cb75deef21c | A |
| S47 | 3.2.5.8.1.2 | Sending Fast-Path Input Event PDU | 37879f07-d502-4426-b218-c6119f58349c | A |
| S48 | 3.3.5.8.1.2 | Processing Fast-Path Input Event PDU | 178aef78-2606-4e44-a94a-6ee6f6dc5cc6 | A |
| S49 | 3.3.5.9.3 | Processing Fast-Path Update PDU | 000966f4-4863-4668-9c13-852e252bb376 | A |
| S50 | 3.2.5.9.3.1 | Processing Fast-Path Update Fragments | 8000f797-c2b6-42da-b469-29d4f90f375e | A |
| S51 | 3.2.5.3.14…3.2.5.3.18 | Sending Synchronize / Cooperate / Request / Persistent / FontList | 4606db9f-03d7-4e50-9514-67d265402094 / 6e014444-be22-4118-84fe-cc0567b60e68 / e3a79a2c-6be2-48b9-9b7a-1b7be3bb25dd / 94ecc579-7514-4325-a084-5e5d2efabac3 / e038dd4d-c0ea-44b3-9378-25e14938b954 | A |
| S52 | 3.2.5.3.19…3.2.5.3.22 | Processing Synchronize / Cooperate / Granted / FontMap（客户端） | 310aad49-1b52-43ec-bc32-ac42ccebb846 / 5331309d-646f-4210-bd6c-3cfbad605647 / 45216e28-843b-4df5-b3b5-526ffb88f87b / d246ad43-d84e-4de8-a808-46e11035db56 | A |
| S53 | 3.3.5.3.14…3.3.5.3.22 | 服务端侧处理/发送（Synchronize…FontMap） | e39c31bb-e641-49dd-a48c-ce590632a3bd / 430aea93-8c00-4543-a8b1-c214b663a5b6 / 06c3757d-0d2f-4301-b1ed-0ad7f5ee1352 / 72de97df-c81a-4c38-ba37-cfb9e37b5829 / 630f3d34-7086-4761-8c7d-cd4e1371347e / 3d9e9d28-9bb0-4fd3-8ed9-62483a0bdc1e / 49163186-c55f-4990-9960-cca5478bcb02 / d65b41be-d888-44cb-b1bf-cc6f05525890 | A |
| S54 | 2.2.5.1.1 | Set Error Info PDU Data（ERRINFO_* 码表） | a21a1bd9-2303-49c1-90ec-3932435c248c | A |
| S55 | 5.3.8 | Packet Layout in the I/O Data Stream | 261d841e-6ce3-427d-8735-7a6e6c2cfb2c | A |
| S56 | 5.3.2 | Negotiating the Cryptographic Configuration | b9a49d9e-44db-46aa-90a7-bb7f75718e02 | A |
| S57 | 5.3.1 | Encryption Levels | f1c7c93b-94cc-4551-bb90-532a0185246a | A |
| S58 | 3.1.8.2.1 | Setting the Compression Flags | 9355a663-ef22-4431-afeb-d72ac68f25fd | A |
| S59 | 4.1.14 | Annotated Client Synchronize PDU（官方 dump） | 见 `MS-RDPBCGR_text.txt` L369 | A-dump |
| S60 | 4.1.18 | Annotated Client Font List PDU（官方 dump） | 见 `MS-RDPBCGR_text.txt` L374 | A-dump |
| S61 | 4.1.19 | Annotated Server Synchronize PDU（官方 dump） | 见 `MS-RDPBCGR_text.txt` L374–375 | A-dump |
| S62 | 4.1.20 | Annotated Server Control - Cooperate（官方 dump） | 见 `MS-RDPBCGR_text.txt` L375–376 | A-dump |
| S63 | 4.1.21 | Annotated Server Control - Granted Control（官方 dump） | 见 `MS-RDPBCGR_text.txt` L376 | A-dump |
| S64 | 4.1.22 | Annotated Server Font Map PDU（官方 dump） | 见 `MS-RDPBCGR_text.txt` L376–377 | A-dump |
| S65 | 4.7 | Annotated Fast-Path Input Event PDU（官方 dump） | d8f1be0e-ca81-4caf-a494-3c161d21a7f2 | A-dump |
| S66 | 2.2.9.1.1.2 | Security Headers（输出方向，指向 2.2.8.1.1.2） | 0c7d0164-5101-4f0a-b4cf-1026061d5a29 | A |
| S67 | 2.2.9.1.1.4.1 / .2 | Point (TS_POINT16) / Pointer Position Update | 71d3155c-f57b-4e5b-80b6-3669a2a06d09 / 3058381e-c856-4b26-a93c-d8f5514f8c3c | A |
| S68 | 2.2.9.1.1.3.1.1 / .1.1.1 / .1.1.2 | Palette Update / DATA / RGB Entry | af2fe66b-640a-4ca9-84e1-259b7e00e929 / 8cba3676-376e-4088-95f3-bd56e00f24ad / 81165f40-b207-4728-b5ad-1a8e090dc519 | A |
| S69 | 2.2.9.1.1.4.4 / .4.5 / .4.6 | Color / New / Cached Pointer Update | 71fad4fc-6ad4-4c7f-8103-a442bebaf7d2 / 584e4438-574c-45f4-947f-b0edcd9ae32c / 1296e1bb-15ad-4bbc-8de9-7f0d5776390a | A |
| S70 | 2.2.8.1.1.3.1.1.1…7 | 慢路径输入事件 7 种 | 7acaec9f-c8a6-4ee9-87d6-d9b89cf56489 / 551b9903-8fb9-4d00-b3ac-a187431efb86 / 2c1ced34-340a-46cd-be6e-fc8cab7c3b17 / 2ef7632f-2f2a-4de7-ab58-2585cedcdf48 / 6c5d0ef9-4653-4d69-9ba9-09ba3acd660f / afbdb159-89cf-4e96-890b-ea955b723701 / 9af47964-8bfc-4f43-8a15-4339a89833fa | A |
| S71 | 2.2.9.1.1.3.1.3 | Synchronize Update (TS_UPDATE_SYNC) | 4e591625-8c07-4ad7-9215-dbe4908c3cf5 | A |

> 说明：S59–S64 的逐字节注解来自 `[MS-RDPBCGR]` 官方 PDF 文本（`F:\rtsc\.tmp\MS-RDPBCGR_text.txt`，v20260309，444 页）第 4 章的 annotated dump；这些 dump 与对应章节的结构定义互相印证，属于 A 级证据。

---

## 1. 封装层级与位序约定

### 1.1 两种线上格式

RDP 的共享数据（输入事件、图形更新、连接最终化 PDU）有且只有两种封装形式：

| 形态 | 首字节判别 | 外层结构 | 依据 |
|---|---|---|---|
| Slow-Path | `first_byte == 0x03` | TPKT(4) + X.224 Data TPDU(3) + MCS SDrq/SDin(variable) + securityHeader(可选) + shareDataHeader(18) + PDU 内容 | 2.2.8.1.1（S44/S45/S46）、5.3.8（S55） |
| Fast-Path | `(first_byte & 0x03) == 0x00` | 无 TPKT / 无 X.224 / 无 MCS；`fpInputHeader` 或 `fpOutputHeader` + length + 可选 FIPS/签名 + 事件或更新数组 | 2.2.8.1.2（S10）、2.2.9.1.2（S20） |

Fast-Path 的设计目的（原文，2.2.8.1.2）：

> "Fast-path revises client input packets from the first byte with the goal of improving bandwidth. The TPKT Header, X.224 Class 0 Data TPDU, and MCS Send Data Request are replaced; the Security Header is collapsed into the fast-path input header, and the Share Data Header is replaced by a new fast-path format."

输出方向表述相同（2.2.9.1.2）。

**【推导】** Fast-Path 报文不携带 MCS `channelId`，因此它隐式绑定在 MCS I/O 通道上；接收方无法用 MCS 头做通道路由，只能依据"首字节不是 0x03"这一事实分流。这直接决定了实现里 demux 入口的形状（先看首字节，再决定走 MCS 解析还是 Fast-Path 解析）。

### 1.2 Slow-Path 数据 PDU 的完整层次

```
+--------------------------------------------------------+
| TPKT Header                     4 bytes   offset 0     |  [T123] §8
+--------------------------------------------------------+
| X.224 Class 0 Data TPDU         3 bytes   offset 4     |  [X224] §13.7
+--------------------------------------------------------+
| MCS Send Data Request/Indication variable  offset 7    |  [T125] §11.32 / 11.33
+--------------------------------------------------------+
| securityHeader (可选, 0 / 4 / 12 / 16 bytes)           |  2.2.8.1.1.2
+--------------------------------------------------------+
| shareDataHeader                18 bytes                |  2.2.8.1.1.1.2
|   shareControlHeader            6 bytes                |  2.2.8.1.1.1.1
|   shareID(4) pad1(1) streamID(1)                       |
|   uncompressedLength(2) pduType2(1)                    |
|   compressedType(1) compressedLength(2)                |
+--------------------------------------------------------+
| PDU 内容（由 pduType / pduType2 决定）                  |  2.2
+--------------------------------------------------------+
```

**必须澄清的两个长度口径**（实现中最易出错处）：

1. `shareDataHeader` 的 18 字节**包含** 6 字节 `shareControlHeader`（2.2.8.1.1.1.2 的结构图把 `shareControlHeader` 画在 `shareDataHeader` 内部）。因此 `18 = 6 + 12`，而不是 `6 + 18 = 24`。
2. `TS_SHARECONTROLHEADER.totalLength` 从 `shareControlHeader` 第一个字节开始计数，**不含** securityHeader、TPKT、X.224、MCS。证据：4.1.14 客户端 Synchronize 的 `totalLength = 0x0016 = 22`，而 22 = 18（shareDataHeader）+ 4（messageType + targetUser）；其外层还有 12 字节 `TS_SECURITY_HEADER1` 未计入（S59）。

**红证（算术闭合，S59 / 4.1.14）**：该 PDU 的线上布局逐项可对齐：

```
03 00 00 30             TPKT，length = 0x0030 = 48
02 f0 80                X.224 Data TPDU（3 字节）
64 00 06 03 eb 70 22    MCS SDrq 头（7 字节），userData 长度 = 0x22 = 34
28 00                   securityHeader.flags      (2)
81 f8                   securityHeader.flagsHi    (2)
59 ff cb 2f 73 57 2b 42 dataSignature             (8)
db 88 … 44 75           密文负载                  (22)
```

校验：`4 + 3 + 7 + 34 = 48` ✔（TPKT 声明值）。`MCS userData = 34 = 12 + 22` ✔，其中 12 = `TS_SECURITY_HEADER1`（`flags`2 + `flagsHi`2 + `dataSignature`8），22 = 密文负载。而解密后明文首字段 `totalLength = 0x0016 = 22` ✔ —— **正好等于密文负载长度，不含 12 字节 securityHeader1**。

结论：**`totalLength` 只统计 `shareControlHeader` 起的明文长度；`securityHeader` 与 MAC 都在其外**。同时提醒：TPKT `length` 与 `totalLength` 是两个不同口径的字段（前者含 TPKT/X.224/MCS/securityHeader，后者不含），不可互相比对。

### 1.3 位序约定（关键，必须严格遵守）

`[MS-RDPBCGR]` 的 bitmask diagram 以 `0 1 2 3 … 31` 从左到右编号。**该编号是"位序号"，最左侧是 bit0（最低位），不是最高位。** 这与"多字节字段小端存放"的约定一致，但与人阅读 MSB-first 位图的习惯相反，是最容易写错的地方。

本节结论由**三个独立官方 dump 交叉验证**（属于红证，非猜测）：

| 证据 | 字节 | 官方注解 | 唯一自洽的位切分 |
|---|---|---|---|
| S65 `fpInputHeader` | `0xc4` | `action = 0`、`numEvents = 1`、`flags = 0x3` | `action = [1:0]`、`numEvents = [5:2]`、`flags = [7:6]` |
| S65 `eventHeader` | `0x20` | `eventCode = 1 (MOUSE)`、`eventFlags = 0` | `eventFlags = [4:0]`、`eventCode = [7:5]` |
| S59 `pduType` | `0x0017` | `type = 7 (PDUTYPE_DATAPDU)`、`PDUVersion = 1` | `type = [3:0]`、`PDUVersion = [15:4]` |

**反证（若按 MSB-first 读会怎样）**：

- `0xc4 = 1100 0100`：取高 2 位得 `action = 3`，会被判成 **slow-path**，与"这是 Fast-Path Input PDU"的官方结论直接矛盾。
- `0x20 = 0010 0000`：取低 3 位得 `eventCode = 0`（SCANCODE），则后续应只有 1 字节 `keyCode`，但 dump 明确余下 6 字节是 `pointerFlags(2) + xPos(2) + yPos(2)` 且 `pointerFlags = 0x0800 = PTRFLAGS_MOVE`、`xPos = 0x02ab`、`yPos = 0x016f` 全部自洽。只有 `eventCode = [7:5] = 1` 能解释。
- `pduType = 0x0017`：取高 4 位得 `type = 0`（未定义），与"Data PDU"矛盾。

因此本文所有位域表统一采用：

```
位段写法 [hi:lo]，hi/lo 均为 bit 序号（bit0 = 最低位 = 线上该字节的最右位）
```

并在每个位域表额外给出"掩码/移位"表达式，便于直接落码。

### 1.4 通用约定

| 约定 | 说明 | 依据 |
|---|---|---|
| 多字节整数 | 除 Fast-Path 的 `length1/length2` 组合外，一律 **little-endian** | 2.2 全章结构定义；各 dump 印证 |
| Fast-Path 长度 | `length1/length2` 组合为 **big-endian** | 2.2.8.1.2、2.2.9.1.2 |
| 填充字段（`pad*`） | 值必须忽略，不得用于校验，不得因非零而断连 | 各结构字段说明 |
| 字符串 | 除特别说明外为 UTF-16LE，且多数带"字节数"前缀（非字符数） | 各结构字段说明 |
| "MUST / SHOULD / MAY" | 保留规范原义；本文凡写"必须"对应 MUST，"应"对应 SHOULD，"可"对应 MAY | — |

---

## 2. Slow-Path（共享）头

### 2.1 `TS_SHARECONTROLHEADER`（2.2.8.1.1.1.1）

固定 6 字节，是所有共享 PDU 的公共前缀。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 来源 |
|---|---|---|---|---|---|
| 0 | 2 | `totalLength` | u16 LE | 整包总长（含本头 6 字节）；若等于 `0x8000` 则该头及其后数据可能应被解释为 T.128 FlowPDU，**必须忽略** | 2.2.8.1.1.1.1 |
| 2 | 2 | `pduType` | u16 LE 位域 | `type`(4) + `PDUVersion`(12) | 2.2.8.1.1.1.1 |
| 4 | 2 | `pduSource` | u16 LE | 发送该 PDU 的 MCS 通道 ID | 2.2.8.1.1.1.1 |

`pduType` 位域（掩码表达式见右列）：

| 位段 | 宽度 | 字段 | 提取表达式 | 说明 |
|---|---|---|---|---|
| `[3:0]` | 4 | `type` | `pduType & 0x000F` | PDU 类型，见 §2.2 |
| `[15:4]` | 12 | `PDUVersion` | `(pduType >> 4) & 0x0FFF` | PDU 版本；Data PDU 必须为 `TS_PROTOCOL_VERSION (0x1)`（2.2.8.1.1.1.2） |

**红证**：4.1.14 dump `pduType = 0x0017`，`0x0017 = 0x10 | 0x0007`，官方注解为 `TS_PROTOCOL_VERSION | PDUTYPE_DATAPDU`（S59）。4.1.19 服务端 Synchronize 同为 `0x0017`（S61）。4.1.15/4.1.16/4.1.17/4.1.18 亦全为 `0x0017`。

**`totalLength == 0x8000` 特殊分支**

- 规范原文（2.2.8.1.1.1.1）："If the `totalLength` field equals 0x8000, then the Share Control Header and any data that follows MAY be interpreted as a T.128 FlowPDU as described in [T128] section 8.5 ... and MUST be ignored."
- **【建议】** 不要因为 `0x8000` 直接断连；按规范"忽略该 PDU"，但仍必须消费掉它所占字节，否则后续帧错位。由于 `0x8000` 是"长度不可信"标记，实际可消费长度只能取外层 MCS `userData` 的剩余长度。

**`totalLength` 一致性校验**（3.2.5.2 / 3.3.5.2 原文要求）：接收方**必须**校验 `totalLength` 与实际收到的数据一致，不一致时 SHOULD 断连。注意"实际收到的数据"指 `shareControlHeader` 起点到 MCS `userData` 末尾的字节数，**不含** securityHeader。

### 2.2 `pduType.type` 完整枚举（2.2.8.1.1.1.1）

| 名称 | 数值 | 含义 | 引用章节 |
|---|---|---|---|
| `PDUTYPE_DEMANDACTIVEPDU` | `0x1` | Demand Active PDU（服务端→客户端，能力交换） | 2.2.1.13.1 |
| `PDUTYPE_CONFIRMACTIVEPDU` | `0x3` | Confirm Active PDU（客户端→服务端） | 2.2.1.13.2 |
| `PDUTYPE_DEACTIVATEALLPDU` | `0x6` | Deactivate All PDU | 2.2.3.1 |
| `PDUTYPE_DATAPDU` | `0x7` | Data PDU（真实类型由 `pduType2` 给出） | 2.2.8.1.1.1.2 |
| `PDUTYPE_SERVER_REDIR_PKT` | `0xA` | Enhanced Security Server Redirection PDU | 2.2.13.3.1 |

规范只列出上述 5 个值。其余 4 位组合（`0x0, 0x2, 0x4, 0x5, 0x8, 0x9, 0xB…0xF`）未定义；服务端为此定义错误码 `ERRINFO_UNKNOWNPDUTYPE (0x000010CA)`（2.2.5.1.1 / S54）。

**含 `TS_SHARECONTROLHEADER` 的 PDU 完整清单**（2.2.8.1.1.1.1 原文列举）：

1. Demand Active PDU（2.2.1.13.1）
2. Confirm Active PDU（2.2.1.13.2）
3. Deactivate All PDU（2.2.3.1）
4. Enhanced Security Server Redirection PDU（2.2.13.3.1）
5. 所有 Data PDU（2.2.8.1.1.1.2）——完整清单见 §2.5

### 2.3 `TS_SHAREDATAHEADER`（2.2.8.1.1.1.2）

总长 18 字节（含内嵌的 6 字节 Share Control Header）。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 来源 |
|---|---|---|---|---|---|
| 0 | 6 | `shareControlHeader` | 结构 | 见 §2.1；`PDUVersion` 必须为 `TS_PROTOCOL_VERSION (0x1)` | 2.2.8.1.1.1.2 |
| 6 | 4 | `shareID` | u32 LE | 共享标识（T.128 §8.4.2） | 2.2.8.1.1.1.2 |
| 10 | 1 | `pad1` | u8 | 填充，必须忽略 | 2.2.8.1.1.1.2 |
| 11 | 1 | `streamID` | u8 | 流优先级，见 §2.4 | 2.2.8.1.1.1.2 |
| 12 | 2 | `uncompressedLength` | u16 LE | 包**未压缩**时的长度（字节） | 2.2.8.1.1.1.2 |
| 14 | 1 | `pduType2` | u8 | Data PDU 类型，见 §2.5 | 2.2.8.1.1.1.2 |
| 15 | 1 | `compressedType` | u8 | 压缩类型 + 压缩标志，见 §2.6 | 2.2.8.1.1.1.2 |
| 16 | 2 | `compressedLength` | u16 LE | 包**压缩后**的长度（字节） | 2.2.8.1.1.1.2 |

**字段语义边界（重要）**

- `uncompressedLength` / `compressedLength` 是"长度声明"，**不是分帧依据**。规范在 3.2.5.2 / 3.3.5.2 只要求校验 `totalLength`，未要求校验这两个字段；官方 dump 里 `uncompressedLength` 甚至出现"与实际不符"与"未初始化"（见 §5.1 的 Font List 例）。
- `shareID` 在单会话内通常是常量（官方 dump 恒为 `0x000103ea`）。规范未要求客户端校验它，**不要**把它当校验字段。
- `pad1` 在官方 dump 中出现过 `0x00`、`0x14`、`0xb5`、`0x12`、`0x45` 等多种值（S59–S64），进一步证明它是纯填充。

### 2.4 `streamID` 枚举（2.2.8.1.1.1.2）

| 名称 | 数值 | 含义 | 备注 |
|---|---|---|---|
| `STREAM_UNDEFINED` | `0x00` | 未定义流优先级 | 规范明确：可能出现在 Server Synchronize PDU 中（服务端 bug），且**不得**与其他 PDU 一起使用 |
| `STREAM_LOW` | `0x01` | 低优先级流 | — |
| `STREAM_MED` | `0x02` | 中优先级流 | — |
| `STREAM_HI` | `0x04` | 高优先级流 | — |

`0x03` **不是**合法值（这四个是离散枚举，不是位标志组合）。接收端**必须忽略**该字段（3.2.5.2："The remaining Share Control Header and Share Data Header fields MAY be ignored"）。

**官方 dump 实测分布**（可作为测试向量）：

| PDU | `streamID` | 来源 |
|---|---|---|
| Client Synchronize（4.1.14） | `0x01` (LOW) | S59 |
| Client Control - Cooperate（4.1.15） | `0x01` (LOW) | S34 相关 dump |
| Client Control - Request（4.1.16） | `0x01` (LOW) | S35 相关 dump |
| Client Persistent Key List（4.1.17） | `0x01` (LOW) | S36 相关 dump |
| Client Font List（4.1.18） | `0x01` (LOW) | S60 |
| Server Synchronize（4.1.19） | `0x00` (UNDEFINED) | S61 |
| Server Control - Cooperate（4.1.20） | `0x02` (MED) | S62 |
| Server Control - Granted（4.1.21） | `0x02` (MED) | S63 |
| Server Font Map（4.1.22） | `0x02` (MED) | S64 |

注意 `STREAM_UNDEFINED` 只出现在 Server Synchronize，与规范描述完全吻合（这是服务端 bug 的实证）。

### 2.5 `pduType2`（sharedPDUType）完整枚举（2.2.8.1.1.1.2）

Data PDU 的真实类型。逐项给出数值、名称、承载结构、方向与章节。

| 数值 | 名称 | 承载的 PDU / 结构 | 方向 | 引用章节 |
|---|---|---|---|---|
| `0x02` | `PDUTYPE2_UPDATE` | Graphics Update PDU（`TS_GRAPHICS_PDU`，二级 `updateType` 再细分） | S→C | 2.2.9.1.1.3 |
| `0x14` | `PDUTYPE2_CONTROL` | Control PDU（`TS_CONTROL_PDU`） | 双向 | 2.2.1.15.1 |
| `0x1B` | `PDUTYPE2_POINTER` | Pointer Update PDU（`TS_POINTER_PDU`） | S→C | 2.2.9.1.1.4 |
| `0x1C` | `PDUTYPE2_INPUT` | Input Event PDU（`TS_INPUT_PDU_DATA`） | C→S | 2.2.8.1.1.3 |
| `0x1F` | `PDUTYPE2_SYNCHRONIZE` | Synchronize PDU（`TS_SYNCHRONIZE_PDU`） | 双向 | 2.2.1.14.1 |
| `0x21` | `PDUTYPE2_REFRESH_RECT` | Refresh Rect PDU | C→S | 2.2.11.2.1 |
| `0x22` | `PDUTYPE2_PLAY_SOUND` | Play Sound PDU（`TS_PLAY_SOUND_PDU_DATA`） | S→C | 2.2.9.1.1.5.1 |
| `0x23` | `PDUTYPE2_SUPPRESS_OUTPUT` | Suppress Output PDU | C→S | 2.2.11.3.1 |
| `0x24` | `PDUTYPE2_SHUTDOWN_REQUEST` | Shutdown Request PDU | C→S | 2.2.2.1.1 |
| `0x25` | `PDUTYPE2_SHUTDOWN_DENIED` | Shutdown Request Denied PDU | S→C | 2.2.2.2.1 |
| `0x26` | `PDUTYPE2_SAVE_SESSION_INFO` | Save Session Info PDU（`TS_SAVE_SESSION_INFO_PDU_DATA`） | S→C | 2.2.10.1.1 |
| `0x27` | `PDUTYPE2_FONTLIST` | Font List PDU（`TS_FONT_LIST_PDU`） | C→S | 2.2.1.18.1 |
| `0x28` | `PDUTYPE2_FONTMAP` | Font Map PDU（`TS_FONT_MAP_PDU`） | S→C | 2.2.1.22.1 |
| `0x29` | `PDUTYPE2_SET_KEYBOARD_INDICATORS` | Set Keyboard Indicators PDU | S→C | 2.2.8.2.1.1 |
| `0x2B` | `PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST` | Persistent Key List PDU（`TS_BITMAPCACHE_PERSISTENT_LIST_PDU`） | C→S | 2.2.1.17.1 |
| `0x2C` | `PDUTYPE2_BITMAPCACHE_ERROR_PDU` | Bitmap Cache Error PDU | 双向（错误） | [MS-RDPEGDI] 2.2.2.3.1 |
| `0x2D` | `PDUTYPE2_SET_KEYBOARD_IME_STATUS` | Set Keyboard IME Status PDU | S→C | 2.2.8.2.2.1 |
| `0x2E` | `PDUTYPE2_OFFSCRCACHE_ERROR_PDU` | Offscreen Bitmap Cache Error PDU | 双向（错误） | [MS-RDPEGDI] 2.2.2.3.2 |
| `0x2F` | `PDUTYPE2_SET_ERROR_INFO_PDU` | Set Error Info PDU（`TS_SET_ERROR_INFO_PDU`） | S→C | 2.2.5.1.1 |
| `0x30` | `PDUTYPE2_DRAWNINEGRID_ERROR_PDU` | DrawNineGrid Cache Error PDU | 双向（错误） | [MS-RDPEGDI] 2.2.2.3.3 |
| `0x31` | `PDUTYPE2_DRAWGDIPLUS_ERROR_PDU` | GDI+ Error PDU | 双向（错误） | [MS-RDPEGDI] 2.2.2.3.4 |
| `0x32` | `PDUTYPE2_ARC_STATUS_PDU` | Auto-Reconnect Status PDU | S→C | 2.2.4.1.1 |
| `0x36` | `PDUTYPE2_STATUS_INFO_PDU` | Status Info PDU | S→C | 2.2.5.2 |
| `0x37` | `PDUTYPE2_MONITOR_LAYOUT_PDU` | Monitor Layout PDU | S→C | 2.2.12.1 |

共 **24** 个已定义值。

**枚举空洞**：`0x00, 0x01, 0x03…0x13, 0x15…0x1A, 0x1D, 0x1E, 0x20, 0x2A, 0x33…0x35, 0x38…0xFF` 未定义。服务端错误码 `ERRINFO_UNKNOWNPDUTYPE2 (0x000010C9)` 专用于此情形（2.2.5.1.1）。处理策略见 §6.2。

**【建议】** 枚举必须用"稀疏表 + 默认分支"实现。不要用 `switch` 覆盖 `0x02…0x37` 连续区间，更不要用数组下标直接索引（`0x37 - 0x02 = 53` 个槽位里 29 个是空洞）。

### 2.6 `compressedType` 字段（2.2.8.1.1.1.2 + 3.1.8.2.1）

`compressedType` = 压缩类型（低 4 位）| 压缩标志（高位）。

**低 4 位：压缩包类型（`CompressionTypeMask = 0x0F`）**

| 数值 | 名称 | 含义 | 引用 |
|---|---|---|---|
| `0x0` | `PACKET_COMPR_TYPE_8K` | RDP 4.0 bulk compression | 3.1.8.4.1 |
| `0x1` | `PACKET_COMPR_TYPE_64K` | RDP 5.0 bulk compression | 3.1.8.4.2 |
| `0x2` | `PACKET_COMPR_TYPE_RDP6` | RDP 6.0 bulk compression | [MS-RDPEGDI] 3.1.8.1 |
| `0x3` | `PACKET_COMPR_TYPE_RDP61` | RDP 6.1 bulk compression | [MS-RDPEGDI] 3.1.8.2 |

**高位：压缩标志**

| 数值 | 名称 | 含义 | 约束 |
|---|---|---|---|
| `0x20` | `PACKET_COMPRESSED` | 负载已压缩（等价 MPPC bit C） | 压缩成功时必须置位；置位后长度不得大于原始数据 |
| `0x40` | `PACKET_AT_FRONT` | 解压结果必须放到历史缓冲区开头（MPPC bit B） | **必须**与 `PACKET_COMPRESSED` 同时置位 |
| `0x80` | `PACKET_FLUSHED` | 解压器必须用 0 重置历史缓冲区并把 `HistoryOffset` 归零（MPPC bit A） | 若同时有 `0x20`，**先**处理 `0x80` |

来源：2.2.8.1.1.1.2（字段表）与 3.1.8.2.1（S58，flags 语义与约束）。

**判定顺序**（依据 2.2.8.1.1.1.2 原文 "If the PACKET_COMPRESSED (0x20) flag is also present, then the PACKET_FLUSHED flag MUST be processed first"）：

```
if (compressedType & 0x80) reset_history_buffer();          // 先 flush
if (compressedType & 0x20) decompress(pkg = compressedType & 0x0F);
else                       payload_is_raw;
```

`PACKET_AT_FRONT` 只影响解压结果写入历史缓冲区的位置，不改变"是否需要解压"的判断。

**长度语义**：压缩时 `compressedLength` 是线上负载字节数、`uncompressedLength` 是解压后字节数；未压缩时两者**不要求相等**（官方 Font List dump 即为反例，见 §5.1）。

### 2.7 `TS_SECURITY_HEADER`（Basic，2.2.8.1.1.2.1）

固定 4 字节。

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 2 | `flags` | u16 LE | 安全标志，见 §2.8 |
| 2 | 2 | `flagsHi` | u16 LE | 保留；仅当 `flags` 含 `SEC_FLAGSHI_VALID (0x8000)` 时内容有效 |

**关键结论（纠正常见误解）**：`flagsHi` 是结构体内**固定存在的 2 字节**，不是可选字段。`SEC_FLAGSHI_VALID` 决定的是它**是否有效**，而非**是否存在**。规范原文：

> "**flagsHi (2 bytes):** ... This field MUST contain valid data only if the SEC_FLAGSHI_VALID bit (0x8000) is set in the **flags** field. If this bit is not set, the **flagsHi** field is uninitialized and MAY contain random data."（2.2.8.1.1.2.1）

**红证**：4.1.14 中 `flags = 0x0028`（不含 `0x8000`），紧接着仍有 `81 f8` 两字节被标注为 `flagsHi — ignored`（S59）。4.1.15 的 `08 00` / `81 f8`、4.1.19 的 `08 08` / `02 03` 同理。因此**不能**用"`flagsHi` 是否存在"推断头长；头长完全由"选用了哪种安全头结构"决定（§2.11）。

### 2.8 安全头 `flags` 完整枚举（2.2.8.1.1.2.1）

| 数值 | 名称 | 含义 / 约束 | 方向限制 |
|---|---|---|---|
| `0x0001` | `SEC_EXCHANGE_PKT` | 该包是 Security Exchange PDU（2.2.1.10）；仅当启用标准 RDP 安全且将加密时由客户端发送 | 仅 C→S |
| `0x0002` | `SEC_TRANSPORT_REQ` | 该包是 Initiate Multitransport Request PDU（2.2.15.1）；不得出现在 C→S 包；不得出现在非 MCS 消息通道 | 仅 S→C |
| `0x0004` | `SEC_TRANSPORT_RSP` | 该包是 Initiate Multitransport Response PDU（2.2.15.2）；不得出现在 S→C 包；不得出现在非 MCS 消息通道 | 仅 C→S |
| `0x0008` | `SEC_ENCRYPT` | 该包已加密 | 双向 |
| `0x0010` | `SEC_RESET_SEQNO` | **不被任何 RDP 客户端/服务端处理，必须忽略** | 双向（无效） |
| `0x0020` | `SEC_IGNORE_SEQNO` | **不被任何 RDP 客户端/服务端处理，必须忽略** | 双向（无效） |
| `0x0040` | `SEC_INFO_PKT` | 该包是 Client Info PDU（2.2.1.11）；启用标准 RDP 安全时该包必须同时加密 | 仅 C→S |
| `0x0080` | `SEC_LICENSE_PKT` | 该包是 Licensing PDU（2.2.1.12） | 双向 |
| `0x0200` | `SEC_LICENSE_ENCRYPT_CS` | 服务端告知客户端"服务端能处理加密 licensing 包"，随任一 licensing PDU 发送 | 仅 S→C |
| `0x0200` | `SEC_LICENSE_ENCRYPT_SC` | 客户端告知服务端"客户端能处理加密 licensing 包"，与 `SEC_EXCHANGE_PKT` 一起在 Security Exchange PDU 中发送 | 仅 C→S |
| `0x0400` | `SEC_REDIRECTION_PKT` | 该包是 Standard Security Server Redirection PDU（2.2.13.2.1）且已加密 | 双向 |
| `0x0800` | `SEC_SECURE_CHECKSUM` | 该 PDU 的 MAC 用 "salted MAC generation" 技术生成（5.3.6.1.1）；未置位则用标准技术（2.2.8.1.1.2.2 / 2.2.8.1.1.2.3） | 双向 |
| `0x1000` | `SEC_AUTODETECT_REQ` | 该包是 Auto-Detect Request PDU（2.2.14.3）；不得出现在 C→S 包；不得出现在非 MCS 消息通道 | 仅 S→C |
| `0x2000` | `SEC_AUTODETECT_RSP` | 该包是 Auto-Detect Response PDU（2.2.14.4）；不得出现在 S→C 包；不得出现在非 MCS 消息通道 | 仅 C→S |
| `0x4000` | `SEC_HEARTBEAT` | 该包是 Heartbeat PDU（2.2.16.1）；不得出现在非 MCS 消息通道 | 双向 |
| `0x8000` | `SEC_FLAGSHI_VALID` | `flagsHi` 含有效数据；未置位时 `flagsHi` 内容必须忽略 | 双向 |

**三个必须注意的规范事实**

1. `SEC_LICENSE_ENCRYPT_CS` 与 `SEC_LICENSE_ENCRYPT_SC` **数值相同**（都是 `0x0200`）。区分只能靠方向（S→C = CS；C→S = SC）。实现里不要试图用位掩码区分二者。
2. `0x0100` 在规范中**没有任何定义**（表里从 `0x0080` 直接跳到 `0x0200`）。这是规范真实空洞，不是抄漏。
3. `SEC_RESET_SEQNO` / `SEC_IGNORE_SEQNO` 是"占位但无效"的标志：定义存在，但规范明确说"not processed by any RDP clients or servers and MUST be ignored"。**不要**因为收到它们而改变序列号处理逻辑。

**官方 dump 实测值**（可直接作为测试向量）：

| PDU | `flags` | 分解 | 来源 |
|---|---|---|---|
| Client Synchronize（4.1.14） | `0x0028` | `SEC_IGNORE_SEQNO \| SEC_ENCRYPT` | S59 |
| Client Control - Cooperate（4.1.15） | `0x0008` | `SEC_ENCRYPT` | S34 dump |
| Client Control - Request（4.1.16） | `0x0008` | `SEC_ENCRYPT` | S35 dump |
| Client Persistent Key List（4.1.17） | `0x0008` | `SEC_ENCRYPT` | S36 dump |
| Client Font List（4.1.18） | `0x0008` | `SEC_ENCRYPT` | S60 |
| Server Synchronize（4.1.19） | `0x0808` | `SEC_SECURE_CHECKSUM \| SEC_ENCRYPT` | S61 |
| Server Control - Cooperate（4.1.20） | `0x0808` | 同上 | S62 |
| Server Control - Granted（4.1.21） | `0x0808` | 同上 | S63 |
| Server Font Map（4.1.22） | `0x0808` | 同上 | S64 |

**方向不对称的实证**：客户端方向全部是 `0x0008`（无 `SEC_SECURE_CHECKSUM`），服务端方向全部是 `0x0808`（有）。这与规范一致——`SEC_SECURE_CHECKSUM` 由发送方按自身实现选择，接收方必须两种都能处理。

### 2.9 `TS_SECURITY_HEADER1`（Non-FIPS，2.2.8.1.1.2.2）

固定 12 字节 = Basic 头 4 字节 + 8 字节 MAC。

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 2 | `flags` | u16 LE | 同 §2.8 |
| 2 | 2 | `flagsHi` | u16 LE | 同 §2.7（仅 `0x8000` 置位时有效） |
| 4 | 8 | `dataSignature` | 8×u8 | 64 位 MAC，生成方法见 5.3.6.1 |

**MAC 何时存在**：`TS_SECURITY_HEADER1` 一旦被选用，`dataSignature` 就**一定**存在（8 字节），与 `SEC_ENCRYPT` 是否置位无关。选不选 `HEADER1` 取决于协商出的 Encryption Method（§2.11）。

**MAC 生成（非 FIPS，5.3.6.1）**：

```
Pad1 = 0x36 重复 40 次（320 bit）
Pad2 = 0x5C 重复 48 次（384 bit）
SHAComponent = SHA(MACKeyN + Pad1 + DataLength + Data)
MACSignature = First64Bits(MD5(MACKeyN + Pad2 + SHAComponent))
```

其中 `DataLength` 是待加密数据的字节数（**小端 u32**），`MACKeyN` 依协商强度取 `MACKey40` / `MACKey56` / `MACKey128`。取 MD5 结果前 8 字节作为线上 MAC。解密时反向：先 RC4 解密，再对明文重算 16 字节 MAC，比较前 8 字节；不匹配则断连。

**关键顺序**：MAC 在**加密之前**对**明文**计算，密文追加在 MAC 之后。这与"先压缩后 MAC"的顺序约束（3.2.5.1："this MUST be done before any MAC signature is constructed and encryption methods applied"）共同构成流水线：`compress → MAC → encrypt`。

### 2.10 `TS_SECURITY_HEADER2`（FIPS，2.2.8.1.1.2.3）

固定 16 字节。

| 偏移 | 长度 | 字段 | 类型 | 固定值 / 说明 |
|---|---|---|---|---|
| 0 | 2 | `flags` | u16 LE | 同 §2.8 |
| 2 | 2 | `flagsHi` | u16 LE | 同 §2.7 |
| 4 | 2 | `length` | u16 LE | **必须** `0x0010`（16） |
| 6 | 1 | `version` | u8 | 应为 `TSFIPS_VERSION1 (0x01)` |
| 7 | 1 | `padlen` | u8 | 加密前追加到包尾的填充字节数，使待加密数据为 3DES 块长（8 字节）整数倍 |
| 8 | 8 | `dataSignature` | 8×u8 | 64 位 MAC（5.3.6.2） |

**注意**：`length = 0x0010 = 16` 正好等于整个 `TS_SECURITY_HEADER2` 的长度（含 `flags`/`flagsHi`），**不是**"MAC 之后还有 16 字节"。

**`padlen` 的作用**：FIPS 用 3DES，块长 64 bit = 8 字节，待加密数据必须补齐到 8 的倍数；`padlen` 告知接收方要剥掉尾部多少字节。这是 FIPS 模式独有的字段，Basic/Non-FIPS 头都没有。

### 2.11 安全头长度可变性规则（A-4 权威结论）

安全头长度**不是**由 `SEC_FLAGSHI_VALID` 决定，而是由"Encryption Level + Encryption Method"三者择一：

| 条件 | 安全头结构 | 长度 | 依据 |
|---|---|---|---|
| `EncryptionLevel == NONE (0)` 且 `EncryptionMethod == NONE (0)` | **无安全头**（例外见下） | 0 | 2.2.1.14 / 2.2.1.19 / 5.3.8 |
| `EncryptionLevel == LOW (1)` | `TS_SECURITY_HEADER`（Basic） | 4 | 2.2.1.19、2.2.1.20、2.2.1.21、2.2.1.22 |
| `EncryptionMethod ∈ {40BIT(0x1), 56BIT(0x8), 128BIT(0x2)}` | `TS_SECURITY_HEADER1`（Non-FIPS） | 12 | 2.2.8.1.1.2.2 |
| `EncryptionMethod == FIPS (0x10)` | `TS_SECURITY_HEADER2`（FIPS） | 16 | 2.2.8.1.1.2.3 |

**例外（必须记住）**：即使 `EncryptionLevel == 0` 且 `EncryptionMethod == 0`，**Client Info PDU（2.2.1.11）与 Licensing PDU（2.2.1.12）仍然始终带安全头**。原文（5.3.8 / S55）：

> "The Security Header will not be included with any data sent on the wire, except for the Client Info (section 2.2.1.11) and licensing PDUs (section 2.2.1.12), which always contain the Security Header."

**方向不对称（易踩坑）**

- 服务端→客户端方向（2.2.1.19 / .20 / .21 / .22）：明文列出 Basic / Non-FIPS / FIPS 三种，**包含** Basic（4 字节）分支。
- 客户端→服务端方向的 Data PDU（2.2.8.1.1.3 / 2.2.1.14 / .15 / .16 / .17 / .18）：只列出 Non-FIPS 与 FIPS 两种，**没有** Basic 分支。

**【推导】** 这不是笔误：Basic 头只有 `flags` + `flagsHi`、无 MAC，若用于加密流量就无法校验完整性；它只在 `ENCRYPTION_LEVEL_LOW`（仅客户端→服务端加密）场景下由服务端下行使用。

**【建议】** 客户端解析入站包必须支持 0/4/12/16 四种长度；服务端解析入站包按 0/12/16 处理，并对 4 字节 Basic 头做兼容（见 §8 U-7）。

**解析算法**

```
security_header_len(level, method):
    if method == FIPS(0x10):        return 16
    if method in {0x1, 0x8, 0x2}:   return 12
    if level == LOW(1):             return 4
    if level == 0 and method == 0:  return 0      # ClientInfo/License 例外 -> 4
    return 0
```

**不要**从 `flags` 反推长度：`flags` 里没有"头长"信息，只有"内容语义"信息。

**FIPS 时长度相关的额外注意**：`TS_SECURITY_HEADER2.padlen` 指示的填充字节在**密文尾部**，不属于安全头本身。因此"安全头 16 字节 + 密文（含 padlen 字节填充）"才是完整的线上布局。

---

## 3. Fast-Path

### 3.1 Fast-Path vs Slow-Path 判定规则（首字节）

规范给出的判定依据是首字节的 `action` 字段（2 位）：

| `action` | 名称 | 含义 |
|---|---|---|
| `0x0` | `FASTPATH_INPUT_ACTION_FASTPATH` / `FASTPATH_OUTPUT_ACTION_FASTPATH` | 该 PDU 是 fast-path 格式 |
| `0x3` | `FASTPATH_INPUT_ACTION_X224` / `FASTPATH_OUTPUT_ACTION_X224` | 存在 TPKT 版本字节，即该 PDU 是 slow-path（此时首字节完整值**必须**为 `0x03`） |

来源：2.2.8.1.2（S10）、2.2.9.1.2（S20）。

**"最高位"这个说法的准确含义**：任务描述中的"首字节最高位"是常见口语表述，但**规范的实际定义是 `action` 取首字节的最低 2 位**（§1.3 已用三个官方 dump 交叉证明）。准确的判别式是：

```c
bool is_slow_path(const uint8_t *p) { return p[0] == 0x03; }
bool is_fast_path(const uint8_t *p) { return (p[0] & 0x03) == 0x00; }
```

两条判据互补且**覆盖不全**：首字节低 2 位为 `0x1` 或 `0x2` 时两者皆假。这种情况应判为协议错误（见 §6.4）。

**为什么不能按 MSB 判**（红证，S65）：首字节 `0xc4`。

- `0xc4 = 1100 0100`；若 `action` 取高 2 位 → `0b11 = 3`，会被判成 slow-path，与"这是 Fast-Path Input PDU"的官方结论矛盾。
- 若取低 2 位 → `0b00 = 0`，判为 fast-path，与官方注解一致。
- 官方注解同时给出 `numEvents = 1`、`flags = 0x3`。只有"低 2 位 = action、次 4 位 = numEvents、高 2 位 = flags"这一种切分能同时满足三个值。

**两个头字节的权威位布局**：

| 位（bit7…bit0） | 宽度 | `fpInputHeader` | `fpOutputHeader` | 掩码 / 移位 |
|---|---|---|---|---|
| `[7:6]` | 2 | `flags` | `flags` | `(b >> 6) & 0x03` |
| `[5:2]` | 4 | `numEvents` | `reserved`（必须 0） | `(b >> 2) & 0x0F` |
| `[1:0]` | 2 | `action` | `action` | `b & 0x03` |

**【推导】** 输出头的 `reserved` 与输入头 `numEvents` 同位：2.2.9.1.2 位图顺序为 `action | reserved | flags`，与输入头 `action | numEvents | flags` 同构，故 `[5:2]` 为 `reserved`。规范正文未逐位给号，但位图顺序一致且 `reserved` 语义为"未使用"，同位推断可靠。

### 3.2 `TS_FP_INPUT_PDU`（2.2.8.1.2）

| 偏移 | 长度 | 字段 | 必选性 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `fpInputHeader` | 必选 | `action`(2) + `numEvents`(4) + `flags`(2) |
| 1 | 1 | `length1` | 必选 | 长度编码，见 §3.4 |
| 2 | 1 | `length2` | 条件 | 仅当 `length1` bit7 置位时存在 |
| 2 或 3 | 4 | `fipsInformation` | 条件 | 仅当 Encryption Method 为 FIPS（0x10）时存在（`TS_FP_FIPS_INFO`） |
| 变 | 8 | `dataSignature` | 条件 | 仅当 `flags` 含 `FASTPATH_INPUT_ENCRYPTED (0x2)` 时存在 |
| 变 | 1 | `numEvents` | 条件 | 仅当头部 `numEvents` 位域为 0 时存在（1…255） |
| 变 | var | `fpInputEvents` | 必选 | `TS_FP_INPUT_EVENT` 数组 |

`fpInputHeader.flags`（2 位）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x1` | `FASTPATH_INPUT_SECURE_CHECKSUM` | MAC 用 salted 技术生成（5.3.6.1.1）；否则用标准技术 |
| `0x2` | `FASTPATH_INPUT_ENCRYPTED` | 在可选 `length2` 之后有 8 字节 MAC，且内容已加密 |

`fpInputHeader.numEvents`（4 位）规则（2.2.8.1.2）：

- 事件数 1…15 → 直接放入该 4 位字段；
- 事件数 > 15 → 该 4 位字段**必须**置 0，并在 `dataSignature` 之后插入 1 字节 `numEvents` 字段（上限 255）。

**边界**：`numEvents == 0` 且无扩展 `numEvents` 字段 = 畸形（既不是 1…15 的紧凑编码，也没有扩展字段）。但注意"扩展字段存在"的判据就是"位域为 0"，所以位域为 0 时**必须**读扩展字段，其值也必须 ≥ 1。若扩展字段值为 0，判为畸形（§6.4）。

`TS_FP_FIPS_INFO`（2.2.8.1.2.1）4 字节：

| 偏移 | 长度 | 字段 | 固定值 / 说明 |
|---|---|---|---|
| 0 | 2 | `length` | 必须 `0x0010`（16） |
| 2 | 1 | `version` | 应为 `TSFIPS_VERSION1 (0x01)` |
| 3 | 1 | `padlen` | 填充字节数（使待加密长度为 8 的倍数） |

**注意**：`TS_FP_FIPS_INFO.length = 0x0010` 指的是它所替代的 `TS_SECURITY_HEADER2` 的总长，**不是** `TS_FP_FIPS_INFO` 自身的 4 字节长度。

**Enhanced Security 时的字段禁止**（3.2.5.8.1.2 原文）：若 Enhanced RDP Security 生效，`fipsInformation` 与 `dataSignature` **必须不出现**，整包由外部安全协议（TLS/CredSSP）保护。这与"Fast-Path 头里仍有 flags 位"不冲突——flags 位此时应为 0。

### 3.3 `TS_FP_UPDATE_PDU`（2.2.9.1.2）

| 偏移 | 长度 | 字段 | 必选性 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `fpOutputHeader` | 必选 | `action`(2) + `reserved`(4) + `flags`(2) |
| 1 | 1 | `length1` | 必选 | 见 §3.4 |
| 2 | 1 | `length2` | 条件 | `length1` bit7 置位时存在 |
| 变 | 4 | `fipsInformation` | 条件 | FIPS 时存在 |
| 变 | 8 | `dataSignature` | 条件 | `FASTPATH_OUTPUT_ENCRYPTED (0x2)` 置位时存在 |
| 变 | var | `fpOutputUpdates` | 必选 | `TS_FP_UPDATE` 数组（**无显式计数字段**，靠长度遍历） |

**与输入头的重要差异**：输出 PDU **没有** `numEvents` 字段，更新个数只能通过"消耗到 `length` 为止"来确定。这是实现中必须注意的结构差异，也是最容易写出死循环的地方（见 §6.4 的遍历不变量）。

`fpOutputHeader.flags`（2 位）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x1` | `FASTPATH_OUTPUT_SECURE_CHECKSUM` | MAC 用 salted 技术 |
| `0x2` | `FASTPATH_OUTPUT_ENCRYPTED` | 有 8 字节 MAC 且内容加密 |

`reserved`（4 位）**必须**为 0（2.2.9.1.2）。**【建议】** 收到非零 `reserved` 时记录告警但不断连（前向兼容），因为规范只说发送方"MUST be set to zero"，未规定接收方行为。

**输出 PDU 的 `action` 检查（3.3.5.9.3 原文）**：若 `action` 不是 `FASTPATH_OUTPUT_ACTION_FASTPATH (0)`，则该 PDU **不是** Fast-Path Update PDU，必须按 slow-path 处理（3.2.5.2）。这意味着 demux 层的判定必须与解析层一致，不能各自实现一套。

### 3.4 `length1` / `length2` 长度编码判定规则（B-5 权威结论）

Fast-Path 唯一的长度来源。规则如下（2.2.8.1.2 与 2.2.9.1.2 原文完全一致）：

```
if ((length1 & 0x80) == 0):
    pdu_length = length1                             # 1..127，length2 不存在
else:
    pdu_length = ((length1 & 0x7F) << 8) | length2   # 大端，length2 存在
```

| `length1` bit7 | `length1` 取值 | `length2` | 长度公式 | 可表达范围 |
|---|---|---|---|---|
| 0 | `0x01…0x7F` | 不存在 | `length1` | 1…127 |
| 1 | `0x80…0xFF` | 存在 | `((length1 & 0x7F) << 8) \| length2` | 0…32767（实际 1…16383） |

**必须记住的五点**

1. **大端**：高 7 位来自 `length1`，低 8 位来自 `length2`。原文："in big-endian order (the `length2` field contains the low-order bits)"。这与 RDP 其余字段的小端约定**相反**，是唯一的例外。
2. **`pdu_length` 包含首字节**：它统计整个 fast-path 报文（`fpInputHeader`/`fpOutputHeader` + `length1` [+ `length2`] [+ `fipsInformation`] [+ `dataSignature`] [+ `numEvents`] + 事件/更新数据）。
3. **上限是 SHOULD 不是 MUST**：原文 "The overall PDU length SHOULD be less than or equal to 16,383 bytes." 收到 16384…32767 不应直接判非法，但按 16383 设接收缓冲区上限是合规的【建议】。
4. **最小长度**：至少 2 字节（header + length1）。`pdu_length < 2` 一定是畸形。
5. **`0x80 0x00` 编码**：`length1 = 0x80` 表示 bit7 置位、低 7 位为 0，配合 `length2 = 0x00` 得 `pdu_length = 0`。这在语义上非法（小于最小长度 2），必须拒绝。

**红证 1（官方 dump，S65 / 4.7）**：`length1 = 0x11 = 17`（bit7 = 0，故无 `length2`）。

```
c4                      fpInputHeader（action=0, numEvents=1, flags=3）
11                      length1 = 0x11 = 17
30 35 6b 5b b5 34 c8 47 dataSignature（8 字节）
26 18 5e 76 0e de 28    密文 fpInputEvents（7 字节）
```

校验：`1 + 1 + 8 + 7 = 17` ✔。反证：若把 `pdu_length` 误解为"不含首字节与 `length1`"，则负载应为 17 字节，但线上只有 `8 + 7 = 15` 字节 → 会多读 2 字节并越界；若误解为"不含首字节但含 `length1`"，则负载应为 17 字节而实际 16 字节 → 仍差 1 字节。只有"含首字节"这一读法能闭合。

**红证 2（两字节分支，推导示例）**：若要发送 300 字节的 fast-path 报文，则 `length1 = 0x80 | (300 >> 8) = 0x81`，`length2 = 300 & 0xFF = 0x2C`。线上为 `81 2C`。若按小端误读成 `0x2C81 = 11393`，接收缓冲区会读越界——这是实际事故的常见成因。

**红证 3（同章 BER 长度的同类编码，跨编码体系印证）**：S59 同章的 Connect Initial dump 里 `04 82 01 33` 被官方注解为"`0x82` 最高位为 1，低 7 位 `0x02` 表示后续有 2 个长度字节，即 `0x0133 = 307`"（见 `MS-RDPBCGR_text.txt` L335）。这证明"最高位置位 = 后续有长度字节、长度本身按大端拼接"在 RDP 使用的 BER 编码里也是同一思路。**注意**：该处是 BER 的 definite-long-form（可变字节数），而 Fast-Path 的 `length1/length2` 是**固定最多 2 字节**的专用编码，二者不可混用——引用它只为说明"最高位作标志、长度大端"这一惯例在本文档体系内并非孤例。

### 3.5 `TS_FP_INPUT_EVENT` 与 `eventHeader`（2.2.8.1.2.2）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 1 | `eventHeader` | `eventFlags`(5) + `eventCode`(3) |
| 1 | var | `eventData` | 由 `eventCode` 决定 |

`eventHeader` 位布局：

| 位（bit7…bit0） | 宽度 | 字段 | 掩码 / 移位 |
|---|---|---|---|
| `[7:5]` | 3 | `eventCode` | `(b >> 5) & 0x07` |
| `[4:0]` | 5 | `eventFlags` | `b & 0x1F` |

**红证（S65）**：`eventHeader = 0x20 = 0010 0000`，官方注解 `eventFlags = 0`、`eventCode = 1 (FASTPATH_INPUT_EVENT_MOUSE)`。只有"低 5 位是 flags、高 3 位是 code"成立。

`eventCode` 完整枚举（2.2.8.1.2.2）：

| 数值 | 名称 | 对应结构 | 章节 |
|---|---|---|---|
| `0x0` | `FASTPATH_INPUT_EVENT_SCANCODE` | `TS_FP_KEYBOARD_EVENT` | 2.2.8.1.2.2.1 |
| `0x1` | `FASTPATH_INPUT_EVENT_MOUSE` | `TS_FP_POINTER_EVENT` | 2.2.8.1.2.2.3 |
| `0x2` | `FASTPATH_INPUT_EVENT_MOUSEX` | `TS_FP_POINTERX_EVENT` | 2.2.8.1.2.2.4 |
| `0x3` | `FASTPATH_INPUT_EVENT_SYNC` | `TS_FP_SYNC_EVENT` | 2.2.8.1.2.2.5 |
| `0x4` | `FASTPATH_INPUT_EVENT_UNICODE` | `TS_FP_UNICODE_KEYBOARD_EVENT` | 2.2.8.1.2.2.2 |
| `0x5` | `FASTPATH_INPUT_EVENT_MOUSEREL` | `TS_FP_RELPOINTER_EVENT` | 2.2.8.1.2.2.7 |
| `0x6` | `FASTPATH_INPUT_EVENT_QOE_TIMESTAMP` | `TS_FP_QOETIMESTAMP_EVENT` | 2.2.8.1.2.2.6 |
| `0x7` | — | 未定义 | — |

**注意事件类型的编码顺序 ≠ 章节编号顺序**：`UNICODE (0x4)` 排在 `SYNC (0x3)` 之后，但其结构章节是 `.2.2.2`（在 `.2.2.3` 鼠标之前）。实现以**数值**为准，不要按章节顺序建表。

**未知 `eventCode` 的处理**（3.3.5.8.1.2 原文）："If a Fast-Path Input Event structure is received that does not match one of the known types, the server SHOULD drop the connection." 对应错误码 `ERRINFO_INVALIDINPUTPDUTYPE (0x000010CF)`（2.2.5.1.1）。

### 3.6 Fast-Path 输入事件逐字段（2.2.8.1.2.2.1 … .2.2.7）

#### 3.6.1 `TS_FP_KEYBOARD_EVENT`（2.2.8.1.2.2.1，`eventCode = 0`）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `eventHeader` | u8 | `eventCode` 必须为 0；`eventFlags` 见下 |
| 1 | 1 | `keyCode` | u8 | 触发事件的键的 scancode |

总长 **2 字节**。

`eventFlags`（5 位）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x01` | `FASTPATH_INPUT_KBDFLAGS_RELEASE` | 置位 = 抬起；不置位 = 按下 |
| `0x02` | `FASTPATH_INPUT_KBDFLAGS_EXTENDED` | 含扩展 scancode（右 ALT/右 CTRL、INS/DEL/HOME/END/PGUP/PGDN/方向键簇、小键盘 `/` 与 Enter） |
| `0x04` | `FASTPATH_INPUT_KBDFLAGS_EXTENDED1` | 用于 PAUSE 键 |

PAUSE 键必须按以下四事件序列发送，且两个 CTRL 事件都带 `0x04`：

```
CTRL(0x1D) DOWN, NUMLOCK(0x45) DOWN, CTRL(0x1D) UP, NUMLOCK(0x45) UP
```

#### 3.6.2 `TS_FP_UNICODE_KEYBOARD_EVENT`（2.2.8.1.2.2.2，`eventCode = 4`）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `eventHeader` | u8 | `eventCode` 必须为 4 |
| 1 | 2 | `unicodeCode` | u16 LE | Unicode 字符码 |

总长 **3 字节**。`eventFlags` 只定义 `0x01 = FASTPATH_INPUT_KBDFLAGS_RELEASE`。
前提：服务端在 Input Capability Set（2.2.7.1.6）中通告了 Unicode 支持。

#### 3.6.3 `TS_FP_POINTER_EVENT`（2.2.8.1.2.2.3，`eventCode = 1`）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `eventHeader` | u8 | `eventCode` 必须为 1；`eventFlags` **必须为 0** |
| 1 | 2 | `pointerFlags` | u16 LE | 语义同 `TS_POINTER_EVENT.pointerFlags` |
| 3 | 2 | `xPos` | u16 LE | 相对服务端桌面左上角的 x |
| 5 | 2 | `yPos` | u16 LE | 相对服务端桌面左上角的 y |

总长 **7 字节**。若 `pointerFlags` 含 `PTRFLAGS_WHEEL (0x0200)` 或 `PTRFLAGS_HWHEEL (0x0400)`，`xPos`/`yPos` 应被服务端忽略。

`pointerFlags` 取值（2.2.8.1.1.3.1.1.3）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x8000` | `PTRFLAGS_DOWN` | 按下事件；此时至少一个 button 标志必须置位 |
| `0x4000` | `PTRFLAGS_BUTTON3` | 中键（滚轮键）按下/抬起 |
| `0x2000` | `PTRFLAGS_BUTTON2` | 右键按下/抬起 |
| `0x1000` | `PTRFLAGS_BUTTON1` | 左键按下/抬起 |
| `0x0800` | `PTRFLAGS_MOVE` | 必须把指针移动到 `xPos`/`yPos` |
| `0x0400` | `PTRFLAGS_HWHEEL` | 水平滚轮；此时只有 `PTRFLAGS_WHEEL_NEGATIVE` 与 `WheelRotationMask` 有效 |
| `0x0200` | `PTRFLAGS_WHEEL` | 垂直滚轮；同上 |
| `0x0100` | `PTRFLAGS_WHEEL_NEGATIVE` | 滚动量为负，注入前必须符号扩展 |
| `0x01FF` | `WheelRotationMask` | 滚动单位数（有符号，配合 `0x0100`） |

若同时置 `PTRFLAGS_WHEEL` 与 `PTRFLAGS_HWHEEL`，`PTRFLAGS_WHEEL` 优先（2.2.8.1.1.3.1.1.3）。

**红证（S65 解密后）**：

```
20          eventHeader（eventFlags=0, eventCode=1 MOUSE）
00 08       pointerFlags = 0x0800 = PTRFLAGS_MOVE
ab 02       xPos = 0x02ab = 683
6f 01       yPos = 0x016f = 367
```

校验：`1 + 2 + 2 + 2 = 7` 字节 ✔，与 §3.4 红证 1 的密文长度吻合。

#### 3.6.4 `TS_FP_POINTERX_EVENT`（2.2.8.1.2.2.4，`eventCode = 2`）

字节布局与 3.6.3 完全相同（1 + 2 + 2 + 2 = 7 字节），差异只在 `pointerFlags` 语义：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x8000` | `PTRXFLAGS_DOWN` | 按下 |
| `0x0001` | `PTRXFLAGS_BUTTON1` | 扩展键 1（即 button 4） |
| `0x0002` | `PTRXFLAGS_BUTTON2` | 扩展键 2（即 button 5） |

前提：服务端在 Input Capability Set（2.2.7.1.6）中通告了扩展鼠标支持。

#### 3.6.5 `TS_FP_SYNC_EVENT`（2.2.8.1.2.2.5，`eventCode = 3`）

只有 1 字节 `eventHeader`，总长 **1 字节**。`eventFlags` 承载 toggle key 的"亮灯"状态：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x01` | `FASTPATH_INPUT_SYNC_SCROLL_LOCK` | Scroll Lock 指示灯应亮 |
| `0x02` | `FASTPATH_INPUT_SYNC_NUM_LOCK` | Num Lock 指示灯应亮 |
| `0x04` | `FASTPATH_INPUT_SYNC_CAPS_LOCK` | Caps Lock 指示灯应亮 |
| `0x08` | `FASTPATH_INPUT_SYNC_KANA_LOCK` | Kana Lock 指示灯应亮 |

`eventFlags` 是 5 位但只定义低 4 位，bit4 未定义（§8 U-10）。

**语义**：该事件用于同步 toggle 键状态并把服务端键状态重置为"全部抬起"。规范建议其后跟随 key-down 事件以告知当前按下的键（2.2.8.1.2.2.5 / 3.2.5.8.1.1）。

#### 3.6.6 `TS_FP_QOETIMESTAMP_EVENT`（2.2.8.1.2.2.6，`eventCode = 6`）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `eventHeader` | u8 | `eventCode` = 6；`eventFlags` **必须为 0** |
| 1 | 4 | `timestamp` | u32 LE | 客户端生成的毫秒时间戳（本批输入的编码时刻） |

总长 **5 字节**。首个时间戳隐式定义原点，服务端负责处理回绕。

**发送前提**：只有在 Input Capability Set 中收到 `TS_INPUT_FLAG_QOE_TIMESTAMPS (0x0200)` 时才允许发送；该事件仅供信息/调试用途，规范原文 "MUST NOT be transmitted to the server if the TS_INPUT_FLAG_QOE_TIMESTAMPS (0x0200) flag was not received"。

#### 3.6.7 `TS_FP_RELPOINTER_EVENT`（2.2.8.1.2.2.7，`eventCode = 5`）

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `eventHeader` | u8 | `eventCode` = 5；`eventFlags` **必须为 0** |
| 1 | 2 | `pointerFlags` | u16 LE | 同 `TS_RELPOINTER_EVENT` 的 flags |
| 3 | 2 | `xDelta` | **i16** LE | x 位移；负值 = 向左 |
| 5 | 2 | `yDelta` | **i16** LE | y 位移；负值 = 向上 |

总长 **7 字节**。`pointerFlags` 可用值：`PTRFLAGS_MOVE (0x0800)`、`PTRFLAGS_DOWN (0x8000)`、`PTRFLAGS_BUTTON1/2/3 (0x1000/0x2000/0x4000)`、`PTRXFLAGS_BUTTON1/2 (0x0001/0x0002)`。

**注意符号**：`xDelta`/`yDelta` 是**有符号** 16 位，而 `TS_FP_POINTER_EVENT` 的 `xPos`/`yPos` 是**无符号** 16 位。混用会导致反向移动变成大幅正向跳变。

### 3.7 Fast-Path 输入事件尺寸汇总表（用于遍历与校验）

| `eventCode` | 结构 | 固定长度 | 变长条件 |
|---|---|---|---|
| `0x0` | `TS_FP_KEYBOARD_EVENT` | 2 | — |
| `0x1` | `TS_FP_POINTER_EVENT` | 7 | — |
| `0x2` | `TS_FP_POINTERX_EVENT` | 7 | — |
| `0x3` | `TS_FP_SYNC_EVENT` | 1 | — |
| `0x4` | `TS_FP_UNICODE_KEYBOARD_EVENT` | 3 | — |
| `0x5` | `TS_FP_RELPOINTER_EVENT` | 7 | — |
| `0x6` | `TS_FP_QOETIMESTAMP_EVENT` | 5 | — |

**全部事件长度固定**——这意味着输入事件的遍历可以精确前进，不需要"猜测边界"。遍历不变量：

```
remaining = pdu_length - header_and_signature_bytes
for i in 0..numEvents-1:
    need = event_size(eventCode)
    assert remaining >= need
    consume(need)
    remaining -= need
assert remaining == 0        # 严格相等，多余字节即畸形
```

最后一条 `remaining == 0` 是**强校验**：由于所有事件长度固定且 `numEvents` 已知，任何剩余字节都说明长度字段与实际内容矛盾。规范未明文要求此校验，但 `ERRINFO_INPUTPDUBADLENGTH (0x000010DE)` 的存在（2.2.5.1.1："There is not enough data to process ... a Fast-Path Input Event PDU"）支持这一方向。

### 3.8 `TS_FP_UPDATE` 通用结构（2.2.9.1.2.1）

| 偏移 | 长度 | 字段 | 必选性 | 说明 |
|---|---|---|---|---|
| 0 | 1 | `updateHeader` | 必选 | `updateCode`(4) + `fragmentation`(2) + `compression`(2) |
| 1 | 1 | `compressionFlags` | 条件 | 仅当 `compression == 0x2` 时存在；语义同 `compressedType`（2.2.8.1.1.1.2） |
| 1 或 2 | 2 | `size` | 必选 | `updateData` 的字节数 |
| 变 | var | `updateData` | 条件 | 具体更新数据（可为空） |

`updateHeader` 位布局：

| 位（bit7…bit0） | 宽度 | 字段 | 掩码 / 移位 |
|---|---|---|---|
| `[7:6]` | 2 | `compression` | `(b >> 6) & 0x03` |
| `[5:4]` | 2 | `fragmentation` | `(b >> 4) & 0x03` |
| `[3:0]` | 4 | `updateCode` | `b & 0x0F` |

**【推导】** 依据：位图顺序 `updateCode | fragmentation | compression` 与 `fpInputHeader` 的 `action | numEvents | flags` 同构，而后者已由 S65 红证确认"位图最左 = 最低位"（§1.3）。规范正文未逐位给号，且第 4 章无 fast-path 输出 dump，故标为推导（§8 U-2）。

`updateCode` 完整枚举（2.2.9.1.2.1）：

| 数值 | 名称 | 对应更新结构 | 章节 |
|---|---|---|---|
| `0x0` | `FASTPATH_UPDATETYPE_ORDERS` | Fast-Path Orders Update | [MS-RDPEGDI] 2.2.2.2 |
| `0x1` | `FASTPATH_UPDATETYPE_BITMAP` | `TS_FP_UPDATE_BITMAP` | 2.2.9.1.2.1.2 |
| `0x2` | `FASTPATH_UPDATETYPE_PALETTE` | `TS_FP_UPDATE_PALETTE` | 2.2.9.1.2.1.1 |
| `0x3` | `FASTPATH_UPDATETYPE_SYNCHRONIZE` | `TS_FP_UPDATE_SYNCHRONIZE` | 2.2.9.1.2.1.3 |
| `0x4` | `FASTPATH_UPDATETYPE_SURFCMDS` | `TS_FP_SURFCMDS` | 2.2.9.1.2.1.10 |
| `0x5` | `FASTPATH_UPDATETYPE_PTR_NULL` | `TS_FP_SYSTEMPOINTERHIDDENATTRIBUTE` | 2.2.9.1.2.1.5 |
| `0x6` | `FASTPATH_UPDATETYPE_PTR_DEFAULT` | `TS_FP_SYSTEMPOINTERDEFAULTATTRIBUTE` | 2.2.9.1.2.1.6 |
| `0x7` | — | 未定义 | — |
| `0x8` | `FASTPATH_UPDATETYPE_PTR_POSITION` | `TS_FP_POINTERPOSATTRIBUTE` | 2.2.9.1.2.1.4 |
| `0x9` | `FASTPATH_UPDATETYPE_COLOR` | `TS_FP_COLORPOINTERATTRIBUTE` | 2.2.9.1.2.1.7 |
| `0xA` | `FASTPATH_UPDATETYPE_CACHED` | `TS_FP_CACHEDPOINTERATTRIBUTE` | 2.2.9.1.2.1.9 |
| `0xB` | `FASTPATH_UPDATETYPE_POINTER` | `TS_FP_POINTERATTRIBUTE` | 2.2.9.1.2.1.8 |
| `0xC` | `FASTPATH_UPDATETYPE_LARGE_POINTER` | `TS_FP_LARGEPOINTERATTRIBUTE` | 2.2.9.1.2.1.11 |
| `0xD…0xF` | — | 未定义 | — |

**空洞**：`0x7`、`0xD`、`0xE`、`0xF` 无定义（§8 U-2）。

`fragmentation`（2 位）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x0` | `FASTPATH_FRAGMENT_SINGLE` | 非分片序列的一部分 |
| `0x1` | `FASTPATH_FRAGMENT_LAST` | 分片序列的最后一个 |
| `0x2` | `FASTPATH_FRAGMENT_FIRST` | 分片序列的第一个 |
| `0x3` | `FASTPATH_FRAGMENT_NEXT` | 分片序列的第二个或后续 |

`compression`（2 位）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x0` | — | 无 `compressionFlags` 字段（未定义名称，为默认情形） |
| `0x1` | — | 未定义 |
| `0x2` | `FASTPATH_OUTPUT_COMPRESSION_USED` | `compressionFlags` 字段存在 |
| `0x3` | — | 未定义 |

**注意**：只有 `0x2` 有定义且其含义是"字段存在"，不是"数据已压缩"。数据是否真的压缩由 `compressionFlags & PACKET_COMPRESSED (0x20)` 决定。这是两处独立信息，不能混为一谈。

### 3.9 Fast-Path 更新逐字段（2.2.9.1.2.1.1 … .11）

所有更新共享前缀 `updateHeader [+ compressionFlags] + size`（3 或 4 字节）。下表只列 `updateData` 部分。

#### 3.9.1 `TS_FP_UPDATE_PALETTE`（2.2.9.1.2.1.1，code 2）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 2 | `updateType` | 必须 `UPDATETYPE_PALETTE (0x0002)` |
| 2 | 2 | `pad2Octets` | 填充，忽略 |
| 4 | 4 | `numberColors` | 必须 `256`（8bpp 调色板项数） |
| 8 | 3×N | `paletteEntries` | RGB 三元组，N = `numberColors` |

`updateData` 总长 = `8 + 768 = 776` 字节（N=256 时）。数据结构复用慢路径 `TS_UPDATE_PALETTE_DATA`（2.2.9.1.1.3.1.1.1）。

#### 3.9.2 `TS_FP_UPDATE_BITMAP`（2.2.9.1.2.1.2，code 1）

`updateData` 是完整的 `TS_UPDATE_BITMAP_DATA`（2.2.9.1.1.3.1.2.1）：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 2 | `updateType` | 必须 `UPDATETYPE_BITMAP (0x0001)` |
| 2 | 2 | `numberRectangles` | 矩形数 |
| 4 | 18×N + Σlen | `rectangles` | 每个 `TS_BITMAP_DATA` |

每个 `TS_BITMAP_DATA` 的字段：

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 2 | `destLeft` |
| 2 | 2 | `destTop` |
| 4 | 2 | `destRight` |
| 6 | 2 | `destBottom` |
| 8 | 2 | `width` |
| 10 | 2 | `height` |
| 12 | 2 | `bitsPerPixel` |
| 14 | 2 | `flags` |
| 16 | 2 | `bitmapLength` |
| 18 | 2 | `pad2Octets` |
| 20 | `bitmapLength` | `bitmapData` |

`updateData` 总长 = `4 + Σ(20 + bitmapLength)`。

#### 3.9.3 `TS_FP_UPDATE_SYNCHRONIZE`（2.2.9.1.2.1.3，code 3）

`updateData` **为空**，`size` **必须为 0**。整个更新只有 3 字节（或 4 字节，含 `compressionFlags`）。

#### 3.9.4 `TS_FP_POINTERPOSATTRIBUTE`（2.2.9.1.2.1.4，code 8）

`updateData` 4 字节 = `TS_POINTERPOSATTRIBUTE`（2.2.9.1.1.4.2）：`position` 为 `TS_POINT16`，即 `xPos(2) yPos(2)`。

#### 3.9.5 `TS_FP_SYSTEMPOINTERHIDDENATTRIBUTE`（2.2.9.1.2.1.5，code 5）

`updateData` **为空**，`size` **必须为 0**。用于隐藏指针。

#### 3.9.6 `TS_FP_SYSTEMPOINTERDEFAULTATTRIBUTE`（2.2.9.1.2.1.6，code 6）

`updateData` **为空**，`size` **必须为 0**。用于把指针恢复为操作系统默认形状。

#### 3.9.7 `TS_FP_COLORPOINTERATTRIBUTE`（2.2.9.1.2.1.7，code 9）

`updateData` = `TS_COLORPOINTERATTRIBUTE`（2.2.9.1.1.4.4）：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 2 | `cacheIndex` | 指针缓存槽位（0 基） |
| 2 | 4 | `hotSpot` | `TS_POINT16`：`xPos(2) yPos(2)` |
| 6 | 2 | `width` | 像素宽；未开 `LARGE_POINTER_FLAG_96x96` 时上限 32，开了上限 96 |
| 8 | 2 | `height` | 像素高；同上 |
| 10 | 2 | `lengthAndMask` | `andMaskData` 字节数（**u16**） |
| 12 | 2 | `lengthXorMask` | `xorMaskData` 字节数（**u16**） |
| 14 | `lengthXorMask` | `xorMaskData` | 24bpp 自底向上 XOR 掩码，每扫描行补齐到 2 字节边界 |
| 变 | `lengthAndMask` | `andMaskData` | 1bpp 自底向上 AND 掩码，每扫描行补齐到 2 字节边界 |
| 变 | 0/1 | `pad` | 可选填充，忽略 |

**注意 `lengthAndMask` / `lengthXorMask` 是 u16**（本结构），而大指针更新里是 u32（§3.9.11）。两个不同结构，不能混用。

#### 3.9.8 `TS_FP_POINTERATTRIBUTE`（2.2.9.1.2.1.8，code 11）

`updateData` = `TS_POINTERATTRIBUTE`（2.2.9.1.1.4.5）：`xorBpp(2)` + `colorPtrAttr`（一个完整 `TS_COLORPOINTERATTRIBUTE`，但 XOR 数据按 `xorBpp` 的色深解释：8bpp 每字节一个调色板索引，4bpp 每字节两个索引）。

#### 3.9.9 `TS_FP_CACHEDPOINTERATTRIBUTE`（2.2.9.1.2.1.9，code 10）

`updateData` 2 字节 = `cacheIndex`（u16 LE）。指向此前由 Color/New Pointer Update 缓存的槽位。

#### 3.9.10 `TS_FP_SURFCMDS`（2.2.9.1.2.1.10，code 4）

`updateData` = 一个或多个 `TS_SURFCMD`（2.2.9.1.2.1.10.1）。`TS_SURFCMD` 自身格式：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 2 | `cmdType` | 命令类型（Set Surface Bits / Stream Surface Bits / Frame Marker 等） |
| 2 | 2 | `cmdLength` | 该命令总长（**含 4 字节头**） |
| 4 | 变 | `cmdData` | 命令数据 |

遍历方式：从 `updateData` 起点开始，每次读 4 字节头、按 `cmdLength` 前进，直到耗尽 `size`。**`cmdLength < 4` 必须判为畸形**，否则会死循环。

#### 3.9.11 `TS_FP_LARGEPOINTERATTRIBUTE`（2.2.9.1.2.1.11，code 12）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 2 | `xorBpp` | XOR 掩码色深 |
| 2 | 2 | `cacheIndex` | 指针缓存槽位 |
| 4 | 4 | `hotSpot` | `TS_POINT16` |
| 8 | 2 | `width` | 上限 384 像素 |
| 10 | 2 | `height` | 上限 384 像素 |
| 12 | 4 | `lengthAndMask` | **u32**，`andMaskData` 字节数 |
| 16 | 4 | `lengthXorMask` | **u32**，`xorMaskData` 字节数 |
| 20 | `lengthXorMask` | `xorMaskData` | 24bpp 自底向上，每行补到 2 字节 |
| 变 | `lengthAndMask` | `andMaskData` | 1bpp 自底向上，每行补到 2 字节 |
| 变 | 0/1 | `pad` | 可选填充 |

**校验要点**：`width/height ≤ 384`；`lengthXorMask` 应等于 `height × align2(width × 3)`；`lengthAndMask` 应等于 `height × align2(ceil(width / 8))`。两者不符即为畸形（§6）。

### 3.10 Fast-Path 更新尺寸汇总表

| `updateCode` | 结构 | `updateData` 长度 |
|---|---|---|
| `0x0` | Orders | 由 [MS-RDPEGDI] 决定（可变） |
| `0x1` | Bitmap | `4 + Σ(20 + bitmapLength)` |
| `0x2` | Palette | 776（N=256 固定） |
| `0x3` | Synchronize | 0（`size` 必须 0） |
| `0x4` | SurfCmds | `Σ cmdLength`（每个 ≥ 4） |
| `0x5` | Ptr Null | 0（`size` 必须 0） |
| `0x6` | Ptr Default | 0（`size` 必须 0） |
| `0x8` | Ptr Position | 4 |
| `0x9` | Color Pointer | `14 + lengthXorMask + lengthAndMask` (+0/1 pad) |
| `0xA` | Cached Pointer | 2 |
| `0xB` | New Pointer | `2 + (14 + lengthXorMask + lengthAndMask)` |
| `0xC` | Large Pointer | `20 + lengthXorMask + lengthAndMask` (+0/1 pad) |

**遍历不变量（输出 PDU）**：

```
remaining = pdu_length - header_and_signature_bytes
while remaining > 0:
    assert remaining >= 3                      # 至少 updateHeader + size
    read updateHeader
    hdr = 1 + (compression == 0x2 ? 1 : 0)
    assert remaining >= hdr + 2
    read size
    assert size <= remaining - hdr - 2         # 防越界
    consume(hdr + 2 + size)
    remaining -= (hdr + 2 + size)
assert remaining == 0
```

`assert size <= remaining - hdr - 2` 是**必需的**：`size` 是 u16（最大 65535），而整个 PDU 可能只有几十字节，不校验就会越界读。

### 3.11 分片与重组规则（2.2.9.1.2 + 3.2.5.9.3.1）

**触发条件**：`updateHeader.fragmentation != FASTPATH_FRAGMENT_SINGLE (0)`。是否支持分片由 Multifragment Update Capability Set（2.2.7.2.6）协商。

**合法序列**（3.2.5.9.3.1 原文）：

```
FIRST, LAST
FIRST, NEXT, ..., NEXT, LAST
```

- `FASTPATH_FRAGMENT_FIRST` 必须开启序列；
- 中间可以有 **0 个、1 个或多个** `FASTPATH_FRAGMENT_NEXT`；
- `FASTPATH_FRAGMENT_LAST` 必须跟在 `NEXT` 或 `FIRST` 之后。

**违规处理**：原文 "Any deviation from the set of valid fragment sequences SHOULD trigger a disconnect."（3.2.5.9.3.1）。

**重组规则**

1. 按到达顺序拼接，**不重排**（原文："Fragments MUST be reassembled in the order in which they arrive from the server"）。
2. 所有分片的 `updateCode` 与 `compression` 子字段**必须相同**；类型由 `updateCode` 决定（3.2.5.9.3.1 原文："all updates MUST have the same `updateCode` and `compression` subfield values"）。
3. 收到 `LAST` 时，重组缓冲区内容即为一个完整更新，交给对应更新处理器。
4. **交错禁止**：同时只允许一个重组序列在途。收到新的 `FIRST` 时若已有未完成序列，应断连（依据 3.2.5.9.3.1 的 "deviation" 条款）。
5. **`SINGLE` 期间不得有在途序列**：若收到 `SINGLE` 而重组缓冲区非空，同样是 deviation。

**压缩与分片的交互**（§8 U-6）：规范只说"所有分片的 `compression` 子字段必须相同"，未说明 `compressionFlags` 是否逐片出现。**【建议】** 保守实现：

- 每个分片独立按自身 `compressionFlags` 解压后再拼接（因为 `size` 是"本片 `updateData` 的字节数"，压缩标志天然是分片级的）；
- 若首片声明 `PACKET_COMPRESSED` 而后片未声明，按畸形处理；
- 若 `compression == 0x2` 只在首片出现而后片不出现，同样按畸形处理（违反"必须相同"）。

**缓冲区上限【建议】**：`min(协商的 MultifragmentUpdate.MaxRequestSize, 硬上限)`。硬上限建议 16 MiB，并对"累计长度超限"立即断连，防止内存放大攻击。

**状态机（可直接落码）**

```
IDLE --FIRST--> ACCUMULATING (reset buffer, record updateCode/compression)
ACCUMULATING --NEXT--> ACCUMULATING (append)
ACCUMULATING --LAST--> IDLE (deliver)
ACCUMULATING --FIRST--> ERROR (nested FIRST)
ACCUMULATING --SINGLE--> ERROR (single inside sequence)
IDLE --SINGLE--> IDLE (deliver directly)
IDLE --NEXT/LAST--> ERROR (orphan fragment)
```

---

## 4. Connection Finalization（连接最终化）

### 4.1 阶段定位与规范约束

Connection Finalization 是连接序列的第 8 阶段（1.3.1.1，S43）。进入条件：Capabilities Exchange 已完成（客户端已发 Confirm Active PDU）。

三条原文是 §4.8 时序表的**全部**依据：

> "The client-to-server PDUs sent during this phase have no dependencies on any of the server-to-client PDUs; they can be sent as a single batch, provided that sequencing is maintained."（1.3.1.1）

> "The server-to-client PDUs sent during the Connection Finalization phase have dependencies on the client-to-server PDUs."（1.3.1.1）

> "Once the client has sent the Confirm Active PDU, it can start sending mouse and keyboard input to the server, and upon receipt of the Font List PDU the server can start sending graphics output to the client."（1.3.1.1）

由此得到三个硬结论：

1. **客户端可以批量发送**全部 5 个（含可选的 Persistent Key List 序列）C→S 最终化 PDU，只要保持内部顺序；不需要等待任何 S→C 响应。
2. **服务端不能批量发送**：每个 S→C 最终化 PDU 都依赖某个 C→S PDU 的到达。
3. **"输入可早发、图形必须晚发"**：客户端在 Confirm Active 之后即可发输入（不必等最终化完成）；服务端必须等到收到 Font List 之后才能发图形。

### 4.2 `TS_SYNCHRONIZE_PDU`（2.2.1.14.1）

总长 22 字节。

| 偏移 | 长度 | 字段 | 类型 | 固定值 / 说明 |
|---|---|---|---|---|
| 0 | 18 | `shareDataHeader` | 结构 | `pduType.type` = `PDUTYPE_DATAPDU (7)`；`pduType2` = `PDUTYPE2_SYNCHRONIZE (31)` |
| 18 | 2 | `messageType` | u16 LE | **必须** `SYNCMSGTYPE_SYNC (1)` |
| 20 | 2 | `targetUser` | u16 LE | 目标用户的 MCS 通道 ID |

`targetUser` 的方向差异：

| 方向 | 取值要求 | 依据 |
|---|---|---|
| 客户端发送 | SHOULD 设为 Server Channel ID（存于 Server Channel ID store，3.2.1.6） | 3.2.5.3.14（S51） |
| 服务端发送 | SHOULD 设为 0（存在服务端 bug，官方 dump 中为未初始化值） | 3.3.5.3.19（S53）、S61 |
| 服务端接收 | 内容**必须忽略** | 3.3.5.3.14（S53） |
| 客户端接收 | 无明确要求，建议忽略 | 【建议】 |

**红证（S59 / 4.1.14）**：客户端 Synchronize 的 `targetUser = 0x03ea = 1002`，正是服务端通道 ID（同 dump 中服务端 PDU 的 `pduSource` 也是 `0x03ea`）。

**红证（S61 / 4.1.19）**：服务端 Synchronize 的 `targetUser = 0x4463`，官方标注 "uninitialized due to bug"。这证明服务端并不填 0，而是留下未初始化内存——因此**接收端绝不能校验该字段**，否则会与真实 Windows 服务端不兼容。

### 4.3 `TS_CONTROL_PDU`（2.2.1.15.1）

总长 26 字节。被四个 PDU 复用：Client Cooperate（2.2.1.15）、Client Request Control（2.2.1.16）、Server Cooperate（2.2.1.20）、Server Granted Control（2.2.1.21）。

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 18 | `shareDataHeader` | 结构 | `pduType.type` = `PDUTYPE_DATAPDU (7)`；`pduType2` = `PDUTYPE2_CONTROL (20)` |
| 18 | 2 | `action` | u16 LE | 动作码，见下表 |
| 20 | 2 | `grantId` | u16 LE | 授权标识 |
| 22 | 4 | `controlId` | u32 LE | 控制标识 |

`action` 完整枚举（2.2.1.15.1）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x0001` | `CTRLACTION_REQUEST_CONTROL` | 请求控制 |
| `0x0002` | `CTRLACTION_GRANTED_CONTROL` | 已授予控制 |
| `0x0003` | `CTRLACTION_DETACH` | 分离 |
| `0x0004` | `CTRLACTION_COOPERATE` | 协作 |

**各 PDU 的字段固定值**（必须逐项遵守）：

| PDU | `action` | `grantId` | `controlId` | 依据 |
|---|---|---|---|---|
| Client Control - Cooperate（2.2.1.15） | `CTRLACTION_COOPERATE (4)` | **必须 0** | **必须 0** | 2.2.1.15（S34） |
| Client Control - Request Control（2.2.1.16） | `CTRLACTION_REQUEST_CONTROL (1)` | **必须 0** | **必须 0** | 2.2.1.16（S35） |
| Server Control - Cooperate（2.2.1.20） | `CTRLACTION_COOPERATE (4)` | **必须 0** | **必须 0** | 2.2.1.20（S39） |
| Server Control - Granted Control（2.2.1.21） | `CTRLACTION_GRANTED_CONTROL (2)` | User Channel ID | Server Channel ID（`0x03EA`） | 2.2.1.21（S40） |

**红证（S63 / 4.1.21）**：服务端 Granted Control 解出 `action = 0x0002`、`grantId = 0x03ef (1007)`、`controlId = 0x03ea (1002)`，与上表完全一致。而 4.1.20 服务端 Cooperate 的 `grantId`/`controlId` 全 0（S62）。

**接收端宽容度（必须实现）**：

- 服务端处理 Request Control 时，"The contents of the `controlId` and `grantId` fields MUST be ignored."（3.3.5.3.16 / S53）
- 客户端处理 Server Cooperate 时同样忽略这两个字段（3.2.5.3.20 / S52）
- 因此**不要**把非零的 `grantId`/`controlId` 判为错误（官方 dump 里 Granted Control 就是非零）。

**`CTRLACTION_DETACH (0x0003)` 的位置**：它定义在 `TS_CONTROL_PDU.action` 枚举里，但**不属于** Connection Finalization 序列（1.3.1.1 未列出）。**【建议】** 收到时按"未知/未预期控制动作"处理（不断连，记录），因为规范未规定其在本阶段的语义。对应错误码 `ERRINFO_INVALIDCONTROLPDUACTION (0x000010CE)` 仅在 `action` 值本身非法（不在 1…4 内）时使用。

### 4.4 `TS_FONT_LIST_PDU`（2.2.1.18.1）

总长 26 字节。

| 偏移 | 长度 | 字段 | 类型 | 固定值 / 说明 |
|---|---|---|---|---|
| 0 | 18 | `shareDataHeader` | 结构 | `pduType.type` = `PDUTYPE_DATAPDU (7)`；`pduType2` = `PDUTYPE2_FONTLIST (39)` |
| 18 | 2 | `numberFonts` | u16 LE | SHOULD 为 0 |
| 20 | 2 | `totalNumFonts` | u16 LE | SHOULD 为 0 |
| 22 | 2 | `listFlags` | u16 LE | SHOULD 为 `0x0003` = `FONTLIST_FIRST (0x0001)` \| `FONTLIST_LAST (0x0002)` |
| 24 | 2 | `entrySize` | u16 LE | SHOULD 为 `0x0032`（50） |

**接收端行为（强制）**：服务端处理 Font List 时，"The contents of the `numberFonts`, `totalNumFonts`, `listFlags`, and `entrySize` fields MUST be ignored."（3.3.5.3.18 / S53）。处理成功后**必须**回 Font Map PDU；失败则 SHOULD 断连。

**红证（S60 / 4.1.18）**：解出 `numberFonts=0, totalNumFonts=0, listFlags=0x0003, entrySize=0x0032`，且 `uncompressedLength` 被官方标注为 "uninitialized due to bug"（见 §5.1）。这是"不要校验 `uncompressedLength`"的直接证据。

### 4.5 `TS_FONT_MAP_PDU`（2.2.1.22.1）

总长 26 字节。

| 偏移 | 长度 | 字段 | 类型 | 固定值 / 说明 |
|---|---|---|---|---|
| 0 | 18 | `shareDataHeader` | 结构 | `pduType.type` = `PDUTYPE_DATAPDU (7)`；`pduType2` = `PDUTYPE2_FONTMAP (40)` |
| 18 | 2 | `numberEntries` | u16 LE | SHOULD 为 0 |
| 20 | 2 | `totalNumEntries` | u16 LE | SHOULD 为 0 |
| 22 | 2 | `mapFlags` | u16 LE | SHOULD 为 `0x0003` = `FONTMAP_FIRST (0x0001)` \| `FONTMAP_LAST (0x0002)` |
| 24 | 2 | `entrySize` | u16 LE | SHOULD 为 `0x0004`（4） |

**红证（S64 / 4.1.22）**：`numberEntries=0, totalNumEntries=0, mapFlags=0x0003, entrySize=0x0004`。

**发送约束**：该 PDU SHOULD NOT 被压缩（3.3.5.3.22 / S53）。发出后服务端即可开始发送图形/指针更新（3.3.5.3.22）。

**注意 `entrySize` 的差异**：Font List 是 `0x0032`（50），Font Map 是 `0x0004`（4）。两者不相等，不要用同一个常量。

### 4.6 `TS_SAVE_SESSION_INFO_PDU_DATA`（2.2.10.1.1）

结构 = 18 字节 `shareDataHeader` + 4 字节 `infoType` + 变长 `infoData`。

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 18 | `shareDataHeader` | 结构 | `pduType.type` = `PDUTYPE_DATAPDU (7)`；`pduType2` = `PDUTYPE2_SAVE_SESSION_INFO (38)` |
| 18 | 4 | `infoType` | u32 LE | 登录信息类型，见下表 |
| 22 | var | `infoData` | 变体 | 由 `infoType` 决定 |

`infoType` 枚举（2.2.10.1.1）：

| 数值 | 名称 | `infoData` 结构 | 版本限制 |
|---|---|---|---|
| `0x00000000` | `INFOTYPE_LOGON` | `TS_LOGON_INFO`（2.2.10.1.1.1） | 全部 |
| `0x00000001` | `INFOTYPE_LOGON_LONG` | `TS_LOGON_INFO_VERSION_2`（2.2.10.1.1.2） | 除 RDP 4.0/5.0；若 General Capability Set 置了 `LONG_CREDENTIALS_SUPPORTED (0x00000004)` 则 SHOULD 用此型 |
| `0x00000002` | `INFOTYPE_LOGON_PLAINNOTIFY` | Plain Notify（含 576 字节填充，2.2.10.1.1.3） | 除 RDP 4.0/5.0 |
| `0x00000003` | `INFOTYPE_LOGON_EXTENDED_INFO` | `TS_LOGON_INFO_EXTENDED`（2.2.10.1.1.4） | 除 RDP 4.0/5.0/5.1 |

**方向**：仅 S→C。它**不是** Connection Finalization 阶段的 PDU，而是登录后由服务端主动发送（2.2.10.1），因此**不得**纳入最终化时序的强依赖链（见 §4.8 注 3）。

**实现要点【建议】**：

- `infoType` 未知时按"整包丢弃 + 继续"处理，不要断连（这是登录后的信息性通知，不影响会话可用性）。
- `infoData` 解析必须严格按 `cb*` 长度字段做边界检查，否则极易越界。
- `INFOTYPE_LOGON_PLAINNOTIFY` 的 `infoData` 是**固定 576 字节填充**，不解析其内容。

### 4.7 `TS_BITMAPCACHE_PERSISTENT_LIST_PDU`（2.2.1.17.1）

结构 = 18 字节 `shareDataHeader` + 24 字节固定字段 + 8×N 字节条目。

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 18 | `shareDataHeader` | 结构 | `pduType.type` = `PDUTYPE_DATAPDU (7)`；`pduType2` = `PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST (43)` |
| 18 | 2 | `numEntriesCache0` | u16 LE | 本 PDU 中 Cache 0 的条目数 |
| 20 | 2 | `numEntriesCache1` | u16 LE | 本 PDU 中 Cache 1 的条目数 |
| 22 | 2 | `numEntriesCache2` | u16 LE | 本 PDU 中 Cache 2 的条目数 |
| 24 | 2 | `numEntriesCache3` | u16 LE | 本 PDU 中 Cache 3 的条目数 |
| 26 | 2 | `numEntriesCache4` | u16 LE | 本 PDU 中 Cache 4 的条目数 |
| 28 | 2 | `totalEntriesCache0` | u16 LE | 整个序列中 Cache 0 的期望总数；序列内必须不变 |
| 30 | 2 | `totalEntriesCache1` | u16 LE | 同上，Cache 1 |
| 32 | 2 | `totalEntriesCache2` | u16 LE | 同上，Cache 2 |
| 34 | 2 | `totalEntriesCache3` | u16 LE | 同上，Cache 3 |
| 36 | 2 | `totalEntriesCache4` | u16 LE | 同上，Cache 4 |
| 38 | 1 | `bBitMask` | u8 | 序列标志，见下表 |
| 39 | 1 | `Pad2` | u8 | 填充，忽略 |
| 40 | 2 | `Pad3` | u16 LE | 填充，忽略 |
| 42 | 8×N | `entries` | 数组 | `TS_BITMAPCACHE_PERSISTENT_LIST_ENTRY`：`Key1(4) Key2(4)` |

`bBitMask` 枚举（2.2.1.17.1）：

| 数值 | 名称 | 含义 |
|---|---|---|
| `0x01` | `PERSIST_FIRST_PDU`（规范别名 `PERSIST_PDU_FIRST`） | 序列中的第一个 PDU |
| `0x02` | `PERSIST_LAST_PDU`（规范别名 `PERSIST_PDU_LAST`） | 序列中的最后一个 PDU |
| 其他（两位都不置） | — | 序列中的中间包 |

> 注：规范在同一节内混用了 `PERSIST_FIRST_PDU` / `PERSIST_PDU_FIRST` 两种写法（2.2.1.17.1 的表格用前者，紧随其后的说明文字用后者），指向同一常量。实现时以**数值**为准。

`TS_BITMAPCACHE_PERSISTENT_LIST_ENTRY`（2.2.1.17.1.1）：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | `Key1` | 64 位持久缓存键的**低** 32 位 |
| 4 | 4 | `Key2` | 64 位持久缓存键的**高** 32 位 |

**约束**

1. 五个 `totalEntriesCacheN` 之和 **MUST NOT** 超过 **262,144**（2.2.1.17.1）。违反 → `ERRINFO_PERSISTENTKEYPDUTOOMANYTOTALKEYS (0x000010DC)`。
2. `entries` 必须按"缓存号从低到高"排列；同一缓存内按键序排列。规范举例：若 Cache 0 有 1 个键、Cache 1 有 2 个键，则 `numEntriesCache0=1`、`numEntriesCache1=2`、其余为 0，条目顺序为 (Cache 0, Key 1), (Cache 1, Key 1), (Cache 1, Key 2)。
3. 单个 PDU 内的键数 SHOULD 限制在 **169**（2.2.1.17.1）。
4. 发送条件（2.2.1.17）：客户端有持久位图缓存、服务端通告了 Bitmap Host Cache Support Capability Set（2.2.7.2.1）、且不在 Deactivation-Reactivation 序列中。
5. 内容 MUST NOT 被压缩（3.2.5.3.17 / S51）。
6. `totalEntriesCacheN` 在整个序列内**必须保持不变**；若第二个 PDU 改了总数 → 应判畸形。

**红证（S36 / 4.1.17）**：`totalLength = 0x00f2 = 242`，`numEntriesCache2 = 0x19 = 25`，`totalEntriesCache2 = 0x19 = 25`，`bBitMask = 0x03`（FIRST|LAST），条目起点偏移 42，`42 + 25×8 = 242` ✔。这是校验本结构布局的最佳样本。

**条目数与长度的一致性校验（必须实现）**：

```
expected_total = 42 + 8 * (numEntriesCache0 + ... + numEntriesCache4)
assert totalLength == expected_total
```

这是本结构中唯一可靠的边界判据。若不校验，`numEntriesCacheN` 被篡改成大值会导致越界读。

### 4.8 完整时序表（C-11 权威结论）

#### 4.8.1 前置状态

| 状态 | 说明 |
|---|---|
| Capabilities Exchange 已完成 | 服务端已发 Demand Active（+ 可选 Monitor Layout）；客户端已发 Confirm Active |
| 加密已就绪 | 若为标准 RDP 安全，session keys 已从 Security Exchange 阶段派生；安全头形态已确定（§2.11） |
| `shareID` 已确定 | 来自 Demand Active PDU 的 `shareID`（官方 dump 为 `0x000103ea`） |
| 通道 ID 已确定 | User Channel ID（客户端）、Server Channel ID（`0x03ea`）、MCS I/O Channel ID（`0x03eb`） |

#### 4.8.2 客户端 → 服务端（可整体批量）

| 序 | PDU | 结构 | 关键固定值 | 依赖 | 是否可批量 |
|---|---|---|---|---|---|
| C1 | Client Synchronize（2.2.1.14） | `TS_SYNCHRONIZE_PDU`（22 B） | `pduType2 = 0x1F`；`messageType = 1`；`targetUser` SHOULD = Server Channel ID | 必须在 Confirm Active 之后 | ✅ 可与 C2–C5 同批 |
| C2 | Client Control - Cooperate（2.2.1.15） | `TS_CONTROL_PDU`（26 B） | `pduType2 = 0x14`；`action = 4`；`grantId = 0`；`controlId = 0` | 必须在 C1 之后（序依赖） | ✅ |
| C3 | Client Control - Request Control（2.2.1.16） | `TS_CONTROL_PDU`（26 B） | `action = 1`；`grantId = 0`；`controlId = 0` | 必须在 C2 之后 | ✅ |
| C4 | Persistent Key List（2.2.1.17，**可选**，可多个） | `TS_BITMAPCACHE_PERSISTENT_LIST_PDU`（42 + 8N B） | `pduType2 = 0x2B`；`bBitMask` 首包 `0x01`、末包 `0x02` | 必须在 C3 之后；仅在有持久缓存且服务端支持时发送 | ✅ 整个序列可批量 |
| C5 | Client Font List（2.2.1.18） | `TS_FONT_LIST_PDU`（26 B） | `pduType2 = 0x27`；`listFlags = 0x0003`；`entrySize = 0x0032` | 必须在 C4 之后；若未发 C4 则必须在 C3 之后 | ✅ |

**批量规则（依据 1.3.1.1）**：C1→C2→C3→[C4…]→C5 这五类 PDU **内部顺序必须保持**，但它们**不依赖任何 S→C 最终化 PDU**，因此可以在一次 flush 中连续发出（例如合并进同一个 TCP 段或连续 write）。规范原文用词是 "can be sent as a single batch, provided that sequencing is maintained"。

**"保持 sequencing"的含义**：由于它们都走 MCS I/O 通道，MCS 层本身保序，所以只要按上表顺序写入同一通道即可。**不要**把它们分散到不同通道或不同连接。

#### 4.8.3 服务端 → 客户端（不可批量，逐项依赖）

| 序 | PDU | 结构 | 关键固定值 | 触发条件（依赖） |
|---|---|---|---|---|
| S1 | Server Synchronize（2.2.1.19） | `TS_SYNCHRONIZE_PDU`（22 B） | `pduType2 = 0x1F`；`messageType = 1`；`targetUser` SHOULD 0（实测为未初始化） | 收到 **Confirm Active**（2.2.1.13.2）后 |
| S2 | Server Control - Cooperate（2.2.1.20） | `TS_CONTROL_PDU`（26 B） | `action = 4`；`grantId = 0`；`controlId = 0` | 发出 **S1** 之后（序依赖，非客户端触发） |
| S3 | Server Control - Granted Control（2.2.1.21） | `TS_CONTROL_PDU`（26 B） | `action = 2`；`grantId` = User Channel ID；`controlId` = Server Channel ID | 收到 **C3**（Client Request Control）后 |
| S4 | Server Font Map（2.2.1.22） | `TS_FONT_MAP_PDU`（26 B） | `pduType2 = 0x28`；`mapFlags = 0x0003`；`entrySize = 0x0004` | 收到 **C5**（Client Font List）后 |

**为什么不可批量**：S3 依赖 C3、S4 依赖 C5，而 C1–C5 可能在不同时刻到达（客户端虽可批量发，但不保证服务端在同一时刻全部收到）。服务端必须**按到达事件驱动**逐个发送。原文（1.3.1.1）："The server-to-client PDUs sent during the Connection Finalization phase have dependencies on the client-to-server PDUs."

**S1 的特殊性**：S1 依赖 Confirm Active（上一阶段），不是最终化阶段的 C→S PDU。因此 S1 可以**早于**任何 C1–C5 发出——实际 Windows 服务端正是这么做的（收到 Confirm Active 立即发 Server Synchronize）。

#### 4.8.4 交叉时序（含依赖标注）

```
客户端                                        服务端
  |                                             |
  |--- Confirm Active PDU -------------------->|   （Capabilities Exchange 结束）
  |                                             |
  |                                             |--- Server Synchronize (S1) ----|
  |                                             |     依赖: Confirm Active        |
  |                                             |--- Server Control Cooperate (S2)
  |                                             |     依赖: S1（纯序依赖）         |
  |                                             |
  |=== 以下 C1..C5 可合并为一次批量发送 ===      |
  |--- Client Synchronize (C1) --------------->|
  |--- Client Control Cooperate (C2) --------->|
  |--- Client Control Request (C3) ----------->|
  |--- [Persistent Key List xN] (C4) --------->|  （可选）
  |--- Client Font List (C5) ----------------->|
  |                                             |
  |                                             |--- Server Control Granted (S3)
  |                                             |     依赖: C3
  |                                             |--- Server Font Map (S4)
  |                                             |     依赖: C5
  |                                             |
  |<== 此后服务端可发图形/指针更新 =============|
  |<== 客户端自 Confirm Active 起即可发输入 ====|
```

**关键观察**：图中 S1/S2 在 C1 之前发出，这不是笔误——它们只依赖 Confirm Active。这解释了为什么服务端不能"等全部 C→S 完成再统一发"。

#### 4.8.5 依赖关系图（严格）

```
Confirm Active ──► S1 Server Synchronize
                        │
                        └──► S2 Server Control Cooperate

Client Synchronize (C1) ──► [无 S→C 响应]

Client Control Cooperate (C2) ──► [无 S→C 响应]

Client Control Request (C3) ──► S3 Server Control Granted Control

Client Persistent Key List (C4) ──► [无 S→C 响应；仅服务端内部存储键]

Client Font List (C5) ──► S4 Server Font Map ──► 图形/指针输出解禁
```

**注意：C1 和 C2 没有对应的 S→C 响应。** 这是最容易被误实现的地方——很多实现会"等待服务端对 Synchronize 的确认"，但规范中不存在这样的 PDU。S1 是对 Confirm Active 的响应，不是对 C1 的响应。

#### 4.8.6 门禁与副作用

| 事件 | 允许的后续行为 | 依据 |
|---|---|---|
| 客户端发出 Confirm Active | 客户端**可立即**开始发送鼠标/键盘输入（无需等最终化） | 1.3.1.1 |
| 服务端收到 Font List（C5） | 服务端**可开始**发送图形输出 | 1.3.1.1 |
| 服务端发出 Font Map（S4） | 服务端 SHOULD 开始发送图形/指针更新 | 3.3.5.3.22 |
| 客户端收到 Font Map（S4） | 客户端可认为最终化完成 | 【推导】由 3.2.5.3.22 的"处理 Font Map"语义推出 |

**【推导】为什么"客户端收到 Font Map = 最终化完成"**：规范没有单独一句"最终化在 Font Map 后结束"，但 1.3.1.1 把 Font Map 列为最终化阶段最后一个 S→C PDU，且 3.2.5.3.22（处理 Font Map）是客户端侧最终化序列的最后一步。因此以 Font Map 到达作为完成标志是合理的。

#### 4.8.7 异常与顺序违规

| 违规 | 建议处理 | 依据 / 错误码 |
|---|---|---|
| 客户端在 Confirm Active 之前发 C1 | 断连 | 1.3.1.1（阶段约束） |
| 客户端 C2 早于 C1 | 断连 | 2.2.1.15（"sent after transmitting the Client Synchronize PDU"） |
| 客户端 C3 早于 C2 | 断连 | 2.2.1.16（"sent after transmitting the Client Control (Cooperate) PDU"） |
| 客户端 C5 早于 C3（且未发 C4） | 断连 | 2.2.1.18（"sent after transmitting the ... Request Control PDU"） |
| `action` 不在 1…4 | 断连 | `ERRINFO_INVALIDCONTROLPDUACTION (0x000010CE)` |
| 最终化 PDU 乱序 | 断连 | `ERRINFO_DATAPDUSEQUENCE (0x000010CB)` / `ERRINFO_CONTROLPDUSEQUENCE (0x000010CD)` |
| Persistent Key List 的 FIRST 重复 | 断连 | `ERRINFO_PERSISTENTKEYPDUILLEGALFIRST (0x000010DB)` |
| Persistent Key List 数据不足 | 断连 | `ERRINFO_PERSISTENTKEYPDUBADLENGTH (0x000010DA)` |
| Persistent Key List 总数 > 262144 | 断连 | `ERRINFO_PERSISTENTKEYPDUTOOMANYTOTALKEYS (0x000010DC)` |
| Persistent Key List 单缓存键数超上限 | 断连 | `ERRINFO_PERSISTENTKEYPDUTOOMANYCACHEKEYS (0x000010DD)` |
| Font List / Control 数据不足 | 断连 | `ERRINFO_SHAREDATATOOSHORT (0x000010E2)` |

---

## 5. 十六进制 dump 逐字节注解

本章提供 6 个 dump：前 5 个是 `[MS-RDPBCGR]` 第 4 章**官方 annotated dump**（A-dump 级），最后 1 个是**按结构推导**的合成样本（标注为【推导】），用于覆盖"无加密、无安全头"这一官方 dump 未提供的分支。

### 5.1 Dump #1：Client Synchronize PDU（官方，4.1.14 / S59）

**原始线上字节（含 TPKT / X.224 / MCS / securityHeader1）**：

```
00000000  03 00 00 30 02 f0 80 64 00 06 03 eb 70 22 28 00   ...0...d....p"(.
00000010  81 f8 59 ff cb 2f 73 57 2b 42 db 88 2e 23 a9 97   ..Y../sW+B...#..
00000020  c2 b1 f5 74 bc 49 cc 8a d8 fd 60 8a 7a f6 44 75   ...t.I....`.z.Du
```

**逐字节注解**：

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00 | `03` | TPKT `version` | 3（[T123] §8） |
| 0x01 | `00` | TPKT `reserved` | 0 |
| 0x02–0x03 | `00 30` | TPKT `length` | `0x0030 = 48`（大端） |
| 0x04 | `02` | X.224 `LI` | 2 |
| 0x05 | `f0` | X.224 `code` | `0xF0` = Data TPDU |
| 0x06 | `80` | X.224 `TPDU-NR/EOT` | EOT 置位 |
| 0x07–0x0D | `64 00 06 03 eb 70 22` | MCS `SDrq` 头（7 字节，PER aligned） | 官方注解：initiator = 1007 (`0x03ef`)；channelId = 1003 (`0x03eb`)；dataPriority = high；segmentation = begin\|end；`userData` 长度 = `0x22 = 34`。PER 内部字段边界不逐字节展开（超出本文范围） |
| 0x0E–0x0F | `28 00` | `TS_SECURITY_HEADER.flags` | `0x0028 = SEC_IGNORE_SEQNO(0x20) \| SEC_ENCRYPT(0x08)` |
| 0x10–0x11 | `81 f8` | `TS_SECURITY_HEADER.flagsHi` | **被忽略**（`flags` 不含 `SEC_FLAGSHI_VALID (0x8000)`）；值 `0xf881` 为随机残留 |
| 0x12–0x19 | `59 ff cb 2f 73 57 2b 42` | `TS_SECURITY_HEADER1.dataSignature` | 8 字节 MAC |
| 0x1A–0x2F | `db 88 … 44 75` | 密文负载 | 22 字节（`0x2F - 0x1A + 1 = 22`），解密后为下面的明文 |

**解密后的明文（`shareControlHeader` 起点）**：

```
00000000  16 00 17 00 ef 03 ea 03 01 00 00 01 08 00 1f 00   ................
00000010  00 00 01 00 ea 03                                 ......
```

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00–0x01 | `16 00` | `totalLength` | `0x0016 = 22`（= 18 + 4，不含 12 字节安全头） |
| 0x02–0x03 | `17 00` | `pduType` | `0x0017`；`type = 0x7`（DATAPDU）、`PDUVersion = 0x1` |
| 0x04–0x05 | `ef 03` | `pduSource` | `0x03ef = 1007`（客户端 User Channel ID） |
| 0x06–0x09 | `ea 03 01 00` | `shareID` | `0x000103ea` |
| 0x0A | `00` | `pad1` | 0（忽略） |
| 0x0B | `01` | `streamID` | `0x01 = STREAM_LOW` |
| 0x0C–0x0D | `08 00` | `uncompressedLength` | `0x0008 = 8`（= 4 字节 PDU 内容） |
| 0x0E | `1f` | `pduType2` | `0x1F = PDUTYPE2_SYNCHRONIZE (31)` |
| 0x0F | `00` | `compressedType` | `0`（未压缩） |
| 0x10–0x11 | `00 00` | `compressedLength` | 0 |
| 0x12–0x13 | `01 00` | `TS_SYNCHRONIZE_PDU.messageType` | `1 = SYNCMSGTYPE_SYNC` |
| 0x14–0x15 | `ea 03` | `TS_SYNCHRONIZE_PDU.targetUser` | `0x03ea = 1002`（服务端通道 ID） |

**本 dump 的教学要点**：

1. `totalLength = 22` 与"密文负载 22 字节"**恰好相等**，证明 `totalLength` 不含安全头。
2. `flagsHi` 值为 `0xf881`（非零、看似有意义），但 `flags` 无 `0x8000` 位，所以它是**随机残留**。若实现按"`flagsHi` 非零即有效"判断，会得到完全错误的结论。
3. `uncompressedLength = 8` 而 `totalLength = 22`。若误以为 `uncompressedLength` 应等于 `totalLength`，会误判此包为畸形。
4. `pad1 = 0x00` 只是本例巧合；4.1.18 的 `pad1 = 0x00`、4.1.20 的 `pad1 = 0xb5`、4.1.21 的 `pad1 = 0x12`、4.1.22 的 `pad1 = 0x45`（S62/S63/S64），证明它是纯填充。

### 5.2 Dump #2：Fast-Path Input Event PDU（官方，4.7 / S65）

**原始线上字节**：

```
00000000  c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de   ..05k[.4.G&.^v..
00000010  28                                                (
```

**逐字节注解**：

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00 | `c4` | `fpInputHeader` | `0xc4 = 1100 0100`；`action = [1:0] = 0b00 = 0`（FASTPATH_INPUT_ACTION_FASTPATH）；`numEvents = [5:2] = 0b0001 = 1`；`flags = [7:6] = 0b11 = 3` |
| — | — | `flags` 分解 | `3 = FASTPATH_INPUT_SECURE_CHECKSUM(0x1) \| FASTPATH_INPUT_ENCRYPTED(0x2)` |
| 0x01 | `11` | `length1` | `0x11 = 17`；bit7 = 0 → **无 `length2`**，`pdu_length = 17` |
| 0x02 | — | `length2` | **不存在**（因 `length1` bit7 = 0） |
| 0x02 | — | `fipsInformation` | **不存在**（非 FIPS） |
| 0x02–0x09 | `30 35 6b 5b b5 34 c8 47` | `dataSignature` | 8 字节 MAC（因 `FASTPATH_INPUT_ENCRYPTED` 置位） |
| 0x0A | — | `numEvents`（扩展） | **不存在**（头部 `numEvents = 1 ≠ 0`） |
| 0x0A–0x10 | `26 18 5e 76 0e de 28` | `fpInputEvents`（密文） | 7 字节 |

**长度校验**：`1 (header) + 1 (length1) + 8 (signature) + 7 (events) = 17` ✔ 等于 `length1`。

**解密后的 `fpInputEvents`**：

```
00000000  20 00 08 ab 02 6f 01                              ....o.
```

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00 | `20` | `eventHeader` | `0x20 = 0010 0000`；`eventCode = [7:5] = 0b001 = 1`（FASTPATH_INPUT_EVENT_MOUSE）；`eventFlags = [4:0] = 0`（必须为 0 ✔） |
| 0x01–0x02 | `00 08` | `pointerFlags` | `0x0800 = PTRFLAGS_MOVE` |
| 0x03–0x04 | `ab 02` | `xPos` | `0x02ab = 683` |
| 0x05–0x06 | `6f 01` | `yPos` | `0x016f = 367` |

**本 dump 的教学要点**：

1. 首字节 `0xc4` 的**最高位是 1**。若按"最高位 = fast-path 标志"理解，取高 2 位得 `action = 0b11 = 3`，会把它判成 **slow-path**，与官方结论（Fast-Path Input PDU）直接矛盾。**必须按低 2 位判**（§3.1）。
2. `length1` 单字节即可表达 17，无需 `length2`。这是绝大多数实际输入包的情形（鼠标/键盘事件都在 2–10 字节量级）。
3. `numEvents = 1` 走紧凑编码，因此**没有**扩展 `numEvents` 字段。若实现总是读扩展字段，会吃掉 1 字节事件数据导致解析错位。
4. `eventFlags = 0` 对鼠标事件是**强制**要求（2.2.8.1.2.2.3："MUST be zeroed out"）。若收到非零值应判畸形。

### 5.3 Dump #3：Client Font List PDU（官方，4.1.18 / S60）

**解密后的明文**（本 dump 的密文部分官方只给出 `uncompressedLength` 的注解，明文如下）：

```
00000000  1a 00 17 00 ef 03 ea 03 01 00 00 01 3b da 27 00   ............;.'.
00000010  00 00 00 00 00 00 03 00 32 00                     ........2.
```

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00–0x01 | `1a 00` | `totalLength` | `0x001a = 26` |
| 0x02–0x03 | `17 00` | `pduType` | `0x0017`（DATAPDU, v1） |
| 0x04–0x05 | `ef 03` | `pduSource` | `0x03ef = 1007` |
| 0x06–0x09 | `ea 03 01 00` | `shareID` | `0x000103ea` |
| 0x0A | `00` | `pad1` | 0（忽略） |
| 0x0B | `01` | `streamID` | `STREAM_LOW` |
| 0x0C–0x0D | `3b da` | `uncompressedLength` | `0xda3b = 55867` —— **官方标注 "uninitialized due to bug"，此值无意义** |
| 0x0E | `27` | `pduType2` | `0x27 = PDUTYPE2_FONTLIST (39)` |
| 0x0F | `00` | `compressedType` | 0 |
| 0x10–0x11 | `00 00` | `compressedLength` | 0 |
| 0x12–0x13 | `00 00` | `numberFonts` | 0 |
| 0x14–0x15 | `00 00` | `totalNumFonts` | 0 |
| 0x16–0x17 | `03 00` | `listFlags` | `0x0003 = FONTLIST_FIRST \| FONTLIST_LAST` |
| 0x18–0x19 | `32 00` | `entrySize` | `0x0032 = 50` |

**本 dump 的教学要点（这是最重要的反例）**：

1. **`uncompressedLength = 55867` 是垃圾值**。整个 PDU 只有 26 字节，而这个字段声明 55867 字节。若实现校验 `uncompressedLength == totalLength`，会**拒绝真实 Windows 客户端发出的合法 PDU**。
2. 正确做法：`uncompressedLength` / `compressedLength` 只在 `compressedType & PACKET_COMPRESSED` 时才有意义（作为解压后/前的长度），未压缩时**必须忽略**。
3. `pad1 = 0x00`、`compressedType = 0`、`compressedLength = 0` 三者组合表明这是未压缩包。

### 5.4 Dump #4：Server Font Map PDU（官方，4.1.22 / S64）

```
00000000  1a 00 17 00 ea 03 ea 03 01 00 45 02 1a 00 28 00   ..........E...(.
00000010  00 00 00 00 00 00 03 00 04 00                     ..........
```

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00–0x01 | `1a 00` | `totalLength` | `0x001a = 26` |
| 0x02–0x03 | `17 00` | `pduType` | `0x0017`（DATAPDU, v1） |
| 0x04–0x05 | `ea 03` | `pduSource` | `0x03ea = 1002`（**服务端**通道 ID，与客户端 dump 的 `0x03ef` 不同） |
| 0x06–0x09 | `ea 03 01 00` | `shareID` | `0x000103ea` |
| 0x0A | `45` | `pad1` | `0x45` —— **非零填充**，必须忽略 |
| 0x0B | `02` | `streamID` | `0x02 = STREAM_MED` |
| 0x0C–0x0D | `1a 00` | `uncompressedLength` | `0x001a = 26`（**此处恰好正确**，与 totalLength 相等） |
| 0x0E | `28` | `pduType2` | `0x28 = PDUTYPE2_FONTMAP (40)` |
| 0x0F | `00` | `compressedType` | 0 |
| 0x10–0x11 | `00 00` | `compressedLength` | 0 |
| 0x12–0x13 | `00 00` | `numberEntries` | 0 |
| 0x14–0x15 | `00 00` | `totalNumEntries` | 0 |
| 0x16–0x17 | `03 00` | `mapFlags` | `0x0003 = FONTMAP_FIRST \| FONTMAP_LAST` |
| 0x18–0x19 | `04 00` | `entrySize` | `0x0004 = 4` |

**本 dump 的教学要点**：

1. `pad1 = 0x45` 非零，与 5.3 的 `0x00` 形成对照 → 再次证明 `pad1` 不可校验。
2. `uncompressedLength = 26` 与 `totalLength = 26` 相等，与 5.3 的 `55867` 形成对照 → 进一步证明该字段不可靠（有时对、有时错）。
3. `streamID = STREAM_MED (0x02)`，与客户端最终化 PDU 的 `STREAM_LOW (0x01)` 不同 → 接收端不可假设固定值。

### 5.5 Dump #5：Client Persistent Key List PDU（官方，4.1.17 / S36，节选）

**解密后的明文前 48 字节**：

```
00000000  f2 00 17 00 ef 03 ea 03 01 00 00 01 00 00 2b 00   ..............+.
00000010  00 00 00 00 00 00 19 00 00 00 00 00 00 00 00 00   ................
00000020  19 00 00 00 00 00 03 00 00 00 a3 1e 51 16 48 29   ............Q.H)
```

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00–0x01 | `f2 00` | `totalLength` | `0x00f2 = 242` |
| 0x02–0x03 | `17 00` | `pduType` | `0x0017`（DATAPDU, v1） |
| 0x04–0x05 | `ef 03` | `pduSource` | `0x03ef = 1007` |
| 0x06–0x09 | `ea 03 01 00` | `shareID` | `0x000103ea` |
| 0x0A | `00` | `pad1` | 0 |
| 0x0B | `01` | `streamID` | `STREAM_LOW` |
| 0x0C–0x0D | `00 00` | `uncompressedLength` | **0**（又是不可靠值：整包 242 字节却声明 0） |
| 0x0E | `2b` | `pduType2` | `0x2B = PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST (43)` |
| 0x0F | `00` | `compressedType` | 0 |
| 0x10–0x11 | `00 00` | `compressedLength` | 0 |
| 0x12–0x13 | `00 00` | `numEntriesCache0` | 0 |
| 0x14–0x15 | `00 00` | `numEntriesCache1` | 0 |
| 0x16–0x17 | `19 00` | `numEntriesCache2` | `0x19 = 25` |
| 0x18–0x19 | `00 00` | `numEntriesCache3` | 0 |
| 0x1A–0x1B | `00 00` | `numEntriesCache4` | 0 |
| 0x1C–0x1D | `00 00` | `totalEntriesCache0` | 0 |
| 0x1E–0x1F | `00 00` | `totalEntriesCache1` | 0 |
| 0x20–0x21 | `19 00` | `totalEntriesCache2` | `0x19 = 25` |
| 0x22–0x23 | `00 00` | `totalEntriesCache3` | 0 |
| 0x24–0x25 | `00 00` | `totalEntriesCache4` | 0 |
| 0x26 | `03` | `bBitMask` | `0x03 = PERSIST_FIRST_PDU \| PERSIST_LAST_PDU` |
| 0x27 | `00` | `Pad2` | 0 |
| 0x28–0x29 | `00 00` | `Pad3` | 0 |
| 0x2A–0x2D | `a3 1e 51 16` | `entries[0].Key1` | `0x16511ea3`（Cache 2, Key 0 低 32 位） |
| 0x2E–0x31 | `48 29 22 78` | `entries[0].Key2` | `0x78222948`（Cache 2, Key 0 高 32 位） |

**长度闭合校验**：`42 + 25 × 8 = 242` ✔ 等于 `totalLength`。

**本 dump 的教学要点**：

1. 这是**唯一**能验证"固定字段 24 字节 + 条目从偏移 42 开始"的官方样本。若把 `bBitMask` 当成 2 字节、或漏掉 `Pad2`/`Pad3`，条目起点就会偏移，`42 + 8N` 的闭合校验立刻失败。
2. `uncompressedLength = 0` 而整包 242 字节 → 第三次证明该字段不可靠。
3. `bBitMask = 0x03` 表示这既是首包也是末包（单包序列），因此**不要**假设"必须至少两个 PDU"。

### 5.6 Dump #6：无加密 Client Font List（**按结构推导**，非官方）

**【推导】** 本节 dump 由 §2.3 / §2.11 / §4.4 的结构定义合成，用于覆盖"`EncryptionLevel = 0` 且 `EncryptionMethod = 0`、无安全头"这一官方第 4 章未提供 dump 的分支。推导依据：`totalLength = 18 + 8 = 26 = 0x1a`；`pduType = (1 << 4) | 7 = 0x0017`；`pduType2 = 39 = 0x27`；`listFlags = 0x0003`；`entrySize = 0x0032`。字段值取自 S60 的实测值，仅移除安全头。

```
00000000  03 00 00 28 02 f0 80 64 00 06 03 eb 70 1a 1a 00   ...(...d....p...
00000010  17 00 ef 03 ea 03 01 00 00 01 1a 00 27 00 00 00   ............'...
00000020  00 00 00 00 03 00 32 00                           ......2.
```

| 偏移 | 字节 | 字段 | 值 / 解析 |
|---|---|---|---|
| 0x00 | `03` | TPKT `version` | 3 |
| 0x01 | `00` | TPKT `reserved` | 0 |
| 0x02–0x03 | `00 28` | TPKT `length` | `0x0028 = 40` = 4 + 3 + 7 + 26 |
| 0x04–0x06 | `02 f0 80` | X.224 Data TPDU | LI=2, code=0xF0, EOT |
| 0x07–0x0D | `64 00 06 03 eb 70 1a` | MCS `SDrq` 头（7 字节） | initiator = 1007；channelId = 1003；`userData` 长度 = `0x1a = 26` |
| 0x0E | — | `securityHeader` | **不存在**（level=0, method=0） |
| 0x0E–0x0F | `1a 00` | `totalLength` | `0x001a = 26` |
| 0x10–0x11 | `17 00` | `pduType` | `0x0017`（`type=7`, `PDUVersion=1`） |
| 0x12–0x13 | `ef 03` | `pduSource` | `0x03ef` |
| 0x14–0x17 | `ea 03 01 00` | `shareID` | `0x000103ea` |
| 0x18 | `00` | `pad1` | 0 |
| 0x19 | `01` | `streamID` | LOW |
| 0x1A–0x1B | `1a 00` | `uncompressedLength` | `0x001a = 26`（本样本按"正确填法"生成；实际可能为任意值，见 5.3） |
| 0x1C | `27` | `pduType2` | FONTLIST (39) |
| 0x1D | `00` | `compressedType` | 0 |
| 0x1E–0x1F | `00 00` | `compressedLength` | 0 |
| 0x20–0x21 | `00 00` | `numberFonts` | 0 |
| 0x22–0x23 | `00 00` | `totalNumFonts` | 0 |
| 0x24–0x25 | `03 00` | `listFlags` | `0x0003` |
| 0x26–0x27 | `32 00` | `entrySize` | `0x0032` |

**长度闭合校验**：`0x28 = 40 = 4 + 3 + 7 + 26` ✔；`MCS userData (26) == totalLength (26)` ✔（无安全头且未压缩时必然相等）。

**本 dump 的教学要点**：

1. **无安全头时，`shareControlHeader` 紧跟 MCS `userData` 起点**。这是"安全头长度 = 0"分支的唯一形态。
2. `MCS userData 长度 (26) == totalLength (26)`。在无安全头且未压缩时，两者必然相等——这是一个有用的断言（但**仅**在此条件下成立）。
3. 若实现硬编码"跳过 12 字节安全头"，则会把 `totalLength` 的低字节当成 `flags`，全盘错位。这是最常见的实现 bug。

---

## 6. 长度校验、畸形与错误处理

### 6.1 分层校验清单（必须按顺序执行）

| 层 | 校验项 | 不通过时 | 依据 |
|---|---|---|---|
| L1 传输层 | TPKT `length ≥ 4`；实际收到字节数 == `length` | 断连 | 3.2.5.2 / 3.3.5.2（"If there is any discrepancy, the connection SHOULD be dropped"） |
| L1 传输层 | X.224 `LI == 2`；`code == 0xF0` | 断连 | [X224] §13.7 |
| L2 MCS | MCS `userData` 长度与实际一致 | 断连 | 3.2.5.2 / 3.3.5.2 |
| L2 MCS | `channelId` 在已加入的通道集合内 | 断连（`ERRINFO_INVALIDCHANNELID 0x000010EF`） | 2.2.5.1.1 |
| L3 安全 | 安全头长度足够（4/12/16 按协商） | 断连（`ERRINFO_SECURITYDATATOOSHORT2/3`） | 2.2.5.1.1 |
| L3 安全 | FIPS `length == 0x0010` | 断连 | 2.2.8.1.1.2.3 |
| L3 安全 | MAC 校验通过 | 断连（`ERRINFO_DECRYPTFAILED`） | 5.3.6、3.2.5.2 |
| L4 共享头 | `pduType.PDUVersion == 1`（Data PDU） | 断连 | 2.2.8.1.1.1.2 |
| L4 共享头 | `totalLength` == 实收（`shareControlHeader` 起算） | 断连 | 3.2.5.2 / 3.3.5.2 |
| L4 共享头 | `totalLength ≥ 18`（至少容纳 shareDataHeader） | 断连（`ERRINFO_SHAREDATATOOSHORT`） | 2.2.5.1.1 |
| L5 类型 | `pduType.type` 已定义 | 断连（`ERRINFO_UNKNOWNPDUTYPE 0x000010CA`） | 2.2.5.1.1 |
| L5 类型 | `pduType2` 已定义 | 断连（`ERRINFO_UNKNOWNPDUTYPE2 0x000010C9`） | 2.2.5.1.1 |
| L5 类型 | 该 `pduType2` 在当前方向合法 | 断连或忽略（见 §6.2） | 2.2.8.1.1.1.2 方向列 |
| L6 内容 | 解压成功 | 断连 | 3.1.8.3 |
| L6 内容 | 各 PDU 的固定字段符合 MUST | 断连（见 §6.3） | 各 PDU 章节 |
| L7 语义 | 序列状态合法 | 断连（见 §4.8.7） | 1.3.1.1、3.3.5.3.x |

### 6.2 未知 `pduType` / `pduType2` 的处理建议

规范给出两个专用错误码（2.2.5.1.1 / S54）：

| 错误码 | 名称 | 语义 |
|---|---|---|
| `0x000010C9` | `ERRINFO_UNKNOWNPDUTYPE2` | 收到 Share Data Header 中的未知 `pduType2` |
| `0x000010CA` | `ERRINFO_UNKNOWNPDUTYPE` | 收到 Share Control Header 中的未知 `pduType` |

**分层策略【建议】**：

| 情形 | 处理 | 理由 |
|---|---|---|
| `pduType.type` 未知 | **断连** | 共享头都无法解析，后续字节无边界，无法安全跳过 |
| `pduType2` 未知，但 `totalLength` 自洽 | **跳过 + 记录**，不断连 | 共享头已给出可靠边界，可以安全跳过；规范未强制断连（`ERRINFO_UNKNOWNPDUTYPE2` 只是"可上报"的错误码） |
| `pduType2` 未知且 `totalLength` 不自洽 | **断连** | 无法确定边界 |
| 方向不匹配（如客户端收到 `PDUTYPE2_INPUT`） | **断连** | 属协议违规，且暗示对端实现错误 |
| `eventCode` 未知 | **断连** | 3.3.5.8.1.2 明确 SHOULD drop |
| `updateCode` 未知 | **跳过该 update**（`size` 给出边界）+ 记录 | 与 `pduType2` 同理；`size` 是可靠边界 |
| `updateCode` 未知且 `size` 越界 | **断连** | 无法确定边界 |

**为什么 `pduType2` 未知可以"跳过"**：因为 `totalLength` 提供了完整的包边界，跳过它不会破坏后续帧同步。而 `pduType` 未知时连"`totalLength` 从哪算"都不确定（虽然实际上位置固定），所以更保守地断连。

**与规范的措辞一致性说明**：规范只给出错误码，未规定"必须断连"。原文对 `ERRINFO_UNKNOWNPDUTYPE2` 的描述仅为 "Unknown `pduType2` field in a received Share Data Header"（2.2.5.1.1），是**错误上报**语义，不是**强制断连**语义。因此"跳过 + 上报"是合规的，且对前向兼容更友好。

### 6.3 各 PDU 的长度与固定值校验表

| PDU | 长度校验 | 固定值校验 | 不通过时 |
|---|---|---|---|
| `TS_SHARECONTROLHEADER` | `totalLength ≥ 6` | `PDUVersion == 1`（Data PDU） | 断连 |
| `TS_SHAREDATAHEADER` | `totalLength ≥ 18` | `pad1` 忽略；`streamID` 忽略 | 断连（长度）；忽略（pad/stream） |
| `TS_SYNCHRONIZE_PDU` | `totalLength == 22` | `messageType == 1`；`pduType2 == 31` | 断连 |
| `TS_CONTROL_PDU` | `totalLength == 26` | `action ∈ {1,2,3,4}`；`pduType2 == 20` | 断连（`ERRINFO_INVALIDCONTROLPDUACTION`） |
| `TS_FONT_LIST_PDU` | `totalLength == 26` | `pduType2 == 39`；其余 4 字段**忽略** | 断连（仅长度/类型） |
| `TS_FONT_MAP_PDU` | `totalLength == 26` | `pduType2 == 40` | 断连 |
| `TS_BITMAPCACHE_PERSISTENT_LIST_PDU` | `totalLength == 42 + 8ΣN` | `pduType2 == 43`；Σ total ≤ 262144 | 断连 |
| `TS_SAVE_SESSION_INFO_PDU_DATA` | `totalLength ≥ 22` | `pduType2 == 38`；`infoType` 已知 | 未知 `infoType` → 丢弃该包 |
| `TS_FP_INPUT_PDU` | `pdu_length ≥ 2`；事件长度和 == 剩余 | `action == 0`；`eventFlags` 按事件类型 | 断连 |
| `TS_FP_UPDATE_PDU` | `pdu_length ≥ 2`；update 遍历闭合 | `action == 0`；`reserved == 0` | 断连（遍历失败） |

**"长度必须精确相等"的适用边界**：上表对 `TS_SYNCHRONIZE_PDU` / `TS_CONTROL_PDU` / `TS_FONT_LIST_PDU` / `TS_FONT_MAP_PDU` 要求 `totalLength` **精确等于**结构长度（22 / 26 / 26 / 26）。这四类 PDU 结构完全固定、无变长字段，因此精确校验是安全且必要的。而 `TS_SAVE_SESSION_INFO_PDU_DATA` 与 Persistent Key List 是变长的，只能做下界/公式校验。

**`totalLength` 与实际长度不一致时怎么办**（任务 D-12 的核心问题）：

| 差异方向 | 含义 | 处理 |
|---|---|---|
| `totalLength > 实收` | 声明比实际长（包被截断） | **断连**。无法补全，且后续字节流位置不明 |
| `totalLength < 实收` | 声明比实际短 | **断连**。多出的字节无法归属，可能是注入或错位 |
| `totalLength == 0x8000` | T.128 FlowPDU 标记 | **忽略该 PDU**，按外层 `userData` 长度消费（§2.1） |
| `totalLength < 18` | 装不下 shareDataHeader | **断连**（`ERRINFO_SHAREDATATOOSHORT`） |
| Fast-Path `pdu_length` 与实际不符 | 长度字段错 | **断连**。Fast-Path 无外层长度可依，无法恢复 |

**为什么"声明比实际短"也必须断连**：因为 RDP 是流式协议，`totalLength` 是唯一的分帧依据。若允许"按声明长度消费、剩余字节重新同步"，则恶意对端可以构造重叠帧实施状态混淆攻击。规范措辞是 "If there is any discrepancy, the connection SHOULD be dropped"（3.2.5.2 / 3.3.5.2），未区分方向。

### 6.4 Fast-Path 专项畸形检查

| 检查项 | 判据 | 处理 |
|---|---|---|
| `action` 非法 | `(b & 0x03) == 0x1` 或 `0x2` | 断连 |
| `pdu_length < 2` | — | 断连 |
| `pdu_length` 超上限 | `> 16383`（SHOULD 上限） | 记录告警；超过硬上限（建议 65535）则断连 |
| 输入 `numEvents` 位域 = 0 且无扩展字段空间 | 剩余字节 < 1 | 断连 |
| 输入 `numEvents` 扩展字段 = 0 | — | 断连 |
| 输入事件遍历有剩余 | `remaining != 0` | 断连（`ERRINFO_INPUTPDUBADLENGTH`） |
| 输入事件遍历越界 | `remaining < event_size` | 断连 |
| 输出 `reserved != 0` | — | 告警（前向兼容） |
| 输出 update `size` 越界 | `size > remaining - hdr - 2` | 断连 |
| 输出 update `updateCode` 未知且 `size` 合理 | — | 跳过该 update |
| 输出 update 遍历不闭合 | `remaining != 0` | 断连 |
| `compression == 0x2` 但 `size` 读取越界 | 剩余 < 1 | 断连 |
| `compression == 0x1` 或 `0x3`（未定义） | — | 断连（无法确定 `compressionFlags` 是否存在，无法继续） |
| 分片序列违规 | 见 §3.11 状态机 | 断连 |
| `TS_FP_FIPS_INFO.length != 0x0010` | — | 断连 |
| 加密标志与协商不符 | Enhanced Security 下 `FASTPATH_*_ENCRYPTED` 置位 | 断连（3.2.5.8.1.2 / 3.3.5.9.3："double-encryption is not used"） |

**`compression == 0x1` / `0x3` 为什么必须断连**：这两个值未定义，但它们的取值决定了 `compressionFlags` 字段是否存在于线上。若猜测"不存在"，而实际存在，则后续 `size` 会读错 1 字节，整个 update 数组错位。无法安全继续。

### 6.5 建议的错误码映射（与规范一致）

| 检测到 | 上报 `ERRINFO_*` | 数值 |
|---|---|---|
| 未知 `pduType` | `ERRINFO_UNKNOWNPDUTYPE` | `0x000010CA` |
| 未知 `pduType2` | `ERRINFO_UNKNOWNPDUTYPE2` | `0x000010C9` |
| Data PDU 乱序 | `ERRINFO_DATAPDUSEQUENCE` | `0x000010CB` |
| Control/Active PDU 乱序 | `ERRINFO_CONTROLPDUSEQUENCE` | `0x000010CD` |
| `action` 非法 | `ERRINFO_INVALIDCONTROLPDUACTION` | `0x000010CE` |
| 输入事件类型非法 | `ERRINFO_INVALIDINPUTPDUTYPE` | `0x000010CF` |
| 鼠标 flags 非法 | `ERRINFO_INVALIDINPUTPDUMOUSE` | `0x000010D0` |
| Persistent Key List 数据不足 | `ERRINFO_PERSISTENTKEYPDUBADLENGTH` | `0x000010DA` |
| Persistent Key List FIRST 重复 | `ERRINFO_PERSISTENTKEYPDUILLEGALFIRST` | `0x000010DB` |
| Persistent Key List 总数超限 | `ERRINFO_PERSISTENTKEYPDUTOOMANYTOTALKEYS` | `0x000010DC` |
| Persistent Key List 单缓存键数超限 | `ERRINFO_PERSISTENTKEYPDUTOOMANYCACHEKEYS` | `0x000010DD` |
| 输入 PDU 数据不足 | `ERRINFO_INPUTPDUBADLENGTH` | `0x000010DE` |
| Fast-Path 签名不足 | `ERRINFO_SECURITYDATATOOSHORT` | `0x000010E0` |
| 共享头/控制/FontList 数据不足 | `ERRINFO_SHAREDATATOOSHORT` | `0x000010E2` |
| 基础安全头不足 | `ERRINFO_SECURITYDATATOOSHORT2` | `0x00001111` |
| Non-FIPS/FIPS 安全头不足 | `ERRINFO_SECURITYDATATOOSHORT3` | `0x00001112` |
| 解密失败 | `ERRINFO_DECRYPTFAILED` | `0x00001192` |
| 加密失败 | `ERRINFO_ENCRYPTFAILED` | `0x00001193` |
| 收到明文但应为密文 | `ERRINFO_DECRYPTFAILED2` | `0x00001195` |

全部数值来自 2.2.5.1.1（S54）。

---

## 7. 实现检查清单

### 7.1 解析器必须满足的不变量

| # | 不变量 | 依据 |
|---|---|---|
| 1 | 首字节 `== 0x03` → slow-path；低 2 位 `== 0` → fast-path；否则报错 | §3.1 |
| 2 | 位域提取统一用 `[hi:lo]` 掩码，禁止按 MSB-first 读 | §1.3（三处红证） |
| 3 | 安全头长度只由 (level, method) 决定，不由 `flags` 决定 | §2.11 |
| 4 | `flagsHi` 恒定存在 2 字节，仅有效性由 `0x8000` 决定 | §2.7 |
| 5 | `totalLength` 不含安全头/MAC；不含 TPKT/X.224/MCS | §1.2、§5.1 |
| 6 | `uncompressedLength` / `compressedLength` 未压缩时**不得**参与校验 | §5.3（反例 55867） |
| 7 | Fast-Path `length1/length2` 为**大端**组合，`pdu_length` 含首字节 | §3.4 |
| 8 | 输入 `numEvents` 位域为 0 才读扩展字段 | §3.2 |
| 9 | 输出 PDU 无计数，必须按 `size` 遍历到 `pdu_length` 耗尽 | §3.3 |
| 10 | `updateHeader.compression == 0x2` 才读 `compressionFlags` | §3.8 |
| 11 | 分片必须按到达顺序拼接，`updateCode`/`compression` 必须一致 | §3.11 |
| 12 | 客户端最终化 PDU 可批量，服务端必须逐项响应 | §4.8 |
| 13 | `targetUser`、`grantId`、`controlId`、`pad*`、`streamID`、Font List 四字段**不得**校验 | §4.2–§4.5 |

### 7.2 常量表（可直接落码）

```
PDUTYPE_DEMANDACTIVEPDU            0x1
PDUTYPE_CONFIRMACTIVEPDU           0x3
PDUTYPE_DEACTIVATEALLPDU           0x6
PDUTYPE_DATAPDU                    0x7
PDUTYPE_SERVER_REDIR_PKT           0xA
TS_PROTOCOL_VERSION                0x1

STREAM_UNDEFINED                   0x00
STREAM_LOW                         0x01
STREAM_MED                         0x02
STREAM_HI                          0x04

PDUTYPE2_UPDATE                    0x02
PDUTYPE2_CONTROL                   0x14
PDUTYPE2_POINTER                   0x1B
PDUTYPE2_INPUT                     0x1C
PDUTYPE2_SYNCHRONIZE               0x1F
PDUTYPE2_REFRESH_RECT              0x21
PDUTYPE2_PLAY_SOUND                0x22
PDUTYPE2_SUPPRESS_OUTPUT           0x23
PDUTYPE2_SHUTDOWN_REQUEST          0x24
PDUTYPE2_SHUTDOWN_DENIED           0x25
PDUTYPE2_SAVE_SESSION_INFO         0x26
PDUTYPE2_FONTLIST                  0x27
PDUTYPE2_FONTMAP                   0x28
PDUTYPE2_SET_KEYBOARD_INDICATORS   0x29
PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST 0x2B
PDUTYPE2_BITMAPCACHE_ERROR_PDU     0x2C
PDUTYPE2_SET_KEYBOARD_IME_STATUS   0x2D
PDUTYPE2_OFFSCRCACHE_ERROR_PDU     0x2E
PDUTYPE2_SET_ERROR_INFO_PDU        0x2F
PDUTYPE2_DRAWNINEGRID_ERROR_PDU    0x30
PDUTYPE2_DRAWGDIPLUS_ERROR_PDU     0x31
PDUTYPE2_ARC_STATUS_PDU            0x32
PDUTYPE2_STATUS_INFO_PDU           0x36
PDUTYPE2_MONITOR_LAYOUT_PDU        0x37

SEC_EXCHANGE_PKT                   0x0001
SEC_TRANSPORT_REQ                  0x0002
SEC_TRANSPORT_RSP                  0x0004
SEC_ENCRYPT                        0x0008
SEC_RESET_SEQNO                    0x0010
SEC_IGNORE_SEQNO                   0x0020
SEC_INFO_PKT                       0x0040
SEC_LICENSE_PKT                    0x0080
SEC_LICENSE_ENCRYPT_CS             0x0200
SEC_LICENSE_ENCRYPT_SC             0x0200
SEC_REDIRECTION_PKT                0x0400
SEC_SECURE_CHECKSUM                0x0800
SEC_AUTODETECT_REQ                 0x1000
SEC_AUTODETECT_RSP                 0x2000
SEC_HEARTBEAT                      0x4000
SEC_FLAGSHI_VALID                  0x8000

FASTPATH_INPUT_ACTION_FASTPATH     0x0
FASTPATH_INPUT_ACTION_X224         0x3
FASTPATH_INPUT_SECURE_CHECKSUM     0x1
FASTPATH_INPUT_ENCRYPTED           0x2
FASTPATH_OUTPUT_ACTION_FASTPATH    0x0
FASTPATH_OUTPUT_ACTION_X224        0x3
FASTPATH_OUTPUT_SECURE_CHECKSUM    0x1
FASTPATH_OUTPUT_ENCRYPTED          0x2

FASTPATH_INPUT_EVENT_SCANCODE      0x0
FASTPATH_INPUT_EVENT_MOUSE         0x1
FASTPATH_INPUT_EVENT_MOUSEX        0x2
FASTPATH_INPUT_EVENT_SYNC          0x3
FASTPATH_INPUT_EVENT_UNICODE       0x4
FASTPATH_INPUT_EVENT_MOUSEREL      0x5
FASTPATH_INPUT_EVENT_QOE_TIMESTAMP 0x6

FASTPATH_INPUT_KBDFLAGS_RELEASE    0x01
FASTPATH_INPUT_KBDFLAGS_EXTENDED   0x02
FASTPATH_INPUT_KBDFLAGS_EXTENDED1  0x04
FASTPATH_INPUT_SYNC_SCROLL_LOCK    0x01
FASTPATH_INPUT_SYNC_NUM_LOCK       0x02
FASTPATH_INPUT_SYNC_CAPS_LOCK      0x04
FASTPATH_INPUT_SYNC_KANA_LOCK      0x08

FASTPATH_UPDATETYPE_ORDERS         0x0
FASTPATH_UPDATETYPE_BITMAP         0x1
FASTPATH_UPDATETYPE_PALETTE        0x2
FASTPATH_UPDATETYPE_SYNCHRONIZE    0x3
FASTPATH_UPDATETYPE_SURFCMDS       0x4
FASTPATH_UPDATETYPE_PTR_NULL       0x5
FASTPATH_UPDATETYPE_PTR_DEFAULT    0x6
FASTPATH_UPDATETYPE_PTR_POSITION   0x8
FASTPATH_UPDATETYPE_COLOR          0x9
FASTPATH_UPDATETYPE_CACHED         0xA
FASTPATH_UPDATETYPE_POINTER        0xB
FASTPATH_UPDATETYPE_LARGE_POINTER  0xC

FASTPATH_FRAGMENT_SINGLE           0x0
FASTPATH_FRAGMENT_LAST             0x1
FASTPATH_FRAGMENT_FIRST            0x2
FASTPATH_FRAGMENT_NEXT             0x3
FASTPATH_OUTPUT_COMPRESSION_USED   0x2

SYNCMSGTYPE_SYNC                   1
CTRLACTION_REQUEST_CONTROL         0x0001
CTRLACTION_GRANTED_CONTROL         0x0002
CTRLACTION_DETACH                  0x0003
CTRLACTION_COOPERATE               0x0004

FONTLIST_FIRST                     0x0001
FONTLIST_LAST                      0x0002
FONTMAP_FIRST                      0x0001
FONTMAP_LAST                       0x0002
PERSIST_FIRST_PDU                  0x01
PERSIST_LAST_PDU                   0x02

INFOTYPE_LOGON                     0x00000000
INFOTYPE_LOGON_LONG                0x00000001
INFOTYPE_LOGON_PLAINNOTIFY         0x00000002
INFOTYPE_LOGON_EXTENDED_INFO       0x00000003

PACKET_COMPRESSED                  0x20
PACKET_AT_FRONT                    0x40
PACKET_FLUSHED                     0x80
CompressionTypeMask                0x0F
PACKET_COMPR_TYPE_8K               0x0
PACKET_COMPR_TYPE_64K              0x1
PACKET_COMPR_TYPE_RDP6             0x2
PACKET_COMPR_TYPE_RDP61            0x3

TSFIPS_VERSION1                    0x01
```

### 7.3 结构尺寸速查

| 结构 | 固定尺寸 |
|---|---|
| `TS_SHARECONTROLHEADER` | 6 |
| `TS_SHAREDATAHEADER` | 18（含上者） |
| `TS_SECURITY_HEADER` | 4 |
| `TS_SECURITY_HEADER1` | 12 |
| `TS_SECURITY_HEADER2` | 16 |
| `TS_FP_FIPS_INFO` | 4 |
| `TS_SYNCHRONIZE_PDU` | 22 |
| `TS_CONTROL_PDU` | 26 |
| `TS_FONT_LIST_PDU` | 26 |
| `TS_FONT_MAP_PDU` | 26 |
| `TS_BITMAPCACHE_PERSISTENT_LIST_PDU` | 42 + 8N |
| `TS_SAVE_SESSION_INFO_PDU_DATA` | 22 + len(infoData) |
| `TS_FP_KEYBOARD_EVENT` | 2 |
| `TS_FP_UNICODE_KEYBOARD_EVENT` | 3 |
| `TS_FP_POINTER_EVENT` | 7 |
| `TS_FP_POINTERX_EVENT` | 7 |
| `TS_FP_SYNC_EVENT` | 1 |
| `TS_FP_QOETIMESTAMP_EVENT` | 5 |
| `TS_FP_RELPOINTER_EVENT` | 7 |
| `TS_FP_UPDATE`（前缀） | 3 或 4 |
| `TS_POINTERPOSATTRIBUTE` | 4 |
| `TS_CACHEDPOINTERATTRIBUTE` | 2 |

### 7.4 测试向量（最小集）

| # | 用例 | 期望 |
|---|---|---|
| T1 | 解析 5.1 明文（22 字节） | `pduType2=31`、`messageType=1`、`targetUser=1002` |
| T2 | 解析 5.2（17 字节 fast-path） | `numEvents=1`、`eventCode=1`、`xPos=683`、`yPos=367` |
| T3 | 解析 5.3（26 字节 Font List） | 不因 `uncompressedLength=55867` 报错 |
| T4 | 解析 5.4（26 字节 Font Map） | `pad1=0x45` 被忽略，`entrySize=4` |
| T5 | 解析 5.5（242 字节 Persistent List） | `42 + 25*8 == 242` 校验通过 |
| T6 | 解析 5.6（无安全头 26 字节） | 安全头长度为 0，`totalLength=26` |
| T7 | 构造 300 字节 fast-path | 编码为 `81 2C`，解码回 300 |
| T8 | 构造 `length1=0x80, length2=0x00` | 判为畸形（长度 0 < 2） |
| T9 | 把 5.2 首字节改为 `0xc1` | `action=1` → 判为非法 |
| T10 | 把 5.1 的 `totalLength` 改为 23 | 长度不符 → 断连 |
| T11 | 把 5.3 的 `pad1` 改为任意值 | 仍解析成功 |
| T12 | 把 5.4 的 `entrySize` 改为 50 | 仍解析成功（该字段被忽略） |
| T13 | 把 5.5 的 `numEntriesCache2` 改为 26 | `42+26*8=250 ≠ 242` → 断连 |
| T14 | Fast-Path update `size` 设为 0xFFFF | 越界检查触发 → 断连 |

---

## 8. 不确定项

以下各项在 `[MS-RDPBCGR]` 中**没有明确答案**，或本文只能给出推导。实现时须按此清单确认，不得当作已证实结论。

| 编号 | 问题 | 现状 | 本文立场 |
|---|---|---|---|
| **U-1** | `TS_SHARECONTROLHEADER.pduType` 的位图渲染顺序（`type` 在左、`PDUVersion` 在右）是否意味着 `type` 是**低位**？ | 规范只说 "`type` (4 bits)" / "`PDUVersion` (12 bits)"，未给位号 | **已由红证确定**：`0x0017` 解出 `type=7, version=1`，故 `type` 为低 4 位。此项**已不是不确定项**，仅在此备案以说明推导链 |
| **U-2** | `TS_FP_UPDATE.updateHeader` 的 `updateCode`/`fragmentation`/`compression` 精确位号 | 规范只给位图，第 4 章**无** fast-path 输出 dump 可供反证 | 按 §1.3 的通用惯例推定为 `updateCode=[3:0]`、`fragmentation=[5:4]`、`compression=[7:6]`。**这是本文最需要实机验证的一条**。验证方法：抓一个含 `FASTPATH_UPDATETYPE_PTR_POSITION (8)` 的真实服务端输出包，若按此切分能解出合理的 4 字节坐标，则成立 |
| **U-3** | `fpOutputHeader.reserved` 的精确位号 | 同 U-2 | 推定为 `[5:2]`（与输入头 `numEvents` 同位） |
| **U-4** | `TS_FP_SYNC_EVENT.eventFlags` 的 bit4（第 5 位）语义 | 规范只定义 `0x01`–`0x08` 四位，bit4 未定义 | 忽略 bit4；不断连 |
| **U-5** | `updateHeader.compression` 取值 `0x1` / `0x3` 的语义 | 规范只定义 `0x2` | 判为畸形并断连（因为无法确定 `compressionFlags` 是否存在） |
| **U-6** | 分片时 `compressionFlags` 是逐片出现还是仅首片 | 规范只说"所有分片的 `updateCode` 与 `compression` 子字段必须相同"，未说 `compressionFlags` 字段的出现规则 | 按"逐片出现"实现（§3.11 建议）。若实机发现仅首片出现，需改为"首片携带、后续继承" |
| **U-7** | 客户端→服务端方向是否可能收到 4 字节 Basic 安全头 | 客户端→服务端各 PDU 章节只列 Non-FIPS/FIPS，未列 Basic；但 2.2.8.1.1.2.1 本身未限制方向 | 服务端解析入站包时**兼容** 4 字节 Basic 头（不报错），但发送时只发 12/16。若实机证明 Basic 头从不下行到服务端，可收紧为拒绝 |
| **U-8** | `totalLength == 0x8000` 时"消费多少字节" | 规范只说"MAY be interpreted as FlowPDU ... and MUST be ignored"，未给 FlowPDU 的长度字段位置 | 按外层 MCS `userData` 剩余长度消费（§2.1）。若 FlowPDU 有独立长度字段则需修正 |
| **U-9** | `TS_FP_INPUT_PDU` 在 `numEvents` 位域为 0 且扩展字段也为 0 时的语义 | 规范说"事件数 > 15 时位域置 0 并插入扩展字段"，未说扩展字段为 0 的含义 | 判为畸形（§6.4）。另一种可能是"0 个事件"的合法空包，但规范未支持此读法 |
| **U-10** | `PDUTYPE2_*` 的方向归属 | 2.2.8.1.1.1.2 的枚举表**不含方向列**；本文方向列来自各 PDU 章节的"sent from client/server to ..."描述 | 方向列属**推导汇总**，逐项有章节依据，但规范未集中声明。若实现需要严格方向校验，建议按本文表格，并对不匹配情形仅告警（除 `PDUTYPE2_INPUT` 外） |
| **U-11** | `TS_FP_QOETIMESTAMP_EVENT` 的 `timestamp` 原点与回绕处理细节 | 规范说"第一个时间戳隐式定义原点，服务端负责处理回绕"，未给回绕判定阈值 | 实现可自由处理（该事件仅供信息用途）；建议用无符号 32 位差值与 2^31 比较判回绕 |
| **U-12** | `TS_FP_LARGEPOINTERATTRIBUTE` 的 `pad` 字段是否存在 | 规范写 "An optional 8-bit, unsigned integer used for padding" | 解析时按"若剩余 1 字节则视为 pad"处理，不因缺失报错 |
| **U-13** | `TS_COLORPOINTERATTRIBUTE.pad` 同上 | 同上 | 同上 |
| **U-14** | `TS_SAVE_SESSION_INFO_PDU_DATA` 的 `infoType` 未知时是否应断连 | 规范未规定 | 建议丢弃该包不断连（§4.6） |
| **U-15** | `CTRLACTION_DETACH` 在 Connection Finalization 阶段的语义 | 枚举中有定义，但 1.3.1.1 的最终化序列未列出 | 建议记录并忽略，不断连（§4.3） |
| **U-16** | Persistent Key List 的 `bBitMask` 常量名不一致 | 规范表格用 `PERSIST_FIRST_PDU` / `PERSIST_LAST_PDU`，紧随的说明文字用 `PERSIST_PDU_FIRST` / `PERSIST_PDU_LAST` | 同一常量，以数值 `0x01` / `0x02` 为准 |
| **U-17** | `SEC_LICENSE_ENCRYPT_CS` 与 `SEC_LICENSE_ENCRYPT_SC` 数值冲突 | 规范给二者**相同**数值 `0x0200` | 按方向区分（§2.8）。这是规范的真实设计（同一 bit 在两个方向含义不同），不是笔误 |
| **U-18** | `flags` 位 `0x0100` 的语义 | 规范枚举表从 `0x0080` 直接跳到 `0x0200`，`0x0100` 无定义 | 视为未定义位；收到时忽略并记录（可能是历史遗留位） |
| **U-19** | `TS_FP_UPDATE_SYNCHRONIZE` / `PTR_NULL` / `PTR_DEFAULT` 的 `size` 是否可能非 0 | 规范写 "This field MUST be set to zero" | 严格校验 `size == 0`；非 0 判畸形（规范用 MUST） |
| **U-20** | Fast-Path 加密时 `length1/length2` 是否包含 `dataSignature` 的 8 字节 | 规范说 `pdu_length` 是 "overall PDU length"，未逐项列举 | **已由红证确定**：5.2 中 `17 = 1 + 1 + 8 + 7`，**包含**签名。此项**已不是不确定项**，备案以说明推导链 |
| **U-21** | 客户端收到 `STREAM_UNDEFINED (0x00)` 时是否需要特殊处理 | 规范只说该值可能出现在 Server Synchronize（服务端 bug），且不得与其他 PDU 一起用 | 完全忽略 `streamID`（§2.4），因此无需特殊处理 |
| **U-22** | 服务端发送 Server Synchronize 的 `targetUser` 应填什么 | 3.3.5.3.19 说 SHOULD 0；实测为未初始化垃圾值（S61） | 发送时填 0（合规）；接收时忽略（§4.2） |

### 8.1 待实机验证优先级

| 优先级 | 项 | 验证方法 |
|---|---|---|
| P0 | U-2（`updateHeader` 位序） | 抓真实服务端 fast-path 输出，找 `PTR_POSITION`（code 8）包，按推定切分解坐标 |
| P0 | U-6（分片压缩标志） | 构造 >16KB 的位图更新，观察服务端分片时 `compressionFlags` 的出现位置 |
| P1 | U-3（`reserved` 位序） | 与 U-2 同批验证（同一字节） |
| P1 | U-7（Basic 头下行到服务端） | 用 `ENCRYPTION_LEVEL_LOW` 配置连接，观察 C→S 方向是否出现 4 字节头 |
| P2 | U-9（`numEvents` 扩展为 0） | 需构造畸形包，观察真实 Windows 服务端行为 |
| P2 | U-15（`CTRLACTION_DETACH`） | 在会话中触发控制权转移，观察是否出现该 action |

### 8.2 本文未覆盖的范围

以下内容**不在** P4 范围内，需由其他文档承担：

| 内容 | 归属 |
|---|---|
| Capability Sets 的完整字段（`TS_GENERAL_CAPABILITYSET` 等） | P3（Capabilities Exchange） |
| 压缩算法（MPPC / RDP6 / RDP61）的位流细节 | 独立文档（3.1.8.x） |
| 位图/调色板/指针更新的渲染语义 | 独立文档（2.2.9.1.1.3 / .4） |
| Surface Commands 的具体命令格式 | 独立文档（2.2.9.2） |
| 虚拟通道（`CHANNEL_PDU_HEADER`） | 独立文档（2.2.6.1） |
| 标准 RDP 安全的密钥派生（`MACKeyN` / `EncryptKey`） | P2（Security） |
| Fast-Path Orders Update（`FASTPATH_UPDATETYPE_ORDERS`）的内部格式 | [MS-RDPEGDI] 2.2.2.2 |

---

## 9. 变更记录

| 版本 | 日期 | 说明 |
|---|---|---|
| v1.0 | 2026-10-22 | 初版。覆盖 A（Slow-Path 头）、B（Fast-Path）、C（连接最终化）、D（错误与畸形）全部 12 项要求。全部事实标注章节号；3 处关键位序/长度规则以官方 dump 红证；6 个十六进制 dump（5 官方 + 1 推导）；22 项不确定项备案 |

---

## 附录 A：本文引用的官方 dump 位置索引

| dump | `MS-RDPBCGR_text.txt` 行号 | 章节 |
|---|---|---|
| Client Synchronize | L369 | 4.1.14 |
| Client Control - Cooperate | L369–370 | 4.1.15 |
| Client Control - Request Control | L370–371 | 4.1.16 |
| Client Persistent Key List | L371–372 | 4.1.17 |
| Client Font List | L373–374 | 4.1.18 |
| Server Synchronize | L374–375 | 4.1.19 |
| Server Control - Cooperate | L375–376 | 4.1.20 |
| Server Control - Granted Control | L376 | 4.1.21 |
| Server Font Map | L376–377 | 4.1.22 |
| Fast-Path Input Event PDU | 独立页面（S65） | 4.7 |

> 索引对应 `F:\rtsc\.tmp\MS-RDPBCGR_text.txt`（v20260309，444 页）。该文件的章节标题行号可作为二次核对的锚点。

