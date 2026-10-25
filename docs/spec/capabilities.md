# P4 能力交换（Capability Exchange）权威规范

本文件是 RTSC 项目 RDP 客户端 **Capability Exchange 阶段**的实现依据：共享 PDU 头、Fast-Path 头、
Demand Active / Confirm Active、全部 capability set 的字节布局、Deactivate All、Font List / Font Map，
以及客户端状态机。

> **范围声明**：本文件只描述**线上字节格式与处理规则**，不含 C++ 代码，不含 CMake 变更。
> 本文件不描述 Licensing（[MS-RDPELE]）、CredSSP（[MS-CSSP]）、EGFX 管线（[MS-RDPEGFX]）的内部结构。

---

## 0. 规范来源清单

### 0.1 抓取方式与可复现命令

主来源为 **Microsoft Open Specifications** 官方页面，并额外下载官方 DOCX 全文用于逐字段比对
（网页版位域图在纯文本转换中会丢失列对齐，DOCX 的表格结构可保留）。

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
# 1) 官方 DOCX 全文（[MS-RDPBCGR] v62.0，2026-03-09）
Invoke-WebRequest -Uri 'https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RDPBCGR/%5bMS-RDPBCGR%5d-260309.docx' `
  -OutFile 'F:\rtsc\.tmp\bcgr.docx' -UseBasicParsing -MaximumRedirection 5
# 2) 官方 DOCX 全文（[MS-RDPEGDI]，2024-04-23）
Invoke-WebRequest -Uri 'https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RDPEGDI/%5bMS-RDPEGDI%5d-240423.docx' `
  -OutFile 'F:\rtsc\.tmp\egdi.docx' -UseBasicParsing -MaximumRedirection 5
# 3) 章节 GUID 表（权威章节号 → 页面 GUID 映射）
Invoke-WebRequest -Uri 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/toc.json' `
  -OutFile 'F:\rtsc\.tmp\toc.json' -UseBasicParsing
```

> 注：`azurefd.net` 直链返回 **308 Permanent Redirect**，实际内容域为
> `winprotocoldoc.z19.web.core.windows.net`；必须跟随重定向，否则拿到 0 字节。

### 0.2 章节来源表（全部实际抓取，HTTP 200）

| 编号 | 章节 | 标题 | URL（learn.microsoft.com/en-us/openspecs/windows_protocols/ 之后部分） |
|---|---|---|---|
| S01 | 2.2 | Message Syntax | `ms-rdpbcgr/b61e1c76-5d7c-4285-b61a-b69f85e4a0e2` |
| S02 | 1.3.1.1 | Connection Sequence | `ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee` |
| S03 | 1.3.1.3 | Deactivation-Reactivation Sequence | `ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432` |
| S04 | 1.7 | Versioning and Capability Negotiation | `ms-rdpbcgr/18bdcc20-2ca8-4520-9073-65e52a1c6733` |
| S05 | 2.2.1.13 | Mandatory Capability Exchange | `ms-rdpbcgr/8be0074f-2a5f-4809-9e9f-76826792489c` |
| S06 | 2.2.1.13.1 | Server Demand Active PDU | `ms-rdpbcgr/a07abad1-38bb-4a1a-96c9-253e3d5440df` |
| S07 | 2.2.1.13.1.1 | Demand Active PDU Data (TS_DEMAND_ACTIVE_PDU) | `ms-rdpbcgr/bd612af5-cb54-43a2-9646-438bc3ecf5db` |
| S08 | 2.2.1.13.1.1.1 | Capability Set (TS_CAPS_SET) | `ms-rdpbcgr/d705c3b6-a392-4b32-9610-391f6af62323` |
| S09 | 2.2.1.13.2 | Client Confirm Active PDU | `ms-rdpbcgr/4c3c2710-0bf0-4c54-8e69-aff40ffcde66` |
| S10 | 2.2.1.13.2.1 | Confirm Active PDU Data (TS_CONFIRM_ACTIVE_PDU) | `ms-rdpbcgr/4e9722c3-ad83-43f5-af5a-529f73d88b48` |
| S11 | 2.2.7 | Capability Sets | `ms-rdpbcgr/7cc40be0-ceb0-4983-85d0-e08af4bec2a6` |
| S12 | 2.2.7.1 | Mandatory Capability Sets | `ms-rdpbcgr/c21e61b5-82a5-4e95-a660-fa95328c2712` |
| S13 | 2.2.7.1.1 | General Capability Set (TS_GENERAL_CAPABILITYSET) | `ms-rdpbcgr/41dc6845-07dc-4af6-bc14-d8281acd4877` |
| S14 | 2.2.7.1.2 | Bitmap Capability Set (TS_BITMAP_CAPABILITYSET) | `ms-rdpbcgr/76670547-e35c-4b95-a242-5729a21b83f6` |
| S15 | 2.2.7.1.3 | Order Capability Set (TS_ORDER_CAPABILITYSET) | `ms-rdpbcgr/9f409c29-480c-4751-9665-510b8ffff294` |
| S16 | 2.2.7.1.4.1 | Revision 1 (TS_BITMAPCACHE_CAPABILITYSET) | `ms-rdpbcgr/101d40a7-56c0-40e1-bcb9-1475ff63cb9d` |
| S17 | 2.2.7.1.4.2 | Revision 2 (TS_BITMAPCACHE_CAPABILITYSET_REV2) | `ms-rdpbcgr/a5b9b9a6-5f67-4089-a95d-009bc8e25bfc` |
| S18 | 2.2.7.1.4.2.1 | Bitmap Cache Cell Info (TS_BITMAPCACHE_CELL_CACHE_INFO) | `ms-rdpbcgr/f6602bd5-355a-47fe-af56-3ba2a1692889` |
| S19 | 2.2.7.1.5 | Pointer Capability Set (TS_POINTER_CAPABILITYSET) | `ms-rdpbcgr/925e2c05-c13f-44b1-aa20-23082051fef9` |
| S20 | 2.2.7.1.6 | Input Capability Set (TS_INPUT_CAPABILITYSET) | `ms-rdpbcgr/b3bc76ae-9ee5-454f-b197-ede845ca69cc` |
| S21 | 2.2.7.1.7 | Brush Capability Set (TS_BRUSH_CAPABILITYSET) | `ms-rdpbcgr/8b6a830f-3dde-4a84-9250-21ffa7d2e342` |
| S22 | 2.2.7.1.8 | Glyph Cache Capability Set (TS_GLYPHCACHE_CAPABILITYSET) | `ms-rdpbcgr/8e292483-9b0f-43b9-be14-dc6cd07e1615` |
| S23 | 2.2.7.1.8.1 | Cache Definition (TS_CACHE_DEFINITION) | `ms-rdpbcgr/cae26830-263c-4c1e-97c2-b561faded3d9` |
| S24 | 2.2.7.1.9 | Offscreen Bitmap Cache Capability Set (TS_OFFSCREEN_CAPABILITYSET) | `ms-rdpbcgr/412fa921-2faa-4f1b-ab5f-242cdabc04f9` |
| S25 | 2.2.7.1.10 | Virtual Channel Capability Set (TS_VIRTUALCHANNEL_CAPABILITYSET) | `ms-rdpbcgr/a8593178-80c0-4b80-876c-cb77e62cecfc` |
| S26 | 2.2.7.1.11 | Sound Capability Set (TS_SOUND_CAPABILITYSET) | `ms-rdpbcgr/fadb6a2c-18fa-4fa7-a155-e970d9b1ac59` |
| S27 | 2.2.7.2 | Optional Capability Sets | `ms-rdpbcgr/c7bf0bde-50e3-48e6-bd41-a296b8ff5b35` |
| S28 | 2.2.7.2.1 | Bitmap Cache Host Support Capability Set | `ms-rdpbcgr/fc05c385-46c3-42cb-9ed2-c475a3990e0b` |
| S29 | 2.2.7.2.2 | Control Capability Set | `ms-rdpbcgr/e0add8ac-1546-4091-85ba-0ea77f54f2c7` |
| S30 | 2.2.7.2.3 | Window Activation Capability Set | `ms-rdpbcgr/97ff3178-9999-4231-ae4c-1e8d10d0e219` |
| S31 | 2.2.7.2.4 | Share Capability Set | `ms-rdpbcgr/75caa232-1929-41bb-9d59-6f8aad59ecf5` |
| S32 | 2.2.7.2.5 | Font Capability Set | `ms-rdpbcgr/18b4ccdc-e5b0-43c4-a453-cfa8c9feb2a4` |
| S33 | 2.2.7.2.6 | Multifragment Update Capability Set | `ms-rdpbcgr/01717954-716a-424d-af35-28fb2b86df89` |
| S34 | 2.2.7.2.7 | Large Pointer Capability Set | `ms-rdpbcgr/41323437-c753-460e-8108-495a6fdd68a8` |
| S35 | 2.2.7.2.8 | Desktop Composition Capability Set | `ms-rdpbcgr/9132002f-f133-4a0f-ba2f-2dc48f1e7f93` |
| S36 | 2.2.7.2.9 | Surface Commands Capability Set | `ms-rdpbcgr/aa953018-c0a8-4761-bb12-86586c2cd56a` |
| S37 | 2.2.7.2.10 | Bitmap Codecs Capability Set | `ms-rdpbcgr/17e80f50-d163-49de-a23b-fd6456aa472f` |
| S38 | 2.2.7.2.10.1 | Bitmap Codecs (TS_BITMAPCODECS) | `ms-rdpbcgr/408b1878-9f6e-4106-8329-1af42219ba6a` |
| S39 | 2.2.7.2.10.1.1 | Bitmap Codec (TS_BITMAPCODEC) | `ms-rdpbcgr/86507fed-a0ee-4242-b802-237534a8f65e` |
| S40 | 2.2.7.2.10.1.1.1 | Globally Unique Identifier (GUID) | `ms-rdpbcgr/8555a21b-8d23-475e-9a2c-a16f656158af` |
| S41 | 2.2.8.1.1.1.1 | Share Control Header (TS_SHARECONTROLHEADER) | `ms-rdpbcgr/73d01865-2eae-407f-9b2c-87e31daac471` |
| S42 | 2.2.8.1.1.1.2 | Share Data Header (TS_SHAREDATAHEADER) | `ms-rdpbcgr/4b5d4c0d-a657-41e9-9c69-d58632f46d31` |
| S43 | 2.2.8.1.1.2.1 | Basic (TS_SECURITY_HEADER) | `ms-rdpbcgr/e13405c5-668b-4716-94b2-1c2654ca1ad4` |
| S44 | 2.2.8.1.1.2.2 | Non-FIPS (TS_SECURITY_HEADER1) | `ms-rdpbcgr/768e12c4-7748-4005-b91d-790847e47025` |
| S45 | 2.2.8.1.1.2.3 | FIPS (TS_SECURITY_HEADER2) | `ms-rdpbcgr/463bd2eb-c3b1-4986-86b0-a240819d9088` |
| S46 | 2.2.8.1.2 | Client Fast-Path Input Event PDU (TS_FP_INPUT_PDU) | `ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133` |
| S47 | 2.2.8.1.2.1 | Fast-Path FIPS Information (TS_FP_FIPS_INFO) | `ms-rdpbcgr/a641797e-3179-4212-8447-fa2a39e19c7b` |
| S48 | 2.2.8.1.2.2 | Fast-Path Input Event (TS_FP_INPUT_EVENT) | `ms-rdpbcgr/76c4dd59-7ba0-445d-a03c-885212ab80f6` |
| S49 | 2.2.8.1.2.2.1 | Fast-Path Keyboard Event | `ms-rdpbcgr/089d362b-31eb-4a1a-b6fa-92fe61bb5dbf` |
| S50 | 2.2.9.1.2 | Server Fast-Path Update PDU (TS_FP_UPDATE_PDU) | `ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597` |
| S51 | 2.2.9.1.2.1 | Fast-Path Update (TS_FP_UPDATE) | `ms-rdpbcgr/a1c4caa8-00ed-45bb-a06e-5177473766d3` |
| S52 | 2.2.3.1 | Server Deactivate All PDU | `ms-rdpbcgr/8a29971a-df3c-48da-add2-8ed9a05edc89` |
| S53 | 2.2.3.1.1 | Deactivate All PDU Data (TS_DEACTIVATE_ALL_PDU) | `ms-rdpbcgr/fc191c40-e688-4d5a-a550-6609cd5b8b59` |
| S54 | 2.2.1.18 | Client Font List PDU | `ms-rdpbcgr/7067da0d-e318-4464-88e8-b11509cf0bd9` |
| S55 | 2.2.1.18.1 | Font List PDU Data (TS_FONT_LIST_PDU) | `ms-rdpbcgr/e373575a-01e2-43a7-a6d8-e1952b83e787` |
| S56 | 2.2.1.22 | Server Font Map PDU | `ms-rdpbcgr/7ba6ba81-e4f4-46a7-9062-2d57a821be26` |
| S57 | 2.2.1.22.1 | Font Map PDU Data (TS_FONT_MAP_PDU) | `ms-rdpbcgr/b4e557f3-7540-46fc-815d-0c12299cf1ee` |
| S58 | 2.2.1.19 | Server Synchronize PDU | `ms-rdpbcgr/5186005a-36f5-4f5d-8c06-968f28e2d992` |
| S59 | 3.2.5.3.13 | Mandatory Capability Exchange（客户端） | `ms-rdpbcgr/78e11b18-ec57-4f51-b8ae-2d43192db915` |
| S60 | 3.2.5.3.13.1 | Processing Demand Active PDU | `ms-rdpbcgr/0108279d-cd8b-4975-993c-a5cb9ee0a888` |
| S61 | 3.2.5.3.13.2 | Sending Confirm Active PDU | `ms-rdpbcgr/dd59bea4-cfc7-49c0-9969-9e90341400e7` |
| S62 | 3.3.5.3.13 | Mandatory Capability Exchange（服务端） | `ms-rdpbcgr/afc747de-b841-4304-a5e1-cc564236a0ef` |
| S63 | 3.3.5.3.13.1 | Sending Demand Active PDU | `ms-rdpbcgr/4aed639a-9ac3-411d-add9-c5253308aa85` |
| S64 | 3.3.5.3.13.2 | Processing Confirm Active PDU | `ms-rdpbcgr/fa5ec7d9-a29d-477c-b234-b023bf6c5519` |
| S65 | 3.2.5.5.1 | Processing Deactivate All PDU | `ms-rdpbcgr/e3dddf9e-ddc7-4622-a0d4-cc1d68f1f1ac` |
| S66 | 3.3.5.5.1 | Sending Deactivate All PDU | `ms-rdpbcgr/b307d88b-167d-4e1a-9d41-3ae39d657239` |
| S67 | 5.3.6.1 | Encrypting and Decrypting the I/O Data Stream — Non-FIPS | `ms-rdpbcgr/7c61b54e-f6cd-4819-a59a-daf200f6bf94` |
| S68 | 5.3.6.1.1 | Salted MAC Generation | `ms-rdpbcgr/f390586a-3fdd-4a96-bbe0-a31575e92056` |
| S69 | 5.3.6.2 | Encrypting and Decrypting the I/O Data Stream — FIPS | `ms-rdpbcgr/e0d4b29b-3899-47af-bb5b-7eb49cec126f` |
| S70 | 4.1.12 | Annotated dump: Server Demand Active PDU | `ms-rdpbcgr/084026ea-8264-4315-ac66-c77dea02b0c1` |
| S71 | 4.1.13 | Annotated dump: Client Confirm Active PDU | `ms-rdpbcgr/54765b0a-39d4-4746-92c6-8914934023da` |
| S72 | 4.1.18 | Annotated dump: Client Font List PDU | `ms-rdpbcgr/c60386e7-bf10-42bd-a9b8-70854e497935` |
| S73 | 4.1.22 | Annotated dump: Server Font Map PDU | `ms-rdpbcgr/a75f7a91-ac1a-4012-b7f6-80de38c26c2f` |
| S74 | 4.7 | Annotated dump: Fast-Path Input Event PDU | `ms-rdpbcgr/d8f1be0e-ca81-4caf-a494-3c161d21a7f2` |
| S75 | 2.2.1.14 | Client Synchronize PDU | `ms-rdpbcgr/e0027486-f99a-4f0f-991c-eda3963521c2` |
| S76 | 2.2.1.15 | Client Control PDU - Cooperate | `ms-rdpbcgr/9d1e1e21-d8b4-4bfd-9caf-4b72ee91a713` |
| S77 | 2.2.1.16 | Client Control PDU - Request Control | `ms-rdpbcgr/4f94e123-970b-4242-8cf6-39820d8e3d35` |
| S78 | 2.2.1.17 | Client Persistent Key List PDU | `ms-rdpbcgr/2d122191-af10-4e36-a781-381e91c182b7` |
| S79 | 2.2.1.1 | Color Table Cache Capability Set（[MS-RDPEGDI]） | `ms-rdpegdi/2b7c6946-3612-4291-95a8-03b7b1387eaf` |
| S80 | 2.2.1.2 | DrawNineGrid Cache Capability Set（[MS-RDPEGDI]） | `ms-rdpegdi/c7fff288-63db-4521-bbe5-77e060fb0780` |
| S81 | 2.2.1.3 | Draw GDI+ Capability Set（[MS-RDPEGDI]） | `ms-rdpegdi/52635737-d144-4f47-9c88-b48ceaf3efb4` |
| S82 | 2.2.1.3.1 | GDI+ Cache Entries（[MS-RDPEGDI]） | `ms-rdpegdi/f7328112-a3a4-45ea-9022-a28033912273` |
| S83 | 2.2.1.3.2 | GDI+ Cache Chunk Size（[MS-RDPEGDI]） | `ms-rdpegdi/cfe60222-9185-4ab4-ab06-b0ec6e2d174e` |
| S84 | 2.2.1.3.3 | GDI+ Image Cache Properties（[MS-RDPEGDI]） | `ms-rdpegdi/73c1767c-f10e-4361-b980-f39e3c44f895` |
| S85 | 2.2.1.1.1 | Remote Programs Capability Set（[MS-RDPERP]） | `ms-rdperp/36a25e21-25e1-4954-aae8-09aaf6715c79` |
| S86 | 2.2.1.1.2 | Window List Capability Set（[MS-RDPERP]） | `ms-rdperp/82ec7a69-f7e3-4294-830d-666178b35d15` |
| S87 | 2.2.1.3 | TS_FRAME_ACKNOWLEDGE_CAPABILITYSET（[MS-RDPRFX]） | `ms-rdprfx/e4d498fd-822b-408d-b8b3-1c216f21265b` |
| S88 | — | [MS-RDPBCGR] 官方 DOCX v62.0（2026-03-09） | `winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RDPBCGR/%5bMS-RDPBCGR%5d-260309.docx` |
| S89 | — | [MS-RDPEGDI] 官方 DOCX（2024-04-23） | `winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RDPEGDI/%5bMS-RDPEGDI%5d-240423.docx` |
| S90 | 2.2.5.1 | Server Set Error Info PDU | `ms-rdpbcgr/ea16f3d6-f41a-4516-9aca-8550b4f742b6` |
| S91 | 2.2.12.1 | Monitor Layout PDU | `ms-rdpbcgr/88186da8-2a0a-488e-ba8d-97af6cd89a3c` |
| S92 | 3.2.6.1 | Client-Side Connection Sequence Timeout | `ms-rdpbcgr/f2252cce-c1af-4366-ac10-c8e656dd80c7` |
| S93 | 3.2.2.1 | Connection Sequence Timeout Timer | `ms-rdpbcgr/33323e8b-d160-4293-b46a-bf63d156307a` |
| S94 | 3.2.5.1 | Constructing a Client-to-Server Slow-Path PDU | `ms-rdpbcgr/b27f8935-ac1f-47f7-b87b-32b92875b869` |
| S95 | 3.2.5.3.17 | Sending Persistent Key List PDU(s) | `ms-rdpbcgr/94ecc579-7514-4325-a084-5e5d2efabac3` |
| S96 | 3.2.5.3.18 | Sending Font List PDU | `ms-rdpbcgr/e038dd4d-c0ea-44b3-9378-25e14938b954` |
| S97 | 3.2.5.3.22 | Processing Font Map PDU | `ms-rdpbcgr/d246ad43-d84e-4de8-a808-46e11035db56` |
| S98 | 3.3.5.3.18 | Processing Font List PDU | `ms-rdpbcgr/630f3d34-7086-4761-8c7d-cd4e1371347e` |
| S99 | 5.3.7.1 | Session Key Updates — Non-FIPS | `ms-rdpbcgr/a4551a30-db5c-437a-a170-a3934cf8770e` |

> 上述 §0.2 表共 **97 个 `learn.microsoft.com` 页面**（S01–S87、S90–S99；S88 / S89 是 DOCX 直链）。
> 可达性：`check_urls.ps1` 覆盖其中 **83 个（全部 HTTP 200）**；其余 **14 个**
> （S01 / S05 / S67 / S69 + 新登记的 S90–S99）已逐条单独 `HEAD` 验证，**14/14 = 200**。
> 合计 **97/97 返回 HTTP 200**（复现方式见 §14.3）。

### 0.3 来源等级

| 等级 | 含义 |
|---|---|
| **A** | 官方规范原文（DOCX / 网页正文），章节号可追溯 |
| **B** | 由 A 级原文的位域表 + 官方 dump 反推（本文件明确标注"推导"） |
| **C** | 无法验证，进入 §15「不确定项」，**不作实现依据** |

---

## 1. 通用约定

### 1.1 字节序

> "All multiple-byte fields within a message MUST be marshaled in **little-endian** byte order, unless otherwise specified."
> —— [MS-RDPBCGR] 2.2（S01）

**唯一例外**是 Fast-Path 的 `length1`/`length2` 组合（§3.4），以及 TPKT `length`（大端，[T123] §8）。

### 1.2 位域图的读法（关键，易错）

[MS-RDPBCGR] 的位域图首行为 `0 | 1 | 2 | 3 | ... | 31`，**列号就是位号，位 0 在最左**。
即：**图的左端是 LSB，图的右端是 MSB**。

这一点用官方 dump 4.7 可证（S74）：

```
c4 -> TS_FP_INPUT_PDU::fpInputHeader = 0xc4
Binary of 0xc4 = 11 0001 00
action = FASTPATH_INPUT_ACTION_FASTPATH (0)
numEvents = 1
flags = 0x3
```

`0xC4 = 0b1100_0100`。规范把 `0xC4` 打印为 `11 0001 00`——**从左到右依次是 bit7…bit0**，
即 `11` = bit7–6、`0001` = bit5–2、`00` = bit1–0：

| 位（编号） | 值 | 归属字段（2.2.8.1.2） | 计算 |
|---|---|---|---|
| bit0–bit1 | `00` | `action` | = 0 → FASTPATH_INPUT_ACTION_FASTPATH |
| bit2–bit5 | `0001` | `numEvents` | = 1 |
| bit6–bit7 | `11` | `flags` | = 3 = SECURE_CHECKSUM + ENCRYPTED |

**提取公式**（`h` = 头部字节）：

```
action    =  h        & 0x03
numEvents = (h >> 2)  & 0x0F
flags     = (h >> 6)  & 0x03
```

代入 `h = 0xC4`：`action = 0x00`、`numEvents = (0xC4 >> 2) & 0x0F = 0x31 & 0x0F = 1`、`flags = (0xC4 >> 6) & 0x03 = 3` ✔

若误按"图左端 = MSB"解读（即 `action` 取 bit7–6），会得到 `action = 0b11 = 3`（X.224 慢路径），
与 dump 矛盾。**本文件所有位域表均按"位 0 在左"给出**，并统一附提取公式。

### 1.3 长度字段的口径（五种，最易混淆）

| 字段 | 覆盖范围 | 来源 |
|---|---|---|
| TPKT `length` | 含 4 字节 TPKT 头在内的**总长** | [T123] §8 |
| `TS_SHARECONTROLHEADER.totalLength` | 含 6 字节 Share Control Header 在内的**总长**（不含 TPKT/X.224/MCS/securityHeader） | 2.2.8.1.1.1.1（S41） |
| `TS_SHAREDATAHEADER.uncompressedLength` | 压缩前长度（含 18 字节 Share Data Header） | 2.2.8.1.1.1.2（S42） |
| `TS_CAPS_SET.lengthCapability` | 含 `capabilitySetType` + `lengthCapability` 自身在内的长度 | 2.2.1.13.1.1.1（S08） |
| `TS_DEMAND_ACTIVE_PDU.lengthCombinedCapabilities` | `numberCapabilities` + `pad2Octets` + `capabilitySets` 之和 | 2.2.1.13.1.1（S07） |

### 1.4 任务提示中的章节号订正

任务提示给出的若干章节号与规范原文不符。**以下以规范原文为准**（这一节同时是给审阅者的对照表）：

| 任务提示 | 规范原文事实 | 依据 |
|---|---|---|
| TS_SHARECONTROLHEADER「2.2.8.1」 | **2.2.8.1.1.1.1** | S41 |
| TS_SHAREDATAHEADER「2.2.8.1.1.1」 | **2.2.8.1.1.1.2** | S42 |
| TS_SECURITY_HEADER「2.2.8.1.1.2」 | **2.2.8.1.1.2.1**（2.2.8.1.1.2 是"Security Headers"小节本身） | S43 |
| TS_SECURITY_HEADER1「2.2.8.1.1.2.1」 | **2.2.8.1.1.2.2** | S44 |
| TS_FP_UPDATE_PDU「2.2.9.1.2.1」 | **2.2.9.1.2**（2.2.9.1.2.1 是 TS_FP_UPDATE，即 subtype 容器） | S50 / S51 |
| Bitmap 编号「3」 | **`CAPSTYPE_BITMAP = 0x0002`** | S08 |
| Order 编号「5」 | **`CAPSTYPE_ORDER = 0x0003`** | S08 |
| BitmapCache 编号「4」 | 正确，但 0x0004 只是 **Revision 1**；Rev2 是 **0x0013** | S08 |
| VirtualChannel 编号「14」 | **`CAPSTYPE_VIRTUALCHANNEL = 0x0014`（十进制 20）**；0x000E 是 **Font** | S08 |
| 「ShareControl」capability | **不存在**。Share Capability Set 的类型号是 `CAPSTYPE_SHARE = 0x0009` | S08 |
| Deactivate All「2.2.1.13.3」 | **2.2.3.1 / 2.2.3.1.1** | S52 / S53 |
| Font Map「2.2.1.19」 | **2.2.1.22 / 2.2.1.22.1**；2.2.1.19 是 **Server Synchronize PDU** | S56 / S57 / S58 |

---

## 2. 共享 PDU 头

### 2.1 TS_SHARECONTROLHEADER（2.2.8.1.1.1.1）

MUST 出现在以下 PDU 中（S41 原文列举）：

- Demand Active PDU（2.2.1.13.1）
- Confirm Active PDU（2.2.1.13.2）
- Deactivate All PDU（2.2.3.1）
- Enhanced Security Server Redirection PDU（2.2.13.3.1）
- 所有 Data PDU（2.2.8.1.1.1.2）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `totalLength` | LE16，**含本 6 字节头**在内的包总长 |
| 2 | 2 | `pduType` | LE16，位域见下 |
| 4 | 2 | `pduSource` | LE16，发送该 PDU 的 MCS 通道 ID |

`totalLength` 特殊值：**等于 `0x8000` 时**，整个 Share Control Header 及其后数据 MAY 被解释为
T.128 FlowPDU（[T128] §8.5），并且 **MUST 被忽略**（S41）。

`pduType` 位域（S41，位 0 在左）：

| 位 | 长度 | 字段 | 取值 |
|---|---|---|---|
| 0–3 | 4 | `type` | 见下表 |
| 4–15 | 12 | `PDUVersion` | `TS_PROTOCOL_VERSION = 0x1` |

| `type` | 名称 | 含义 |
|---:|---|---|
| 0x1 | `PDUTYPE_DEMANDACTIVEPDU` | Demand Active PDU（2.2.1.13.1） |
| 0x3 | `PDUTYPE_CONFIRMACTIVEPDU` | Confirm Active PDU（2.2.1.13.2） |
| 0x6 | `PDUTYPE_DEACTIVATEALLPDU` | Deactivate All PDU（2.2.3.1） |
| 0x7 | `PDUTYPE_DATAPDU` | Data PDU，实际类型由 `pduType2` 决定 |
| 0xA | `PDUTYPE_SERVER_REDIR_PKT` | Enhanced Security Server Redirection PDU（2.2.13.3.1） |

**编码等价式**（官方 dump 4.1.12 注解，S70）：

```
pduType = 0x0011 = 0x0010 | 0x0001 = TS_PROTOCOL_VERSION | PDUTYPE_DEMANDACTIVEPDU
pduType = 0x0013 = 0x0010 | 0x0003 = TS_PROTOCOL_VERSION | PDUTYPE_CONFIRMACTIVEPDU
pduType = 0x0017 = 0x0010 | 0x0007 = TS_PROTOCOL_VERSION | PDUTYPE_DATAPDU
```

即 `pduType = (PDUVersion << 4) | type`，`PDUVersion = 0x1` ⇒ 高 12 位 = 0x001。

> **实现要点**：读 `pduType` 时 `type = pduType & 0x000F`，`PDUVersion = pduType >> 4`。
> Confirm Active 的 `pduSource` 在官方 dump 中是 `0x03EF = 1007`（**User Channel ID**，不是 I/O channel 1003）；
> 这符合 3.2.5.1 "`pduSource` MUST be set to the User Channel ID"（S94；S61 = 3.2.5.3.13.2 段内无此句）。

### 2.2 TS_SHAREDATAHEADER（2.2.8.1.1.1.2）

MUST 出现在**所有** Data PDU 中（S42）。固定 **18 字节**。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 6 | `shareControlHeader` | §2.1，其 `PDUVersion` MUST = `TS_PROTOCOL_VERSION (0x1)` |
| 6 | 4 | `shareID` | LE32，Share 标识符（[T128] §8.4.2） |
| 10 | 1 | `pad1` | 填充，MUST 忽略 |
| 11 | 1 | `streamID` | 流优先级，见下表 |
| 12 | 2 | `uncompressedLength` | LE16，压缩前包长（含本 18 字节头） |
| 14 | 1 | `pduType2` | Data PDU 类型，见下表 |
| 15 | 1 | `compressedType` | 压缩类型 + 标志，见下 |
| 16 | 2 | `compressedLength` | LE16，压缩后包长 |

`streamID`（S42）：

| 值 | 名称 | 含义 |
|---:|---|---|
| 0x00 | `STREAM_UNDEFINED` | 未定义优先级；**仅** Server Synchronize PDU 可因服务端 bug 使用，其它 PDU MUST NOT 使用 |
| 0x01 | `STREAM_LOW` | 低优先级 |
| 0x02 | `STREAM_MED` | 中优先级 |
| 0x04 | `STREAM_HI` | 高优先级 |

`pduType2` 中与本阶段相关的取值（S42 全表节选；完整表见 S42）：

| 值 | 名称 | 对应 PDU |
|---:|---|---|
| 0x02 | `PDUTYPE2_UPDATE` | Graphics Update PDU（2.2.9.1.1.3） |
| 0x14 | `PDUTYPE2_CONTROL` | Control PDU（2.2.1.15.1） |
| 0x1B | `PDUTYPE2_POINTER` | Pointer Update PDU（2.2.9.1.1.4） |
| 0x1C | `PDUTYPE2_INPUT` | Input Event PDU（2.2.8.1.1.3） |
| 0x1F | `PDUTYPE2_SYNCHRONIZE` | Synchronize PDU（2.2.1.14.1） |
| 0x27 | `PDUTYPE2_FONTLIST` | Font List PDU（2.2.1.18.1） |
| 0x28 | `PDUTYPE2_FONTMAP` | Font Map PDU（2.2.1.22.1） |
| 0x2B | `PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST` | Persistent Key List PDU（2.2.1.17.1） |
| 0x37 | `PDUTYPE2_MONITOR_LAYOUT_PDU` | Monitor Layout PDU（2.2.12.1，S91） |

`compressedType`（S42）：

| 位 / 值 | 名称 | 含义 |
|---|---|---|
| 0x0F | `CompressionTypeMask` | 压缩包类型掩码 |
| 0x20 | `PACKET_COMPRESSED` | 载荷已压缩（等价 MPPC bit C） |
| 0x40 | `PACKET_AT_FRONT` | 解压后放历史缓冲**开头**（MPPC bit B） |
| 0x80 | `PACKET_FLUSHED` | 解压器 MUST 以 0 重填历史缓冲并复位 HistoryOffset（MPPC bit A）；若同时置 `PACKET_COMPRESSED`，**先**处理 `PACKET_FLUSHED` |

压缩包类型（低 4 位）：

| 值 | 名称 | 含义 |
|---:|---|---|
| 0x0 | `PACKET_COMPR_TYPE_8K` | RDP 4.0 bulk（3.1.8.4.1） |
| 0x1 | `PACKET_COMPR_TYPE_64K` | RDP 5.0 bulk（3.1.8.4.2） |
| 0x2 | `PACKET_COMPR_TYPE_RDP6` | RDP 6.0 bulk（[MS-RDPEGDI] 3.1.8.1） |
| 0x3 | `PACKET_COMPR_TYPE_RDP61` | RDP 6.1 bulk（[MS-RDPEGDI] 3.1.8.2） |

### 2.3 TS_SECURITY_HEADER（2.2.8.1.1.2.1）

"Basic" 安全头，**4 字节**。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `flags` | LE16，安全标志，见下表 |
| 2 | 2 | `flagsHi` | LE16，保留；**仅当 `SEC_FLAGSHI_VALID (0x8000)` 置位时有效**，否则未初始化、MAY 含随机数据 |

`flags`（S43 全表）：

| 值 | 名称 | 含义 |
|---:|---|---|
| 0x0001 | `SEC_EXCHANGE_PKT` | Security Exchange PDU（2.2.1.10）；仅 client→server |
| 0x0002 | `SEC_TRANSPORT_REQ` | Initiate Multitransport Request PDU（2.2.15.1）；MUST NOT 出现在 client→server，且 MUST 走 MCS message channel |
| 0x0004 | `SEC_TRANSPORT_RSP` | Initiate Multitransport Response PDU（2.2.15.2）；MUST NOT 出现在 server→client，且 MUST 走 MCS message channel |
| 0x0008 | `SEC_ENCRYPT` | 包体已加密 |
| 0x0010 | `SEC_RESET_SEQNO` | 任何 RDP 端都不处理，MUST 忽略 |
| 0x0020 | `SEC_IGNORE_SEQNO` | 任何 RDP 端都不处理，MUST 忽略 |
| 0x0040 | `SEC_INFO_PKT` | Client Info PDU（2.2.1.11）；仅 client→server；Standard RDP Security 下 MUST 同时加密 |
| 0x0080 | `SEC_LICENSE_PKT` | Licensing PDU（2.2.1.12） |
| 0x0200 | `SEC_LICENSE_ENCRYPT_CS` | 服务端能处理加密 licensing 包（server→client） |
| 0x0200 | `SEC_LICENSE_ENCRYPT_SC` | 客户端能处理加密 licensing 包（client→server，随 `SEC_EXCHANGE_PKT` 一起发） |
| 0x0400 | `SEC_REDIRECTION_PKT` | Standard Security Server Redirection PDU（2.2.13.2.1）且已加密 |
| 0x0800 | `SEC_SECURE_CHECKSUM` | MAC 用 **salted** 生成（5.3.6.1.1）；未置位则用标准方法 |
| 0x1000 | `SEC_AUTODETECT_REQ` | Auto-Detect Request PDU（2.2.14.3）；仅 server→client，且走 message channel |
| 0x2000 | `SEC_AUTODETECT_RSP` | Auto-Detect Response PDU（2.2.14.4）；仅 client→server，且走 message channel |
| 0x4000 | `SEC_HEARTBEAT` | Heartbeat PDU（2.2.16.1）；走 message channel |
| 0x8000 | `SEC_FLAGSHI_VALID` | `flagsHi` 含有效数据 |

> 注意 `SEC_LICENSE_ENCRYPT_CS` 与 `SEC_LICENSE_ENCRYPT_SC` **数值相同（0x0200）**，区别只在方向。
> 这是规范原文的写法（S43），实现时不要试图区分位值。

**securityHeader 是否存在**（2.2.1.13.1 / 2.2.1.13.2 原文，S06 / S09）：

- 若服务端选的 `Encryption Level > ENCRYPTION_LEVEL_NONE (0)` **且** `Encryption Method > ENCRYPTION_METHOD_NONE (0)`：
  - `Encryption Level == ENCRYPTION_LEVEL_LOW (1)` → `TS_SECURITY_HEADER`（Basic）
  - `Encryption Method ∈ {40BIT(0x01), 56BIT(0x08), 128BIT(0x02)}` → `TS_SECURITY_HEADER1`（Non-FIPS）
  - `Encryption Method == FIPS(0x10)` → `TS_SECURITY_HEADER2`（FIPS）
- 若两者均为 0 → **MUST NOT** 包含 securityHeader。

> **Enhanced RDP Security（TLS/CredSSP）场景**：3.2.5.3.13.1/2 明示
> "in this scenario the `securityHeader` field **MUST NOT** be present"（S60 / S61）。
> 即 NLA 连接上 Demand Active / Confirm Active 都是**明文**（由 TLS 保护），不带 securityHeader。

### 2.4 TS_SECURITY_HEADER1（2.2.8.1.1.2.2，Non-FIPS，含 MAC）

扩展 Basic 头，**12 字节**。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `flags` | 同 §2.3 |
| 2 | 2 | `flagsHi` | 同 §2.3 |
| 4 | 8 | `dataSignature` | **64-bit MAC**，按 5.3.6.1 生成 |

MAC 生成（5.3.6.1 Non-FIPS，S67）：

```
Pad1 = 0x36 repeated 40 times to give 320 bits
Pad2 = 0x5C repeated 48 times to give 384 bits
SHAComponent = SHA(MACKeyN + Pad1 + DataLength + Data)
MACSignature = First64Bits(MD5(MACKeyN + Pad2 + SHAComponent))
```

- `DataLength`：待加密数据的字节数，**LE32**
- `Data`：待加密信息
- `MACKeyN`：`MACKey40` / `MACKey56` / `MACKey128`，取决于协商密钥强度
- 取 MD5 结果的**前 8 字节**作为线上 8 字节 MAC

Salted 变体（5.3.6.1.1，S68）：

```
SHAComponent = SHA(MACKeyN + Pad1 + DataLength + Data + EncryptionCount)
MACSignature = First64Bits(MD5(MACKeyN + Pad2 + SHAComponent))
```

`EncryptionCount` 为累计加密次数，LE32。是否用 salted 由 General Capability Set 的
`ENC_SALTED_CHECKSUM (0x0010)` 协商，并由 `SEC_SECURE_CHECKSUM (0x0800)` 逐包指示。

FIPS 变体（5.3.6.2，S69）：

```
MACSignature = First64Bits(HMAC(HMACKey, Data + EncryptionCount))
```

**校验语义**：接收方先解密，再对明文重算 16 字节 MAC，取前 8 字节与线上 8 字节比较；
不匹配则丢弃连接（S67）。

**处理次序（3.2.5.1，S94）**：发送侧 **明文 → 压缩 → 算 MAC → 加密**；接收侧严格反向
（解密 → 校验 MAC → 解压）。原文（`bcgr.txt:7243`）："If the contents of the PDU are to be compressed
(**this MUST be done before any MAC signature is constructed and encryption methods applied**)"。
次序颠倒会让接收方对压缩后的字节算 MAC，MAC 必然失配。

**会话密钥更新（5.3.7.1 Non-FIPS，S99）**：Standard RDP Security 下每**发送或接收 4,096 个包**
重新派生会话密钥（`bcgr.txt:12580`："The encryption and the decryption keys are updated after 4,096
packets have been sent or received."）。该句原文为陈述句、未写 MUST 关键词，但属该模式的固定行为，
实现必须照做，否则第 4,097 个包起双方密钥不同步。FIPS 下（5.3.7.2）连接期间**不做**密钥更新。

### 2.5 TS_SECURITY_HEADER2（2.2.8.1.1.2.3，FIPS）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `flags` | 同 §2.3 |
| 2 | 2 | `flagsHi` | 同 §2.3 |
| 4 | 2 | `length` | MUST = `0x0010`（16 字节） |
| 6 | 1 | `version` | SHOULD = `TSFIPS_VERSION1 (0x01)` |
| 7 | 1 | `padlen` | 为对齐 3DES 块（8 字节）而追加的填充字节数 |
| 8 | 8 | `dataSignature` | 64-bit MAC（5.3.6.2） |

固定 16 字节。`padlen` 解密后必须剔除对应尾部字节。

### 2.6 各 PDU 的头部组合（实测对照）

以官方 dump 4.1.12（S70）为例，Demand Active 的完整分层：

| 层 | 长度 | 内容 |
|---|---:|---|
| TPKT Header | 4 | `03 00 01 82`（length = 0x0182 = 386） |
| X.224 Data TPDU | 3 | `02 F0 80` |
| MCS SendDataIndication | 8 | `68 00 01 03 eb 70 81 73`（userData 371 字节） |
| TS_SECURITY_HEADER | 4 | `08 00 02 03`（flags = 0x0008 = SEC_ENCRYPT） |
| TS_SECURITY_HEADER1.dataSignature | 8 | `56 02 e1 47 ac 5c 50 d9` |
| 加密的 TS_DEMAND_ACTIVE_PDU | 359 | `72 f9 c3 32 ... 81 48` |

校验：`4 + 3 + 8 + 371 = 386` = TPKT length ✔；`4 + 8 + 359 = 371` = MCS userData length ✔。

> 注意：**securityHeader 本身是 4 字节 Basic 头，`dataSignature` 是 `TS_SECURITY_HEADER1` 的扩展部分**。
> 规范把 `TS_SECURITY_HEADER1` 定义为 12 字节整体（4 + 8），dump 注解把它拆成两行标注，
> 二者一致。**实现时应按 12 字节整体读取**，否则会把 MAC 当密文。

---

## 3. Fast-Path

### 3.1 Fast-Path 的定位

> "Fast-path revises client input packets **from the first byte** with the goal of improving bandwidth.
> The TPKT Header, X.224 Class 0 Data TPDU, and MCS Send Data Request are **replaced**;
> the Security Header is **collapsed into** the fast-path input header, and the Share Data Header is
> **replaced by** a new fast-path format."
> —— 2.2.8.1.2（S46）；服务端方向同理见 2.2.9.1.2（S50）

即 Fast-Path PDU **没有** TPKT/X.224/MCS/securityHeader/shareDataHeader 任何一层。
`fpInputHeader` / `fpOutputHeader` **占据 TPKT 首字节的位置**（S46 / S50 明示）。

### 3.2 TS_FP_INPUT_PDU（2.2.8.1.2，client→server）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 1 | `fpInputHeader` | 位域，见下 |
| 1 | 1 | `length1` | PDU 总长（见 §3.4） |
| 2 | 0/1 | `length2` | 可选，条件见 §3.4 |
| 2/3 | 0/4 | `fipsInformation` | 可选，`TS_FP_FIPS_INFO`，仅 FIPS 加密时存在 |
| — | 0/8 | `dataSignature` | 可选 MAC，`FASTPATH_INPUT_ENCRYPTED` 置位时 MUST 存在 |
| — | 0/1 | `numEvents` | 可选，仅当头部 `numEvents` 位域为 0 时存在 |
| — | var | `fpInputEvents` | `TS_FP_INPUT_EVENT` 数组 |

`fpInputHeader` 位域（S46，位 0 在左）：

| 位 | 长度 | 字段 | 取值 |
|---|---|---|---|
| 0–1 | 2 | `action` | 0x0 = `FASTPATH_INPUT_ACTION_FASTPATH`；0x3 = `FASTPATH_INPUT_ACTION_X224`（此时首字节完整值 MUST 为 `0x03`，表示这是慢路径） |
| 2–5 | 4 | `numEvents` | 1..15 时直接编码事件数；**> 15 时此位域 MUST 置 0**，并在 `dataSignature` 之后插入 1 字节 `numEvents` 字段（上限 255） |
| 6–7 | 2 | `flags` | 0x1 = `FASTPATH_INPUT_SECURE_CHECKSUM`；0x2 = `FASTPATH_INPUT_ENCRYPTED` |

> **action 的判别意义**：首字节 bit0–1 是 `0x3` 时整字节为 `0x03`，正是 TPKT version 字段。
> 因此"看首字节低 2 位"就能在同一 TCP 流上区分快/慢路径（S46 明示
> "This byte coincides with the first byte of the TPKT Header"）。

### 3.3 TS_FP_UPDATE_PDU（2.2.9.1.2，server→client）与 `fpOutputHeader`

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 1 | `fpOutputHeader` | 位域，见下 |
| 1 | 1 | `length1` | PDU 总长（见 §3.4） |
| 2 | 0/1 | `length2` | 可选 |
| — | 0/4 | `fipsInformation` | 可选（FIPS） |
| — | 0/8 | `dataSignature` | 可选 MAC |
| — | var | `fpOutputUpdates` | `TS_FP_UPDATE` 数组 |

`fpOutputHeader` 位域（S50，位 0 在左）：

| 位 | 长度 | 字段 | 取值 |
|---|---|---|---|
| 0–1 | 2 | `action` | 0x0 = `FASTPATH_OUTPUT_ACTION_FASTPATH`；0x3 = `FASTPATH_OUTPUT_ACTION_X224`（整字节 MUST 为 `0x03`，慢路径） |
| 2–5 | 4 | `reserved` | **MUST 置 0** |
| 6–7 | 2 | `flags` | 0x1 = `FASTPATH_OUTPUT_SECURE_CHECKSUM`；0x2 = `FASTPATH_OUTPUT_ENCRYPTED` |

**与输入头的差异**（这是实现中最容易混淆的一点）：

| 项 | `fpInputHeader`（2.2.8.1.2） | `fpOutputHeader`（2.2.9.1.2） |
|---|---|---|
| bit0–1 | `action` | `action` |
| bit2–5 | **`numEvents`** | **`reserved`（MUST 0）** |
| bit6–7 | `flags` | `flags` |
| 事件数编码 | 头部 4 bit 或外挂 1 字节 | **头部不含事件数**，由 `TS_FP_UPDATE.size` 逐条界定 |

> 因此：未加密的单条 fast-path 输出 PDU，首字节为 **`0x00`**；
> 加密时首字节为 `0x80`（ENCRYPTED）或 `0xC0`（ENCRYPTED + SECURE_CHECKSUM）。
> 输入方向的 `0xC4` 表示"加密 + salted + 1 个事件"，输出方向 `0xC0` 表示"加密 + salted"，
> 两者**低 6 位含义不同**，不能互推。

### 3.4 长度编码规则（1 字节 vs 2 字节）

S46 / S50 原文（两处措辞完全相同）：

> "If the most significant bit of the `length1` field is **not** set, then the size of the PDU is in the
> range **1 to 127 bytes** and the `length1` field contains the overall PDU length (the `length2` field is
> **not** present in this case). However, if the most significant bit of the `length1` field **is** set,
> then the overall PDU length is given by the **low 7 bits of `length1` concatenated with the 8 bits of
> `length2`, in big-endian order** (the `length2` field contains the low-order bits).
> The overall PDU length **SHOULD be ≤ 16,383 bytes**."

判定与解码：

```
if (length1 & 0x80) == 0:
    totalLength = length1                  # 1..127，无 length2
else:
    totalLength = ((length1 & 0x7F) << 8) | length2   # 大端拼接，length2 为低 8 位
```

**总长的口径**：含 `fpInputHeader`/`fpOutputHeader` 与 `length1`/`length2` 自身在内的整包长度。
用官方 dump 4.7 验证（S74）：

```
c4          fpInputHeader = 0xc4  (action=0, numEvents=1, flags=3)
11          length1 = 0x11 = 17
30 35 6b 5b b5 34 c8 47   dataSignature (8 B)
26 18 5e 76 0e de 28      encrypted fpInputEvents (7 B)
```

`1 + 1 + 8 + 7 = 17 = 0x11` ✔（`length1` 的 MSB 为 0，故无 `length2`）。

`0x80` 形式的实例（规范未给出 fast-path 的 2 字节示例，但 MCS 层同构可佐证）：
dump 4.1.12 的 MCS 长度 `81 73` = `(0x01 << 8) | 0x73` = 371，与 `userData length = 0x173` 一致。

> **实现要点**：`length1 & 0x7F` 最大 0x7F ⇒ 理论上限 0x7FFF = 32,767，但规范 SHOULD ≤ 16,383。
> 超过 16,383 应视为异常（规范未规定 MUST 拒绝，见 §15 不确定项 U-07）。

### 3.5 TS_FP_UPDATE（2.2.9.1.2.1）与各 subtype

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 1 | `updateHeader` | 位域，见下 |
| 1 | 0/1 | `compressionFlags` | 可选；仅当 `updateHeader.compression == 0x2` 时存在 |
| 1/2 | 2 | `size` | LE16，`updateData` 的字节数 |
| 3/4 | var | `updateData` | subtype 特定 |

`updateHeader` 位域（S51，位 0 在左）：

| 位 | 长度 | 字段 | 取值 |
|---|---|---|---|
| 0–3 | 4 | `updateCode` | 见下表 |
| 4–5 | 2 | `fragmentation` | 0x0 `FASTPATH_FRAGMENT_SINGLE`；0x1 `FASTPATH_FRAGMENT_LAST`；0x2 `FASTPATH_FRAGMENT_FIRST`；0x3 `FASTPATH_FRAGMENT_NEXT` |
| 6–7 | 2 | `compression` | 0x2 = `FASTPATH_OUTPUT_COMPRESSION_USED`（表示 `compressionFlags` 存在） |

`updateCode` 全表（S51）：

| 值 | 名称 | 对应结构（章节） | `updateData` 格式 |
|---:|---|---|---|
| 0x0 | `FASTPATH_UPDATETYPE_ORDERS` | [MS-RDPEGDI] 2.2.2.2 | Drawing Orders |
| 0x1 | `FASTPATH_UPDATETYPE_BITMAP` | 2.2.9.1.2.1.2 | `TS_UPDATE_BITMAP_DATA`（2.2.9.1.1.3.1.2.1） |
| 0x2 | `FASTPATH_UPDATETYPE_PALETTE` | 2.2.9.1.2.1.1 | `TS_UPDATE_PALETTE_DATA`（2.2.9.1.1.3.1.1.1） |
| 0x3 | `FASTPATH_UPDATETYPE_SYNCHRONIZE` | 2.2.9.1.2.1.3 | 无（`size` MUST = 0） |
| 0x4 | `FASTPATH_UPDATETYPE_SURFCMDS` | 2.2.9.1.2.1.10 | `TS_SURFCMD` 数组 |
| 0x5 | `FASTPATH_UPDATETYPE_PTR_NULL` | 2.2.9.1.2.1.5 | 无（系统指针隐藏） |
| 0x6 | `FASTPATH_UPDATETYPE_PTR_DEFAULT` | 2.2.9.1.2.1.6 | 无（系统指针默认） |
| 0x8 | `FASTPATH_UPDATETYPE_PTR_POSITION` | 2.2.9.1.2.1.4 | `TS_POINTERPOSATTRIBUTE`（4 字节） |
| 0x9 | `FASTPATH_UPDATETYPE_COLOR` | 2.2.9.1.2.1.7 | `TS_COLORPOINTERATTRIBUTE`（2.2.9.1.1.4.4） |
| 0xA | `FASTPATH_UPDATETYPE_CACHED` | 2.2.9.1.2.1.9 | `TS_CACHEDPOINTERATTRIBUTE`（2 字节） |
| 0xB | `FASTPATH_UPDATETYPE_POINTER` | 2.2.9.1.2.1.8 | `TS_POINTERATTRIBUTE`（2.2.9.1.1.4.5） |
| 0xC | `FASTPATH_UPDATETYPE_LARGE_POINTER` | 2.2.9.1.2.1.11 | `TS_FP_LARGEPOINTERATTRIBUTE` 自有头 + 掩码 |

> **注意 0x7 与 0xD–0xF 未分配**。收到未分配的 `updateCode` 时，规范未给出明确处置
> （见 §15 不确定项 U-08）。实现建议：按 `size` 跳过该 update，继续处理后续 update（不致命），
> 但需记录告警。

`fragmentation` 语义（S51）：分片重组能力由 `TS_MULTIFRAGMENTUPDATE_CAPABILITYSET`
（2.2.7.2.6）的 `MaxRequestSize` 界定；缓冲区必须足以容纳一个完整 update 的全部片段。

`compression` 与 `compressionFlags`（S51）：`compressionFlags` 的位定义与
`TS_SHAREDATAHEADER.compressedType` **完全相同**（复用 §2.2 的表）。

**逐 subtype 的 `updateData` 前导结构**（均为 S51 各子节）：

| subtype | 结构名 | 附加字段（在 `updateData` 内） |
|---|---|---|
| 0x2 Palette | `TS_FP_UPDATE_PALETTE` | `paletteUpdateData`（variable） |
| 0x1 Bitmap | `TS_FP_UPDATE_BITMAP` | `bitmapUpdateData`（variable） |
| 0x3 Synchronize | `TS_FP_UPDATE_SYNCHRONIZE` | 无；`size` MUST = 0 |
| 0x8 PtrPosition | `TS_FP_POINTERPOSATTRIBUTE` | `pointerPositionUpdateData`（4 字节） |
| 0x5 PtrHidden | `TS_FP_SYSTEMPOINTERHIDDENATTRIBUTE` | 无 |
| 0x6 PtrDefault | `TS_FP_SYSTEMPOINTERDEFAULTATTRIBUTE` | 无 |
| 0x9 Color | `TS_FP_COLORPOINTERATTRIBUTE` | `colorPointerUpdateData`（variable） |
| 0xB NewPtr | `TS_FP_POINTERATTRIBUTE` | `newPointerUpdateData`（variable） |
| 0xA Cached | `TS_FP_CACHEDPOINTERATTRIBUTE` | `cachedPointerUpdateData`（2 字节） |
| 0x4 SurfCmds | `TS_FP_SURFCMDS` | `surfaceCommands`（`TS_SURFCMD` 数组） |
| 0xC LargePtr | `TS_FP_LARGEPOINTERATTRIBUTE` | `xorBpp(2) cacheIndex(2) hotSpot(4) width(2) height(2) lengthAndMask(4) lengthXorMask(4) xorMaskData andMaskData pad(1,opt)` |

`TS_FP_LARGEPOINTERATTRIBUTE` 的 `xorMaskData` 是 24-bpp **自底向上**扫描行，每行按 **2 字节**边界补齐；
`andMaskData` 是 1-bpp 自底向上，同样按 2 字节边界补齐（S51）。

### 3.6 TS_FP_FIPS_INFO（2.2.8.1.2.1）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `length` | MUST = `0x0010` |
| 2 | 1 | `version` | SHOULD = `TSFIPS_VERSION1 (0x01)` |
| 3 | 1 | `padlen` | 3DES 块对齐填充字节数 |

固定 4 字节，仅 `ENCRYPTION_METHOD_FIPS` 时出现。

### 3.7 TS_FP_INPUT_EVENT（2.2.8.1.2.2）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 1 | `eventHeader` | 位域：**bit0–4 `eventFlags`**，**bit5–7 `eventCode`** |
| 1 | var | `eventData` | subtype 特定 |

`eventHeader` 位域（2.2.8.1.2.2，S48）。规范位域图的行顺序是 `eventFlags | eventCode`，
按 §1.2 的"位 0 在左"，即：

```
eventCode = (h >> 5) & 0x07
eventFlags =  h       & 0x1F
```

> **这是本节最容易写反的地方**。规范图的字段顺序是 `eventFlags` 在前、`eventCode` 在后，
> 与 §3.2 的 `fpInputHeader`（`action` 在前、`numEvents` 在中、`flags` 在后）方向相反。
> 用 dump 4.7 验证：`h = 0x20 = 0b0010_0000` ⇒ `eventFlags = 0x00`、`eventCode = (0x20>>5) = 1`（MOUSE）✔

`eventCode`（S48）：

| 值 | 名称 | 结构 |
|---:|---|---|
| 0x0 | `FASTPATH_INPUT_EVENT_SCANCODE` | `TS_FP_KEYBOARD_EVENT`（1 字节 `keyCode`） |
| 0x1 | `FASTPATH_INPUT_EVENT_MOUSE` | `TS_FP_POINTER_EVENT`（`pointerFlags(2) xPos(2) yPos(2)`） |
| 0x2 | `FASTPATH_INPUT_EVENT_MOUSEX` | `TS_FP_POINTERX_EVENT`（同上布局） |
| 0x3 | `FASTPATH_INPUT_EVENT_SYNC` | `TS_FP_SYNC_EVENT`（仅 eventHeader） |
| 0x4 | `FASTPATH_INPUT_EVENT_UNICODE` | `TS_FP_UNICODE_KEYBOARD_EVENT`（`unicodeCode(2)`） |
| 0x5 | `FASTPATH_INPUT_EVENT_MOUSEREL` | `TS_FP_RELPOINTER_EVENT`（`pointerFlags(2) xDelta(2) yDelta(2)`） |
| 0x6 | `FASTPATH_INPUT_EVENT_QOE_TIMESTAMP` | `TS_FP_QOETIMESTAMP_EVENT`（`timestamp(4)`） |
| 0x7 | — | **未分配** |

`eventFlags` 5 bit（S48 / 2.2.8.1.2.2.1 / 2.2.8.1.2.2.5）：

| 值 | 名称 | 适用 eventCode |
|---:|---|---|
| 0x01 | `FASTPATH_INPUT_KBDFLAGS_RELEASE` | 0x0 / 0x4 |
| 0x02 | `FASTPATH_INPUT_KBDFLAGS_EXTENDED` | 0x0 |
| 0x04 | `FASTPATH_INPUT_KBDFLAGS_EXTENDED1` | 0x0（PAUSE 键序列） |
| 0x01 | `FASTPATH_INPUT_SYNC_SCROLL_LOCK` | 0x3 |
| 0x02 | `FASTPATH_INPUT_SYNC_NUM_LOCK` | 0x3 |
| 0x04 | `FASTPATH_INPUT_SYNC_CAPS_LOCK` | 0x3 |
| 0x08 | `FASTPATH_INPUT_SYNC_KANA_LOCK` | 0x3 |

> 鼠标类事件（0x1/0x2/0x5）的 `eventFlags` MUST 为 0（S48 各子节原文）。
> 键盘/同步事件复用同一位位置表示不同语义——这是规范原文，不是笔误。

---

## 4. Demand Active PDU（2.2.1.13.1）

### 4.1 定位与时序

> "The Demand Active PDU is an RDP Connection Sequence PDU sent from server to client during the
> **Capabilities Exchange** phase of the RDP Connection Sequence. It is sent upon successful completion
> of the **Licensing** phase."
> —— 2.2.1.13.1（S06）

服务端发送侧规则（3.3.5.3.13.1，S63）：

- `mcsSDin.initiator` MUST = Server Channel ID（`0x03EA`）
- `mcsSDin.channelId` MUST = I/O Channel ID store 中的值（本 dump 为 `0x03EB` = 1003；由 Server Network Data 分配，不可硬编码）
- Enhanced RDP Security 下：整包由外部安全协议加密+摘要，**securityHeader MUST NOT 存在**
- Standard RDP Security 下：可选 securityHeader；加密时 `flags` MUST 含 `SEC_ENCRYPT (0x0008)`

### 4.2 分层封装

| 层 | 长度 | 字段 | 说明 |
|---|---:|---|---|
| 1 | 4 | `tpktHeader` | TPKT（[T123] §8） |
| 2 | 3 | `x224Data` | X.224 Class 0 Data TPDU（[X224] §13.7） |
| 3 | var | `mcsSDin` | MCS Send Data Indication（[T125] §11.33，DomainMCSPDU choice 26） |
| 4 | var | `securityHeader` | 可选，见 §2.3/§2.4/§2.5 |
| 5 | var | `demandActivePduData` | `TS_DEMAND_ACTIVE_PDU`（本节） |

### 4.3 TS_DEMAND_ACTIVE_PDU 完整字段（2.2.1.13.1.1）

规范称其为 "a standard T.128 Demand Active PDU（[T128] §8.4.1）"。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `shareControlHeader.totalLength` | LE16，含本头在内的包总长 |
| 2 | 2 | `shareControlHeader.pduType` | LE16，`type` MUST = `PDUTYPE_DEMANDACTIVEPDU (1)`，`PDUVersion` MUST = `TS_PROTOCOL_VERSION (0x1)` ⇒ 线上 `0x0011` |
| 4 | 2 | `shareControlHeader.pduSource` | LE16，MCS server channel ID（`0x03EA`） |
| 6 | 4 | `shareID` | LE32，Share 标识符 |
| 10 | 2 | `lengthSourceDescriptor` | LE16，`sourceDescriptor` 的字节数 |
| 12 | 2 | `lengthCombinedCapabilities` | LE16，`numberCapabilities` + `pad2Octets` + `capabilitySets` 的**合计字节数** |
| 14 | var | `sourceDescriptor` | 变长字节数组（dump 实测内容为 `52 44 50 00` = `"RDP"` + NUL，长度 4；语义见 [T128] §8.4.1，**未取证**） |
| 14+L1 | 2 | `numberCapabilities` | LE16，`capabilitySets` 中 capability set 的个数 |
| 16+L1 | 2 | `pad2Octets` | LE16，填充，MUST 忽略 |
| 18+L1 | var | `capabilitySets` | `TS_CAPS_SET` 数组，元素数 = `numberCapabilities` |
| 18+L1+C | 4 | `sessionId` | LE32，会话标识；**被客户端忽略** |

其中 `L1 = lengthSourceDescriptor`，`C = lengthCombinedCapabilities - 4`（减去 numberCapabilities 与 pad2Octets）。

**自洽等式**（由字段定义直接得出）：

```
capabilitySets 起始偏移     = 14 + lengthSourceDescriptor + 4
lengthCombinedCapabilities  = 4 + Σ lengthCapability[i]
totalLength                 = (14 + lengthSourceDescriptor + 4) + Σ lengthCapability[i] + 4
                            = 18 + lengthSourceDescriptor + lengthCombinedCapabilities
```

用官方 dump 4.1.12 逐项验证（S70）：

| 量 | dump 值 | 计算 | 结果 |
|---|---:|---|---|
| `lengthSourceDescriptor` | 4 | — | — |
| `lengthCombinedCapabilities` | 337 | `4 + Σ lengthCapability` ⇒ Σ = 333 | 13 个 capability 长度之和实测 = 333 ✔ |
| capabilitySets 起始偏移 | 0x16 = 22 | `14 + 4 + 4 = 22` | ✔ |
| capabilitySets 结束偏移 | 0x163 = 355 | `22 + 333 = 355` | ✔ |
| `sessionId` 位置 | 0x163 | 紧接 capabilitySets | ✔ |
| `totalLength` | 359 | `355 + 4 = 359` | ✔ |

> **这是实现中最容易算错的地方**：`lengthCombinedCapabilities` **不含** `sourceDescriptor`、
> 不含 `shareID`、不含两个 length 字段、不含 `sessionId`；它 = `numberCapabilities(2) + pad2Octets(2) + Σ lengthCapability`。
> 另一种等价写法：`lengthCombinedCapabilities = 4 + Σ lengthCapability`（因为 2 + 2 = 4）。
> 若误把它当作"capabilitySets 总长"，会少算 4 字节并导致 capability 遍历错位。

### 4.4 客户端处理规则（3.2.5.3.13.1，S60）

按原文顺序：

1. **Enhanced RDP Security 生效时**：先用外部安全协议解密并校验整包，然后才能开始处理。
2. **长度一致性**：检查 `tpktHeader` 与 `mcsSDin` 的内嵌长度字段与实收数据是否一致；
   不一致 → **SHOULD 断链**。
3. `mcsSDin.channelId` 用于把 PDU 路由到目标通道。
4. **securityHeader**：若存在，检查 `flags` 是否含 `SEC_ENCRYPT (0x0008)`；含则用 5.3.6 校验并解密；
   MAC 错或解密失败 → **SHOULD 断链**。
5. **pduType 检查**：`shareControlHeader.pduType.type` MUST = `PDUTYPE_DEMANDACTIVEPDU (1)`；
   否则 **SHOULD 忽略该 PDU**。同时检查 `totalLength` 与实际数据是否一致；不一致 → **SHOULD 断链**。
   无长度差异时，把 `pduSource`（server MCS channel ID）存入 **Server Channel ID store**（3.2.1.6）。
6. 其余字段与 capability 数据按 2.2.1.13.1.1 与 2.2.7 解释；capability 存入 **Server Capabilities store**（3.2.1.7），
   并 MUST 用于决定"向服务端发送 RDP 的哪个子集"。`shareID` 存入 **Share ID store**（3.2.1.8）。
7. 处理成功后客户端 **MUST** 发 Confirm Active PDU；失败 → **SHOULD 断链**。

> 注意第 5 条与第 2 条的差别：**pduType 不符 → 忽略（不断链）**；**长度不符 → 断链**。

---

## 5. Confirm Active PDU（2.2.1.13.2）

### 5.1 定位与时序

> "It is sent as a response to the Demand Active PDU. Once the Confirm Active PDU has been sent,
> the client can start sending input PDUs to the server."
> —— 2.2.1.13.2（S09）

### 5.2 分层封装

| 层 | 长度 | 字段 | 说明 |
|---|---:|---|---|
| 1 | 4 | `tpktHeader` | TPKT |
| 2 | 3 | `x224Data` | X.224 Data TPDU |
| 3 | var | `mcsSDrq` | MCS Send Data Request（[T125] §11.32，choice 25） |
| 4 | var | `securityHeader` | 可选 |
| 5 | var | `confirmActivePduData` | `TS_CONFIRM_ACTIVE_PDU` |

### 5.3 TS_CONFIRM_ACTIVE_PDU 完整字段（2.2.1.13.2.1）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `shareControlHeader.totalLength` | LE16 |
| 2 | 2 | `shareControlHeader.pduType` | `type` MUST = `PDUTYPE_CONFIRMACTIVEPDU (3)`，`PDUVersion` MUST = 0x1 ⇒ 线上 `0x0013` |
| 4 | 2 | `shareControlHeader.pduSource` | LE16，**MUST = User Channel ID**（3.2.5.1，S94；dump 中 `0x03EF = 1007`） |
| 6 | 4 | `shareID` | LE32，Share 标识符。**应为 Demand Active 中收到的 shareID**（3.2.5.3.13.1 要求客户端把收到的值存入 Share ID store（3.2.1.8），2.2.1.13.2.1 本身只说"the share identifier for the packet"；dump 中为 `0x000103EA`） |
| 10 | 2 | `originatorID` | LE16，**MUST = server channel ID `0x03EA`** |
| 12 | 2 | `lengthSourceDescriptor` | LE16 |
| 14 | 2 | `lengthCombinedCapabilities` | LE16，同 §4.3 口径 |
| 16 | var | `sourceDescriptor` | 变长字节数组（dump 实测内容为 `4d 53 54 53 43 00` = `"MSTSC"` + NUL，长度 6；语义见 [T128] §8.4.1，**未取证**） |
| 16+L | 2 | `numberCapabilities` | LE16 |
| 18+L | 2 | `pad2Octets` | LE16，填充，MUST 忽略 |
| 20+L | var | `capabilitySets` | `TS_CAPS_SET` 数组 |

`capabilitySets` 起始偏移 = `16 + lengthSourceDescriptor + 4`。
（Demand Active 是 `14 + L + 4`，Confirm Active 多出 `originatorID` 的 2 字节，故整体 +2。）

### 5.4 客户端发送规则（3.2.5.3.13.2，S61）

1. `tpktHeader` / `x224Data` 按 [T123] §8 / [X224] §13.7 初始化。
2. `mcsSDrq.initiator` MUST = **User Channel ID**；`mcsSDrq.channelId` MUST = **MCS I/O Channel ID**。
3. Enhanced RDP Security：整包由外部协议加密+摘要，且 **securityHeader MUST NOT 存在**。
4. Standard RDP Security：可选 securityHeader，加密时 `flags` MUST 含 `SEC_ENCRYPT (0x0008)`。
5. 其余字段按 2.2.1.13.2.1 填充，**组合后的 capability 数据放入 `capabilitySets`**。
6. 发完 Confirm Active 后客户端 **MUST** 发 Synchronize PDU（2.2.1.14）。
7. 发出后客户端 **SHOULD** 开始发送 input PDU（2.2.8）。

### 5.5 服务端处理规则（3.3.5.3.13.2，S64）

- 解密/校验 → 长度一致性 → `channelId` 路由 → securityHeader 检查
- `shareControlHeader.pduType.type` MUST = `PDUTYPE_CONFIRMACTIVEPDU (3)`
- capability 存入 **Client Capabilities store**（3.3.1.7），用于决定向客户端发送的 RDP 子集
- 成功后服务端 **MUST** 发 Synchronize PDU（2.2.1.19）；失败 → **SHOULD 断链**

> 3.3.5.3.13.2（S64）的处理步骤**未要求**校验 `originatorID` / `shareID` 是否与自己的 Demand Active
> 一致；但 2.2.5.1（S90）为两种非法值各定义了专用 ERRINFO：`0x000010D4`（shareID 非法）与
> `0x000010D5`（originatorID 非法），实现**可以**校验并据此断链。
> 客户端仍 MUST 按 §5.3 填对。

---

## 6. Capability Set 通用头

### 6.1 TS_CAPS_SET（2.2.1.13.1.1.1）

> "The `TS_CAPS_SET` structure is used to describe the type and size of a capability set exchanged
> between clients and servers. **All capability sets conform to this basic structure**（section 2.2.7）."
> —— 2.2.1.13.1.1.1（S08）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | LE16，capability set 类型标识 |
| 2 | 2 | `lengthCapability` | LE16，**capability 数据的字节数，含 `capabilitySetType` 与 `lengthCapability` 自身**（即整个 set 的总长） |
| 4 | var | `capabilityData` | 与 `capabilitySetType` 对应结构的剩余部分 |

**关键语义**：`lengthCapability` 是**整个 set 的总长**（含 4 字节头），不是载荷长度。
因此遍历算法为：

```
lcc        = lengthCombinedCapabilities
recv_len   = 实收数据中 capabilitySets 区可用字节数（不含尾部 sessionId）
caps_start = 22（Demand Active）/ 26（Confirm Active）
if lcc < 4: drop                                # 否则 lcc - 4 在 uint16 下溢为 65534
caps_end   = caps_start + lcc - 4
if lcc - 4 < numberCapabilities * 4: drop       # 计数偏大：连头部都放不下
if numberCapabilities == 0: warn                # 合法但无意义，不断链
p = caps_start
for i in 0 .. numberCapabilities-1:
    if p + 4 > caps_end  or  p + 4 > recv_len: drop        # ① 头越界
    type = LE16(p)
    len  = LE16(p+2)
    if len < 4: drop                                       # ② 否则 p 不前进，死循环
    if p + len > caps_end  or  p + len > recv_len: drop    # ③ 体越界
    process(type, p, len)
    p += len
if p != caps_end:
    if p > caps_end: drop                        # 越过 lcc 定界
    else: warn；按 caps_end 重新定界（丢弃尾部 slack）
```

> **三条上界检查不是可选防御**：① `p + 4 <= caps_end`、② `p + len <= caps_end`、
> ③ `p + len <= recv_len`，任一不满足即**断链**，**不得"尽力解析"**。原伪码只有 `len < 4`
> 与末尾 `assert`，没有任何上界，于是（红证 `F:\rtsc\evidence\capabilities\redlit_walk.out.txt`）：
>
> - `numberCapabilities` 偏大（对端可控）→ 循环按对端给的计数继续读下一个头，`p` 已等于 `caps_end`
>   仍执行 `LE16(p)`/`LE16(p+2)` → **越界读**（case A：`OOB-READ-HEADER off=24 end=24`）。
> - `lengthCapability` 大于剩余数据（对端可控）→ `process()` 消费 `len` 字节，越过 `caps_end`
>   与接收缓冲 → **越界读**（case B：`OOB-READ-BODY len=200 end=8`）。
>
> 两条都是**可被对端触发的内存越界**，故按阻断处理（不是按改动量定级）。
>
> `lcc < 4` 的后果性质不同：原伪码中 `lcc - 4` 在 uint16 下溢为 **65534**，循环走完后末尾
> `assert(p == caps_end)` 失败（case D：`ASSERT-FAIL ... end=65534`）——是
> **assert 失败 / 长度下溢**，**不是越界读**。
>
> `assert` 本身也不是处置策略（生产构建关闭 assert 后无动作），所以末尾改为显式分支：
> `p != caps_end` 时先告警并按 `caps_end` 重新定位（丢弃尾部 slack，case E：`ERR-trailing`），
> 只有 `p > caps_end` 才断链。`len < 4` 若不拒绝，`p` 不前进会死循环，必须断链
> （case F：`ERR-len<4`；另见 §15 U-09）。`numberCapabilities == 0` 合法但无意义，只告警。

### 6.2 编号表（规范原文全表，2.2.1.13.1.1.1，S08）

**这是规范原文的完整列表，共 28 个已分配编号。**（任务提示中列的编号有多处与规范不符，见 §1.4）

| `capabilitySetType` | 名称 | 结构定义章节 | 本文件布局 |
|---:|---|---|---|
| 0x0001 | `CAPSTYPE_GENERAL` | 2.2.7.1.1（S13） | §8.1 |
| 0x0002 | `CAPSTYPE_BITMAP` | 2.2.7.1.2（S14） | §8.2 |
| 0x0003 | `CAPSTYPE_ORDER` | 2.2.7.1.3（S15） | §8.3 |
| 0x0004 | `CAPSTYPE_BITMAPCACHE`（**Revision 1**） | 2.2.7.1.4.1（S16） | §8.4 |
| 0x0005 | `CAPSTYPE_CONTROL` | 2.2.7.2.2（S29） | §8.5 |
| 0x0007 | `CAPSTYPE_ACTIVATION` | 2.2.7.2.3（S30） | §8.6 |
| 0x0008 | `CAPSTYPE_POINTER` | 2.2.7.1.5（S19） | §8.7 |
| 0x0009 | `CAPSTYPE_SHARE` | 2.2.7.2.4（S31） | §8.8 |
| 0x000A | `CAPSTYPE_COLORCACHE` | [MS-RDPEGDI] 2.2.1.1（S79） | §8.9 |
| 0x000C | `CAPSTYPE_SOUND` | 2.2.7.1.11（S26） | §8.10 |
| 0x000D | `CAPSTYPE_INPUT` | 2.2.7.1.6（S20） | §8.11 |
| 0x000E | `CAPSTYPE_FONT` | 2.2.7.2.5（S32） | §8.12 |
| 0x000F | `CAPSTYPE_BRUSH` | 2.2.7.1.7（S21） | §8.13 |
| 0x0010 | `CAPSTYPE_GLYPHCACHE` | 2.2.7.1.8（S22） | §8.14 |
| 0x0011 | `CAPSTYPE_OFFSCREENCACHE` | 2.2.7.1.9（S24） | §8.15 |
| 0x0012 | `CAPSTYPE_BITMAPCACHE_HOSTSUPPORT` | 2.2.7.2.1（S28） | §8.16 |
| 0x0013 | `CAPSTYPE_BITMAPCACHE_REV2` | 2.2.7.1.4.2（S17） | §8.17 |
| 0x0014 | `CAPSTYPE_VIRTUALCHANNEL` | 2.2.7.1.10（S25） | §8.18 |
| 0x0015 | `CAPSTYPE_DRAWNINEGRIDCACHE` | [MS-RDPEGDI] 2.2.1.2（S80） | §8.19 |
| 0x0016 | `CAPSTYPE_DRAWGDIPLUS` | [MS-RDPEGDI] 2.2.1.3（S81） | §8.20 |
| 0x0017 | `CAPSTYPE_RAIL` | [MS-RDPERP] 2.2.1.1.1（S85） | §8.21 |
| 0x0018 | `CAPSTYPE_WINDOW` | [MS-RDPERP] 2.2.1.1.2（S86） | §8.22 |
| 0x0019 | `CAPSETTYPE_COMPDESK` | 2.2.7.2.8（S35） | §8.23 |
| 0x001A | `CAPSETTYPE_MULTIFRAGMENTUPDATE` | 2.2.7.2.6（S33） | §8.24 |
| 0x001B | `CAPSETTYPE_LARGE_POINTER` | 2.2.7.2.7（S34） | §8.25 |
| 0x001C | `CAPSETTYPE_SURFACE_COMMANDS` | 2.2.7.2.9（S36） | §8.26 |
| 0x001D | `CAPSETTYPE_BITMAP_CODECS` | 2.2.7.2.10（S37） | §6.4（变长） |
| 0x001E | `CAPSSETTYPE_FRAME_ACKNOWLEDGE` | [MS-RDPRFX] 2.2.1.3（S87） | §8.27 |

**未分配的编号**：规范表（S08）在 `0x0001`–`0x001E` 区间内跳过的值是 **`0x0006`** 与 **`0x000B`**；
`0x0000` 与 `0x001F` 及其后的值也未在表内出现。规范表未列出这些值，
因此**收到未分配编号时的行为规范未定义**（见 §15 U-01）。

> 核对：表内 28 项。其中 27 项为固定长度（§8.1–§8.27），`0x001D` 为变长（§6.4）。

### 6.3 Mandatory / Optional 的规范划分（2.2.7.1 / 2.2.7.2，S12 / S27）

规范用两个小节标题划分，**但"Mandatory"指的是"该小节下的集合在 RDP 中必被实现"，不是"每次都必须发送"**。
逐项的方向约束（各节原文）：

| `capabilitySetType` | 规范小节 | 方向约束（原文） |
|---:|---|---|
| 0x0001 General | 2.2.7.1.1 Mandatory | 双向（"sent by both client and server"） |
| 0x0002 Bitmap | 2.2.7.1.2 Mandatory | 双向 |
| 0x0003 Order | 2.2.7.1.3 Mandatory | 双向 |
| 0x0004 BitmapCache Rev1 | 2.2.7.1.4.1 Mandatory | **仅 client → server** |
| 0x0008 Pointer | 2.2.7.1.5 Mandatory | 双向 |
| 0x000D Input | 2.2.7.1.6 Mandatory | 双向 |
| 0x000F Brush | 2.2.7.1.7 Mandatory | **仅 client → server** |
| 0x0010 GlyphCache | 2.2.7.1.8 Mandatory | **仅 client → server** |
| 0x0011 Offscreen | 2.2.7.1.9 Mandatory | **仅 client → server** |
| 0x0014 VirtualChannel | 2.2.7.1.10 Mandatory | 双向 |
| 0x000C Sound | 2.2.7.1.11 Mandatory | **仅 client → server**（原文 "sent only from client to server"） |
| 0x0013 BitmapCache Rev2 | 2.2.7.1.4.2 Mandatory | **仅 client → server** |
| 0x0012 BmpCacheHostSupport | 2.2.7.2.1 Optional | **仅 server → client** |
| 0x0005 Control | 2.2.7.2.2 Optional | **仅 client → server**（服务端忽略内容） |
| 0x0007 Activation | 2.2.7.2.3 Optional | **仅 client → server**（服务端忽略内容） |
| 0x0009 Share | 2.2.7.2.4 Optional | 双向 |
| 0x000E Font | 2.2.7.2.5 Optional | 双向 |
| 0x001A MultifragUpdate | 2.2.7.2.6 Optional | 双向 |
| 0x001B LargePointer | 2.2.7.2.7 Optional | 双向 |
| 0x0019 CompDesk | 2.2.7.2.8 Optional | 双向 |
| 0x001C SurfaceCommands | 2.2.7.2.9 Optional | 双向 |
| 0x001D BitmapCodecs | 2.2.7.2.10 Optional | 双向 |
| 0x000A ColorCache | [MS-RDPEGDI] 2.2.1.1 | 双向 |
| 0x0015 DrawNineGrid | [MS-RDPEGDI] 2.2.1.2 | **仅 client → server** |
| 0x0016 DrawGdiPlus | [MS-RDPEGDI] 2.2.1.3 | 双向 |
| 0x0017 Rail | [MS-RDPERP] 2.2.1.1.1 | 双向 |
| 0x0018 Window | [MS-RDPERP] 2.2.1.1.2 | 双向 |
| 0x001E FrameAck | [MS-RDPRFX] 2.2.1.3 | 双向 |

> **重要**：`0x0014` 是 **VirtualChannel（十进制 20）**，不是"VirtualChannel = 14"。
> 十进制 14 = `0x000E` = **Font**。这是任务提示中的一处编号错误（§1.4）。

### 6.4 变长 capability：0x001D Bitmap Codecs（2.2.7.2.10）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `0x001D` |
| 2 | 2 | `lengthCapability` | 整个 set 总长（**变长**） |
| 4 | 1 | `bitmapCodecCount` | `bitmapCodecArray` 中 `TS_BITMAPCODEC` 的个数，上限 255 |
| 5 | var | `bitmapCodecArray` | `TS_BITMAPCODEC` 数组 |

`TS_BITMAPCODEC`（2.2.7.2.10.1.1，S39）：

| 偏移（相对本结构） | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 16 | `codecGUID` | GUID（[MS-DTYP] §2.3.4），见下表 |
| 16 | 1 | `codecID` | 客户端→服务端：8-bit 唯一 ID（`CODEC_GUID_NSCODEC` 时 **MUST = 0x01**）；服务端→客户端：被客户端忽略 |
| 17 | 2 | `codecPropertiesLength` | `codecProperties` 的字节数 |
| 19 | var | `codecProperties` | 编码参数（NSCODEC → NSCodec Capability Set；RemoteFX → 对应 container） |

`codecGUID` 取值（S39）：

| 名称 | GUID | 说明 |
|---|---|---|
| `CODEC_GUID_NSCODEC` | `{0xCA8D1BB9, 0x000F, 0x154F, 0x58, 0x9F, 0xAE, 0x2D, 0x1A, 0x87, 0xE2, 0xD6}` | NSCodec；`codecProperties` MUST 为 [MS-RDPNSC] §2.2.1 |
| `CODEC_GUID_REMOTEFX` | `{0x76772F12, 0xBD72, 0x4463, 0xAF, 0xB3, 0xB7, 0x3C, 0x9C, 0x6F, 0x78, 0x86}` | RemoteFX；`codecProperties` MUST 为 [MS-RDPRFX] §2.2.1.1 / §2.2.1.2 |
| `CODEC_GUID_IMAGE_REMOTEFX` | `{0x2744CCD4, 0x9D8A, 0x4E74, 0x80, 0x3C, 0x0E, 0xCB, 0xEE, 0xA1, 0x9C, 0x54}` | RemoteFX image 模式 |
| `CODEC_GUID_IGNORE` | `{0x9C4351A6, 0x3535, 0x42AE, 0x91, 0x0C, 0xCD, 0xFC, 0xE5, 0x76, 0x0B, 0x58}` | **MUST 忽略**该 Bitmap Codec 结构 |

GUID 线上字节序：`codecGUID1(4) | codecGUID2(2) | codecGUID3(2) | codecGUID4..11(各 1)`，
即 Data1 为 LE32、Data2/Data3 为 LE16、Data4 为 8 个原始字节（[MS-DTYP] §2.3.4）。
以 `CODEC_GUID_NSCODEC` 为例，线上为 `B9 1B 8D CA 0F 00 4F 15 58 9F AE 2D 1A 87 E2 D6`。


---

## 7. 客户端在 Confirm Active 中必须/可选声明的 capability

### 7.1 规范给出的"硬约束"清单

规范**没有**一节直接列出"客户端 Confirm Active 的最小 capability 集合"。可提取的硬约束如下
（全部为原文 MUST/SHOULD，逐条标注来源）：

| # | 约束 | 来源 |
|---|---|---|
| 1 | 客户端 MUST 回 Confirm Active 响应 Demand Active | 3.2.5.3.13.1（S60） |
| 2 | Confirm Active 的 `originatorID` MUST = `0x03EA` | 2.2.1.13.2.1（S10） |
| 3 | Confirm Active 的 `shareID` 应回填收到的 shareID（规范正文只说"packet 的 share identifier"，回填依据是 3.2.5.3.13.1 的 Share ID store 要求） | 2.2.1.13.2.1 + 3.2.5.3.13.1（S10 / S60）；见 §15 U-13 |
| 4 | 若声明 Bitmap capability：`bitmapCompressionFlag` MUST = TRUE，`multipleRectangleSupport` MUST = TRUE（否则连接无法继续） | 2.2.7.1.2（S14） |
| 5 | 若声明 Input capability：`inputFlags` 至少 MUST 含 `INPUT_FLAG_SCANCODES (0x0001)` | 2.2.7.1.6（S20） |
| 6 | 若声明 Order capability：`orderFlags` MUST 含 `NEGOTIATEORDERSUPPORT (0x0002)`；客户端 MUST 置 `ZEROBOUNDSDELTASSUPPORT (0x0008)` | 2.2.7.1.3（S15） |
| 7 | 若声明 GlyphCache 且 `GlyphSupportLevel > 0`：MUST 支持 GlyphIndex 或 FastIndex 主绘图订单 | 2.2.7.1.8（S22） |
| 8 | 若声明 BitmapCache Rev1/Rev2：MUST 同时支持 MemBlt 与 Mem3Blt 主绘图订单 | 2.2.7.1.4.1 / 2.2.7.1.4.2（S16 / S17） |
| 9 | 若声明 SurfaceCommands：MUST 同时在 General 的 `extraFlags` 置 `FASTPATH_OUTPUT_SUPPORTED (0x0001)` | 2.2.7.2.9（S36） |
| 10 | 若声明 LargePointer：双方 MUST 同时交换 Multifragment Update，且 `MaxRequestSize` ≥ 38055（96×96）或 ≥ 608299（384×384） | 2.2.7.2.7（S34） |
| 11 | 若声明 Sound 的 `SOUND_FLAG_BEEPS`：MUST 支持 Play Sound PDU | 2.2.7.1.11（S26） |
| 12 | 若声明 BitmapCodecs 且含 `CODEC_GUID_NSCODEC`：其 `codecID` MUST = 0x01，且 0x01 不得分配给其它 codec | 2.2.7.2.10.1.1（S39） |
| 13 | `Refresh Rect` / `Suppress Output` 的 support 位是 **server-only**（客户端填了也被忽略） | 2.2.7.1.1（S13） |

### 7.2 mstsc 实际发送的集合（有官方依据的部分）

**依据 A：官方 dump 4.1.13**（S71，Microsoft RDP 5.1 client ↔ RDP 5.1 server）
`numberCapabilities = 18`，顺序与长度如下（本文 §14.1 已逐字节复算，全部通过）：

| # | `capabilitySetType` | 名称 | `lengthCapability` |
|---:|---:|---|---:|
| 0 | 0x0001 | General | 24 |
| 1 | 0x0002 | Bitmap | 28 |
| 2 | 0x0003 | Order | 88 |
| 3 | 0x0013 | BitmapCacheRev2 | 40 |
| 4 | 0x000A | ColorCache | 8 |
| 5 | 0x0007 | Activation | 12 |
| 6 | 0x0005 | Control | 12 |
| 7 | 0x0008 | Pointer | 10 |
| 8 | 0x0009 | Share | 8 |
| 9 | 0x000D | Input | 88 |
| 10 | 0x000C | Sound | 8 |
| 11 | 0x000E | Font | 8 |
| 12 | 0x0010 | GlyphCache | 52 |
| 13 | 0x000F | Brush | 8 |
| 14 | 0x0011 | Offscreen | 12 |
| 15 | 0x0014 | VirtualChannel | 8 |
| 16 | 0x0015 | DrawNineGrid | 12 |
| 17 | 0x0016 | DrawGdiPlus | 40 |
| | | **合计** | Σ `lengthCapability` = **466**；+ 26 字节头 = **492** = `totalLength` ✔ |

**依据 B：官方 dump 4.1.12 服务端 Demand Active**（S70，同一会话的服务端方向）
`numberCapabilities = 13`，含 `0x0009 Share`、`0x0001 General`、`0x0014 VirtualChannel`、`0x0016 DrawGdiPlus`、
`0x000E Font`（**长度 4，服务端 bug**）、`0x0002 Bitmap`、`0x0003 Order`、`0x000A ColorCache`、
`0x0012 BmpCacheHostSupport`、`0x0008 Pointer`、`0x000D Input`、`0x0017 Rail`、`0x0018 Window`。

> **结论（有依据的）**：RDP 5.1 时代的 mstsc 在 Confirm Active 中发 **18 个** capability，
> 且**不发** `0x0004 BitmapCache Rev1`（只发 Rev2）、**不发** `0x0012 BmpCacheHostSupport`（那是 server-only）、
> **不发** `0x0017/0x0018`（RAIL/Window，仅在 RemoteApp 场景由服务端先发）。
>
> **不能声称的**：本文件**没有**现代 mstsc（10.x）的 Confirm Active 抓包，
> 因此**不能**断言现代 mstsc 的完整集合。§15 U-02 记录该缺口。

### 7.3 本项目建议的最小集合（推导，B 级）

以下是"能完成握手并进入 Connection Finalization"的最小集合。**两张表口径不同，不要混读**：
表 ① 只列**规范 MUST 能推出的**（且都是"声明了该 set 就必须满足"的**条件性** MUST），
表 ② 是**本项目功能需要的**（工程判断，规范没有 MUST 要求）。

**表 ①：规范 MUST 可推出（仅 3 项，全部为"声明后"的条件性 MUST）**

| `capabilitySetType` | 强度 | 理由 | 来源 |
|---|---|---|---|
| `0x0002 Bitmap` | **规范 MUST**（声明时） | 两个 MUST 位：`bitmapCompressionFlag`、`multipleRectangleSupport`，缺一则连接无法继续 | 2.2.7.1.2（S14） |
| `0x0003 Order` | **规范 MUST**（声明时，条件性） | `orderFlags` MUST 含 `NEGOTIATEORDERSUPPORT (0x0002)`；客户端 MUST 置 `ZEROBOUNDSDELTASSUPPORT (0x0008)` | 2.2.7.1.3（S15） |
| `0x000D Input` | **规范 MUST**（声明时，条件性） | `inputFlags` 至少 MUST 含 `INPUT_FLAG_SCANCODES (0x0001)` | 2.2.7.1.6（S20） |

**表 ②：本项目功能需要（工程判断，非规范 MUST）**

| `capabilitySetType` | 强度 | 理由 | 来源 |
|---|---|---|---|
| `0x0001 General` | 工程需要 | 承载 `extraFlags`（fast-path、salted MAC 等协商）；服务端据此决定后续行为 | 2.2.7.1.1 |
| `0x0008 Pointer` | 工程需要 | 指针缓存槽数；为 0 则服务端不用 New Pointer Update | 2.2.7.1.5 |
| `0x0009 Share` | 工程需要 | 回传 nodeID（客户端填 0） | 2.2.7.2.4 |
| `0x0014 VirtualChannel` | 工程需要 | 声明虚拟通道压缩能力 | 2.2.7.1.10 |
| `0x000E Font` | 工程需要 | 与 Font List / Font Map PDU 配套 | 2.2.7.2.5 |
| `0x0004` 或 `0x0013`（BitmapCache） | 工程需要 | 位图缓存；不发则服务端只能发明文位图，带宽显著变差。Rev2 更优，且与 Persistent Key List 配套 | 2.2.7.1.4.1 / 2.2.7.1.4.2 |
| `0x0010 GlyphCache` | 工程需要 | 不发则所有文本走 Bitmap Update，带宽极差 | 2.2.7.1.8 |
| `0x000F Brush` | 工程需要 | 不发则刷子绘制退化为位图 | 2.2.7.1.7 |
| `0x0011 Offscreen` | 工程需要 | offscreen 缓存 | 2.2.7.1.9 |
| `0x001A MultifragmentUpdate` | 工程需要 | 若要用 fast-path 分片或大指针，必须 | 2.2.7.2.6 |
| `0x001C SurfaceCommands` | 工程需要 | 若要用 EGFX/SetSurfaceBits 路径，必须 | 2.2.7.2.9 |
| `0x0005` / `0x0007` | 工程需要 | T.128 遗留，服务端忽略内容；mstsc 会发，照发可最大化兼容 | 2.2.7.2.2 / 2.2.7.2.3 |
| `0x000A ColorCache` | 工程需要 | 规范称 unused，但 mstsc 会发 | [MS-RDPEGDI] 2.2.1.1 |

> 表 ② 是**工程判断**（B 级），不是规范要求。规范对"不发某个 optional capability"的后果
> 只描述为"服务端将用更低效的手段"（如 2.2.7.1.3 对订单、2.2.7.1.8 对字形的说明）。

**最小集合的风险面（服务端拒绝码，2.2.5.1 节选，S90）**

| 拒绝码 | 名称 | 触发条件 | 与最小集合的关系 |
|---|---|---|---|
| `0x000010EA` | `ERRINFO_BADCAPABILITIES` | Confirm Active 里的 capability 服务端不接受（`bcgr.txt:3001`） | 任何声明组合都可能触发；最小集合必须被真实服务端接受 |
| `0x000010E9` | `ERRINFO_NOCURSORCACHE` | Pointer 的 `colorPointerCacheSize` 与 `pointerCacheSize` **都为 0**（`bcgr.txt:3000`） | 最小集合含 `0x0008 Pointer`，两个 size 不能都为 0 |
| `0x000010F4` | `ERRINFO_CACHECAPNOTSET` | 发了 Persistent Key List，但 Confirm Active 未含 Rev2 Bitmap Cache capability（`bcgr.txt:3007`） | 若发 Persistent Key List，必须同时声明 `0x0013` |

---

## 8. 各 capability 的字节布局（逐字段）

> 本章 27 个小节按 `capabilitySetType` 升序。每个表给出**偏移 / 长度 / 字段 / 说明**，
> 偏移由字段宽度累加得出，末行"偏移校验"给出累加结果与 `lengthCapability` 的一致性。
> 所有宽度均取自官方规范原文（S13–S39、S79–S87）；`0x001D` 因变长已在 §6.4 给出。

### 8.1 0x0001 — General Capability Set（`TS_GENERAL_CAPABILITYSET`）

- 章节：**2.2.7.1.1（S13）**
- 方向：client ⇄ server
- 定长：**24 字节**（由字段宽度推出；规范未固定该值）

> 基于 [T128] §8.2.3。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_GENERAL (1)` |
| 2 | 2 | `lengthCapability` | 定长 24（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `osMajorType` | 平台类型：0x0000 UNSPECIFIED / 0x0001 WINDOWS / 0x0002 OS2 / 0x0003 MACINTOSH / 0x0004 UNIX / 0x0005 IOS / 0x0006 OSX / 0x0007 ANDROID / 0x0008 CHROME_OS |
| 6 | 2 | `osMinorType` | 平台版本：0x0000 UNSPECIFIED / 0x0001 WINDOWS_31X / 0x0002 WINDOWS_95 / 0x0003 WINDOWS_NT / 0x0004 OS2_V21 / 0x0005 POWER_PC / 0x0006 MACINTOSH / 0x0007 NATIVE_XSERVER / 0x0008 PSEUDO_XSERVER / 0x0009 WINDOWS_RT |
| 8 | 2 | `protocolVersion` | MUST = `TS_CAPS_PROTOCOLVERSION (0x0200)` |
| 10 | 2 | `pad2octetsA` | 填充，MUST 忽略 |
| 12 | 2 | `compressionTypes` | MUST = 0 |
| 14 | 2 | `extraFlags` | 见下方 extraFlags 表 |
| 16 | 2 | `updateCapabilityFlag` | MUST = 0 |
| 18 | 2 | `remoteUnshareFlag` | MUST = 0 |
| 20 | 2 | `compressionLevel` | MUST = 0 |
| 22 | 1 | `refreshRectSupport` | **server-only**：0x00 = 不支持 Refresh Rect PDU；0x01 = 支持 |
| 23 | 1 | `suppressOutputSupport` | **server-only**：0x00 = 不支持 Suppress Output PDU；0x01 = 支持 |

> 偏移校验：末字段结束 = 24 = 定长 24 ✔

### 8.2 0x0002 — Bitmap Capability Set（`TS_BITMAP_CAPABILITYSET`）

- 章节：**2.2.7.1.2（S14）**
- 方向：client ⇄ server
- 定长：**28 字节**（由字段宽度推出；规范未固定该值）

> 基于 [T128] §8.2.4。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_BITMAP (2)` |
| 2 | 2 | `lengthCapability` | 定长 28（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `preferredBitsPerPixel` | 服务端 MUST 置为会话色深；客户端 SHOULD 置为 Client Core Data（2.2.1.3.2）中请求的色深 |
| 6 | 2 | `receive1BitPerPixel` | **被忽略**，SHOULD = TRUE (0x0001) |
| 8 | 2 | `receive4BitsPerPixel` | **被忽略**，SHOULD = TRUE (0x0001) |
| 10 | 2 | `receive8BitsPerPixel` | **被忽略**，SHOULD = TRUE (0x0001) |
| 12 | 2 | `desktopWidth` | 会话桌面宽度（像素） |
| 14 | 2 | `desktopHeight` | 会话桌面高度（像素） |
| 16 | 2 | `pad2octets` | 填充，MUST 忽略 |
| 18 | 2 | `desktopResizeFlag` | 0x0000 = 不支持通过 Deactivation-Reactivation 改分辨率；0x0001 = 支持 |
| 20 | 2 | `bitmapCompressionFlag` | **MUST = TRUE (0x0001)**——压缩位图是连接继续的必要条件 |
| 22 | 1 | `highColorFlags` | **被忽略**，SHOULD = 0 |
| 23 | 1 | `drawingFlags` | 见下方 drawingFlags 表 |
| 24 | 2 | `multipleRectangleSupport` | **MUST = TRUE (0x0001)**——多矩形是连接继续的必要条件 |
| 26 | 2 | `pad2octetsB` | 填充，MUST 忽略 |

> 偏移校验：末字段结束 = 28 = 定长 28 ✔

### 8.3 0x0003 — Order Capability Set（`TS_ORDER_CAPABILITYSET`）

- 章节：**2.2.7.1.3（S15）**
- 方向：client ⇄ server
- 定长：**88 字节**（由字段宽度推出；规范未固定该值）

> 基于 [T128] §8.2.5。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_ORDER (3)` |
| 2 | 2 | `lengthCapability` | 定长 88（由字段宽度推出；规范未固定该值） |
| 4 | 16 | `terminalDescriptor` | **被忽略**，SHOULD 全 0 |
| 20 | 4 | `pad4octetsA` | 填充，MUST 忽略 |
| 24 | 2 | `desktopSaveXGranularity` | **被忽略**，假定为 1 |
| 26 | 2 | `desktopSaveYGranularity` | **被忽略**，假定为 20 |
| 28 | 2 | `pad2octetsA` | 填充，MUST 忽略 |
| 30 | 2 | `maximumOrderLevel` | **被忽略**，SHOULD = `ORD_LEVEL_1_ORDERS (1)` |
| 32 | 2 | `numberFonts` | **被忽略**，SHOULD = 0 |
| 34 | 2 | `orderFlags` | 见下方 orderFlags 表 |
| 36 | 32 | `orderSupport` | 32 字节数组，下标 = 主绘图订单协商索引；支持则置 0x01。索引表见 §9.4 |
| 68 | 2 | `textFlags` | **MUST 被忽略** |
| 70 | 2 | `orderSupportExFlags` | 0x0002 `ORDERFLAGS_EX_CACHE_BITMAP_REV3_SUPPORT`；0x0004 `ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT` |
| 72 | 4 | `pad4octetsB` | 填充，MUST 忽略 |
| 76 | 4 | `desktopSaveSize` | **被客户端忽略**，假定 230400 字节（480×480） |
| 80 | 2 | `pad2octetsC` | 填充，MUST 忽略 |
| 82 | 2 | `pad2octetsD` | 填充，MUST 忽略 |
| 84 | 2 | `textANSICodePage` | 客户端 ANSI 代码页；**被客户端忽略**，服务端 SHOULD 置 0 |
| 86 | 2 | `pad2octetsE` | 填充，MUST 忽略 |

> 偏移校验：末字段结束 = 88 = 定长 88 ✔

### 8.4 0x0004 — Bitmap Cache Capability Set, Revision 1（`TS_BITMAPCACHE_CAPABILITYSET`）

- 章节：**2.2.7.1.4.1（S16）**
- 方向：**仅 client → server**
- 定长：**40 字节**（由字段宽度推出；规范未固定该值）

> 客户端还 MUST 支持 MemBlt / Mem3Blt 主绘图订单才能接收 Cache Bitmap (Rev 1) 二级订单。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_BITMAPCACHE (4)` |
| 2 | 2 | `lengthCapability` | 定长 40（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `pad1` | 填充，MUST 忽略 |
| 8 | 4 | `pad2` | 填充，MUST 忽略 |
| 12 | 4 | `pad3` | 填充，MUST 忽略 |
| 16 | 4 | `pad4` | 填充，MUST 忽略 |
| 20 | 4 | `pad5` | 填充，MUST 忽略 |
| 24 | 4 | `pad6` | 填充，MUST 忽略 |
| 28 | 2 | `Cache0Entries` | Bitmap Cache 0 条目数，**上限 200** |
| 30 | 2 | `Cache0MaximumCellSize` | Bitmap Cache 0 最大单元尺寸 |
| 32 | 2 | `Cache1Entries` | Bitmap Cache 1 条目数，**上限 600** |
| 34 | 2 | `Cache1MaximumCellSize` | Bitmap Cache 1 最大单元尺寸 |
| 36 | 2 | `Cache2Entries` | Bitmap Cache 2 条目数，**上限 65535** |
| 38 | 2 | `Cache2MaximumCellSize` | Bitmap Cache 2 最大单元尺寸 |

> 偏移校验：末字段结束 = 40 = 定长 40 ✔

### 8.5 0x0005 — Control Capability Set（`TS_CONTROL_CAPABILITYSET`）

- 章节：**2.2.7.2.2（S29）**
- 方向：**仅 client → server**（服务端忽略内容）
- 定长：**12 字节**（由字段宽度推出；规范未固定该值）

> 完整定义见 [T128] §8.2.10。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_CONTROL (5)` |
| 2 | 2 | `lengthCapability` | 定长 12（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `controlFlags` | SHOULD = 0 |
| 6 | 2 | `remoteDetachFlag` | SHOULD = FALSE (0x0000) |
| 8 | 2 | `controlInterest` | SHOULD = `CONTROLPRIORITY_NEVER (0x0002)` |
| 10 | 2 | `detachInterest` | SHOULD = `CONTROLPRIORITY_NEVER (0x0002)` |

> 偏移校验：末字段结束 = 12 = 定长 12 ✔

### 8.6 0x0007 — Window Activation Capability Set（`TS_WINDOWACTIVATION_CAPABILITYSET`）

- 章节：**2.2.7.2.3（S30）**
- 方向：**仅 client → server**（服务端忽略内容）
- 定长：**12 字节**（由字段宽度推出；规范未固定该值）

> 完整定义见 [T128] §8.2.9。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_ACTIVATION (7)` |
| 2 | 2 | `lengthCapability` | 定长 12（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `helpKeyFlag` | SHOULD = FALSE (0x0000) |
| 6 | 2 | `helpKeyIndexFlag` | SHOULD = FALSE (0x0000) |
| 8 | 2 | `helpExtendedKeyFlag` | SHOULD = FALSE (0x0000) |
| 10 | 2 | `windowManagerKeyFlag` | SHOULD = FALSE (0x0000) |

> 偏移校验：末字段结束 = 12 = 定长 12 ✔

### 8.7 0x0008 — Pointer Capability Set（`TS_POINTER_CAPABILITYSET`）

- 章节：**2.2.7.1.5（S19）**
- 方向：client ⇄ server
- 定长：**10 字节**（由字段宽度推出；规范未固定该值）

> 基于 [T128] §8.2.11。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_POINTER (8)` |
| 2 | 2 | `lengthCapability` | 定长 10（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `colorPointerFlag` | **被忽略**，恒按 TRUE 处理（0x0000 = 仅单色；0x0001 = 彩色） |
| 6 | 2 | `colorPointerCacheSize` | 24-bpp 彩色指针缓存槽数（存 Color Pointer Update 数据） |
| 8 | 2 | `pointerCacheSize` | 任意色深指针缓存槽数（存 New Pointer Update 数据）。**若为 0 或客户端未含此字段，服务端不会使用 New Pointer Update** |

> 若 `colorPointerCacheSize` 与 `pointerCacheSize` **都为 0**，服务端可回
> `ERRINFO_NOCURSORCACHE (0x000010E9)` 后断链（2.2.5.1，S90）；客户端侧这两个值不应都为 0。

> 偏移校验：末字段结束 = 10 = 定长 10 ✔

### 8.8 0x0009 — Share Capability Set（`TS_SHARE_CAPABILITYSET`）

- 章节：**2.2.7.2.4（S31）**
- 方向：client ⇄ server
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

> 基于 [T128] §8.2.12。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_SHARE (9)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `nodeID` | 客户端 SHOULD 置 0；服务端置为 server channel ID `0x03EA` |
| 6 | 2 | `pad2octets` | 填充，MUST 忽略 |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.9 0x000A — Color Table Cache Capability Set（`TS_COLORTABLE_CAPABILITYSET`）

- 章节：**[MS-RDPEGDI] 2.2.1.1（S79）**
- 方向：client ⇄ server
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

> 规范称其为"unused capability set"：实际色表缓存存在性由 MemBlt/Mem3Blt 订单支持隐含。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_COLORCACHE (0x000A)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `colorTableCacheSize` | **MUST 在能力交换期间忽略**，恒假定为 `0x0006` |
| 6 | 2 | `pad2octets` | 任意值，MUST 忽略 |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.10 0x000C — Sound Capability Set（`TS_SOUND_CAPABILITYSET`）

- 章节：**2.2.7.1.11（S26）**
- 方向：**仅 client → server**
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

> 若客户端声明 beep 支持，则 MUST 支持 Play Sound PDU（2.2.9.1.1.5）。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_SOUND (12)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `soundFlags` | 0x0001 = `SOUND_FLAG_BEEPS`（支持播放 beep） |
| 6 | 2 | `pad2octetsA` | 填充，MUST 忽略 |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.11 0x000D — Input Capability Set（`TS_INPUT_CAPABILITYSET`）

- 章节：**2.2.7.1.6（S20）**
- 方向：client ⇄ server
- 定长：**88 字节**（由字段宽度推出；规范未固定该值）

> **至少 `INPUT_FLAG_SCANCODES` MUST 置位**。服务端方向的 keyboard*/imeFileName SHOULD 为 0。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_INPUT (13)` |
| 2 | 2 | `lengthCapability` | 定长 88（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `inputFlags` | 见下方 inputFlags 表。**至少 `INPUT_FLAG_SCANCODES` MUST 置位** |
| 6 | 2 | `pad2octetsA` | 填充，MUST 忽略 |
| 8 | 4 | `keyboardLayout` | 活动输入 locale 标识符（HKL），如 0x00000409 = US。**仅客户端置有效值**，SHOULD 与 Client Core Data 一致 |
| 12 | 4 | `keyboardType` | 键盘类型：0x1 IBM PC/XT(83) / 0x2 Olivetti ICO(102) / 0x3 IBM PC/AT(84) / 0x4 IBM enhanced(101/102) / 0x5 Nokia 1050 / 0x6 Nokia 9140 / 0x7 Japanese。**仅客户端置有效值** |
| 16 | 4 | `keyboardSubType` | 键盘子类型（OEM 相关）。**仅客户端置有效值** |
| 20 | 4 | `keyboardFunctionKey` | 功能键数量。**仅客户端置有效值** |
| 24 | 64 | `imeFileName` | IME 文件名，最多 31 个 Unicode 字符 + NUL。**仅客户端置有效值** |

> 偏移校验：末字段结束 = 88 = 定长 88 ✔

### 8.12 0x000E — Font Capability Set（`TS_FONT_CAPABILITYSET`）

- 章节：**2.2.7.2.5（S32）**
- 方向：client ⇄ server
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

> ⚠ 官方 dump 4.1.12 中服务端发的该 capability **lengthCapability = 4**（缺 `fontSupportFlags`/`pad2octets`），规范注解称这是服务端 bug。**解析器必须容忍 4 字节形态**。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_FONT (14)` |
| 2 | 2 | `lengthCapability` | 规范值 8；**实测服务端会发 4** |
| 4 | 2 | `fontSupportFlags` | SHOULD = `FONTSUPPORT_FONTLIST (0x0001)`；**当 lengthCapability = 4 时此字段缺失** |
| 6 | 2 | `pad2octets` | 填充，MUST 忽略；**当 lengthCapability = 4 时此字段缺失** |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.13 0x000F — Brush Capability Set（`TS_BRUSH_CAPABILITYSET`）

- 章节：**2.2.7.1.7（S21）**
- 方向：**仅 client → server**
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_BRUSH (15)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `brushSupportLevel` | 0x00000000 `BRUSH_DEFAULT`（RDP 4.0）/ 0x00000001 `BRUSH_COLOR_8x8`（≤8×8 彩色刷 + 缓存）/ 0x00000002 `BRUSH_COLOR_FULL`（任意尺寸） |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.14 0x0010 — Glyph Cache Capability Set（`TS_GLYPHCACHE_CAPABILITYSET`）

- 章节：**2.2.7.1.8（S22）**
- 方向：**仅 client → server**
- 定长：**52 字节**（由字段宽度推出；规范未固定该值）

> `GlyphCache` 是 10 个 `TS_CACHE_DEFINITION`（2.2.7.1.8.1，S23）的数组，每个 4 字节。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_GLYPHCACHE (16)` |
| 2 | 2 | `lengthCapability` | 定长 52（由字段宽度推出；规范未固定该值） |
| 4 | 40 | `GlyphCache[0..9]` | 10 × `TS_CACHE_DEFINITION`：`CacheEntries(2)` + `CacheMaximumCellSize(2)`。Cache ID 0..9 |
| 44 | 4 | `FragCache` | `TS_CACHE_DEFINITION`：条目上限 256，单元上限 256 字节 |
| 48 | 2 | `GlyphSupportLevel` | 0x0000 NONE / 0x0001 PARTIAL / 0x0002 FULL / 0x0003 ENCODE（Rev 2 Cache Glyph 订单） |
| 50 | 2 | `pad2octets` | 填充，MUST 忽略 |

> 偏移校验：末字段结束 = 52 = 定长 52 ✔

### 8.15 0x0011 — Offscreen Bitmap Cache Capability Set（`TS_OFFSCREEN_CAPABILITYSET`）

- 章节：**2.2.7.1.9（S24）**
- 方向：**仅 client → server**
- 定长：**12 字节**（由字段宽度推出；规范未固定该值）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_OFFSCREENCACHE (17)` |
| 2 | 2 | `lengthCapability` | 定长 12（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `offscreenSupportLevel` | 0x00000000 = 不支持；0x00000001 = 支持 |
| 8 | 2 | `offscreenCacheSize` | 客户端 offscreen 位图缓存最大尺寸，**单位 KB** |
| 10 | 2 | `offscreenCacheEntries` | 客户端 offscreen 位图缓存最大条目数 |

> 偏移校验：末字段结束 = 12 = 定长 12 ✔

### 8.16 0x0012 — Bitmap Cache Host Support Capability Set（`TS_BITMAPCACHE_HOSTSUPPORT_CAPABILITYSET`）

- 章节：**2.2.7.2.1（S28）**
- 方向：**仅 server → client**
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

> 用于声明持久化位图缓存支持。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_BITMAPCACHE_HOSTSUPPORT (18)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 1 | `cacheVersion` | MUST = `TS_BITMAPCACHE_REV2 (0x01)` |
| 5 | 1 | `pad1` | 填充，MUST 忽略 |
| 6 | 2 | `pad2` | 填充，MUST 忽略 |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.17 0x0013 — Bitmap Cache Capability Set, Revision 2（`TS_BITMAPCACHE_CAPABILITYSET_REV2`）

- 章节：**2.2.7.1.4.2（S17）**
- 方向：**仅 client → server**
- 定长：**40 字节**（由字段宽度推出；规范未固定该值）

> 客户端还 MUST 支持 MemBlt / Mem3Blt 才能接收 Cache Bitmap (Rev 2) 二级订单。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_BITMAPCACHE_REV2 (19)` |
| 2 | 2 | `lengthCapability` | 定长 40（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `CacheFlags` | 0x0001 `PERSISTENT_KEYS_EXPECTED_FLAG`（客户端将在 Connection Finalization 发 Persistent Key List PDU）；0x0002 `ALLOW_CACHE_WAITING_LIST_FLAG`（支持 cache waiting list，位图第二次命中才缓存） |
| 6 | 1 | `Pad2` | 填充，MUST 忽略 |
| 7 | 1 | `NumCellCaches` | 位图缓存个数，**上限 5** |
| 8 | 4 | `BitmapCache0CellInfo` | `TS_BITMAPCACHE_CELL_CACHE_INFO`；条目上限 **600**；仅当 NumCellCaches ≥ 1 有效 |
| 12 | 4 | `BitmapCache1CellInfo` | 同上；条目上限 **600**；仅当 NumCellCaches ≥ 2 有效 |
| 16 | 4 | `BitmapCache2CellInfo` | 同上；条目上限 **65536**；仅当 NumCellCaches ≥ 3 有效 |
| 20 | 4 | `BitmapCache3CellInfo` | 同上；条目上限 **4096**；仅当 NumCellCaches ≥ 4 有效 |
| 24 | 4 | `BitmapCache4CellInfo` | 同上；条目上限 **2048**；仅当 NumCellCaches = 5 有效 |
| 28 | 12 | `Pad3` | 填充，MUST 忽略 |

> 偏移校验：末字段结束 = 40 = 定长 40 ✔

### 8.18 0x0014 — Virtual Channel Capability Set（`TS_VIRTUALCHANNEL_CAPABILITYSET`）

- 章节：**2.2.7.1.10（S25）**
- 方向：client ⇄ server
- 定长：**8 字节**（无 `VCChunkSize`，官方 dump 的形态）或 **12 字节**（含 `VCChunkSize`）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_VIRTUALCHANNEL (20)` |
| 2 | 2 | `lengthCapability` | 8（无 VCChunkSize）或 12（含 VCChunkSize） |
| 4 | 4 | `flags` | 0x00000000 `VCCAPS_NO_COMPR` / 0x00000001 `VCCAPS_COMPR_SC`（客户端支持 server→client 压缩）/ 0x00000002 `VCCAPS_COMPR_CS_8K`（服务端支持 client→server 压缩，限 RDP 4.0 bulk） |
| 8 | 4 | `VCChunkSize（可选）` | 服务端发：虚拟通道 chunk 最大尺寸，MUST ∈ [`CHANNEL_CHUNK_LENGTH`, 16256]；客户端发：被服务端忽略 |

> 偏移校验：末字段结束 = **8**（无 `VCChunkSize`）/ **12**（含 `VCChunkSize`）✔
> 官方 dump 4.1.12 / 4.1.13 中的实例均为 8 字节；`VCChunkSize` 在 8 字节形态中**不存在**。

### 8.19 0x0015 — DrawNineGrid Cache Capability Set（`TS_DRAW_NINEGRID_CAPABILITYSET`）

- 章节：**[MS-RDPEGDI] 2.2.1.2（S80）**
- 方向：**仅 client → server**
- 定长：**12 字节**（由字段宽度推出；规范未固定该值）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_DRAWNINEGRIDCACHE (0x0015)` |
| 2 | 2 | `lengthCapability` | 定长 12（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `drawNineGridSupportLevel` | 0x00000000 NO_SUPPORT / 0x00000001 SUPPORTED（Rev 1 stream bitmap 订单）/ 0x00000002 SUPPORTED_REV2（Rev 2 stream bitmap 订单） |
| 8 | 2 | `drawNineGridCacheSize` | NineGrid 位图缓存最大尺寸（KB），当前服务端上限 **2560** |
| 10 | 2 | `drawNineGridCacheEntries` | 缓存最大条目数，当前服务端上限 **256** |

> 偏移校验：末字段结束 = 12 = 定长 12 ✔

### 8.20 0x0016 — Draw GDI+ Capability Set（`TS_DRAW_GDIPLUS_CAPABILITYSET`）

- 章节：**[MS-RDPEGDI] 2.2.1.3（S81）**
- 方向：client ⇄ server
- 定长：**40 字节**（由字段宽度推出；规范未固定该值）

> 只有客户端初始化 `GdipVersion` / `GdipCacheEntries` / `GdipCacheChunkSize` / `GdipImageCacheProperties`。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSTYPE_DRAWGDIPLUS (0x0016)` |
| 2 | 2 | `lengthCapability` | 定长 40（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `drawGDIPlusSupportLevel` | 0x00000000 `TS_DRAW_GDIPLUS_DEFAULT`（不支持）/ 0x00000001 `TS_DRAW_GDIPLUS_SUPPORTED` |
| 8 | 4 | `GdipVersion` | 底层 GDI+ 1.1 子系统 build 号；**仅 client→server 实例有效** |
| 12 | 4 | `drawGdiplusCacheLevel` | 0x00000000 CACHE_LEVEL_DEFAULT / 0x00000001 CACHE_LEVEL_ONE |
| 16 | 10 | `GdipCacheEntries` | `TS_GDIPLUS_CACHE_ENTRIES`（S82）：Graphics(2) Brush(2) Pen(2) Image(2) ImageAttributes(2)；上限 10/5/5/10/2 |
| 26 | 8 | `GdipCacheChunkSize` | `TS_GDIPLUS_CACHE_CHUNK_SIZE`（S83）：Graphics(2) Brush(2) Pen(2) ImageAttributes(2)；上限 512/2048/1024/64 字节 |
| 34 | 6 | `GdipImageCacheProperties` | `TS_GDIPLUS_IMAGE_CACHE_PROPERTIES`（S84）：ChunkSize(2) TotalSize(2) MaxSize(2)；上限 4096 B / 256 chunks / 128 chunks |

> 偏移校验：末字段结束 = 40 = 定长 40 ✔

### 8.21 0x0017 — Remote Programs Capability Set（RAIL）

- 章节：**[MS-RDPERP] 2.2.1.1.1（S85）**
- 方向：client ⇄ server
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

> 声明可通过 RAIL 静态虚拟通道通信。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `CapabilitySetType` | MUST = `CAPSTYPE_RAIL (0x0017)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `RailSupportLevel` | 位域（bit0 在左）：bit0 `S` = `TS_RAIL_LEVEL_SUPPORTED`；bit1 `L` = DOCKED_LANGBAR；bit2 `H` = SHELL_INTEGRATION；bit3 `I` = LANGUAGE_IME_SYNC；bit4 `C` = SERVER_TO_CLIENT_IME_SYNC；bit5 `M` = HIDE_MINIMIZED_APPS；bit6 `K` = WINDOW_CLOAKING；bit7 `E` = HANDSHAKE_EX。**S 为 0 时其余位 MUST 为 0** |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.22 0x0018 — Window List Capability Set

- 章节：**[MS-RDPERP] 2.2.1.1.2（S86）**
- 方向：client ⇄ server
- 定长：**11 字节**（由字段宽度推出；规范未固定该值）

> 声明支持 Windowing Alternate Secondary Drawing Orders。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `CapabilitySetType` | MUST = `CAPSTYPE_WINDOW (0x0018)` |
| 2 | 2 | `lengthCapability` | 定长 11（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `WndSupportLevel` | 0x00000000 NOT_SUPPORTED / 0x00000001 SUPPORTED / 0x00000002 SUPPORTED_EX（额外支持 CLIENTAREASIZE、RPCONTENT、ROOTPARENT 字段） |
| 8 | 1 | `NumIconCaches` | 图标缓存个数（Demand Active 为服务端请求值，Confirm Active 为客户端支持值） |
| 9 | 2 | `NumIconCacheEntries` | 每个图标缓存的条目数 |

> 偏移校验：末字段结束 = 11 = 定长 11 ✔

### 8.23 0x0019 — Desktop Composition Capability Set（`TS_COMPDESK_CAPABILITYSET`）

- 章节：**2.2.7.2.8（S35）**
- 方向：client ⇄ server
- 定长：**6 字节**（由字段宽度推出；规范未固定该值）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `0x0019`（`CAPSETTYPE_COMPDESK`） |
| 2 | 2 | `lengthCapability` | 定长 6（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `CompDeskSupportLevel` | 0x0000 `COMPDESK_NOT_SUPPORTED` / 0x0001 `COMPDESK_SUPPORTED` |

> 偏移校验：末字段结束 = 6 = 定长 6 ✔

### 8.24 0x001A — Multifragment Update Capability Set（`TS_MULTIFRAGMENTUPDATE_CAPABILITYSET`）

- 章节：**2.2.7.2.6（S33）**
- 方向：client ⇄ server
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

> 界定 Fast-Path Update 分片重组的缓冲上限。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSETTYPE_MULTIFRAGMENTUPDATE (26)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `MaxRequestSize` | 重组 Fast-Path Update 所用缓冲区大小；缓冲区必须足以容纳一个 update 的**全部**片段 |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

### 8.25 0x001B — Large Pointer Capability Set（`TS_LARGE_POINTER_CAPABILITYSET`）

- 章节：**2.2.7.2.7（S34）**
- 方向：client ⇄ server
- 定长：**6 字节**（由字段宽度推出；规范未固定该值）

> 启用大指针时双方 MUST 同时交换 Multifragment Update（2.2.7.2.6）。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSETTYPE_LARGE_POINTER (27)` |
| 2 | 2 | `lengthCapability` | 定长 6（由字段宽度推出；规范未固定该值） |
| 4 | 2 | `largePointerSupportFlags` | 0x0001 `LARGE_POINTER_FLAG_96x96`；0x0002 `LARGE_POINTER_FLAG_384x384`（含 Fast-Path Large Pointer Update） |

> 偏移校验：末字段结束 = 6 = 定长 6 ✔

### 8.26 0x001C — Surface Commands Capability Set（`TS_SURFCMDS_CAPABILITYSET`）

- 章节：**2.2.7.2.9（S36）**
- 方向：client ⇄ server
- 定长：**12 字节**（由字段宽度推出；规范未固定该值）

> 若客户端声明支持 surface commands，MUST 同时在 General 的 `extraFlags` 置 `FASTPATH_OUTPUT_SUPPORTED (0x0001)`。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `0x001C`（`CAPSETTYPE_SURFACE_COMMANDS`） |
| 2 | 2 | `lengthCapability` | 定长 12（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `cmdFlags` | 0x00000002 `SURFCMDS_SETSURFACEBITS` / 0x00000010 `SURFCMDS_FRAMEMARKER` / 0x00000040 `SURFCMDS_STREAMSURFACEBITS` |
| 8 | 4 | `reserved` | 保留，**MUST = 0** |

> 偏移校验：末字段结束 = 12 = 定长 12 ✔

### 8.27 0x001E — Frame Acknowledge Capability Set（`TS_FRAME_ACKNOWLEDGE_CAPABILITYSET`）

- 章节：**[MS-RDPRFX] 2.2.1.3（S87）**
- 方向：client ⇄ server
- 定长：**8 字节**（由字段宽度推出；规范未固定该值）

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `capabilitySetType` | MUST = `CAPSETTYPE_FRAME_ACKNOWLEDGE (0x001E)` |
| 2 | 2 | `lengthCapability` | 定长 8（由字段宽度推出；规范未固定该值） |
| 4 | 4 | `maxUnacknowledgedFrameCount` | 服务端可置 0（仅声明能收）；客户端给出可缓冲的 in-flight 帧数提示 |

> 偏移校验：末字段结束 = 8 = 定长 8 ✔

## 9. 枚举与位域明细

### 9.1 General.extraFlags（2.2.7.1.1，S13）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0001 | `FASTPATH_OUTPUT_SUPPORTED` | 声明方支持 fast-path 输出 |
| 0x0004 | `LONG_CREDENTIALS_SUPPORTED` | 支持 Save Session Info PDU 中的长用户名/密码/域（RDP 4.0/5.0 之外） |
| 0x0008 | `AUTORECONNECT_SUPPORTED` | 支持自动重连（5.5） |
| 0x0010 | `ENC_SALTED_CHECKSUM` | 支持 salted MAC 生成（5.3.6.1.1） |
| 0x0400 | `NO_BITMAP_COMPRESSION_HDR` | 支持省略 8 字节 Compressed Data Header |

> 0x0004 在 RDP 4.0/5.0 之外支持；0x0008 / 0x0010 在 RDP 4.0/5.0/5.1 之外支持（S13 原文分档）。

### 9.2 Bitmap.drawingFlags（2.2.7.1.2，S14）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x02 | `DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY` | 支持 32-bpp 位图逐像素降色保真度的有损压缩 |
| 0x04 | `DRAW_ALLOW_COLOR_SUBSAMPLING` | 支持色度抽样 |
| 0x08 | `DRAW_ALLOW_SKIP_ALPHA` | 支持压缩时去除 alpha 通道（alpha 视为 0xFF，即不透明） |
| 0x10 | `DRAW_UNUSED_FLAG` | 未使用；若出现在 server→client 的 Bitmap Capability Set 中，客户端 MUST 忽略 |

### 9.3 Order.orderFlags（2.2.7.1.3，S15）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0002 | `NEGOTIATEORDERSUPPORT` | 支持用 `orderSupport` 声明订单；**MUST 置位** |
| 0x0008 | `ZEROBOUNDSDELTASSUPPORT` | 支持 `TS_ZERO_BOUNDS_DELTAS (0x20)` 标志；**客户端 MUST 置位** |
| 0x0020 | `COLORINDEXSUPPORT` | 支持订单中发送颜色索引（而非 RGB 值） |
| 0x0040 | `SOLIDPATTERNBRUSHONLY` | 本端只能接收实心刷与图案刷 |
| 0x0080 | `ORDERFLAGS_EXTRA_FLAGS` | `orderSupportExFlags` 含有效数据 |

### 9.4 Order.orderSupport 索引表（2.2.7.1.3，S15）

`orderSupport` 是 32 字节数组，下标 = 主绘图订单协商索引；**支持则该字节 MUST 为 0x01**，不支持为 0x00。

| 索引 | 名称 | 对应主绘图订单（[MS-RDPEGDI] 2.2.2.2.1.1.2） |
|---:|---|---|
| 0x00 | `TS_NEG_DSTBLT_INDEX` | DstBlt |
| 0x01 | `TS_NEG_PATBLT_INDEX` | PatBlt + OpaqueRect |
| 0x02 | `TS_NEG_SCRBLT_INDEX` | ScrBlt |
| 0x03 | `TS_NEG_MEMBLT_INDEX` | MemBlt |
| 0x04 | `TS_NEG_MEM3BLT_INDEX` | Mem3Blt |
| 0x05 | `UnusedIndex1` | **MUST 忽略** |
| 0x06 | `UnusedIndex2` | **MUST 忽略** |
| 0x07 | `TS_NEG_DRAWNINEGRID_INDEX` | DrawNineGrid |
| 0x08 | `TS_NEG_LINETO_INDEX` | LineTo |
| 0x09 | `TS_NEG_MULTI_DRAWNINEGRID_INDEX` | MultiDrawNineGrid |
| 0x0A | `UnusedIndex3` | **MUST 忽略** |
| 0x0B | `TS_NEG_SAVEBITMAP_INDEX` | SaveBitmap |
| 0x0C | `UnusedIndex4` | **MUST 忽略** |
| 0x0D | `UnusedIndex5` | **MUST 忽略** |
| 0x0E | `UnusedIndex6` | **MUST 忽略** |
| 0x0F | `TS_NEG_MULTIDSTBLT_INDEX` | MultiDstBlt |
| 0x10 | `TS_NEG_MULTIPATBLT_INDEX` | MultiPatBlt |
| 0x11 | `TS_NEG_MULTISCRBLT_INDEX` | MultiScrBlt |
| 0x12 | `TS_NEG_MULTIOPAQUERECT_INDEX` | MultiOpaqueRect |
| 0x13 | `TS_NEG_FAST_INDEX_INDEX` | FastIndex |
| 0x14 | `TS_NEG_POLYGON_SC_INDEX` | PolygonSC + PolygonCB |
| 0x15 | `TS_NEG_POLYGON_CB_INDEX` | PolygonCB + PolygonSC |
| 0x16 | `TS_NEG_POLYLINE_INDEX` | Polyline |
| 0x17 | `UnusedIndex7` | **MUST 忽略** |
| 0x18 | `TS_NEG_FAST_GLYPH_INDEX` | FastGlyph |
| 0x19 | `TS_NEG_ELLIPSE_SC_INDEX` | EllipseSC + EllipseCB |
| 0x1A | `TS_NEG_ELLIPSE_CB_INDEX` | EllipseCB + EllipseSC |
| 0x1B | `TS_NEG_INDEX_INDEX` | GlyphIndex |
| 0x1C | `UnusedIndex8` | **MUST 忽略** |
| 0x1D | `UnusedIndex9` | **MUST 忽略** |
| 0x1E | `UnusedIndex10` | **MUST 忽略** |
| 0x1F | `UnusedIndex11` | **MUST 忽略** |

> 注意 `0x14` 与 `0x15`、`0x19` 与 `0x1A` 在规范原文中互相引用同一对订单——
> 这是原文写法（PolygonSC/PolygonCB 共用一对索引），不是笔误。

### 9.5 Input.inputFlags（2.2.7.1.6，S20）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0001 | `INPUT_FLAG_SCANCODES` | 支持 scancode 键盘事件；**至少此位 MUST 置位** |
| 0x0004 | `INPUT_FLAG_MOUSEX` | 支持扩展鼠标事件（button 4/5） |
| 0x0008 | `INPUT_FLAG_FASTPATH_INPUT` | RDP 5.0/5.1 服务端用于声明 fast-path 输入 |
| 0x0010 | `INPUT_FLAG_UNICODE` | 支持 Unicode 键盘事件 |
| 0x0020 | `INPUT_FLAG_FASTPATH_INPUT2` | RDP 4.0/5.0/5.1 之外的服务端声明 fast-path 输入 |
| 0x0040 | `INPUT_FLAG_UNUSED1` | 未使用；server→client 出现时客户端 MUST 忽略 |
| 0x0080 | `INPUT_FLAG_MOUSE_RELATIVE` | 相对鼠标模式；若 Client Core Data 协议版本 < 0x00080011 则服务端 MUST 忽略 |
| 0x0100 | `TS_INPUT_FLAG_MOUSE_HWHEEL` | 支持水平滚轮事件 |
| 0x0200 | `TS_INPUT_FLAG_QOE_TIMESTAMPS` | 支持 QoE 时间戳事件（仅 fast-path） |

> **规范原文缺陷**：官方 dump 4.1.12/4.1.13 的注解把 `0x0010` 标注为 `INPUT_FLAG_VKPACKET`，
> 但 2.2.7.1.6 正文的枚举名是 `INPUT_FLAG_UNICODE`。两者数值相同（0x0010），语义一致
> （均指 Unicode/虚拟键输入）。见 §15 U-04。

### 9.6 GlyphCache.GlyphSupportLevel（2.2.7.1.8，S22）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0000 | `GLYPH_SUPPORT_NONE` | 不支持字形缓存，文本以 Bitmap Update 发送 |
| 0x0001 | `GLYPH_SUPPORT_PARTIAL` | 支持 Rev 1 Cache Glyph 二级订单 |
| 0x0002 | `GLYPH_SUPPORT_FULL` | 支持 Rev 1 Cache Glyph 二级订单 |
| 0x0003 | `GLYPH_SUPPORT_ENCODE` | 支持 Rev 2 Cache Glyph 二级订单 |

> `PARTIAL` 与 `FULL` 的规范描述文字相同（均指 Rev 1 订单），这是原文表述，见 §15 U-05。

### 9.7 BitmapCacheRev2.CacheFlags（2.2.7.1.4.2，S17）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0001 | `PERSISTENT_KEYS_EXPECTED_FLAG` | 客户端将在 Connection Finalization 发 Persistent Key List PDU |
| 0x0002 | `ALLOW_CACHE_WAITING_LIST_FLAG` | 支持 cache waiting list（位图第二次命中才缓存） |

### 9.8 `TS_BITMAPCACHE_CELL_CACHE_INFO.CellInfo` 位域（2.2.7.1.4.2.1，S18）

| 位 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0–30 | 31 | `NumEntries` | 该缓存的条目数 |
| 31 | 1 | `k` | 1 = 该缓存跨连接持久，服务端 MUST 为每个插入的位图发送 64-bit key |

**编码等价式**（官方 dump 4.1.13 实测）：`CellInfo = (k << 31) | NumEntries`。
dump 中 `fb 09 00 80` → `0x800009FB` → `NumEntries = 0x9FB = 2555`、`k = TRUE`。


---

## 10. Deactivate All PDU

### 10.1 定位

> "The Deactivate All PDU is sent from server to client to indicate that the connection will be dropped
> or that a **capability re-exchange** using a Deactivation-Reactivation Sequence will occur."
> —— 2.2.3.1（S52）

1.3.1.3（S03）补充：

> "After the connection sequence has run to completion, the server can determine that the client has to be
> connected to an existing session. To accomplish this task the server signals the client with a
> Deactivate All PDU. ... If a capability re-exchange is required, then the **Capability Exchange and
> Connection Finalization phases** of the connection sequence are **re-executed**."

### 10.2 分层封装（2.2.3.1）

| 层 | 长度 | 字段 | 说明 |
|---|---:|---|---|
| 1 | 4 | `tpktHeader` | TPKT |
| 2 | 3 | `x224Data` | X.224 Data TPDU |
| 3 | var | `mcsSDin` | MCS Send Data Indication（**server → client**） |
| 4 | var | `securityHeader` | 可选（规则同 §2.3） |
| 5 | var | `deactivateAllPduData` | `TS_DEACTIVATE_ALL_PDU` |

### 10.3 TS_DEACTIVATE_ALL_PDU（2.2.3.1.1）

规范称其为 "a standard T.128 Deactivate All PDU（[T128] §8.4.1）"。**无 `sessionId`**，比 Demand Active 短。

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 2 | `shareControlHeader.totalLength` | LE16 |
| 2 | 2 | `shareControlHeader.pduType` | `type` MUST = `PDUTYPE_DEACTIVATEALLPDU (6)`，`PDUVersion` = 0x1 ⇒ 线上 **`0x0016`** |
| 4 | 2 | `shareControlHeader.pduSource` | LE16，server channel ID |
| 6 | 4 | `shareID` | LE32 |
| 10 | 2 | `lengthSourceDescriptor` | LE16 |
| 12 | var | `sourceDescriptor` | 变长；**SHOULD 为 `0x00`**（单字节 0） |

若 `sourceDescriptor` 取 SHOULD 值 `0x00`，则 `lengthSourceDescriptor = 1`、`totalLength = 13`，
线上 `totalLength` = `0x000D`。

> **`pduType = 0x0016` 的记忆法**：`0x0010 | 0x0006`。与 Confirm Active 的 `0x0013` 只差 type 位。

### 10.4 客户端处理规则（3.2.5.5.1，S65）

原文两条：

1. 按 2.2.3.1 的结构与 3.2.5.2 的通用处理技术解析该 PDU。
2. **处理完之后，客户端 MUST 关闭其图形与输入协议处理器**，并准备二选一：
   - **capability 重交换**（走 1.3.1.3 的 Deactivation-Reactivation Sequence），或
   - **断开连接**（客户端 MUST 准备好在此后、实际断开之前接收可选的 MCS Disconnect Provider Ultimatum PDU，3.1.5.1.2）。

> **注意"必须关闭 handler"这一条**：Deactivate All 之后到新的 Demand Active 之间，
> 不应再处理任何图形/输入 PDU。若此时收到图形 PDU，属于协议违规。

### 10.5 服务端发送后必须做的三选一（3.3.5.5.1，S66）

发出 Deactivate All 后，服务端 MUST 从下列三条中选一条：

1. 发 MCS Disconnect Provider Ultimatum PDU（3.1.5.1.1）告知断开来源（"user requested" / "provider initiated"），然后关闭连接。
2. 直接关闭连接（不发 Ultimatum，客户端将不知道断开来源）。
3. **重新执行连接序列**（从 Demand Active PDU 开始）以完成 capability 重交换。

### 10.6 Deactivation-Reactivation 对客户端状态的要求

综合 1.3.1.3（S03）+ 3.2.5.5.1（S65）：

| 状态项 | 重交换时是否保留 | 依据 |
|---|---|---|
| Server Capabilities store（3.2.1.7） | **必须重建**（新 Demand Active 覆盖） | 1.3.1.3 "Capability Exchange ... re-executed" |
| Share ID store（3.2.1.8） | **必须重建**（新 Demand Active 的 `shareID`） | 同上 |
| Server Channel ID store（3.2.1.6） | **必须重建**（新 Demand Active 的 `pduSource`） | 同上 |
| Session keys（3.2.1.12） | **保留**（Deactivate All 不重跑 Security Commencement） | 1.3.1.3 只说重跑 Capability Exchange + Connection Finalization |
| Static virtual channel IDs（3.2.1.2） | **保留**（不重跑 Channel Connection） | 同上 |
| Bitmap caches（3.2.1.13） | 视服务端是否重发 BitmapCache capability 而定 | 推论（B 级），见 §15 U-03 |
| Persisted bitmap keys（3.2.1.15） | **保留**；重交换后是否重发 Persistent Key List 取决于 `PERSISTENT_KEYS_EXPECTED_FLAG` | 2.2.1.17（S78）+ 3.2.5.3.17（S95） |

> 第 5–7 行含推断成分，已列入 §15。

---

## 11. Font List / Font Map PDU

### 11.1 时序位置（1.3.1.1，S02）

Connection Finalization 阶段的客户端发送顺序（顺序固定，但**可整批发送**——1.3.1.1（S02）：client→server
PDU 之间没有依赖，"they can be sent as a single batch, provided that sequencing is maintained"）：

```
Confirm Active
  → Synchronize
  → Control (Cooperate)
  → Control (Request Control)
  → [Persistent Key List]（可选，取决于服务端是否支持 Rev2 bitmap cache）
  → Font List
```

服务端方向：

```
Confirm Active 收到 → Synchronize
  → Control (Cooperate)
  → [收到 Request Control] → Control (Granted Control)
  → [收到 Font List] → Font Map        ← 连接序列的最后一个 PDU
```

> "The Font Map PDU is the **last PDU** in the connection sequence."（2.2.1.22，S56）

### 11.2 Client Font List PDU（2.2.1.18）

分层：`tpktHeader(4) | x224Data(3) | mcsSDrq(var) | securityHeader(var,可选) | fontListPduData(26 字节)`

**`fontListPduData` 固定 26 字节**（S54 明确标注 "fontListPduData (26 bytes)"）。

`TS_FONT_LIST_PDU`（2.2.1.18.1，S55）：

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 18 | `shareDataHeader` | `pduType.type` MUST = `PDUTYPE_DATAPDU (7)`；`pduType2` MUST = `PDUTYPE2_FONTLIST (39 = 0x27)` |
| 18 | 2 | `numberFonts` | LE16，**SHOULD = 0** |
| 20 | 2 | `totalNumFonts` | LE16，**SHOULD = 0** |
| 22 | 2 | `listFlags` | LE16，**SHOULD = 0x0003** = `FONTLIST_FIRST (0x0001)` + `FONTLIST_LAST (0x0002)` |
| 24 | 2 | `entrySize` | LE16，**SHOULD = 0x0032 (50)** |

### 11.3 Server Font Map PDU（2.2.1.22）

分层：`tpktHeader(4) | x224Data(3) | mcsSDin(var) | securityHeader(var,可选) | fontMapPduData(26 字节)`

`TS_FONT_MAP_PDU`（2.2.1.22.1，S57）：

| 偏移 | 长度 | 字段 | 说明 |
|---:|---:|---|---|
| 0 | 18 | `shareDataHeader` | `pduType.type` MUST = `PDUTYPE_DATAPDU (7)`；`pduType2` MUST = `PDUTYPE2_FONTMAP (40 = 0x28)` |
| 18 | 2 | `numberEntries` | LE16，**SHOULD = 0** |
| 20 | 2 | `totalNumEntries` | LE16，**SHOULD = 0** |
| 22 | 2 | `mapFlags` | LE16，**SHOULD = 0x0003** = `FONTMAP_FIRST (0x0001)` + `FONTMAP_LAST (0x0002)` |
| 24 | 2 | `entrySize` | LE16，**SHOULD = 0x0004 (4)** |

### 11.4 处理规则

客户端（3.2.5.3.22，S97）：

> "The contents of the `numberEntries`, `totalNumEntries`, `mapFlags`, and `entrySize` fields
> **MUST be ignored**."

服务端（3.3.5.3.18，S98）：

> "The contents of the `numberFonts`, `totalNumFonts`, `listFlags`, and `entrySize` fields
> **MUST be ignored**."

即：**这两个 PDU 的全部业务字段都被忽略，只起"阶段握手"作用**。
服务端处理完 Font List 后 MUST 发 Font Map；失败 → SHOULD 断链。

> 这与 Font Capability Set（0x000E）的 `fontSupportFlags` 配合：只有声明了
> `FONTSUPPORT_FONTLIST (0x0001)` 才走 Font List/Font Map 流程（2.2.7.2.5，S32 的 SHOULD 值）。
> 但 3.2.5.3.17（S95）的发送规则**未把该 flag 作为前置条件**（3.2.5.3.18 仅规定 `MUST NOT be compressed`）——见 §15 U-06。

---

## 12. 客户端能力交换状态机

### 12.1 状态定义

```
S0  INIT
S1  WAIT_DEMAND_ACTIVE
S2  WAIT_SERVER_SYNC
S3  FINALIZING
S4  ACTIVE
S5  DEACTIVATED
S6  CLOSED
```

### 12.2 状态迁移表

| 当前 | 事件 | 动作 | 下一状态 | 依据 |
|---|---|---|---|---|
| S0 | 收到 Licensing 完成（License Error PDU - Valid Client，或直接进入） | 进入能力交换等待 | S1 | 2.2.1.13.1（S06）"sent upon successful completion of the Licensing phase" |
| S1 | 收到 Demand Active PDU | ① 解密校验 → ② 长度一致性 → ③ 检查 `pduType.type == 1` → ④ 存 `pduSource` 到 Server Channel ID → ⑤ 存 capabilities 到 Server Capabilities → ⑥ 存 `shareID` → ⑦ 构造并发 Confirm Active | S2 | 3.2.5.3.13.1（S60） |
| S1 | 收到 Monitor Layout PDU（2.2.12.1，`pduType2 = 0x37`；服务端在 Demand Active 之后发） | 记录显示器布局；**状态不变**（不触发 Confirm Active 提前/推迟） | S1 | 1.3.1.1（S02）+ 2.2.12.1（S91） |
| S1 | Demand Active 长度不一致 / 解密失败 | **断链** | S6 | 3.2.5.3.13.1 |
| S1 | Demand Active `pduType.type != 1` | **忽略该 PDU**，留在 S1 | S1 | 3.2.5.3.13.1（"SHOULD be ignored"） |
| S2 | Confirm Active 已发出 | 依序发 Synchronize → Control(Cooperate) → Control(Request Control) → [Persistent Key List] → Font List；**发出 Confirm Active 后即获得 input 发送许可**（不必等 Server Synchronize） | S3 | 1.3.1.1（S02）+ 3.2.5.3.13.2（S61）+ 3.2.5.3.14–3.2.5.3.18 |
| S2 | 收到 Monitor Layout PDU（2.2.12.1，`pduType2 = 0x37`） | 记录显示器布局；**状态不变**（不推迟 Confirm Active，也不触发额外发送） | S2 | 1.3.1.1（S02）+ 2.2.12.1（S91） |
| S3 | 收到 Server Synchronize | 记录；**input 发送许可已在 S2 末尾获得**（不以此为许可起点） | S3 | 1.3.1.1；"Once the client has sent the Confirm Active PDU, it can start sending mouse and keyboard input" |
| S3 | 收到 Server Control (Cooperate) | 记录 | S3 | 1.3.1.1 |
| S3 | 收到 Server Control (Granted Control) | 记录；客户端获得控制权 | S3 | 1.3.1.1 |
| S3 | 收到 Font Map PDU | 记录；**服务端此后可开始发图形**；连接完成 | S4 | 1.3.1.1 + 2.2.1.22（S56） |
| S4 | 收到 Deactivate All PDU | **关闭图形与输入 handler**；清空 Server Capabilities / Share ID / Server Channel ID；准备重交换或断开 | S5 | 3.2.5.5.1（S65） |
| S5 | 收到新的 Demand Active PDU | 同 S1 的 ①–⑦（**不重跑** MCS / 安全 / Licensing） | S2 | 1.3.1.3（S03）"Capability Exchange and Connection Finalization phases ... re-executed" |
| S5 | 收到 MCS Disconnect Provider Ultimatum | 断开 | S6 | 3.2.5.5.1（S65） |
| S5 | 连接被关闭（无 Ultimatum） | 断开 | S6 | 3.3.5.5.1 第 2 条（S66） |
| 任意 | 收到 Set Error Info PDU（2.2.5.1，`pduType2 = 0x2F`，`pduSource` MUST = 0） | 记录 `errorInfo`（32 位错误码）；**状态不变**（该 PDU 只是服务端断链前的先导通知，不改变客户端状态机） | 不变 | 2.2.5.1（S90）+ 3.2.5.7.1 |
| 任意 | 收到 MCS Disconnect Provider Ultimatum | 断开 | S6 | 3.1.5.1.2 |
| 任意 | 收到与当前状态不符的 PDU（未在上表列出的 `(state, event)` 组合） | **忽略并告警**（不改状态） | 不变 | 工程防御（B 级）；见 §15 U-01 / U-08 |

**错序处置（通用兜底之外的明确规则）**：

| 错序情形 | 处置 | 理由 |
|---|---|---|
| S1 收到 Monitor Layout / Synchronize / Control / Font Map（尚未收到 Demand Active） | **忽略并告警** | 这些 PDU 依赖 Demand Active 建立的 Server Capabilities / Share ID / Server Channel ID store |
| S2 收到 Synchronize（Server）/ Control / Font Map（Confirm Active 尚未发出） | **忽略并告警**，仍留在 S2 | 服务端 Sync 的触发点是收到 Confirm Active（1.3.1.1） |
| S3 收到 Deactivate All | **正常处理**（转 S5），不算错序 | Deactivate All 可在任意已激活状态出现 |
| S5 收到 Confirm Active 之外的图形/输入 PDU | **忽略并告警** | Deactivate All 后 MUST 已关闭图形与输入 handler（3.2.5.5.1） |
| 任意状态收到第二次 Confirm Active 相关错序（S3/S4 收到 Demand Active） | **忽略并告警** | 只有 S1 / S5 是 Demand Active 的合法接收态 |

### 12.3 时序图

```
   服务端                                   客户端
     |                                        |
     |  (Licensing 完成)                       |
     |                                        |
     |--- Demand Active PDU ----------------->|  S1→S2
     |    pduType=0x0011                      |   · 解密/校验
     |    pduSource=0x03EA                    |   · 长度一致性
     |    shareID=0x000103EA                  |   · 存 Server Channel ID
     |    13 capabilities                     |   · 存 capabilities / shareID
     |                                        |   · 构造 Confirm Active
     |<-- Confirm Active PDU -----------------|  S2
     |    pduType=0x0013                      |
     |    pduSource=User Channel ID (1007)    |
     |    originatorID=0x03EA                 |
     |    shareID=0x000103EA                  |
     |    18 capabilities                     |
     |                                        |
     |--- Synchronize PDU ------------------->|  S3  (响应 Confirm Active)
     |<-- Synchronize PDU --------------------|  S3
     |<-- Control (Cooperate) PDU ------------|
     |<-- Control (Request Control) PDU ------|
     |<-- [Persistent Key List PDU(s)] -------|  (可选)
     |<-- Font List PDU ----------------------|
     |                                        |
     |--- Control (Cooperate) PDU ----------->|
     |--- Control (Granted Control) PDU ----->|  (响应 Request Control)
     |--- Font Map PDU ---------------------->|  S3→S4  连接完成
     |                                        |
     |=== 图形 / 输入数据流 =================>|
     |                                        |
     |--- Deactivate All PDU ---------------->|  S4→S5
     |    pduType=0x0016                      |   · 关闭图形/输入 handler
     |    sourceDescriptor=0x00               |   · 清空 capability/shareID 状态
     |                                        |
     |--- Demand Active PDU ----------------->|  S5→S2  (能力重交换)
     |        ...                             |
```

> **读图要点**：服务端 Synchronize 的触发点是**收到 Confirm Active**（1.3.1.1："The Server Synchronize PDU
> ... is sent in response to the Confirm Active PDU"），不是等客户端那 5 个 PDU 发完。
> 而客户端那 5 个 PDU 之间没有依赖，**可整批发送**（1.3.1.1："they can be sent as a single batch,
> provided that sequencing is maintained"），所以实机抓包的实际观测顺序可能与上图交错——
> 上图只表示**触发关系与先后约束**，不表示真实到达时刻。

### 12.4 状态机实现要点

1. **S1 的"忽略 vs 断链"必须区分**：`pduType` 不符 → 忽略；长度不符 → 断链（§4.4）。
2. **Confirm Active 必须在 Demand Active 处理成功后立即构造**，但**发送顺序**上它必须是
   Connection Finalization 那串 PDU 的**第一个**（Synchronize 紧随其后）。
3. **S5 不重跑安全层**：Deactivate All 不会触发新的 Security Commencement / MCS 连接。
   若实现把 S5 当作"全新连接"，会错误地重发 X.224 CRQ。
4. **S3 与 S4 的边界**：客户端在**发出 Confirm Active 之后**就可以发 input（3.2.5.3.13.2 明示
   "Once the client has successfully transmitted this PDU, input PDUs SHOULD be sent"），**不是**等收到
   Server Synchronize；但**服务端在收到 Font List 之后**才开始发图形（S02 明示）。两者不对称，不要统一处理。
5. **Font Map 是连接序列最后一个 PDU**，收到它才能认为 S4 达成。
6. **Monitor Layout PDU 不改变状态**：它在 Demand Active 之后由服务端发出（1.3.1.1），
   客户端只记录布局（2.2.12.1，S91），既不推迟 Confirm Active，也不触发额外发送。
7. **未列出的 `(state, event)` 组合一律忽略并告警**（不改状态），只有上表"错序处置"列出的
   情形才按该表执行；任何情况下都不要因未知/错序 PDU 而改变状态或断链。

### 12.5 定时器

规范只定义了一个与本阶段相关的定时器（3.2.6.1，S92；计时来源 3.2.2.1，S93）：

| 定时器 | 时长 | 起点 | 到期行为 | 依据 |
|---|---:|---|---|---|
| Connection Sequence Timeout Timer（客户端侧） | **300 s** | 客户端首次向服务端发送网络流量时（Connection Start Time store，3.2.1.16） | 客户端 **MAY** 终止连接（原文 "the client MAY terminate the connection"） | 3.2.6.1（S92）+ 3.2.2.1（S93） |

> **强度是 MAY，不是 MUST**（`bcgr.txt:7634`："In this event the client MAY terminate the connection to the server."）。
> 实现可以自行选择更短的本地超时，但**不得**把它写成规范要求的 MUST。
> 本文件其他各处（如 U-06 等 Font Map 未到达）所说的"按超时处理"，均指本小节的 300 s 定时器。

---

## 13. 十六进制 dump 与逐字节注解

本章给出 4 组**官方规范提供的** dump，全部来自 [MS-RDPBCGR] §4 的 "Annotated Connection Sequence"：

| # | 内容 | 规范小节 | 来源编号 |
|---|---|---|---|
| 13.1 | Server Demand Active PDU（解密后明文，359 字节） | 4.1.12 | S70 |
| 13.2 | Client Confirm Active PDU（解密后明文，492 字节） | 4.1.13 | S71 |
| 13.3 | Client Font List PDU + Server Font Map PDU（各 26 字节） | 4.1.18 / 4.1.22 | S72 / S73 |
| 13.4 | Fast-Path Input Event PDU（完整线上字节，17 字节） | 4.7 | S74 |
| 13.5 | 13.1 的外层封装（用于说明三层长度口径） | 4.1.12 | S70 |

> 这 4 组都是**规范原文提供的示例**，不是按结构推导的合成向量。
> 13.1 / 13.2 / 13.3 是"解密后的明文"（规范原文即如此给出），13.4 是完整线上字节。

### 13.1 dump #1 — Server Demand Active PDU（[MS-RDPBCGR] 4.1.12，S70）

> 来源：官方规范 §4.1.12 注解 dump（Microsoft RDP 5.1 client ↔ RDP 5.1 server）。
> 下表的十六进制是 dump 中 **解密后的 `TS_DEMAND_ACTIVE_PDU` 明文**（359 字节），
> 不含 TPKT / X.224 / MCS / securityHeader。外层封装见 §13.5。

```
00000000  67 01 11 00 ea 03 ea 03 01 00 04 00 51 01 52 44  g...........Q.RD
00000010  50 00 0d 00 00 00 09 00 08 00 ea 03 dc e2 01 00  P...............
00000020  18 00 01 00 03 00 00 02 00 00 00 00 1d 04 00 00  ................
00000030  00 00 00 00 01 01 14 00 08 00 02 00 00 00 16 00  ................
00000040  28 00 00 00 00 00 70 f6 13 f3 01 00 00 00 01 00  (.....p.........
00000050  00 00 18 00 00 00 9c f6 13 f3 61 a6 82 80 00 00  ..........a.....
00000060  00 00 00 50 91 bf 0e 00 04 00 02 00 1c 00 18 00  ...P............
00000070  01 00 01 00 01 00 00 05 00 04 00 00 01 00 01 00  ................
00000080  00 00 01 00 00 00 03 00 58 00 00 00 00 00 00 00  ........X.......
00000090  00 00 00 00 00 00 00 00 00 00 40 42 0f 00 01 00  ..........@B....
000000a0  14 00 00 00 01 00 00 00 22 00 01 01 01 01 01 00  ........".......
000000b0  00 01 01 01 01 01 00 00 00 01 01 01 01 01 01 01  ................
000000c0  01 00 01 01 01 01 00 00 00 00 a1 06 00 00 40 42  ..............@B
000000d0  0f 00 40 42 0f 00 01 00 00 00 00 00 00 00 0a 00  ..@B............
000000e0  08 00 06 00 00 00 12 00 08 00 01 00 00 00 08 00  ................
000000f0  0a 00 01 00 19 00 19 00 0d 00 58 00 35 00 00 00  ..........X.5...
00000100  a1 06 00 00 40 42 0f 00 0c f6 13 f3 93 5a 37 f3  ....@B.......Z7.
00000110  00 90 30 e1 34 1c 38 f3 40 f6 13 f3 04 00 00 00  ..0.4.8.@.......
00000120  4c 54 dc e2 08 50 dc e2 01 00 00 00 08 50 dc e2  LT...P.......P..
00000130  00 00 00 00 38 f6 13 f3 2e 05 38 f3 08 50 dc e2  ....8.....8..P..
00000140  2c f6 13 f3 00 00 00 00 08 00 0a 00 01 00 19 00  ,...............
00000150  17 00 08 00 00 00 00 00 18 00 0b 00 00 00 00 00  ................
00000160  00 00 00 00 00 00 00                             .......
```

| 偏移 | 字节 | 字段 | 值 / 说明 |
|---:|---|---|---|
| 0 (0x000) | 2 | `TS_SHARECONTROLHEADER.totalLength` | `67 01` — 0x0167 = 359 |
| 2 (0x002) | 2 | `TS_SHARECONTROLHEADER.pduType` | `11 00` — 0x0011 = TS_PROTOCOL_VERSION(0x10) OR PDUTYPE_DEMANDACTIVEPDU(1) |
| 4 (0x004) | 2 | `TS_SHARECONTROLHEADER.pduSource` | `ea 03` — 0x03EA = 1002（MCS server channel） |
| 6 (0x006) | 4 | `TS_DEMAND_ACTIVE_PDU.shareID` | `ea 03 01 00` — 0x000103EA |
| 10 (0x00a) | 2 | `lengthSourceDescriptor` | `04 00` — 4 |
| 12 (0x00c) | 2 | `lengthCombinedCapabilities` | `51 01` — 0x0151 = 337 = 4 + Σ lengthCapability(333) |
| 14 (0x00e) | 4 | `sourceDescriptor` | `52 44 50 00` — "RDP" + NUL |
| 18 (0x012) | 2 | `numberCapabilities` | `0d 00` — 13 |
| 20 (0x014) | 2 | `pad2Octets` | `00 00` — 0 |
| 22 (0x016) | 8 | `capability[0] type=0x0009 Share` | `09 00 08 00 ea 03 dc e2` — lengthCapability=8；nodeID=0x03EA, pad2octets=0xE2DC |
| 30 (0x01e) | 24 | `capability[1] type=0x0001 General` | `01 00 18 00 01 00 03 00 ... 00 00 01 01` — lengthCapability=24；osMajor=1(WINDOWS) osMinor=3(WINDOWS_NT) protocolVersion=0x0200 extraFlags=0x041D refreshRect=1 suppressOutput=1 |
| 54 (0x036) | 8 | `capability[2] type=0x0014 VirtualChannel` | `14 00 08 00 02 00 00 00` — lengthCapability=8；flags=0x00000002 (VCCAPS_COMPR_CS_8K) |
| 62 (0x03e) | 40 | `capability[3] type=0x0016 DrawGdiPlus` | `16 00 28 00 00 00 00 00 ... 00 50 91 bf` — lengthCapability=40；drawGDIPlusSupportLevel=0, GdipVersion/drawGdiplusCacheLevel=1, 其余字段服务端未初始化 |
| 102 (0x066) | 4 | `capability[4] type=0x000e Font` | `0e 00 04 00` — lengthCapability=4；**lengthCapability=4（服务端 bug，规范值 8）**，fontSupportFlags 与 pad2octets 缺失 |
| 106 (0x06a) | 28 | `capability[5] type=0x0002 Bitmap` | `02 00 1c 00 18 00 01 00 ... 01 00 00 00` — lengthCapability=28；preferredBitsPerPixel=24, desktop=1280x1024, bitmapCompressionFlag=TRUE, multipleRectangleSupport=TRUE |
| 134 (0x086) | 88 | `capability[6] type=0x0003 Order` | `03 00 58 00 00 00 00 00 ... 00 00 00 00` — lengthCapability=88；orderFlags=0x0022 (COLORINDEXSUPPORT OR NEGOTIATEORDERSUPPORT), desktopSaveSize=1000000 |
| 222 (0x0de) | 8 | `capability[7] type=0x000a ColorCache` | `0a 00 08 00 06 00 00 00` — lengthCapability=8；colorTableCacheSize=6 |
| 230 (0x0e6) | 8 | `capability[8] type=0x0012 BmpCacheHostSupport` | `12 00 08 00 01 00 00 00` — lengthCapability=8；cacheVersion=1 (Rev2) |
| 238 (0x0ee) | 10 | `capability[9] type=0x0008 Pointer` | `08 00 0a 00 01 00 19 00 19 00` — lengthCapability=10；colorPointerFlag=TRUE, colorPointerCacheSize=25, pointerCacheSize=25 |
| 248 (0x0f8) | 88 | `capability[10] type=0x000d Input` | `0d 00 58 00 35 00 00 00 ... 01 00 19 00` — lengthCapability=88；inputFlags=0x0035 (FASTPATH_INPUT2 OR UNICODE OR MOUSEX OR SCANCODES), keyboardLayout/Type/SubType/FunctionKey/imeFileName 服务端未初始化 |
| 336 (0x150) | 8 | `capability[11] type=0x0017 Rail` | `17 00 08 00 00 00 00 00` — lengthCapability=8；railSupportLevel=0 |
| 344 (0x158) | 11 | `capability[12] type=0x0018 Window` | `18 00 0b 00 00 00 00 00 00 00 00` — lengthCapability=11；wndSupportLevel=0, nIconCaches=0, nIconCacheEntries=0 |
| 355 (0x163) | 4 | `TS_DEMAND_ACTIVE_PDU.sessionId` | `00 00 00 00` — 0（被客户端忽略） |

**长度自洽**：`totalLength = 22 + 333 + 4 = 359` ✔（capabilitySets 起于 0x16，13 个 capability 合计 333 字节，
末尾 4 字节 `sessionId`）。`lengthCombinedCapabilities = 4 + 333 = 337 = 0x0151` ✔。

### 13.2 dump #2 — Client Confirm Active PDU（[MS-RDPBCGR] 4.1.13，S71）

> 来源：官方规范 §4.1.13 注解 dump。下表是 dump 中 **解密后的 `TS_CONFIRM_ACTIVE_PDU` 明文**（492 字节）。

```
00000000  ec 01 13 00 ef 03 ea 03 01 00 ea 03 06 00 d6 01  ................
00000010  4d 53 54 53 43 00 12 00 00 00 01 00 18 00 01 00  MSTSC...........
00000020  03 00 00 02 00 00 00 00 1d 04 00 00 00 00 00 00  ................
00000030  00 00 02 00 1c 00 18 00 01 00 01 00 01 00 00 05  ................
00000040  00 04 00 00 01 00 01 00 00 00 01 00 00 00 03 00  ................
00000050  58 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  X...............
00000060  00 00 00 00 00 00 01 00 14 00 00 00 01 00 00 00  ................
00000070  2a 00 01 01 01 01 01 00 00 01 01 01 00 01 00 00  *...............
00000080  00 01 01 01 01 01 01 01 01 00 01 01 01 00 00 00  ................
00000090  00 00 a1 06 00 00 00 00 00 00 00 84 03 00 00 00  ................
000000a0  00 00 e4 04 00 00 13 00 28 00 03 00 00 03 78 00  ........(.....x.
000000b0  00 00 78 00 00 00 fb 09 00 80 00 00 00 00 00 00  ..x.............
000000c0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00  ................
000000d0  08 00 06 00 00 00 07 00 0c 00 00 00 00 00 00 00  ................
000000e0  00 00 05 00 0c 00 00 00 00 00 02 00 02 00 08 00  ................
000000f0  0a 00 01 00 14 00 15 00 09 00 08 00 00 00 00 00  ................
00000100  0d 00 58 00 15 00 20 00 09 04 00 00 04 00 00 00  ..X... .........
00000110  00 00 00 00 0c 00 00 00 00 00 00 00 00 00 00 00  ................
00000120  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000130  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000140  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000150  00 00 00 00 00 00 00 00 0c 00 08 00 01 00 00 00  ................
00000160  0e 00 08 00 01 00 00 00 10 00 34 00 fe 00 04 00  ..........4.....
00000170  fe 00 04 00 fe 00 08 00 fe 00 08 00 fe 00 10 00  ................
00000180  fe 00 20 00 fe 00 40 00 fe 00 80 00 fe 00 00 01  .. ...@.........
00000190  40 00 00 08 00 01 00 01 03 00 00 00 0f 00 08 00  @...............
000001a0  01 00 00 00 11 00 0c 00 01 00 00 00 00 1e 64 00  ..............d.
000001b0  14 00 08 00 01 00 00 00 15 00 0c 00 02 00 00 00  ................
000001c0  00 0a 00 01 16 00 28 00 00 00 00 00 00 00 00 00  ......(.........
000001d0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001e0  00 00 00 00 00 00 00 00 00 00 00 00              ............
```

| 偏移 | 字节 | 字段 | 值 / 说明 |
|---:|---|---|---|
| 0 (0x000) | 2 | `TS_SHARECONTROLHEADER.totalLength` | `ec 01` — 0x01EC = 492 |
| 2 (0x002) | 2 | `TS_SHARECONTROLHEADER.pduType` | `13 00` — 0x0013 = TS_PROTOCOL_VERSION OR PDUTYPE_CONFIRMACTIVEPDU(3) |
| 4 (0x004) | 2 | `TS_SHARECONTROLHEADER.pduSource` | `ef 03` — 0x03EF = 1007（**User Channel ID**） |
| 6 (0x006) | 4 | `shareID` | `ea 03 01 00` — 0x000103EA（回填 Demand Active 的 shareID） |
| 10 (0x00a) | 2 | `originatorID` | `ea 03` — 0x03EA（MUST = server channel ID） |
| 12 (0x00c) | 2 | `lengthSourceDescriptor` | `06 00` — 6 |
| 14 (0x00e) | 2 | `lengthCombinedCapabilities` | `d6 01` — 0x01D6 = 470 = 4 + Σ lengthCapability(466) |
| 16 (0x010) | 6 | `sourceDescriptor` | `4d 53 54 53 43 00` — "MSTSC" + NUL |
| 22 (0x016) | 2 | `numberCapabilities` | `12 00` — 18 |
| 24 (0x018) | 2 | `pad2Octets` | `00 00` — 0 |
| 26 (0x01a) | 24 | `capability[0] type=0x0001 General` | `01 00 18 00 01 00 03 00 ... 00 00 00 00` — lengthCapability=24；extraFlags=0x041D；**refreshRectSupport=0、suppressOutputSupport=0**（客户端置 0，与 Demand Active 的 1 形成对比） |
| 50 (0x032) | 28 | `capability[1] type=0x0002 Bitmap` | `02 00 1c 00 18 00 01 00 ... 01 00 00 00` — lengthCapability=28；preferredBitsPerPixel=24, desktop=1280x1024 |
| 78 (0x04e) | 88 | `capability[2] type=0x0003 Order` | `03 00 58 00 00 00 00 00 ... e4 04 00 00` — lengthCapability=88；orderFlags=0x002A（含 ZEROBOUNDSDELTASSUPPORT，客户端 MUST 置位）, textANSICodePage=0x04E4(1252) |
| 166 (0x0a6) | 40 | `capability[3] type=0x0013 BitmapCacheRev2` | `13 00 28 00 03 00 00 03 ... 00 00 00 00` — lengthCapability=40；CacheFlags=0x0003, NumCellCaches=3, Cache2CellInfo=0x800009FB（k=TRUE, NumEntries=2555） |
| 206 (0x0ce) | 8 | `capability[4] type=0x000a ColorCache` | `0a 00 08 00 06 00 00 00` — lengthCapability=8；colorTableCacheSize=6 |
| 214 (0x0d6) | 12 | `capability[5] type=0x0007 Activation` | `07 00 0c 00 00 00 00 00 00 00 00 00` — lengthCapability=12；全部 0 |
| 226 (0x0e2) | 12 | `capability[6] type=0x0005 Control` | `05 00 0c 00 00 00 00 00 02 00 02 00` — lengthCapability=12；controlInterest=2, detachInterest=2 |
| 238 (0x0ee) | 10 | `capability[7] type=0x0008 Pointer` | `08 00 0a 00 01 00 14 00 15 00` — lengthCapability=10；colorPointerCacheSize=20, pointerCacheSize=21 |
| 248 (0x0f8) | 8 | `capability[8] type=0x0009 Share` | `09 00 08 00 00 00 00 00` — lengthCapability=8；nodeID=0（客户端置 0） |
| 256 (0x100) | 88 | `capability[9] type=0x000d Input` | `0d 00 58 00 15 00 20 00 ... 00 00 00 00` — lengthCapability=88；inputFlags=0x0015 (UNICODE OR MOUSEX OR SCANCODES), keyboardLayout=0x00000409, keyboardType=4, keyboardFunctionKey=12 |
| 344 (0x158) | 8 | `capability[10] type=0x000c Sound` | `0c 00 08 00 01 00 00 00` — lengthCapability=8；soundFlags=0x0001 (SOUND_FLAG_BEEPS) |
| 352 (0x160) | 8 | `capability[11] type=0x000e Font` | `0e 00 08 00 01 00 00 00` — lengthCapability=8；fontSupportFlags=0x0001 (FONTSUPPORT_FONTLIST) |
| 360 (0x168) | 52 | `capability[12] type=0x0010 GlyphCache` | `10 00 34 00 fe 00 04 00 ... 03 00 00 00` — lengthCapability=52；GlyphCache[0..8]: 254 条目；[9]: 64 条目；FragCache: 256/256；GlyphSupportLevel=3 (ENCODE) |
| 412 (0x19c) | 8 | `capability[13] type=0x000f Brush` | `0f 00 08 00 01 00 00 00` — lengthCapability=8；brushSupportLevel=1 (BRUSH_COLOR_8x8) |
| 420 (0x1a4) | 12 | `capability[14] type=0x0011 Offscreen` | `11 00 0c 00 01 00 00 00 00 1e 64 00` — lengthCapability=12；offscreenSupportLevel=1, cacheSize=7680 KB, cacheEntries=100 |
| 432 (0x1b0) | 8 | `capability[15] type=0x0014 VirtualChannel` | `14 00 08 00 01 00 00 00` — lengthCapability=8；flags=0x00000001 (VCCAPS_COMPR_SC) |
| 440 (0x1b8) | 12 | `capability[16] type=0x0015 DrawNineGrid` | `15 00 0c 00 02 00 00 00 00 0a 00 01` — lengthCapability=12；supportLevel=2 (SUPPORTED_REV2), cacheSize=2560 KB, entries=256 |
| 452 (0x1c4) | 40 | `capability[17] type=0x0016 DrawGdiPlus` | `16 00 28 00 00 00 00 00 ... 00 00 00 00` — lengthCapability=40；全部 0（客户端不支持 GDI+ 1.1） |

**长度自洽**：`totalLength = 26 + 466 = 492` ✔（capabilitySets 起于 0x1A = 26，18 个 capability 合计 466 字节，
恰好到文件末尾，**无尾部字段**——Confirm Active 没有 `sessionId`）。
`lengthCombinedCapabilities = 4 + 466 = 470 = 0x01D6` ✔。

### 13.3 dump #3 — Client Font List PDU 与 Server Font Map PDU（[MS-RDPBCGR] 4.1.18 / 4.1.22，S72 / S73）

**Font List（客户端 → 服务端，26 字节明文）**

```
00000000  1a 00 17 00 ef 03 ea 03 01 00 00 01 3b da 27 00  ............;.'.
00000010  00 00 00 00 00 00 03 00 32 00                    ........2.
```

| 偏移 | 字节 | 字段 | 值 / 说明 |
|---:|---|---|---|
| 0 | 2 | `totalLength` | `1a 00` — 0x001A = 26 |
| 2 | 2 | `pduType` | `17 00` — 0x0017 = TS_PROTOCOL_VERSION OR PDUTYPE_DATAPDU(7) |
| 4 | 2 | `pduSource` | `ef 03` — 0x03EF = 1007（User Channel ID） |
| 6 | 4 | `shareID` | `ea 03 01 00` — 0x000103EA |
| 10 | 1 | `pad1` | `00` — 0 |
| 11 | 1 | `streamID` | `01` — 0x01 = STREAM_LOW |
| 12 | 2 | `uncompressedLength` | `3b da` — 0xDA3B（**服务端 bug，未初始化**） |
| 14 | 1 | `pduType2` | `27` — 0x27 = PDUTYPE2_FONTLIST(39) |
| 15 | 1 | `compressedType` | `00` — 0 |
| 16 | 2 | `compressedLength` | `00 00` — 0 |
| 18 | 2 | `numberFonts` | `00 00` — 0（SHOULD） |
| 20 | 2 | `totalNumFonts` | `00 00` — 0（SHOULD） |
| 22 | 2 | `listFlags` | `03 00` — 0x0003 = FONTLIST_FIRST OR FONTLIST_LAST |
| 24 | 2 | `entrySize` | `32 00` — 0x0032 = 50（SHOULD） |

**Font Map（服务端 → 客户端，26 字节明文）**

```
00000000  1a 00 17 00 ea 03 ea 03 01 00 45 02 1a 00 28 00  ..........E...(.
00000010  00 00 00 00 00 00 03 00 04 00                    ..........
```

| 偏移 | 字节 | 字段 | 值 / 说明 |
|---:|---|---|---|
| 0 | 2 | `totalLength` | `1a 00` — 0x001A = 26 |
| 2 | 2 | `pduType` | `17 00` — 0x0017 = TS_PROTOCOL_VERSION OR PDUTYPE_DATAPDU(7) |
| 4 | 2 | `pduSource` | `ea 03` — 0x03EA = 1002（server channel ID） |
| 6 | 4 | `shareID` | `ea 03 01 00` — 0x000103EA |
| 10 | 1 | `pad1` | `45` — 0x45（**未初始化，MUST 忽略**） |
| 11 | 1 | `streamID` | `02` — 0x02 = STREAM_MED |
| 12 | 2 | `uncompressedLength` | `1a 00` — 0x001A = 26 |
| 14 | 1 | `pduType2` | `28` — 0x28 = PDUTYPE2_FONTMAP(40) |
| 15 | 1 | `compressedType` | `00` — 0 |
| 16 | 2 | `compressedLength` | `00 00` — 0 |
| 18 | 2 | `numberEntries` | `00 00` — 0（SHOULD） |
| 20 | 2 | `totalNumEntries` | `00 00` — 0（SHOULD） |
| 22 | 2 | `mapFlags` | `03 00` — 0x0003 = FONTMAP_FIRST OR FONTMAP_LAST |
| 24 | 2 | `entrySize` | `04 00` — 0x0004 = 4（SHOULD） |

> **两个 dump 的关键差异**：`pad1` 在 Font List 中是 0，在 Font Map 中是 0x45。
> 这直接印证 §2.2 的"`pad1` MUST 被忽略"——它不是保留位，任何值都合法。
> `streamID` 也不同（LOW vs MED），说明 streamID 不参与语义判断。

### 13.4 dump #4 — Fast-Path Input Event PDU（[MS-RDPBCGR] 4.7，S74）

> 来源：官方规范 §4.7 注解 dump。这是**线上字节 + 解密后载荷**（17 字节，无 TPKT/X.224/MCS 封装）：
> 前 10 字节（`fpInputHeader` / `length1` / `dataSignature`）是线上原样字节，后 7 字节是**解密后**的
> `fpInputEvents` 明文，**不是**线上密文——线上该 7 字节为 `26 18 5e 76 0e de 28`（与 §3.4 的 dump 一致）。

```
00000000  c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de  ..05k[.4.G&.^v..
00000010  28                                                 (
```

| 偏移 | 字节 | 字段 | 值 / 说明 |
|---:|---|---|---|
| 0 | 1 | `TS_FP_INPUT_PDU.fpInputHeader` | `c4` — 0xC4 = 0b1100_0100；位 0–1 `action`=0（FASTPATH_INPUT_ACTION_FASTPATH）；位 2–5 `numEvents`=1；位 6–7 `flags`=3（SECURE_CHECKSUM OR ENCRYPTED） |
| 1 | 1 | `length1` | `11` — 0x11 = 17；MSB=0 ⇒ **无 length2**，总长即 17 |
| 2 | 8 | `dataSignature` | `30 35 6b 5b b5 34 c8 47` — 8 字节 MAC（salted，因 flags 含 SECURE_CHECKSUM） |
| 10 | 7 | `fpInputEvents（密文）` | `26 18 5e 76 0e de 28` — 7 字节加密载荷（与 §3.4 的 dump 一致） |

解密后的 `fpInputEvents`（7 字节）：

```
00000000  20 00 08 ab 02 6f 01                              ....o.
```

| 偏移 | 字节 | 字段 | 值 / 说明 |
|---:|---|---|---|
| 0 | 1 | `TS_FP_INPUT_EVENT.eventHeader` | `20` — 0x20 = 0b0010_0000；bit0–4 `eventFlags`=0（鼠标事件 MUST 为 0），bit5–7 `eventCode`=(0x20>>5)=1（FASTPATH_INPUT_EVENT_MOUSE） |
| 1 | 2 | `TS_FP_POINTER_EVENT.pointerFlags` | `00 08` — 0x0800 = PTRFLAGS_MOVE |
| 3 | 2 | `xPos` | `ab 02` — 0x02AB = 683 |
| 5 | 2 | `yPos` | `6f 01` — 0x016F = 367 |

**长度自洽**：`1 (fpInputHeader) + 1 (length1) + 8 (MAC) + 7 (events) = 17 = 0x11 = length1` ✔。


---

### 13.5 外层封装对照（dump #1 的长度口径）

dump #1 的 `TS_DEMAND_ACTIVE_PDU` 明文外面还包了 4 层。规范 §4.1.12（S70）给出的完整线上字节如下
（此处只列头部与尾部，中间密文省略）：

```
03 00 01 82   TPKT Header (length = 0x0182 = 386)
02 f0 80      X.224 Data TPDU (LI=2, code=0xF0, EOT=0x80)
68 00 01 03 eb 70 81 73
              PER encoded (ALIGNED variant of BASIC-PER) SendDataIndication
              initiator = 1002 (0x03EA)
              channelId = 1003 (0x03EB)
              dataPriority = high
              segmentation = begin | end
              userData length = 0x173 = 371 bytes
08 00         TS_SECURITY_HEADER::flags = 0x0008 = SEC_ENCRYPT
02 03         TS_SECURITY_HEADER::flagsHi — ignored as flags does not contain
              SEC_FLAGSHI_VALID (0x8000)
56 02 e1 47 ac 5c 50 d9
              TS_SECURITY_HEADER1::dataSignature
72 f9 c3 32 ... 81 48
              Encrypted TS_DEMAND_ACTIVE_PDU (359 bytes)
```

**逐层长度校验**：

| 层 | 起始偏移 | 长度 | 累计 | 依据 |
|---|---:|---:|---:|---|
| TPKT Header | 0 | 4 | 4 | [T123] §8，`length` 含头 |
| X.224 Data TPDU | 4 | 3 | 7 | [X224] §13.7 |
| MCS SendDataIndication 头 | 7 | 8 | 15 | [T125] §11.33；`userData length = 0x173` |
| securityHeader（Basic 4 + MAC 8） | 15 | 12 | 27 | 2.2.8.1.1.2.1 + 2.2.8.1.1.2.2 |
| 加密的 TS_DEMAND_ACTIVE_PDU | 27 | 359 | **386** | 2.2.1.13.1.1 |

`386 = 0x0182` = TPKT length ✔；`4 + 8 + 359 = 371 = 0x173` = MCS userData length ✔。

> **口径结论**（写进实现的三条）：
> 1. `TS_SHARECONTROLHEADER.totalLength` 从**它自己**开始算，不含 TPKT/X.224/MCS/securityHeader。
>    本例 `totalLength = 0x0167 = 359` = 明文全长。
> 2. `mcsSDin` 的 `userData length` 从 **securityHeader 首字节**开始算，含 securityHeader。
>    本例 `0x173 = 371 = 12 + 359`。
> 3. TPKT `length` 从 TPKT 首字节开始算，含全部。
>    本例 `0x0182 = 386 = 4 + 3 + 8 + 12 + 359`。
>
> 三者互不重叠、层层包含。混淆任意两个都会导致长度校验失败。

---

## 14. 验证证据（可复现）

### 14.1 独立长度模型 vs 官方 dump（先红后绿）

为排除"照抄规范表格但算错偏移"的风险，本文件用一份**独立的长度模型**（只声明每个字段的字节宽度，
偏移由累加得出）去**反向遍历**官方 dump 4.1.12 / 4.1.13 的 `capabilitySets`，
并要求：每个 `lengthCapability` 与模型预测一致、遍历终点与 `totalLength` 精确相等。

脚本：`F:\rtsc\evidence\capabilities\verify_caps.py`（归档副本；运行时需先把官方 DOCX 抽成
`F:\rtsc\.tmp\bcgr.txt`，抽取脚本见 `F:\rtsc\evidence\capabilities\docx2txt.py`）。

```
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
python F:\rtsc\evidence\capabilities\verify_caps.py
```

**输出（实测）**：

```
--- Demand Active [BCGR 4.1.12]  totalLength=359  numberCapabilities=13  capStart=0x16  tail=4
  cap[ 0] @0x016 type=0x0009 Share             len=8   expect=8   PASS  BCGR 2.2.7.2.4
  cap[ 1] @0x01e type=0x0001 General           len=24  expect=24  PASS  BCGR 2.2.7.1.1
  cap[ 2] @0x036 type=0x0014 VirtualChannel    len=8   expect=8   PASS  BCGR 2.2.7.1.10
  cap[ 3] @0x03e type=0x0016 DrawGdiPlus       len=40  expect=40  PASS  EGDI 2.2.1.3
  cap[ 4] @0x066 type=0x000e Font              len=4   expect=8   PASS* BCGR 2.2.7.2.5 DOCUMENTED-DEVIATION(server bug, len 4 not 8)
  cap[ 5] @0x06a type=0x0002 Bitmap            len=28  expect=28  PASS  BCGR 2.2.7.1.2
  cap[ 6] @0x086 type=0x0003 Order             len=88  expect=88  PASS  BCGR 2.2.7.1.3
  cap[ 7] @0x0de type=0x000a ColorCache        len=8   expect=8   PASS  EGDI 2.2.1.1
  cap[ 8] @0x0e6 type=0x0012 BmpCacheHost      len=8   expect=8   PASS  BCGR 2.2.7.2.1
  cap[ 9] @0x0ee type=0x0008 Pointer           len=10  expect=10  PASS  BCGR 2.2.7.1.5
  cap[10] @0x0f8 type=0x000d Input             len=88  expect=88  PASS  BCGR 2.2.7.1.6
  cap[11] @0x150 type=0x0017 Rail              len=8   expect=8   PASS  RDPERP 2.2.1.1.1
  cap[12] @0x158 type=0x0018 Window            len=11  expect=11  PASS  RDPERP 2.2.1.1.2
  caps end=0x163  + tail 4 = 0x167  totalLength=359  PASS

--- Confirm Active [BCGR 4.1.13]  totalLength=492  numberCapabilities=18  capStart=0x1a  tail=0
  cap[ 0] @0x01a type=0x0001 General           len=24  expect=24  PASS  BCGR 2.2.7.1.1
  cap[ 1] @0x032 type=0x0002 Bitmap            len=28  expect=28  PASS  BCGR 2.2.7.1.2
  cap[ 2] @0x04e type=0x0003 Order             len=88  expect=88  PASS  BCGR 2.2.7.1.3
  cap[ 3] @0x0a6 type=0x0013 BitmapCacheRev2   len=40  expect=40  PASS  BCGR 2.2.7.1.4.2
  cap[ 4] @0x0ce type=0x000a ColorCache        len=8   expect=8   PASS  EGDI 2.2.1.1
  cap[ 5] @0x0d6 type=0x0007 Activation        len=12  expect=12  PASS  BCGR 2.2.7.2.3
  cap[ 6] @0x0e2 type=0x0005 Control           len=12  expect=12  PASS  BCGR 2.2.7.2.2
  cap[ 7] @0x0ee type=0x0008 Pointer           len=10  expect=10  PASS  BCGR 2.2.7.1.5
  cap[ 8] @0x0f8 type=0x0009 Share             len=8   expect=8   PASS  BCGR 2.2.7.2.4
  cap[ 9] @0x100 type=0x000d Input             len=88  expect=88  PASS  BCGR 2.2.7.1.6
  cap[10] @0x158 type=0x000c Sound             len=8   expect=8   PASS  BCGR 2.2.7.1.11
  cap[11] @0x160 type=0x000e Font              len=8   expect=8   PASS  BCGR 2.2.7.2.5
  cap[12] @0x168 type=0x0010 GlyphCache        len=52  expect=52  PASS  BCGR 2.2.7.1.8
  cap[13] @0x19c type=0x000f Brush             len=8   expect=8   PASS  BCGR 2.2.7.1.7
  cap[14] @0x1a4 type=0x0011 Offscreen         len=12  expect=12  PASS  BCGR 2.2.7.1.9
  cap[15] @0x1b0 type=0x0014 VirtualChannel    len=8   expect=8   PASS  BCGR 2.2.7.1.10
  cap[16] @0x1b8 type=0x0015 DrawNineGrid      len=12  expect=12  PASS  EGDI 2.2.1.2
  cap[17] @0x1c4 type=0x0016 DrawGdiPlus       len=40  expect=40  PASS  EGDI 2.2.1.3
  caps end=0x1ec  + tail 0 = 0x1ec  totalLength=492  PASS

RESULT demand=True confirm=True
```

**读法**：
- 13 + 18 = **31 个 capability 实例**的长度全部与模型预测一致（Font 那 1 个是规范自述的服务端 bug，见 §8.12）。
- Demand Active 遍历终点 `0x163` + 4 字节 `sessionId` = `0x167` = `totalLength` ✔
- Confirm Active 遍历终点 `0x1EC` = `totalLength`，**无尾部字段** ✔
- 这同时验证了 §5.3 的关键结论：**Confirm Active 没有 `sessionId`**（否则终点会差 4）。

> **"先红后绿"记录**：模型第一版把 `capabilitySetType` / `lengthCapability` **也写进了 payload 的
> 字段宽度表**，而脚本的 `SCHEMA` / `LEN` 本来就在宽度和之上再加 4 字节头
> （`LEN = 4 + sum(widths)`）→ 这 4 字节头被**二次计入**，于是 `expect = 4 + 24 = 28`，
> 而 dump 是 `24`，脚本报 `FAIL`。
> 若只多算一个 `pad2octets`（2 字节），得到的是 `4 + 22 = 26`——同样 `FAIL`，
> 但与 dump 只差 2 而非 4，两种错法的红证特征不同（26 vs 28），不要混淆归因。
> 核对规范原文 2.2.7.1.1 的字段表
> （`capabilitySetType, lengthCapability, osMajorType, osMinorType, protocolVersion, pad2octetsA,
> compressionTypes, extraFlags, updateCapabilityFlag, remoteUnshareFlag, compressionLevel,
> refreshRectSupport, suppressOutputSupport` = 13 项，其中前 11 项 2 字节、后 2 项 1 字节 = 24）
> 后把 4 字节头从宽度表移出（只留 11 个 2 字节字段 + 2 个 1 字节字段），脚本转 `PASS`。
> **这就是"红证"**：错误的模型必然被 dump 打回。

### 14.2 逐字段偏移的机器校验

§8 的 27 张表全部由脚本生成（`F:\rtsc\evidence\capabilities\gen_caps_full.py`），脚本对每个字段做
`assert o == off`（声明的偏移必须等于累加值），任一不符立即抛异常、不产出文件。
因此 §8 的偏移**不存在手抄错误**。

```
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
python -X utf8 F:\rtsc\evidence\capabilities\gen_caps_full.py
# 输出：caps=27 bytes=25034（字数随排版微调，以 assert 全部通过为准）
```

### 14.3 URL 可达性验证（97/97 HTTP 200；脚本覆盖 83/97）

```
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
powershell -NoProfile -ExecutionPolicy Bypass -File F:\rtsc\evidence\capabilities\check_urls.ps1
# 输出：checked=85 ok=85 bad=0
```

脚本对列表中的每个 `learn.microsoft.com` URL 发 `HEAD`（失败则回退 `GET`），统计 200 的数量，
实测 `checked=85 ok=85 bad=0`。该列表共 85 条，其中 **83 条**属于本文件 §0.2 表
（另 2 条为历史遗留条目），83 条**全部 200**。

§0.2 表共 **97 个** `learn.microsoft.com` 页面（S01–S87、S90–S99；S88 / S89 是 DOCX 直链）。
脚本未覆盖的 **14 条**——S01（2.2）、S05（2.2.1.13）、S67（5.3.6.1）、S69（5.3.6.2）
以及新登记的 S90–S99——已用 `HEAD` 逐条单独验证，**14/14 = 200**。
故 §0.2 表 **97/97 全部可达**。

### 14.4 位域读法的独立验证

§1.2 断言"位 0 在左（图左端是 LSB）"。验证方式：用 dump 4.7 的 `0xC4` 反推三种可能读法，
只有"位 0 在左"与规范注解（`action=0, numEvents=1, flags=3`）自洽：

| 假设 | `action`(2b) | `numEvents`(4b) | `flags`(2b) | 与注解一致？ |
|---|---|---|---|---|
| 位 0 在左（图左=LSB） | `0b00`=0 | `0b0001`=1 | `0b11`=3 | **✔ 全部一致** |
| 位 0 在右（图左=MSB） | `0b11`=3 | `0b0001`=1 | `0b00`=0 | ✘ action 应为 0 实为 3（会被误判成 X.224 慢路径） |

同理可验 `0x20` 的 `TS_FP_INPUT_EVENT.eventHeader`：位 0 在左时 `eventFlags=0b00000=0`、
`eventCode=(0x20>>5)=0b001=1`（MOUSE），与注解一致；若把 `eventCode` 当成低 3 位，会得到
`eventCode=0`（SCANCODE，只有 1 字节 `keyCode`），与后续 6 字节 `pointerFlags/xPos/yPos` 的长度不匹配。

### 14.5 本文件未能取得的证据（诚实声明）

| 缺口 | 影响 | 处置 |
|---|---|---|
| 无现代 mstsc（10.x）的 Confirm Active 抓包 | §7.2 只能声称"RDP 5.1 时代的 mstsc 发 18 个"，**不能**外推到 10.x | §15 U-02 |
| 无 Fast-Path 2 字节长度（`length1` MSB 置位）的官方 dump | §3.4 的 2 字节解码规则只有规范文字 + MCS 同构佐证 | §15 U-07 |
| 无 Deactivate All 的官方 dump | §10.3 的长度/字节值是按结构推导 | §15 U-10 |
| 未抓取 [T128] 原文 | `sourceDescriptor` 语义、`TS_DEACTIVATE_ALL_PDU` 的 T.128 定义细节只能引用二手 | §15 U-11 |

---

## 15. 不确定项清单

以下各项**规范表述含糊、或本文件无法验证**。实现时不得把它们当作确定事实；
凡涉及行为决策的，已给出"保守做法"建议。

| 编号 | 项 | 现状 | 原因 / 证据缺口 | 建议做法 |
|---|---|---|---|---|
| **U-01** | 收到**未分配** `capabilitySetType`（如 `0x0006`、`0x000B`、`≥0x001F`）时应如何处理 | **规范未规定** | 2.2.1.13.1.1.1（S08）只给出已分配编号表，无"unknown type"处置条款。对比：2.2.7.1.6 对 `INPUT_FLAG_UNUSED1` 明示"MUST 忽略"，但那是位域不是 type | 按 `lengthCapability` **跳过**该 set（不致命），记告警。**不要断链**——否则未来新增 capability 会导致连接失败 |
| **U-02** | 现代 mstsc（10.x）Confirm Active 的完整 capability 集合与顺序 | **无法验证** | 仅有 RDP 5.1 时代的官方 dump 4.1.13（18 个）。本机 `mstscax.dll` 的二进制取证（`F:\rtsc\evidence\mstscax\`）只覆盖 GCC CCrq 模板，未覆盖 capability 构造 | 以 §7.3 的最小集合 + §7.2 的 5.1 集合为基线；实机抓包后再补 |
| **U-03** | Deactivation-Reactivation 后 **bitmap cache 内容**是否保留 | **规范未明示** | 1.3.1.3（S03）只说重跑 "Capability Exchange and Connection Finalization"；3.2.1.13 Bitmap Caches 的抽象数据模型未说明 Deactivate All 是否清空。但 3.2.1.14 Persistent Bitmap Caches 的生命周期**不绑定连接**（`bcgr.txt:7212`："their contents are persisted even after the RDP connection is closed"） | 保守：**清空标准** Bitmap Cache（3.2.1.13）；**保留** Persistent（3.2.1.14）与 Persisted Keys（3.2.1.15），等新 Confirm Active 后按新 capability 重建标准缓存。清空后服务端可能仍引用旧槽位 → 按 [MS-RDPEGDI] 发 `BC_ERR_FLUSH_CACHE` 并黑图重绘；**可用但掉帧** |
| **U-04** | `INPUT_FLAG_VKPACKET` vs `INPUT_FLAG_UNICODE` 命名冲突 | **规范内部不一致** | 2.2.7.1.6（S20）正文枚举名为 `INPUT_FLAG_UNICODE = 0x0010`；官方 dump 4.1.12/4.1.13 的注解写 `INPUT_FLAG_VKPACKET`。数值相同、语义同指 Unicode/虚拟键输入 | 用数值 `0x0010` 判断，命名取正文的 `INPUT_FLAG_UNICODE`；在代码注释里记录别名 |
| **U-05** | `GLYPH_SUPPORT_PARTIAL (1)` 与 `GLYPH_SUPPORT_FULL (2)` 的区别 | **规范表述重复** | 2.2.7.1.8（S22）对两者的描述文字完全相同（都是"支持 Rev 1 Cache Glyph 二级订单"） | 两者按同一能力处理；仅在需要区分缓存策略时参考 `GlyphCache[]` 尺寸 |
| **U-06** | Font List PDU 是否**必须**在 `fontSupportFlags & FONTSUPPORT_FONTLIST` 时发送 | **规范未把 flag 作为前置条件** | 3.2.5.3.17（S95）只说"发完 Persistent Key List（或 Request Control）后 MUST 发 Font List"，未提 flag；3.2.5.3.18（S96）仅规定 `MUST NOT be compressed`；而 2.2.7.2.5（S32）只 SHOULD 置该 flag | **无条件发** Font List（SHOULD 值 + 无条件 MUST 发送规则）；若服务端不发 Font Map，按 §12.5 的 300 s 连接序列超时处理（**MAY** 终止） |
| **U-07** | Fast-Path PDU 总长 **> 16,383** 时的处置 | **规范只说 SHOULD** | 2.2.8.1.2 / 2.2.9.1.2 原文："The overall PDU length **SHOULD** be less than or equal to 16,383 bytes." 未规定 MUST 拒绝 | 接收侧：`length1&0x7F` 最大 0x7F ⇒ 编码上限 32,767；**接受**到 32,767，超过缓冲上限（`MaxRequestSize`）才丢弃。发送侧：遵守 SHOULD，不分片超过 16,383 |
| **U-08** | 收到未分配的 `updateCode`（`0x7`、`0xD`–`0xF`）如何处置 | **规范未规定** | 2.2.9.1.2.1（S51）只列 12 个已分配值（0x0–0x6、0x8–0xC） | 按 `size` 字段**跳过**该 update，继续处理同包后续 update；记告警。**不要断链**（与 U-01 同理） |
| **U-09** | `lengthCapability < 4` 时如何处置 | **规范未规定** | 2.2.1.13.1.1.1（S08）只定义"含头在内的长度"；若 <4 则遍历指针不前进 | **必须**在实现里拒绝（断链或跳过剩余 caps）。这是**防御性必需**，否则死循环 |
| **U-10** | Deactivate All PDU 的 `sourceDescriptor` 实际线上值 | **仅推导** | 2.2.3.1.1（S53）只说 "SHOULD be set to 0x00"；官方无 Deactivate All dump | 发送侧用 `0x00`（长度 1）；接收侧忽略 `sourceDescriptor` 内容，只按 `totalLength` 定界 |
| **U-11** | `sourceDescriptor` 的语义与内容约束 | **未取原文** | 规范反复引用 [T128] §8.4.1，但本文件未抓取 [T128] 原文。已知实测值：Demand Active 为 `"RDP"`，Confirm Active 为 `"MSTSC"` | 发送侧用 `"MSTSC"` + NUL（长度 6）以对齐官方 dump；接收侧**不解析**该字段，只按 `lengthSourceDescriptor` 跳过 |
| **U-12** | `TS_SECURITY_HEADER1` 与 dump 注解的"4 字节 + 8 字节"拆分是否等价 | **两种表述并存** | 2.2.8.1.1.2.2（S44）定义 `TS_SECURITY_HEADER1` 为 12 字节整体；dump 4.1.12 注解把前 4 字节标 `TS_SECURITY_HEADER::flags/flagsHi`、后 8 字节标 `TS_SECURITY_HEADER1::dataSignature` | 按 **12 字节整体**读；两种表述在字节层面完全等价（前 4 字节是 Basic 头，`TS_SECURITY_HEADER1` 是其扩展） |
| **U-13** | 服务端是否校验 Confirm Active 的 `originatorID` / `shareID`；以及 `shareID` 回填是否属于 MUST | **部分未验证** | 3.3.5.3.13.2（S64）的处理规则只检查 `pduType`，未提 `originatorID`/`shareID`；2.2.1.13.2.1（S10）对 `shareID` 只说 "the share identifier for the packet"，未写 "MUST 回填" | `originatorID` 按 S10 的 MUST 填 `0x03EA`；`shareID` 按 3.2.5.3.13.1 的 Share ID store 语义回填（工程上必要，但规范未用 MUST 表述）。**违反后果**：不回填/填错时服务端可回 `0x000010D4`（shareID）或 `0x000010D5`（originatorID）后断链；客户端表现为 S3 卡死，原因只能从 Set Error Info PDU 的 `errorInfo` 读（2.2.5.1，S90）。不要依赖服务端宽容 |
| **U-14** | 同一 `capabilitySetType` 在 `capabilitySets` 中**重复出现**时的语义 | **规范未规定** | 2.2.1.13.1.1（S07）只说"元素数由 `numberCapabilities` 指定"，未禁止重复 | **不做 last-wins**（"后者覆盖前者"不安全）：取交集 / 更保守值——`orderSupport` 按位 AND、`NumCellCaches` 取小、`MaxRequestSize` 取小、`extraFlags` 取交集；无法安全合并 → 断链。理由：重复 set 可单方面改写 `Order.orderSupport`（→ 订单不可解析）、`Rev2.NumCellCaches`/`CellInfo`（→ 画错图）、`General.extraFlags`（→ 若实现按 capability 选 MAC 算法则**可能**失配；注意接收侧可只看逐包 `SEC_SECURE_CHECKSUM` 标志，见 `bcgr.txt:12569`） |
| **U-15** | `TS_DEMAND_ACTIVE_PDU.sessionId` 在客户端侧是否有任何用途 | **规范明示忽略** | 2.2.1.13.1.1（S07）："This field is ignored by the client." | 跳过 4 字节，不存储 |
| **U-16** | General `extraFlags` 中未定义位（如 0x0002、0x0020、0x0100 等）的处置 | **规范未列举** | 2.2.7.1.1（S13）只列 5 个已定义位 | 保留原值、不解释；**不要**因为出现未知位而拒绝 |
| **U-17** | Bitmap `preferredBitsPerPixel` 与 Client Core Data 请求色深不一致时服务端行为 | **规范只说 SHOULD** | 2.2.7.1.2（S14）："client SHOULD set this field to the color depth requested in the Client Core Data" | 客户端按自己请求的色深填；不一致的后果由服务端决定，客户端不补救 |
| **U-18** | 0x001D Bitmap Codecs 中 `codecProperties` 的完整解析 | **超出本文件范围** | 该字段内容为 [MS-RDPNSC] / [MS-RDPRFX] 结构，本文件未抓取这两个规范 | 若要支持 NSCodec/RemoteFX，需另立文档取证；本阶段可只发 `bitmapCodecCount = 0` 或整体不发 |
| **U-19** | `TS_ORDER_CAPABILITYSET.textFlags` 的位含义 | **规范明示忽略，但 dump 给出名字** | 2.2.7.1.3（S15）："Values in this field MUST be ignored."；dump 4.1.13 注解却列出 `TS_TEXTFLAGS_ALLOWCELLHEIGHT` 等 5 个名字 | 按规范**忽略**；dump 的名字仅供对照，不作为实现依据 |
| **U-20** | 服务端发来 `lengthCapability` 与规范固定值不符（除 Font 的已知 bug）时的处置 | **规范未规定** | 规范未固定取值（各 capability 节的字段宽度决定期望总长），也未规定接收方校验义务 | 按**实际 `lengthCapability`** 定界遍历（这是唯一能保证不错位的做法）；对已知字段只在 `len >= 预期` 时读取，`len < 预期` 时缺失字段取 0 并告警 |
| **U-21** | Deactivate All PDU 的 `pduType` 实际线上值 | **仅推导** | 2.2.3.1.1（S53）未给完整 dump；由 S41 的 `(PDUVersion << 4) OR type` 表推得 `0x0016`（version 1 + type 6） | 发送/接收均按 `0x0016` 处理；官方无该 PDU 的完整 dump，故仅列为推导值 |

### 15.1 已全部核实、无不确定性的项

以下各项**已用官方原文核实**；多数另有官方 dump 佐证，个别仅有原文表比对（逐行注明核实方式），可作确定事实使用：

| 项 | 核实方式 |
|---|---|
| 28 个 `capabilitySetType` 的编号与名称 | 规范原文表（S08）逐行比对 |
| 21 类型 × 31 实例的长度 | 总长由字段累加保证；**字段宽度为人工转录，已由审计逐字段比对规范原文（27/27 一致）**；§14.1 dump 反向匹配 31/31 通过（Font 的 4 字节为已记录的规范自述 bug）。另有 6 个类型（`0x0004` / `0x0019` / `0x001A` / `0x001B` / `0x001C` / `0x001E`）无 dump 佐证：它们未出现在任何官方 dump 中，长度仅由字段宽度推导，未经反向匹配 |
| `TS_SHARECONTROLHEADER` / `TS_SHAREDATAHEADER` 的字段与长度（6 / 18 字节） | 规范原文（S41 / S42）+ dump 4.1.18 逐字节（18 字节头精确对齐 `pduType2` 偏移 14） |
| `pduType` 的 `(PDUVersion << 4) OR type` 编码 | 规范原文（S41）+ dump 中 `0x0011` / `0x0013` / `0x0017` 三个实例 |
| `TS_SECURITY_HEADER` / `_HEADER1` / `_HEADER2` 的 4 / 12 / 16 字节 | 规范原文（S43 / S44 / S45）+ dump 4.1.12 的 `08 00 02 03` + 8 字节 MAC |
| Fast-Path 1 字节长度编码 | 规范原文（S46 / S50）+ dump 4.7 的 `0x11 = 17` 精确等于 `1+1+8+7` |
| Fast-Path 位域"位 0 在左" | 规范位域图 + dump 4.7 的 `0xC4` / `0x20` 双重验证（§14.4） |
| `lengthCombinedCapabilities` 的口径 | 规范原文（S07）+ dump 4.1.12 的 `337 = 4 + 333` 与 `totalLength = 359` 双约束 |
| Confirm Active **无** `sessionId` | 规范原文（S10 字段表无该字段）+ dump 4.1.13 遍历终点 `0x1EC` 恰等于 `totalLength` |
| Font List / Font Map 均为 26 字节 | 规范原文（S54 / S56 标注 "26 bytes"）+ dump 4.1.18 / 4.1.22 实测 26 字节 |

---

## 16. 与任务提示的偏差汇总

本节集中列出**任务提示与规范原文不一致**的地方，便于审阅者核对（§1.4 是章节号层面，本节是内容层面）：

| # | 任务提示 | 规范原文事实 | 依据 |
|---|---|---|---|
| 1 | 「Bitmap(3)、Order(5)、BitmapCache(4)、Pointer(8)、Input(13)、VirtualChannel(14)」 | `BITMAP=0x0002`、`ORDER=0x0003`、`BITMAPCACHE=0x0004`(Rev1) / `0x0013`(Rev2)、`POINTER=0x0008`、`INPUT=0x000D`(13)、`VIRTUALCHANNEL=0x0014`(20) | S08 |
| 2 | 「ShareControl? 按规范实际编号」 | **不存在 ShareControl capability**。Share Capability Set 的类型号是 `CAPSTYPE_SHARE = 0x0009` | S08 / S31 |
| 3 | 「全部 capabilitySetType 编号表（2.2.7.1.1 ~ 2.2.7.1.15）」 | 编号表在 **2.2.1.13.1.1.1**（`TS_CAPS_SET`）；2.2.7.1.x 是**各 capability 的结构定义**，且只到 **2.2.7.1.11**（Sound）；`0x0005`/`0x0007`/`0x0009` 等在 **2.2.7.2.x**（Optional） | S08 / S12 / S27 |
| 4 | 「TS_FP_INPUT_PDU / TS_FP_UPDATE_PDU 头（2.2.9.1.2.1 等）」 | `TS_FP_UPDATE_PDU` 在 **2.2.9.1.2**；**2.2.9.1.2.1 是 `TS_FP_UPDATE`**（subtype 容器，不是 PDU 头） | S50 / S51 |
| 5 | 「`fpOutputHeader` 位域（action/flags/length1/length2）」 | `fpOutputHeader` 只含 `action(2)` / `reserved(4)` / `flags(2)`；**`length1`/`length2` 是独立字段，不在位域内** | S50 |
| 6 | 「Deactivate All PDU（2.2.1.13.3）」 | **2.2.3.1 / 2.2.3.1.1**；2.2.1.13.3 **不存在** | S52 / S53 |
| 7 | 「Font List / Font Map PDU（2.2.1.18 / 2.2.1.19）」 | Font List = **2.2.1.18**；Font Map = **2.2.1.22**；**2.2.1.19 = Server Synchronize PDU** | S54 / S56 / S58 |
| 8 | 「服务端 Confirm」（状态机第 3 步） | **不存在名为 "Server Confirm" 的 PDU**。服务端对 Confirm Active 的响应是 **Server Synchronize PDU（2.2.1.19）** | S58 / S64 |
| 9 | 「至少 3 个真实/官方向量的十六进制 dump」 | 已给出 4 个（Demand Active、Confirm Active、Font List + Font Map 合一、Fast-Path Input），全部来自规范 §4 的官方注解 dump | S70 / S71 / S72 / S73 / S74 |

> 第 8 条尤其重要：任务提示的状态机写"收到 Demand Active → 发 Confirm Active → **服务端 Confirm** → 进入 Deactivate All 处理"，
> 但规范里**没有** "Server Confirm" 这个 PDU。实际是
> `Confirm Active → Server Synchronize → ... → Font Map`（§12.2）。本文件按规范实现状态机。

---

## 17. 实现检查清单

供执行阶段对照（每项都指向本文件的具体小节与规范章节）：

### 17.1 解析（接收方向）

- [ ] 首字节低 2 位为 `0x3` ⇒ 慢路径；为 `0x0` ⇒ fast-path（§3.2，2.2.8.1.2 / 2.2.9.1.2）
- [ ] Fast-Path：`length1 & 0x80` 决定是否读 `length2`，拼接为 `((length1 & 0x7F) << 8) | length2`（§3.4）
- [ ] Fast-Path 输入：`fpInputHeader` 位 2–5 为 `numEvents`，为 0 时读外挂 1 字节（§3.2）
- [ ] Fast-Path 输出：`fpOutputHeader` 位 2–5 为 `reserved`（MUST 0），**不读事件数**（§3.3）
- [ ] `TS_FP_UPDATE`：`updateHeader` 位 0–3 `updateCode`、位 4–5 `fragmentation`、位 6–7 `compression`（§3.5）
- [ ] `compression == 0x2` 时先读 1 字节 `compressionFlags`，再读 2 字节 `size`（§3.5）
- [ ] 慢路径：`totalLength` 校验（不含外层头）；不一致 → **SHOULD** 断链（§2.1 / §4.4；原文 "SHOULD be dropped"，非 MUST）
- [ ] `pduType.type` 不符 → **忽略**，不断链（§4.4）
- [ ] `securityHeader` 是否存在由 Encryption Level/Method 决定；Enhanced Security 下**必须不存在**（§2.3）
- [ ] `TS_SECURITY_HEADER1` 按 12 字节整体读（4 + 8）（§2.4 / U-12）
- [ ] `flagsHi` 仅在 `SEC_FLAGSHI_VALID` 置位时有效（§2.3）
- [ ] capability 遍历：**三条上界全查**——`p + 4 <= caps_end`、`p + len <= caps_end`、`p + len <= recv_len`，任一不满足即断链（§6.1）
- [ ] capability 遍历：先判 `lcc >= 4`（否则 `lcc - 4` 下溢为 65534）；`lcc - 4 >= numberCapabilities * 4`（§6.1）
- [ ] capability 遍历：`len < 4` 必须拒绝（U-09）；未分配 type 跳过（U-01）；`numberCapabilities == 0` 只告警
- [ ] capability 遍历结束：`p == caps_end`；`p > caps_end` 断链，`p < caps_end` 告警后按 `caps_end` 重新定界（§6.1）
- [ ] 按**实际** `lengthCapability` 定界，不按规范期望值（U-20）
- [ ] Font capability 容忍 4 字节形态（§8.12）
- [ ] 收到 Monitor Layout PDU（`pduType2 = 0x37`）：解析并记录显示器布局，**不改状态**（§12.2，2.2.12.1）
- [ ] 收到 Set Error Info PDU（`pduType2 = 0x2F`）：记录 `errorInfo` 32 位错误码，**不改状态**（§12.2，2.2.5.1）
- [ ] 未列出的 `(state, event)` 组合 → 忽略并告警，不改状态（§12.2）

### 17.2 构造（发送方向）

- [ ] `pduType = (0x1 << 4) | type`：Demand/Confirm/Data/Deactivate = `0x0011`/`0x0013`/`0x0017`/`0x0016`（§2.1）
- [ ] Confirm Active `pduSource` = User Channel ID，`originatorID = 0x03EA`，`shareID` 回填（§5.3）
- [ ] `lengthCombinedCapabilities = 4 + Σ lengthCapability`（§4.3 / §5.3）
- [ ] `numberCapabilities` 与 `capabilitySets` 实际元素数一致
- [ ] General `protocolVersion = 0x0200`、`compressionTypes/updateCapabilityFlag/remoteUnshareFlag/compressionLevel = 0`（§8.1）
- [ ] General `refreshRectSupport` / `suppressOutputSupport` 客户端置 0（server-only）（§8.1）
- [ ] Bitmap `bitmapCompressionFlag = TRUE`、`multipleRectangleSupport = TRUE`（MUST）（§8.2）
- [ ] Order `orderFlags` 含 `NEGOTIATEORDERSUPPORT(0x0002)` 且客户端置 `ZEROBOUNDSDELTASSUPPORT(0x0008)`（§8.3）
- [ ] Input `inputFlags` 含 `INPUT_FLAG_SCANCODES(0x0001)`（MUST）（§8.11）
- [ ] Share `nodeID = 0`（§8.8）
- [ ] BitmapCacheRev2 `CacheFlags` 与是否发 Persistent Key List 一致（§8.17）
- [ ] Pointer `colorPointerCacheSize` 与 `pointerCacheSize` 不同时为 0（否则服务端可回 `ERRINFO_NOCURSORCACHE`）（§8.7）
- [ ] 若发 Persistent Key List，Confirm Active 必须含 Rev2 Bitmap Cache，否则服务端可回 `ERRINFO_CACHECAPNOTSET`（§8.17 / §7.3）
- [ ] `mcsSDin.channelId` 取 I/O Channel ID store 的值，**不硬编码** `0x03EB`（§4.1）
- [ ] 发送侧压缩次序：明文 → 压缩 → 算 MAC → 加密；接收侧反向（§2.4）
- [ ] Standard RDP Security 下每收发 4,096 包更新会话密钥（§2.4，5.3.7.1）
- [ ] SurfaceCommands 声明时 General `extraFlags` 置 `FASTPATH_OUTPUT_SUPPORTED`（§8.26）
- [ ] LargePointer 声明时同时发 MultifragmentUpdate 且 `MaxRequestSize` 足够（§8.25）

### 17.3 时序

- [ ] Demand Active 处理成功 → 立即发 Confirm Active（§4.4）
- [ ] Confirm Active 之后按序发 Synchronize → Cooperate → Request Control → [Persistent Key List] → Font List；这串 PDU **可整批发送**（§12.2 / §11.1）
- [ ] **发出 Confirm Active 后即可发 input**，不等 Server Synchronize（§12.2，3.2.5.3.13.2）
- [ ] 收到 Server Synchronize（不是 "Server Confirm"，§16 第 8 条）——它只表示已收到 Confirm Active
- [ ] 收到 Font Map 才算连接完成（§12.2）
- [ ] 收到 Deactivate All → **关闭图形/输入 handler** → 清 capability/shareID/channelID → 等新 Demand Active（§10.4 / §12.2）
- [ ] Deactivate-Reactivation **不重跑** MCS / 安全 / Licensing（§12.4）
- [ ] 300 s 连接序列超时到期 → **MAY** 终止连接（§12.5，3.2.6.1）

---

## 18. 修订记录（2026-10-22，按 41 条审计清单）

本节记录按双审定案的 41 条缺陷清单（`capabilities.consult-b.md` §11.2 + 两份磋商的收窄约束）
对本文件所做的全部修订。**本文件只改文档措辞与伪码，未改任何规范数值、未改任何脚本断言。**

严重度分布（双审盖章）：**阻断 3（F-01 / F-03 / F-12）+ 严重 6（F-02 / F-04 / F-05 / F-06 / F-15 / F-38）+ 一般 32 = 41**。

| F 编号 | 原行号 | 改法一句话 |
|---|---|---|
| **F-01** | 688 | 把 `mcsSDin.channelId` 的旧值（995 的十六进制写法，漏了一位）改为 I/O Channel ID store 的值 `0x03EB`（=1003），并注明由 Server Network Data 分配、不可硬编码 |
| **F-02** | 2159 / 2162-2163 / 2171 | §13.4 的 hex 块改回线上密文 `… 26 18 5e 76 0e de 28`；行 2171 的字节同步改为密文；标题改「线上字节 + 解密后载荷」并加注，解密块保留 |
| **F-03** | 844-853 | §6.1 遍历伪码增加 `caps_end = caps_start + lcc - 4` 与三条上界（`p+4<=caps_end`、`p+len<=caps_end`、`p+len<=recv_len`），任一不满足断链 |
| **F-04** | 822 | §5.5 绝对断言「服务端不校验」改为「3.3.5.3.13.2 未要求校验；但 2.2.5.1 为两种非法值各定义 `0x000010D4`/`0x000010D5`，实现可校验并据此断链」 |
| **F-05** | 1425 / 1436 | §8.18 的「固定总长 12」改为「8（无 VCChunkSize，官方形态）或 12（含）」；偏移校验行改为「分别结束于 8 / 12」 |
| **F-06** | 2368 | U-03 的「清空 bitmap cache」改为「清空标准 Bitmap Cache（3.2.1.13）；保留 Persistent（3.2.1.14）与 Persisted Keys（3.2.1.15）」 |
| **F-07** | 2368 | U-03 补「清空」的代价：服务端可能仍引用旧槽位 → 按 [MS-RDPEGDI] 发 `BC_ERR_FLUSH_CACHE` 并黑图重绘，可用但掉帧 |
| **F-08** | §12（缺） | §12.2 增「任意状态 + Set Error Info（2.2.5.1，`pduType2=0x2F`）→ 记录 errorInfo，状态不变」；§17.1 补检查项；§0.2 登记 S90 |
| **F-09** | §12（缺） | S1 与 S2 各增一行「Monitor Layout（2.2.12.1，`pduType2=0x37`）→ 记录布局，状态不变」；§17.1 补检查项；§0.2 登记 S91 |
| **F-10** | 1889 | §12.2 增通用兜底「与当前状态不符 → 忽略并告警（不改状态）」，并补「错序处置」表（5 种错序逐条给出忽略/断链与理由） |
| **F-11** | §12（缺） | 新增 §12.5 定时器：300 s、强度 **MAY**（非 MUST），引 3.2.6.1（S92）/ 3.2.2.1（S93）；U-06 改为引用该小节 |
| **F-12** | §6.1 | 遍历前验 `lcc - 4 >= numberCapabilities * 4`，计数偏大即断链；遍历中三条上界任一越界即断链；遍历后严格 `p == caps_end` |
| **F-13** | §6.1 | 先判 `lcc >= 4` 否则断链（原文：`lcc-4` 在 uint16 下溢为 65534 → 末尾 assert 失败，非越界读）；`numberCapabilities == 0` 明确「合法但无意义，只告警」 |
| **F-14** | 852 | `assert` 改为显式分支：`p != caps_end` 时先告警并以 `caps_end` 为界重新定位（丢弃尾部 slack），只有 `p > caps_end` 才断链 |
| **F-15** | 2379 | U-14 的 last-wins 改为「取交集/更保守值（orderSupport 按位 AND、NumCellCaches 取小、MaxRequestSize 取小、extraFlags 取交集），无法安全合并则断链」，并按审计乙收窄版写明 extraFlags 仅「若按 capability 选 MAC 算法则可能失配」 |
| **F-16** | 1038-1047 | §7.3 拆两表：① 规范 MUST 可推出（仅 Bitmap + 条件性 Order/Input）② 本项目功能需要；逐行标 `规范 MUST / 工程需要` |
| **F-17** | §7.3 | §7.3 增「最小集合的风险面」表（`0x000010EA`/`0x000010E9`/`0x000010F4` 及触发条件）；§8.7 补「两个 cache size 都为 0 → 服务端可回 NOCURSORCACHE」 |
| **F-18** | 2378 | U-13 补「违反后果」：不回填 → 服务端可回 `0x000010D4` 后断链，客户端表现为 S3 卡死，原因只能从 Set Error Info 读 |
| **F-19** | 2394 | §15.1 证据列改为「总长由累加保证；字段宽度为人工转录，已由审计逐字段比对规范原文（27/27 一致）」；未改动 §14.2 的 assert 描述 |
| **F-20** | 2393 | §15.1 拆两行：「28 个编号与名称：原文表逐行比对」/「21 类型 × 31 实例长度：dump 反向匹配通过；6 个类型无 dump 佐证」 |
| **F-21** | 727-728 | 删 `totalLength` 闭式第二行末尾的 `+ 4`，改为 `= 18 + lengthSourceDescriptor + lengthCombinedCapabilities` |
| **F-22** | 2305 | §14.1 红证归因改为「头字段被写进 payload → `LEN` 的 `4+` 二次计入 → `4+24=28`；只多算一个 `pad2octets` 则 `4+22=26`」；未改 2308 |
| **F-23** | 266 / 792 | `pduSource MUST = User Channel ID` 的出处由 S61 改为 3.2.5.1（S94，S61 段内无此句）；行 792 依据补 3.2.5.1；§0.2 补该章节 |
| **F-24** | 791 | Confirm Active 的 `PDUVersion` 补 MUST：`PDUVersion` MUST = 0x1 ⇒ 线上 `0x0013` |
| **F-25** | 1020 | §7.2 表末合计改为「Σ `lengthCapability` = 466；+ 26 字节头 = 492 = `totalLength`」 |
| **F-26** | 148 | fast-path 长度编码的引用由 `§2.3` 改为 `§3.4` |
| **F-27** | 1677 / 1688 | U-04 / U-05 的引用由 `§12` 改为 `§15`（两处） |
| **F-28** | 2385 + §8 全节 | U-20 原因栏改为「规范未固定取值，字段宽度决定期望总长」；§8 各节「固定总长」改「定长（由字段宽度推出；规范未固定该值）」，表内 `lengthCapability` 的 `MUST = N` 同步改「定长 N」；**所有数值未动** |
| **F-29** | 129 / 2331 | URL 统计改为「97 个 learn 页面（另 2 个 DOCX）；脚本覆盖 83 个全部 200，其余 14 个单独 HEAD 验证 14/14 = 200 → 97/97 可达」；§14.3 标题与正文同步 |
| **F-30** | 2403 | 该行**移出** §15.1（标题「无不确定性」与内容「缺 dump 佐证」矛盾），改列为 §15 的 **U-21**（`pduType = 0x0016` 为 S41 表推导值，无完整 dump） |
| **F-31** | 1785 / 1864 / 1890 / 2371 / 1849 / 1854 / 304 | §0.2 补登 S90–S99（逐条给 guid）；正文相应引用补 S95/S96/S97/S98/S91 标记，消除未登记章节号 |
| **F-32** | 1920-1929 | §12.3 时序图把服务端 Sync 画在 Confirm Active 之后，并加注「客户端 PDU 可整批发送，实际观测顺序可能交错」 |
| **F-33** | 1849 | 「S59 系列」改为直接引用 3.2.5.3.22（S97），§0.2 已登记该章节 |
| **F-34** | 714 / 797 | `sourceDescriptor` 由「内容为 RDP/MSTSC」改为「dump 实测内容为 …；语义见 [T128] §8.4.1（未取证）」 |
| **F-35** | 1795 | 「严格串行」改为「顺序固定，但**可整批发送**（1.3.1.1）」 |
| **F-36** | 2371 | U-06 出处由 3.2.5.3.18 改为 3.2.5.3.17（S95），并注明 3.2.5.3.18 仅规定 `MUST NOT be compressed` |
| **F-37** | 369-411（§2.4） | §2.4 末补「处理次序：明文→压缩→算 MAC→加密，接收侧反向（3.2.5.1）」+「会话密钥更新：Non-FIPS 每收发 4,096 包重新派生（5.3.7.1，S99）；FIPS 不更新」；§0.2 登记 5.3.7.1 |
| **F-38** | 1891 | input 发送许可由「收到 Server Synchronize」移到 S2→S3 行（发出 Confirm Active 即许可）；S3 的 Server Synchronize 行改为「许可已在 S2 末尾获得」 |
| **F-39** | 137 | 「进入 §12『不确定项』」改为 `§15` |
| **F-40** | 998 | 「本文 §14.2 已逐字节复算」改为 `§14.1` |
| **F-41** | 2441 | 检查清单改为「不一致 → **SHOULD** 断链（SHOULD，非 MUST）」 |

### 18.1 机械自检结果

| 检查项 | 要求 | 实测 | 结论 |
|---|---|---|---|
| 旧 channelId 值（995 的十六进制写法）出现次数（F-01） | **必须为 0** | **0** | ✔ |
| `0x03EB` 出现次数 | ≥ 2 | **5**（§4.1 + §13.5 原行 2202 + §17.2 检查项 + 本节 F-01 行 + 本行） | ✔ |
| `26 18 5e 76` 出现次数（F-02） | ≥ 2 | **6**（§3.4 原有 + §13.4 hex 块 + §13.4 表 + §13.4 注释 + 本节 F-02 行 + 本行） | ✔ |
| `ERRINFO` 出现次数（F-08） | > 0 | **8**（§5.5 + §7.3 风险面 3 处 + §8.7 + §17.2 2 处 + 本行） | ✔ |
| `3.2.6.1` 出现次数（F-11） | > 0 | **6**（§0.2 S92 + §12.5 标题行 + §12.5 表 + §17.3 + 本节 F-11 行 + 本行） | ✔ |
| 文件行数 | 记录变化（原 2498 行） | **原 2497 行（`readlines()`）/ 2498（含末尾空行计数）→ 现 2743 行**，净增 246 行 | ✔ |
| §15.1 表内「缺 dump 佐证」出现次数（F-30） | **必须为 0** | **0** | ✔ |
| `U-21` 存在且含 `0x0016`（F-30） | 必须成立 | **存在** | ✔ |
| `[Ll]engthCapability` + `MUST` 组合（大小写不敏感，F-28） | **必须为 0** | **0** | ✔ |

> 计数口径：上表数值是**全文**出现次数（Python `str.count`，UTF-8），因此包含本节自检行自身与 §18 修订记录
> 中对字面量的引用。F-01 那项要求严格为 0，故其自检行只写「旧 channelId 值（995 的十六进制写法）」，
> 不写出该字面量本身（本节与 §18 的 F-01 记录行同样回避该串）。

### 18.2 回归验证

- `verify_caps.py`：`RESULT demand=True confirm=True`（31/31 PASS，含 Font 的 1 个已记录 DOCUMENTED-DEVIATION）
- `gen_caps_full.py`：`caps=27 bytes=25034`（27 张表字节数与修订前完全一致）

### 18.3 未修订条目

**无。** F-01 … F-41 全部按清单落地，无一条因表格歧义而卡住。


### 18.4 复核轮补修（审计乙第二轮，2026-10-22）

审计乙复核时发现两处**残留**，经父会话独立实测确认后补修。三行改动如下：

| # | 行 | 原文 | 改为 |
|---|---|---|---|
| 1 | 1555 | 字段名首字母大写的 `LengthCapability`，配旧强度标签（8 字节） | `lengthCapability` 改小写，强度标签改「定长 8（由字段宽度推出；规范未固定该值）」 |
| 2 | 1571 | 字段名首字母大写的 `LengthCapability`，配旧强度标签（11 字节） | `lengthCapability` 改小写，强度标签改「定长 11（由字段宽度推出；规范未固定该值）」 |
| 3 | 2512 | `以下各项**已用官方原文 + dump 双向核实**，可作确定事实使用：` | `以下各项**已用官方原文核实**；多数另有官方 dump 佐证，个别仅有原文表比对（逐行注明核实方式），可作确定事实使用：` |

**为什么要补这三行**：

- **第 1、2 行（F-28 残留）**：§8.21（RAIL）与 §8.22（Window）的字段名写成首字母大写的
  `LengthCapability`，而 §8 其余 25 节是小写 `lengthCapability`。审计甲的 `check_acceptance.py`
  判据正则**大小写敏感**，因此这两行被漏检、F-28 误报 PASS。**由审计乙复核发现**，父会话实测确认。
  这两行同时仍是 `MUST = N` 旧标签，一并按 F-28 改为「定长 N（由字段宽度推出）」。
- **第 3 行（F-30 残留）**：§15.1 的导语原写「已用官方原文 **+ dump 双向核实**」，但该表 10 个数据行中
  有 1 行（「28 个 `capabilitySetType` 的编号与名称」，仅原文表比对、无 dump）不含 dump 佐证，
  导语强度大于内容强度。改为「已用官方原文核实；多数另有官方 dump 佐证，个别仅有原文表比对」，
  使导语与逐行内容一致。**行 2517 不需要改**：那 6 个无 dump 的类型用「另有」引出，句法上在主语之外，
  故「21 类型已核实」与「另有 6 个无 dump」同时为真（集合恒等式 `28 = 21 + 6 + 1`，三集合两两不相交）。

**数值未动**：第 1、2 行的 8 / 11 与 §14.1 dump 一致，仅改标签与字段名大小写。

**回归（改后实测）**：

- `check_acceptance.py`：`PASS=80 FAIL=0 MANUAL=2`，exit=0
- `accept_consult_b.py`：机械判据 **17/17 通过**，exit=0（改前 15/17，FAIL=[F-28, F-30]）
- `verify_caps.py`：`RESULT demand=True confirm=True`，exit=0（31/31 PASS）

### 18.5 修订完成声明

1. **41 条 + 3 行补修全部落地。** 双审定案的 F-01 … F-41 共 41 条缺陷已逐条修订；复核轮补修 3 行
   （F-28 两行：§8.21 / §8.22 的字段名改小写并统一为「定长 N」标签；F-30 一行：§15.1 导语强度
   降到与逐行内容一致）。无遗留、无跳过。

2. **三套独立判据的最终状态（改后实测）**：

   | 判据套件 | 结果 | exit |
   |---|---|---|
   | 审计甲 `check_acceptance.py`（82 条判据） | `PASS=80  FAIL=0  MANUAL=2` | 0 |
   | 审计乙 `accept_consult_b.py`（17 条机械判据） | **17 / 17 通过**，未通过：无 | 0 |
   | `verify_caps.py`（官方 dump 反向遍历） | `RESULT demand=True confirm=True`（31/31 PASS，含 Font 的 1 个已记录 DOCUMENTED-DEVIATION） | 0 |

3. **关键计数（全文实测）**：

   | 项 | 计数 |
   |---|---:|
   | 旧 channelId 值（995 的十六进制写法） | **0** |
   | `[Ll]engthCapability` 与 `MUST` 同行组合（大小写不敏感） | **0** |
   | F-15 的过度断言（断言所有包 MAC 均失配的句式） | **0** |

4. **结论声明**：本文件已按双审定案的 41 条缺陷清单完成修订，并经两套独立判据交叉验证。

5. **数值未动**：§8 各节 `lengthCapability` 的数值与修订前备份逐一相同（**27/27**），
   本次修订只改标签、字段名大小写、措辞与伪码，未改任何规范数值。

---

## 19. 参考章节速查

| 需要查什么 | 看本文件 | 规范章节 |
|---|---|---|
| 共享头字段与位域 | §2.1 / §2.2 | 2.2.8.1.1.1.1 / 2.2.8.1.1.1.2 |
| 安全头与 MAC | §2.3–§2.5 | 2.2.8.1.1.2.1 / .2 / .3 + 5.3.6 |
| Fast-Path 头与长度 | §3.2–§3.4 | 2.2.8.1.2 / 2.2.9.1.2 |
| Fast-Path update subtype | §3.5 | 2.2.9.1.2.1 |
| Demand Active 字段 | §4.3 | 2.2.1.13.1.1 |
| Confirm Active 字段 | §5.3 | 2.2.1.13.2.1 |
| capability 编号表 | §6.2 | 2.2.1.13.1.1.1 |
| 某个 capability 的字节布局 | §8.1–§8.27 | 2.2.7.1.x / 2.2.7.2.x / [MS-RDPEGDI] 2.2.1.x |
| 位域/枚举明细 | §9.1–§9.8 | 2.2.7.x 各节 |
| Deactivate All | §10.3 | 2.2.3.1.1 |
| Font List / Font Map | §11.2 / §11.3 | 2.2.1.18.1 / 2.2.1.22.1 |
| 状态机 | §12 | 3.2.5.3.13 / 3.2.5.5.1 |
| 官方 dump | §13 | 4.1.12 / 4.1.13 / 4.1.18 / 4.1.22 / 4.7 |

---

*本文件所有事实性论断均标注来源章节号（`Sxx` 对应 §0.2 表）。含推导成分的论断标注为 B 级并列入 §15。*
