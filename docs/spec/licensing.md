# RDP 许可阶段（Licensing）权威规范

本文件是 RTSC 项目 **P4 许可阶段**的实现依据。所有结构、常量、位域、字节布局均来自
Microsoft 官方规范 **[MS-RDPELE]**（Remote Desktop Protocol: Licensing Extension，v18.0，
2024-04-23）与 **[MS-RDPBCGR]**（Remote Desktop Protocol: Basic Connectivity and Graphics
Remotely，含 2026-03-06 修订页）的网页原文，逐条给出**章节号**与**精确 URL**。

本文件不含任何 C++ 代码，不修改 `CMakeLists.txt`；纯取证 + 规范整理。

---

## 0. 阅读约定与来源等级

| 等级 | 含义 |
|---|---|
| A | 微软官方规范网页原文（`Accept: text/markdown`，HTTP 200）逐字引用 |
| B | 微软官方 Win32 API 文档原文（结构定义，用于交叉验证 blob 布局） |
| C | 由 A/B 级原文**推导**（本文明确标"推导"，给出推导链与自校验） |
| D | 本地可执行推导（本文标"本地推导 dump"，附生成方法，可复现） |

**符号约定**

- 偏移一律从该结构的**第一个字节**起算，单位字节。
- 所有多字节整数除特别注明外均为 **little-endian（LE）**（[MS-RDPBCGR] §2.2 全局约定；
  每张表重复标注，避免误用）。
- `u8` / `u16` / `u32` 分别表示 1 / 2 / 4 字节无符号整数。
- "MUST / SHOULD / MAY" 保留 RFC 2119 语义，与规范原文一致。

---

## 0.1 规范来源清单（全部实际抓取，HTTP 200）

### 0.1.1 [MS-RDPELE] 正文

前缀：`https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/`

| 编号 | 章节 | 标题 | URL 后缀 | 等级 |
|---|---|---|---|---|
| E00 | 封面 | MS-RDPELE 首页 / 版本表（v18.0, 2024-04-23） | `/ms-rdpele/` | A |
| E01 | 1.3.1 | Licensing Architecture | `a229ac6a-0d37-448f-929f-8940f32254fd` | A |
| E02 | 1.3.3 | Licensing PDU Flows | `32851b14-da8a-4a72-9fd4-41209bddd6e8` | A |
| E03 | 1.3.3.1 | New License Flow | `dd6be724-d27b-4eff-956a-0306c9ee8349` | A |
| E04 | 1.3.3.2 | Upgrade License Flow | `a293be2e-7b25-4cad-ba06-73dfcba2b25a` | A |
| E05 | 1.6 | Applicability Statement | `cf456df1-4891-452d-856a-ca9bbde617b9` | A |
| E06 | 1.7 | Versioning and Capability Negotiation | `b7bbd65f-4098-4d8d-8c75-724f75652e51` | A |
| E07 | 2.1 | Transport | `db50c145-6953-4383-9804-50e2dd83e306` | A |
| E08 | 2.2.2 | Licensing PDU (TS_LICENSING_PDU) | `dfeaae30-7fa2-48a1-abc6-8c027e413c16` | A |
| E09 | 2.2.2.1 | Server License Request (SERVER_LICENSE_REQUEST) | `e17772e9-9642-4bb6-a2bc-82875dd6da7c` | A |
| E10 | 2.2.2.1.1 | Product Information (PRODUCT_INFO) | `a6bed56c-9a69-42b6-a459-6c9d5235ff14` | A |
| E11 | 2.2.2.1.2 | Scope List (SCOPE_LIST) | `f1b80189-6e7a-497e-90cd-239757964a26` | A |
| E12 | 2.2.2.1.2.1 | Scope (SCOPE) | `c750d5c6-aa2a-4199-9e43-852e5e104b19` | A |
| E13 | 2.2.2.2 | Client New License Request (CLIENT_NEW_LICENSE_REQUEST) | `c57e4890-9049-421e-9fe8-9a6f9519675a` | A |
| E14 | 2.2.2.3 | Client License Information (CLIENT_LICENSE_INFO) | `9407b2eb-f180-4827-9488-cdbff4a5d4ea` | A |
| E15 | 2.2.2.3.1 | Client Hardware Identification (CLIENT_HARDWARE_ID) | `95ada355-e25e-4601-83fa-a4b00392a352` | A |
| E16 | 2.2.2.4 | Server Platform Challenge (SERVER_PLATFORM_CHALLENGE) | `41e129ad-0f35-43ad-a399-1b10e7d007a9` | A |
| E17 | 2.2.2.5 | Client Platform Challenge Response | `f53ab87c-d07d-4bf9-a2ac-79542f7b456c` | A |
| E18 | 2.2.2.5.1 | Platform Challenge Response Data | `2b2c3c3b-8f90-4192-b634-17c42f7be4f6` | A |
| E19 | 2.2.2.6 | Server Upgrade License (SERVER_UPGRADE_LICENSE) | `e8339fbd-1fe3-42c2-a599-27c04407166d` | A |
| E20 | 2.2.2.6.1 | New License Information (NEW_LICENSE_INFO) | `9d7e740c-2b29-42b8-89be-ce02229bccfd` | A |
| E21 | 2.2.2.7 | Server New License (SERVER_NEW_LICENSE) | `2236709a-47c6-4603-85e2-836bd42b042d` | A |
| E22 | 2.2.2.8 | Licensing Error Message (LICENSE_ERROR_MESSAGE) | `d9e81247-90fe-43a0-9c0f-1d196433bba0` | A |
| E23 | 2.2.2.9 | X.509 Certificate Extensions | `99e6bdc5-4517-45a3-be72-a254e8389546` | A |
| E24 | 2.2.2.9.1 | Licensed Product Info (LICENSED_PRODUCT_INFO) | `822c87ef-8200-4372-9a32-d3ae164cfb84` | A |
| E25 | 2.2.2.9.1.1 | Licensed Version Info (LICENSED_VERSION_INFO) | `a7e9f7ff-0ebf-4f97-aade-ac73906d653a` | A |
| E26 | 2.2.1.2 | Licensing Preamble (LICENSE_PREAMBLE) | `5d2705f0-6b86-4178-8560-97db37c664f8` | A |
| E27 | 2.2.1.3 | Licensing Binary BLOB (LICENSE_BINARY_BLOB) | `2db17387-6fb4-4fb9-b186-9505a5e0fd1d` | A |
| E28 | 2.2.1.4 | Server Certificate (SERVER_CERTIFICATE) | `883836b7-0b3b-4ad9-8017-33cce0dfeef2` | A |
| E29 | 2.2.1.4.2 | X.509 Certificate Chain (X509_CERTIFICATE_CHAIN) | `bf2cc9cc-2b01-442e-a288-6ddfa3b80d59` | A |
| E30 | 2.2.1.4.2.1 | CertBlob (CERT_BLOB) | `ad3d569f-9f38-4a33-ae41-071b55885376` | A |
| E31 | 2.2.1.4.3 | Proprietary Certificate (PROPRIETARYSERVERCERTIFICATE) | `72f16935-b9e1-4be8-a64c-2ceb2ea85822` | A |
| E32 | 3.1.5.1 | Message Integrity Checking | `1162caf5-dc84-45c2-9164-85b283bbc429` | A |
| E33 | 3.1.5.2 | Sending Licensing Error Messages | `0121dfc8-5f39-49dd-806b-1a84f816dbc3` | A |
| E34 | 3.1.5.3 | Processing Licensing Error Messages | `c990e139-abbb-44f6-a0c0-1a27cdd00ae4` | A |
| E35 | 3.1.5.3.1 | Client State Transition | `8f9b860a-3687-401d-b3bc-7e9f5d4f7528` | A |
| E36 | 3.2.1.6 | Platform Challenge | `1cb4469b-c8c8-4818-83a1-8f2f92731b25` | A |
| E37 | 3.2.1.7 | License | `3704cca1-7d86-4fc7-a258-8a925612e67b` | A |
| E38 | 3.2.1.10 | Encryption Keys（server 侧） | `4c140aaf-536b-4eba-a77b-0b4d7a12b877` | A |
| E39 | 3.2.1.11 | Server Licensing States | `60397737-b90f-4e1f-8777-253e5f272469` | A |
| E40 | 3.2.5.1 | Sending Server License Request PDUs | `476bcb84-8b48-4d66-9fa1-579703f39293` | A |
| E41 | 3.2.5.2 | Processing Client New License Requests | `45ee98e3-ef54-4698-a211-08b9fb830bb7` | A |
| E42 | 3.2.5.3 | Processing Client License Information | `89ed5e64-d4c5-4023-8df3-dd02f01e7102` | A |
| E43 | 3.2.5.4 | Sending Server Platform Challenges | `e07de099-eb6e-4a70-9bea-6438959fea70` | A |
| E44 | 3.2.5.7 | Sending Server New Licenses | `39ae0463-8097-4001-b1dd-c2b54166b66d` | A |
| E45 | 3.2.5.8 | Handling Out-of-Sequence（server） | `8583e546-7deb-4527-aa18-4972ad5bfa02` | A |
| E46 | 3.3.1.3 | Preferred Key Exchange Algorithm ID | `fcd6e713-a7b5-4611-bc9b-84037d94585e` | A |
| E47 | 3.3.1.6 | Encrypted Premaster Secret | `4e53ec98-68da-4991-a521-18bf7a735bb3` | A |
| E48 | 3.3.1.9 | Client Hardware Identification（语义） | `1e65a534-cf12-4f9a-b4ec-3f53966521e4` | A |
| E49 | 3.3.1.11 | Client Licensing States | `c139988d-895e-4c32-b38e-a09defa3d685` | A |
| E50 | 3.3.2.1 | Client Packet Wait Timer | `567ce148-0109-45e9-8758-488202df9697` | A |
| E51 | 3.3.5.1 | Processing Server License Requests（client） | `6fa4554e-9849-472b-bc3a-301fda87e7a8` | A |
| E52 | 3.3.5.2 | Sending Client New License Requests | `0e7432c2-e85a-49eb-b519-81b9b4bb6ea8` | A |
| E53 | 3.3.5.3 | Sending Client License Information | `1f50d62d-c1ad-4b54-9534-8a6b5a66dc74` | A |
| E54 | 3.3.5.4 | Processing Server Platform Challenges | `deecb140-3ec8-467e-b256-927ae1c6057d` | A |
| E55 | 3.3.5.5 | Sending Client Platform Challenge Responses | `7be55d52-772a-4206-aa60-bb64c9924d18` | A |
| E56 | 3.3.5.6 | Processing Server Upgrade Licenses | `485e8499-9c5e-4e02-a9d1-bd8261f019be` | A |
| E57 | 3.3.5.7 | Processing Server New Licenses | `136ce1a2-6d7f-47db-981a-0d23ffb26b54` | A |
| E58 | 3.3.5.8 | Handling Out-of-Sequence（client） | `c694ffc6-7b11-4907-b4a8-8850bdb1d67d` | A |
| E59 | 3.3.5.9 | Handling Invalid MACs | `603c7ba4-7ae3-4ed2-83ca-770e2255bc4e` | A |
| E60 | 4.1 | 示例：Server License Request（逐字节注解） | `a870d76a-639b-4757-9370-a9bdfbfd6961` | A |
| E61 | 4.2 | 示例：Client New License Request（逐字节注解） | `9b4e7ee7-9e85-46f0-9583-77cfd397864e` | A |
| E62 | 4.3 | 示例：Client License Information（逐字节注解） | `9fea482b-f9e5-4175-9350-ac540a804eba` | A |
| E63 | 4.4 | 示例：Server Platform Challenge（逐字节注解） | `3e78e067-83a8-42b5-b5b3-054679ade7c7` | A |
| E64 | 4.5 | 示例：Client Platform Challenge Response（逐字节注解） | `58e79794-58f8-4607-a510-c0b5fef49c40` | A |
| E65 | 4.6 | 示例：Server New License（逐字节注解） | `73c596f1-9550-4649-b880-2947c36c1bb6` | A |
| E66 | 5.1.1.1 | Encrypting the Premaster Secret | `f4ca545b-3e08-48ba-9007-3e54ef4d1273` | A |
| E67 | 5.1.1.2 | Decrypting the Premaster Secret | `b2e30f79-f194-4914-a964-1195f0fcb838` | A |
| E68 | 5.1.2 | Generating the Licensing Encryption and MAC Salt Keys | `88061224-4a2f-4a28-a52e-e896b75ed2d3` | A |
| E69 | 5.1.3 | Encrypting Licensing Session Data | `7ad6cc1d-fc0e-4c74-bd15-01c19fcd8a5d` | A |
| E70 | 5.1.4 | Decrypting Licensing Session Data | `8d905bc3-0971-4dfc-8265-a6bb55c53482` | A |
| E71 | 5.1.5 | MAC Generation | `d749a2e4-1480-4777-9906-d8ba69061e17` | A |
| E72 | 6 | Appendix A: Product Behavior（`<1>`–`<20>` 脚注） | `1040af38-c733-4fb3-acd1-8db8cc979eda` | A |

### 0.1.2 [MS-RDPBCGR] 相关章节

前缀：`https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/`

| 编号 | 章节 | 标题 | URL 后缀 | 等级 |
|---|---|---|---|---|
| B01 | 1.3.1.1 | Connection Sequence（十阶段总览） | `023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee` | A |
| B02 | 2.2.1.4.3 | Server Security Data (TS_UD_SC_SEC1) | `3e86b68d-3e2e-4433-b486-878875778f4b` | A |
| B03 | 2.2.1.4.3.1 | Server Certificate (SERVER_CERTIFICATE) | `54e72cc6-3422-404c-a6b4-2486db125342` | A |
| B04 | 2.2.1.4.3.1.1 | Server Proprietary Certificate | `a37d449a-73ac-4f00-9b9d-56cefc954634` | A |
| B05 | 2.2.1.4.3.1.1.1 | RSA Public Key (RSA_PUBLIC_KEY) | `fe93545c-772a-4ade-9d02-ad1e0d81b6af` | A |
| B06 | 2.2.1.10 | Client Security Exchange PDU | `9cde84cd-5055-475a-ac8b-704db419b66f` | A |
| B07 | 2.2.1.12 | Server License Error PDU - Valid Client | `7d941d0d-d482-41c5-b728-538faa3efb31` | A |
| B08 | 2.2.1.12.1 | Valid Client License Data | `7e2fe1e0-e793-45b7-983d-af344d9ca327` | A |
| B09 | 2.2.1.12.1.1 | Licensing Preamble (LICENSE_PREAMBLE) | `73170ca2-5f82-4a2d-9d1b-b439f3d8dadc` | A |
| B10 | 2.2.1.12.1.2 | Licensing Binary Blob (LICENSE_BINARY_BLOB) | `0a1c6079-af4d-4742-bb64-fecb8fa6e1a0` | A |
| B11 | 2.2.1.12.1.3 | Licensing Error Message | `f18b6c9f-f3d8-4a0e-8398-f9b153233dca` | A |
| B12 | 2.2.1.13.1 | Server Demand Active PDU | `a07abad1-38bb-4a1a-96c9-253e3d5440df` | A |
| B13 | 2.2.8.1.1.2.1 | Basic (TS_SECURITY_HEADER) | `e13405c5-668b-4716-94b2-1c2654ca1ad4` | A |
| B14 | 2.2.8.1.1.2.2 | Non-FIPS (TS_SECURITY_HEADER1) | `768e12c4-7748-4005-b91d-790847e47025` | A |
| B15 | 2.2.8.1.1.2.3 | FIPS (TS_SECURITY_HEADER2) | `463bd2eb-c3b1-4986-86b0-a240819d9088` | A |
| B16 | 3.2.1.10 | Server Licensing Encryption Ability | `29781952-c6c5-416e-b602-9671453092c2` | A |
| B17 | 3.2.5.3.4 | Processing MCS Connect Response PDU | `d4fa5ef0-87c2-4256-b958-d50718a58d0b` | A |
| B18 | 3.2.5.3.10 | Sending Security Exchange PDU | `3815ccd7-e609-474b-acf6-7a53b191767b` | A |
| B19 | 3.2.5.3.12 | Processing License Error PDU - Valid Client | `14404ccf-4cc9-42fc-8746-0f4d13c9db58` | A |
| B20 | 3.3.1.6 | Client Licensing Encryption Ability | `568a1ce8-b33b-4809-95c4-155046c8d56f` | A |
| B21 | 3.3.5.3.11 | Processing Client Info PDU | `ef9db6a5-36f4-4613-84b3-97501679d210` | A |
| B22 | 3.3.5.3.12 | Sending License Error PDU - Valid Client | `4e0177cd-b6a9-402b-910e-362a486799ae` | A |
| B23 | 5.3 | Standard RDP Security | `8e8b2cca-c1fa-456c-8ecb-a82fc60b2322` | A |
| B24 | 5.3.1 | Encryption Levels | `f1c7c93b-94cc-4551-bb90-532a0185246a` | A |
| B25 | 5.3.2 | Negotiating the Cryptographic Configuration | `b9a49d9e-44db-46aa-90a7-bb7f75718e02` | A |
| B26 | 5.3.3.1 | Proprietary Certificates | `8adb6a70-6e3e-4375-adcf-a6ca2db2a7b8` | A |
| B27 | 5.3.3.1.2 | Signing a Proprietary Certificate | `73fba7da-9490-4492-8ba9-a75e491312db` | A |
| B28 | 5.3.4 | Client and Server Random Values | `5c763306-c9c0-483d-8674-31ed881de118` | A |
| B29 | 5.3.4.1 | Encrypting Client Random | `761e2583-6406-4a71-bfec-cca52294c099` | A |
| B30 | 5.3.5 | Initial Session Key Generation | `9791c9e2-e5be-462f-8c23-3404c4af63b3` | A |
| B31 | 5.3.6.1 | Non-FIPS（MAC 生成） | `7c61b54e-f6cd-4819-a59a-daf200f6bf94` | A |
| B32 | 5.4 | Enhanced RDP Security | `592a0337-dc91-4de3-a901-e1829665291d` | A |
| B33 | 5.4.2 | Security-Enhanced Connection Sequence | `9a0c1e57-6784-4c1d-bdec-8c221642669b` | A |
| B34 | 5.4.2.3 | Changes to the Security Commencement Phase | `3e0c6ad2-f1eb-42b8-ab20-4f4d889a3172` | A |
| B35 | 5.4.2.4 | Disabling Forced Encryption of Licensing Packets | `9c2aafca-c206-4ca9-9f0d-ee6848040df2` | A |
| B36 | 5.4.5 | External Security Protocols Used By RDP | `422e59a0-98c8-4a28-af9f-235a572b6e4d` | A |
| B37 | 5.4.5.2 | CredSSP（PROTOCOL_HYBRID / HYBRID_EX） | `8e11581d-094f-461a-9fde-ba51af90cf8b` | A |
| B38 | 4.8 | Java Code to Encrypt/Decrypt a Sample Client Random | `fb406d1d-8ab1-4517-a9cc-1b761f8866ac` | A |

### 0.1.3 Win32 文档（blob 布局交叉验证）

| 编号 | 标题 | URL | 等级 |
|---|---|---|---|
| W01 | Base Provider Key BLOBs | `https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs` | B |
| W02 | PUBLICKEYSTRUC (wincrypt.h) | `https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-publickeystruc` | B |
| W03 | RSAPUBKEY (wincrypt.h) | `https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey` | B |

### 0.1.4 本地项目证据

| 编号 | 文件 | 用途 |
|---|---|---|
| L01 | `F:\rtsc\evidence\handshake-001.md` | 真实服务器 192.168.1.7:3389 的 CCF，`selectedProtocol=0x08 PROTOCOL_HYBRID_EX` |
| L02 | `F:\rtsc\evidence\mstscax\imports.txt` | mstscax.dll 导入表（HWID 取证线索，见 §7.4） |
| L03 | `F:\rtsc\docs\spec\connection-initiation.md` | 本仓库前序阶段规范（协商结果口径） |

---

## 0.2 任务前提修正（先读，6 处）

任务书中的部分术语/结构名与官方规范不一致。**以官方规范为准**，逐条修正并给出依据：

| # | 任务书表述 | 官方事实 | 依据 |
|---|---|---|---|
| C1 | 共享头叫 `LICENSE_HEADER` | 官方结构名是 **`LICENSE_PREAMBLE`**（Licensing Preamble），4 字节。MS-RDPELE 全文不存在 `LICENSE_HEADER` 类型 | [MS-RDPBCGR] §2.2.1.12.1.1；[MS-RDPELE] §2.2.2 字段名 `preamble (4 bytes)` |
| C2 | PREAMBLE 含 `dwFlags` / `dwVersion` | `LICENSE_PREAMBLE` **只有 3 个字段**：`bMsgType(1)` / `flags(1)` / `wMsgSize(2)`，共 4 字节。无 `dwFlags`、无 `dwVersion`。`dwVersion` 只出现在 `PRODUCT_INFO` 与 `NEW_LICENSE_INFO` | [MS-RDPBCGR] §2.2.1.12.1.1 结构图；[MS-RDPELE] §2.2.2.1.1、§2.2.2.6.1 |
| C3 | 消息枚举含 `LICENSE_REQUEST_FAILED` | **不存在**该消息类型。许可失败统一走 `ERROR_ALERT (0xFF)` + `LICENSE_ERROR_MESSAGE` | [MS-RDPELE] §2.2.2 的 bMsgType 全表（共 8 个值）；[MS-RDPBCGR] §2.2.1.12.1.3 |
| C4 | `LICENSE_ERROR_ALERT` 一律视为失败 | `ERROR_ALERT` **也可能是成功信号**：`dwErrorCode=STATUS_VALID_CLIENT(0x07)` + `dwStateTransition=ST_NO_TRANSITION(0x02)` 表示许可阶段正常结束，客户端进入 "Client Licensing Completed" | [MS-RDPELE] §3.1.5.3、§3.3.1.11；[MS-RDPBCGR] §2.2.1.12.1 |
| C5 | 收到 `LICENSE_REQUEST` → 回 `NEW_LICENSE_REQUEST` | 三条合法分支：① 本地有匹配 CAL → 回 `LICENSE_INFO(0x12)`；② 无匹配 CAL → 回 `NEW_LICENSE_REQUEST(0x13)`；③ 主动放弃 → `ERROR_ALERT(ERR_NO_LICENSE)` | [MS-RDPELE] §3.3.5.1（MUST 分支枚举） |
| C6 | RSA blob 是 `bType/bVersion/reserved/keyalg/magic/bitlen/pubexp/modulus` | 那是 **CryptoAPI `PUBLICKEYBLOB`** 的内存布局（`PUBLICKEYSTRUC` + `RSAPUBKEY` + modulus）。**RDP 线上格式不同**：无 `bType/bVersion/reserved/aiKeyAlg`，改为 `magic/keylen/bitlen/datalen/pubExp/modulus`，且 modulus 尾部强制 8 字节零填充 | [MS-RDPBCGR] §2.2.1.4.3.1.1.1 vs W01/W02/W03；详见 §9.3 双表对照 |

> 这 6 条不改变任务目标，只修正术语与语义，避免实现时按错误字段布局解码。

---

## 1. 许可阶段在整体连接序列中的位置与触发条件

### 1.1 位置

[MS-RDPBCGR] §1.3.1.1 把 RDP 连接序列划分为 **10 个阶段**，并明确"所有消息交换严格顺序执行"：

| 序号 | 阶段 | 本仓库对应文档 |
|---|---|---|
| 1 | Connection Initiation（X.224 CRQ/CCF） | `connection-initiation.md` |
| 2 | Basic Settings Exchange（MCS Connect Initial/Response + GCC） | `mcs-connect.md` |
| 3 | Channel Connection（Erect Domain / Attach User / Channel Join） | `mcs-domain.md` |
| 4 | RDP Security Commencement（Security Exchange PDU） | 待补 |
| 5 | Secure Settings Exchange（Client Info PDU） | 待补 |
| 6 | Optional Connect-Time Auto-Detection | — |
| 7 | **Licensing（本文件）** | `licensing.md`（本文） |
| 8 | Optional Multitransport Bootstrapping | — |
| 9 | Capabilities Exchange（Demand Active / Confirm Active） | — |
| 10 | Connection Finalization | — |

> **推导说明（C 级）**：[MS-RDPBCGR] §1.3.1.1 的网页 markdown 在渲染时把有序列表编号打乱
> （"Licensing" 段落显示为 `5.`，"Optional Multitransport Bootstrapping" 显示为 `6.`），
> 但**段落先后顺序**是权威的：Licensing 位于 "Secure Settings Exchange" 与
> "Optional Connect-Time Auto-Detection" 之后、"Optional Multitransport Bootstrapping" 与
> "Capabilities Exchange" 之前。按段落顺序计数即为第 7 阶段。原文亦明确
> "The goal of the licensing exchange is to transfer a license from the server to the client"。

**关键顺序约束**（全部 A 级）：

1. Licensing 阶段在 Client Info PDU 成功处理之后才开始：
   "Once the server has successfully processed the Client Info PDU, it can enter the Licensing phase"
   —— [MS-RDPBCGR] §3.3.5.3.11。
2. Demand Active PDU 在 Licensing 阶段成功完成之后才发送：
   "It is sent upon successful completion of the Licensing phase" —— [MS-RDPBCGR] §2.2.1.13.1。
3. 服务器发完 `License Error (Valid Client)` PDU 后**必须**紧接发送 Demand Active：
   "After sending the License Error (Valid Client) PDU, the server MUST send the Demand Active PDU"
   —— [MS-RDPBCGR] §3.3.5.3.12。
4. Multitransport Bootstrapping 在许可阶段跑完之后才可能启动：
   "After the connection has been secured and the Licensing phase has run to completion"
   —— [MS-RDPBCGR] §1.3.1.1。

### 1.2 触发条件（服务器何时发许可 PDU）

| 触发事件 | 服务器动作 | 依据 |
|---|---|---|
| 收到并成功处理 Client Info PDU | **发起**许可协议：发 `SERVER_LICENSE_REQUEST`（bMsgType=0x01） | [MS-RDPELE] §1.3.3、§3.2.5.1 |
| 目标是 personal terminal server（客户端 SKU / 远程管理模式的终端服务器） | **不发** License Request / Platform Challenge，直接发 `ERROR_ALERT`，`dwErrorCode=STATUS_VALID_CLIENT(0x07)`、`dwStateTransition=ST_NO_TRANSITION(0x02)`，许可阶段立即结束 | [MS-RDPELE] §1.3.3、§3.2.5.2、§3.2.5.4；Appendix A `<1>` |
| 收到 `CLIENT_NEW_LICENSE_REQUEST`（终端服务器模式） | 派生许可密钥 → 发 `SERVER_PLATFORM_CHALLENGE`（0x02） | [MS-RDPELE] §3.2.5.2、§3.2.5.4 |
| 收到 `CLIENT_LICENSE_INFO` 且 CAL 需升级（过期 / 7 天内到期 / 临时 / 非法） | 发 `SERVER_PLATFORM_CHALLENGE`（0x02） | [MS-RDPELE] §3.2.5.3 Case 2 |
| 收到 `CLIENT_LICENSE_INFO` 且 CAL 有效且无需升级 | 发 `ERROR_ALERT(0x07, 0x02)`，许可阶段结束 | [MS-RDPELE] §3.2.5.3 Case 1 |
| 收到 `CLIENT_PLATFORM_CHALLENGE_RESPONSE` | 发 `SERVER_NEW_LICENSE`（0x03）或 `SERVER_UPGRADE_LICENSE`（0x04） | [MS-RDPELE] §3.2.5.5、§3.2.5.6、§3.2.5.7 |
| 收到乱序 / 畸形 / 未识别消息 | 发 `ERROR_ALERT(ERR_INVALID_CLIENT 0x08, ST_TOTAL_ABORT 0x01)` | [MS-RDPELE] §3.2.5.8 |

**"Valid Client License PDU" 的准确含义**：它就是 `ERROR_ALERT` 载荷为 `STATUS_VALID_CLIENT` 的那条 PDU，
在 [MS-RDPBCGR] 里被单独命名为 `Server License Error PDU - Valid Client`，载荷结构为
`LICENSE_VALID_CLIENT_DATA` = `LICENSE_PREAMBLE(bMsgType=0xFF)` + `LICENSE_ERROR_MESSAGE`
（`dwStateTransition` MUST = `ST_NO_TRANSITION(0x02)`，`bbErrorInfo` MUST 为**空**的 `BB_ERROR_BLOB(0x0004)`）
—— [MS-RDPBCGR] §2.2.1.12、§2.2.1.12.1。

> 因此：服务器在**不需要发许可证**时（personal terminal server、或已持有有效 CAL）用这条 PDU 宣告
> "许可阶段成功结束"，客户端**必须**把它当成功处理，不能当错误断开。

### 1.3 传输封装（5 层）

`TS_LICENSING_PDU` 的完整封装（[MS-RDPELE] §2.2.2）：

```
+--------------------------------------------------------------+
| TPKT Header                     4 bytes   ([T123] §8)        |
+--------------------------------------------------------------+
| X.224 Class 0 Data TPDU         3 bytes   ([X224] §13.7)     |
|   02 F0 80                                                   |
+--------------------------------------------------------------+
| MCS Send Data Request/Indication (PER)   variable ([T125])   |
|   客户端→服务器: SDrq (choice 25)                            |
|   服务器→客户端: SDin (choice 26)                            |
+--------------------------------------------------------------+
| securityHeader                  variable  ([MS-RDPBCGR]      |
|                                            §2.2.8.1.1.2.x)   |
|   Basic 4B / Non-FIPS 12B / FIPS 16B                         |
|   标志位 MUST 含 SEC_LICENSE_PKT (0x0080)                    |
+--------------------------------------------------------------+
| preamble (LICENSE_PREAMBLE)     4 bytes                      |
+--------------------------------------------------------------+
| LicensingMessage                variable                     |
+--------------------------------------------------------------+
```

约束（A 级）：

- 许可 PDU **始终**带 security header（RDP 的两个例外之一，另一个是 Client Info PDU）：
  "The Client Info PDU ... and licensing PDUs ... are an exception in that they always have a security header"
  —— [MS-RDPBCGR] §1.3.1.1。
- security header 的 `flags` **MUST** 含 `SEC_LICENSE_PKT (0x0080)`，否则"不能当作许可 PDU 处理，SHOULD 断开"
  —— [MS-RDPELE] §2.2.2、[MS-RDPBCGR] §3.2.5.3.12。
- 服务器→客户端的许可 PDU 在 `ENCRYPTION_LEVEL_NONE(0)` 或 `LOW(1)` 且未置 `SEC_ENCRYPT` 时用 **Basic** 头；
  在 `CLIENT_COMPATIBLE(2)`/`HIGH(3)` 且置 `SEC_ENCRYPT(0x0008)` 时用 **Non-FIPS** 头；
  在 `FIPS(4)` 且置 `SEC_ENCRYPT` 时用 **FIPS** 头 —— [MS-RDPELE] §2.2.2。

---

## 2. 共享头：`LICENSE_PREAMBLE`（4 字节）

> 任务书称 `LICENSE_HEADER`，官方名为 `LICENSE_PREAMBLE`（见 §0.2 C1）。

### 2.1 字节布局

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 1 | `bMsgType` | u8 | 许可消息类型，见 §3 | [MS-RDPBCGR] §2.2.1.12.1.1 |
| 1 | 1 | `flags` | u8 | 位域：低 4 bit = 协议版本，bit7 = 扩展错误支持 | [MS-RDPBCGR] §2.2.1.12.1.1 |
| 2 | 2 | `wMsgSize` | u16 LE | 整个许可包长度，**含 4 字节 preamble 自身** | [MS-RDPBCGR] §2.2.1.12.1.1 |
| 4 | — | `LicensingMessage` | variable | 由 `bMsgType` 决定 | [MS-RDPELE] §2.2.2 |

### 2.2 `flags` 位域

| 位 | 掩码 | 名称 | 语义 | 依据 |
|---|---|---|---|---|
| 0–3 | `0x0F` | `LicenseProtocolVersionMask` | 许可协议版本 | [MS-RDPBCGR] §2.2.1.12.1.1 |
| 4–6 | `0x70` | —（未定义） | 未定义；发送 MUST 置 0，接收 MUST 忽略 | 推导（C 级）：规范仅定义 0x0F 与 0x80 |
| 7 | `0x80` | `EXTENDED_ERROR_MSG_SUPPORTED` | 支持用 `LICENSE_ERROR_MESSAGE` 携带扩展错误信息 | [MS-RDPBCGR] §2.2.1.12.1.1 |

### 2.3 版本值

| 值 | 名称 | 对应产品 | 依据 |
|---|---|---|---|
| `0x2` | `PREAMBLE_VERSION_2_0` | RDP 4.0 | [MS-RDPBCGR] §2.2.1.12.1.1 |
| `0x3` | `PREAMBLE_VERSION_3_0` | RDP 5.0 / 5.1 / 5.2 / 6.0 / 6.1 / 7.0 / 7.1 / 8.0 / 8.1 / 10.0–10.5 | [MS-RDPBCGR] §2.2.1.12.1.1 |

### 2.4 字段命名不一致（重要陷阱）

同一个字节（偏移 1）在两份规范里有**两个名字**：

- [MS-RDPBCGR] §2.2.1.12.1.1 称之为 **`flags`**（并给出 `LicenseProtocolVersionMask` / `EXTENDED_ERROR_MSG_SUPPORTED` 两个掩码）。
- [MS-RDPELE] §2.2.2 与 §4.2/§4.3/§4.5 的逐字节注解称之为 **`bVersion`**，且注解写成
  `83 -> bVersion = 0x80 (ExtendedError supported) | 0x3 (RDP 5.0,5.2,6.0)`。

**结论**：`bVersion` ≡ `flags`，是同一个 u8。实现时按 `flags` 处理（低 4 bit 版本 + bit7 扩展错误），
发送时按 `0x03 | 0x80 = 0x83` 构造即可与 Windows 客户端一致（§11.2/§11.4 的官方 dump 佐证）。

### 2.5 校验规则（实现必须做）

| 规则 | 依据 |
|---|---|
| `wMsgSize` MUST 与实际收到的 `preamble + LicensingMessage` 长度一致；不一致按畸形处理 | 推导（C 级），由 `ERR_INVALID_MESSAGE_LEN(0x0C)` 的存在反证 |
| `wMsgSize < 4` 非法 | 推导（C 级）：preamble 自身 4 字节 |
| `bMsgType` 不在 §3 表内 → 按未识别消息处理（client MUST 断开） | [MS-RDPELE] §3.3.5.8 |
| `flags` 低 4 bit 只接受 0x2 / 0x3；其它值按未识别处理 | 推导（C 级），枚举闭区间见 §2.3 |

---

## 3. 全部许可消息类型枚举

### 3.1 完整枚举表（8 个值，无遗漏）

| 值 | 名称 | 方向 | 载荷结构 | 依据 |
|---|---|---|---|---|
| `0x01` | `LICENSE_REQUEST` | 服务器 → 客户端 | `SERVER_LICENSE_REQUEST`（§4.1） | [MS-RDPELE] §2.2.2；[MS-RDPBCGR] §2.2.1.12.1.1 |
| `0x02` | `PLATFORM_CHALLENGE` | 服务器 → 客户端 | `SERVER_PLATFORM_CHALLENGE`（§4.4） | 同上 |
| `0x03` | `NEW_LICENSE` | 服务器 → 客户端 | `SERVER_NEW_LICENSE`（§4.6） | 同上 |
| `0x04` | `UPGRADE_LICENSE` | 服务器 → 客户端 | `SERVER_UPGRADE_LICENSE`（§4.6） | 同上 |
| `0x12` | `LICENSE_INFO` | 客户端 → 服务器 | `CLIENT_LICENSE_INFO`（§4.3） | 同上 |
| `0x13` | `NEW_LICENSE_REQUEST` | 客户端 → 服务器 | `CLIENT_NEW_LICENSE_REQUEST`（§4.2） | 同上 |
| `0x15` | `PLATFORM_CHALLENGE_RESPONSE` | 客户端 → 服务器 | `CLIENT_PLATFORM_CHALLENGE_RESPONSE`（§4.5） | 同上 |
| `0xFF` | `ERROR_ALERT` | 双向 | `LICENSE_ERROR_MESSAGE`（§4.7） | [MS-RDPELE] §2.2.2；[MS-RDPBCGR] §2.2.1.12.1.3 |

### 3.2 枚举边界（实现要点）

1. **不是连续区间**：0x01–0x04 与 0x12/0x13/0x15 之间有空隙（0x05–0x11、0x14、0x16–0xFE 全部未定义）。
   实现 MUST 用白名单匹配，不能 `if (type <= 0x04)` 之类的范围判断。
2. **`ERROR_ALERT` 用 0xFF 而非 0x05**：RDP 惯例把最大 u8 当错误码。
3. 任务书列的 `LICENSE_REQUEST_FAILED` **不存在**（§0.2 C3）。许可失败路径唯一：
   `ERROR_ALERT(0xFF)` 携带 `dwErrorCode ∈ {ERR_*}` 与 `dwStateTransition ∈ {ST_*}`。
4. 服务器侧只接受 0x12 / 0x13 / 0x15 / 0xFF；收到 0x01–0x04 视为乱序 →
   `ERROR_ALERT(ERR_INVALID_CLIENT, ST_TOTAL_ABORT)` —— [MS-RDPELE] §3.2.5.8。
5. 客户端侧只接受 0x01 / 0x02 / 0x03 / 0x04 / 0xFF；收到 0x12/0x13/0x15 视为乱序 →
   **MUST 断开连接**（客户端不像服务器那样回错误 PDU）—— [MS-RDPELE] §3.3.5.8。

### 3.3 消息方向速查（ASCII）

```
  server                                          client
    |                                               |
    |--- 0x01 LICENSE_REQUEST ---------------------->|
    |                                               |
    |<-- 0x12 LICENSE_INFO (有 CAL) ----------------|
    |<-- 0x13 NEW_LICENSE_REQUEST (无 CAL) ---------|
    |<-- 0xFF ERROR_ALERT (放弃) -------------------|
    |                                               |
    |--- 0x02 PLATFORM_CHALLENGE ------------------>|
    |<-- 0x15 PLATFORM_CHALLENGE_RESPONSE ----------|
    |                                               |
    |--- 0x03 NEW_LICENSE / 0x04 UPGRADE_LICENSE -->|
    |                                               |
    |--- 0xFF ERROR_ALERT (0x07,0x02) ------------->|   ← 也可能直接走到这里
    |                                               |
    |--- Demand Active PDU (2.2.1.13.1) ----------->|
```

---

## 4. 各消息的完整字节结构

### 4.1 `SERVER_LICENSE_REQUEST`（bMsgType = 0x01）

来源：[MS-RDPELE] §2.2.2.1。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 32 | `ServerRandom` | u8[32] | 服务器 CSPRNG 随机数，用于派生许可加密密钥 | §2.2.2.1 |
| 32 | var | `ProductInfo` | `PRODUCT_INFO` | 所需产品许可信息 | §2.2.2.1.1 |
| 32+len(PI) | var | `KeyExchangeList` | `LICENSE_BINARY_BLOB`（type MUST = `BB_KEY_EXCHG_ALG_BLOB 0x000D`） | 服务器支持的密钥交换算法列表（u32 数组） | §2.2.2.1 |
| … | var | `ServerCertificate` | `LICENSE_BINARY_BLOB`（type MUST = `BB_CERTIFICATE_BLOB 0x0003`） | 终端服务器证书；`wBlobLen=0` 表示不发送 | §2.2.2.1 |
| … | var | `ScopeList` | `SCOPE_LIST` | 许可证签发者列表，供客户端检索 license store | §2.2.2.1.2 |

**`ServerCertificate` 的三个分支**（A 级，§2.2.2.1）：

1. 正常发送：`wBlobType=0x0003`，`wBlobLen>0`，内容为 `SERVER_CERTIFICATE`（[MS-RDPBCGR] §2.2.1.4.3.1），
   其 `certData` 可能是 `PROPRIETARYSERVERCERTIFICATE`（`CERT_CHAIN_VERSION_1`）或 X.509 链（`CERT_CHAIN_VERSION_2`）。
2. `wBlobLen=0`：服务器选择不发证书。
3. 不发证书 + 加密已生效：客户端**改用** Server MCS Connect Response PDU 的 Server Security Data 里带的公钥
   （[MS-RDPBCGR] §2.2.1.4.3）。Appendix A `<3>`：Windows Server 2008 在加密已保护 RDP 流量时不发此证书。

**`KeyExchangeList` 内容**（§2.2.2.1）：

| 值 | 名称 | 含义 | 依据 |
|---|---|---|---|
| `0x00000001` | `KEY_EXCHANGE_ALG_RSA` | RSA 密钥交换；规范正文写 "512-bit asymmetric key"；Appendix A `<2>` 修正：Windows 实际用 **2048-bit**，仅当组合中含 Server 2003 / XP 时才是 512-bit | §2.2.2.1、Appendix A `<2>` |

> 规范明确"终端服务器目前只支持一种密钥交换算法，因此 BLOB 只含上述一个值"（§2.2.2.1）。

#### 4.1.1 `PRODUCT_INFO`

来源：[MS-RDPELE] §2.2.2.1.1。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `dwVersion` | u32 LE | 高 16 bit = 终端服务器 OS 主版本，低 16 bit = 次版本 | §2.2.2.1.1；Appendix A `<5>` |
| 4 | 4 | `cbCompanyName` | u32 LE | `pbCompanyName` 字节数，**含结尾 NUL**；MUST > 0 | §2.2.2.1.1 |
| 8 | var | `pbCompanyName` | UTF-16LE 字符串 | NUL 结尾的 Unicode 公司名 | §2.2.2.1.1；Appendix A `<6>`（微软许可服务器发 "Microsoft Corporation"） |
| 8+cb | 4 | `cbProductId` | u32 LE | `pbProductId` 字节数，含结尾 NUL；MUST > 0 | §2.2.2.1.1 |
| … | var | `pbProductId` | UTF-16LE 字符串 | 许可类型标识 | §2.2.2.1.1 |

`pbProductId` 取值（§2.2.2.1.1）：

| 值 | 含义 |
|---|---|
| `"A02"` | Per device 或 Per user 许可（当前唯一有定义的值） |

**字节数自校验**：`"A02"` + NUL = 4 个 UTF-16 码元 = **8 字节**，故 `cbProductId` 必须为 `0x00000008`
（§11.1 的 `PRODUCT_INFO` 与 §11.5 的 `NEW_LICENSE_INFO` 都是 `08 00 00 00`，互相印证）。

#### 4.1.2 `SCOPE_LIST` / `SCOPE`

来源：[MS-RDPELE] §2.2.2.1.2、§2.2.2.1.2.1。

| `SCOPE_LIST` 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `ScopeCount` | u32 LE | `ScopeArray` 元素个数 |
| 4 | var | `ScopeArray` | `SCOPE[ScopeCount]` | 每个元素见下表 |

| `SCOPE` 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 2 | `wBlobType` | u16 LE | MUST = `BB_SCOPE_BLOB (0x000E)` |
| 2 | 2 | `wBlobLen` | u16 LE | `blobData` 字节数 |
| 4 | var | `blobData` | ANSI 字符串 | 签发者名称，NUL 结尾，`ISO/IEC-8859-1` + 实现特定代码页 |

Appendix A `<7>`：微软终端服务器的 ScopeList **只含一个** Scope，内容为 `"microsoft.com"`。
Appendix A `<18>` 给出等价伪代码：

```
ScopeCount = 1
ScopeCountArray[0] = "microsoft.com"
```

### 4.2 `CLIENT_NEW_LICENSE_REQUEST`（bMsgType = 0x13）

来源：[MS-RDPELE] §2.2.2.2。发送条件：客户端 license store 中**没有**匹配 `ProductInfo` 的 CAL
（§3.3.5.1 第 3 分支、§3.3.5.2）。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `PreferredKeyExchangeAlg` | u32 LE | MUST = `KEY_EXCHANGE_ALG_RSA (0x00000001)` | §2.2.2.2；§3.3.1.3 |
| 4 | 4 | `PlatformId` | u32 LE | 见 §4.2.1 | §2.2.2.2 |
| 8 | 32 | `ClientRandom` | u8[32] | 客户端 CSPRNG 生成的 32 字节随机数 | §2.2.2.2 |
| 40 | 4 | `EncryptedPreMasterSecret` 头 | `wBlobType` u16 + `wBlobLen` u16 | MUST = `BB_RANDOM_BLOB (0x0002)` | §2.2.2.2 |
| 44 | var | `EncryptedPreMasterSecret.pBlob` | u8[] | RSA 加密后的 **48 字节** premaster secret；长度 = `(bitlen/8)+8` | §2.2.2.2；§5.1.1.1；[MS-RDPBCGR] §5.3.4.1 |
| … | 4 | `ClientUserName` 头 | `wBlobType` u16 + `wBlobLen` u16 | MUST = `BB_CLIENT_USER_NAME_BLOB (0x000F)` | §2.2.2.2 |
| … | var | `ClientUserName.blobData` | ANSI 字符串 | 用户名，NUL 结尾 | §2.2.2.2 |
| … | 4 | `ClientMachineName` 头 | `wBlobType` u16 + `wBlobLen` u16 | MUST = `BB_CLIENT_MACHINE_NAME_BLOB (0x0010)` | §2.2.2.2 |
| … | var | `ClientMachineName.blobData` | ANSI 字符串 | 机器名，NUL 结尾 | §2.2.2.2 |

**`EncryptedPreMasterSecret` 长度自校验**：

- 512-bit 服务器密钥 → `keylen = 64 + 8 = 72 = 0x48`。
- 2048-bit 服务器密钥 → `keylen = 256 + 8 = 264 = 0x108`。
- §11.2 的官方 dump 中 `wBlobLen = 0x0108`，**证明该抓包的服务器用 2048-bit 密钥**，
  与 Appendix A `<2>` / `<8>` / `<19>` 的"Windows 使用 2048-bit 密钥"完全一致。

#### 4.2.1 `PlatformId` 编码（Appendix A `<9>`/`<10>`/`<11>`）

| 字节（大端视角） | 内容 | 取值 |
|---|---|---|
| 最高字节（bits 31–24） | 客户端 OS 版本 | 见下表 |
| 次高字节（bits 23–16） | ISV 标识 | 见下表 |
| bits 15–8 | ISV 用于 build number | 微软实现未使用（推导，C 级） |
| 最低字节（bits 7–0） | OS 次版本号 | Appendix A `<11>` |

OS 版本（Appendix A `<9>`）：

| 值 | 名称 | 含义 |
|---|---|---|
| `0x01000000` | `CLIENT_OS_ID_WINNT_351` | 3.51 |
| `0x02000000` | `CLIENT_OS_ID_WINNT_40` | 4.0 |
| `0x03000000` | `CLIENT_OS_ID_WINNT_50` | 5.0 |
| `0x04000000` | `CLIENT_OS_ID_WINNT_POST_52` | 5.2–6.3（含） |
| `0x08000000` | `CLIENT_OS_ID_WINNT_POST_100` | 10.0 及以后 |

ISV 标识（Appendix A `<10>`）：

| 值 | 名称 | 含义 |
|---|---|---|
| `0x00010000` | `CLIENT_IMAGE_ID_MICROSOFT` | 微软 |
| `0x00020000` | `CLIENT_IMAGE_ID_CITRIX` | Citrix |

**实例**：§11.2 官方 dump 的 `PlatformId = 00 00 01 04`（LE）→ 数值 `0x04010000`
= `CLIENT_OS_ID_WINNT_POST_52 (0x04000000)` | `CLIENT_IMAGE_ID_MICROSOFT (0x00010000)` | 次版本 0。

> 实现建议：本项目可直接发 `0x04010000`（与 mstsc 在 Windows 10/11 上的实际值一致，有官方 dump 佐证），
> 或发 `0x08010000`（声明 Win10+）。规范只要求"能帮助服务器识别客户端"，未规定校验规则（推导，见 §7）。

### 4.3 `CLIENT_LICENSE_INFO`（bMsgType = 0x12）

来源：[MS-RDPELE] §2.2.2.3。发送条件：客户端 license store 中**有**匹配 CAL（§3.3.5.3）。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `PreferredKeyExchangeAlg` | u32 LE | 同 §4.2，MUST = 1 | §2.2.2.3 |
| 4 | 4 | `PlatformId` | u32 LE | 同 §4.2 | §2.2.2.3 |
| 8 | 32 | `ClientRandom` | u8[32] | 同 §4.2 | §2.2.2.3 |
| 40 | 4 | `EncryptedPreMasterSecret` 头 | u16+u16 | MUST = `BB_RANDOM_BLOB (0x0002)` | §2.2.2.3 |
| 44 | var | `EncryptedPreMasterSecret.pBlob` | u8[] | 同 §4.2 | §2.2.2.3 |
| … | 4 | `LicenseInfo` 头 | u16+u16 | MUST = `BB_DATA_BLOB (0x0001)` | §2.2.2.3 |
| … | var | `LicenseInfo.blobData` | u8[] | CAL 原始字节（来自 license store），即 `NEW_LICENSE_INFO.pbLicenseInfo` | §2.2.2.3、§2.2.2.6.1 |
| … | 4 | `EncryptedHWID` 头 | u16+u16 | 类型见下方"陷阱" | §2.2.2.3 |
| … | var | `EncryptedHWID.pBlob` | u8[] | `CLIENT_HARDWARE_ID`（20 字节）用许可加密密钥 **RC4** 加密 | §2.2.2.3、§5.1.3 |
| … | 16 | `MACData` | u8[16] | 对**未加密**的 `CLIENT_HARDWARE_ID` 计算 MD5 MAC | §2.2.2.3、§5.1.5 |

**陷阱（BLOB 类型不一致）**：

- §2.2.2.3 对 `EncryptedHWID` 只写 "A Licensing Binary BLOB structure"，**未指定 wBlobType**。
- §2.2.2.5（Platform Challenge Response）对同名字段 **MUST** 指定 `BB_ENCRYPTED_DATA_BLOB (0x0009)`。
- [MS-RDPELE] §4.3 的官方 `CLIENT_LICENSE_INFO` dump 里，`EncryptedHWID::wBlobType` 实际是 **`01 00` = `BB_DATA_BLOB`**。
- **结论**：接收方 MUST **忽略** `EncryptedHWID` 的 `wBlobType`；发送方建议按官方 dump 用 `0x0001`（兼容性最稳）。
  这是规范内部不一致点，列入 §12 不确定项 U3。

### 4.4 `SERVER_PLATFORM_CHALLENGE`（bMsgType = 0x02）

来源：[MS-RDPELE] §2.2.2.4。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `ConnectFlags` | u32 | **Reserved**，接收方 MUST 忽略（官方 dump 里是 `FF FF FF FF`） | §2.2.2.4；§11.3 |
| 4 | 4 | `EncryptedPlatformChallenge` 头 | u16+u16 | `wBlobType` **未使用**（Appendix A `<12>`），`wBlobLen` = 密文长度 | §2.2.2.4；Appendix A `<12>` |
| 8 | var | `EncryptedPlatformChallenge.pBlob` | u8[] | 服务器随机串，用许可加密密钥 **RC4** 加密（§5.1.3）；明文为 NUL 结尾 UTF-16LE 字符串（推导，见 §11.3 官方解密结果 `54 00 45 00 53 00 54 00 00 00` = `"TEST\0"`） | §2.2.2.4；§3.2.1.6 |
| … | 16 | `MACData` | u8[16] | 对**未加密**的 platform challenge 数据计算 MD5 MAC | §2.2.2.4、§5.1.5 |

`ConnectFlags` 之所以是 4 字节"保留"：官方 dump 直接写 `FF FF FF FF` 并在注解里标 `(ignored)`
（§11.3），说明服务器**不初始化**该字段。实现 MUST NOT 校验其值。

### 4.5 `CLIENT_PLATFORM_CHALLENGE_RESPONSE`（bMsgType = 0x15）

来源：[MS-RDPELE] §2.2.2.5。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `EncryptedPlatformChallengeResponse` 头 | u16+u16 | MUST = `BB_ENCRYPTED_DATA_BLOB (0x0009)` | §2.2.2.5 |
| 4 | var | 同上 `.pBlob` | u8[] | `PLATFORM_CHALLENGE_RESPONSE_DATA` 用许可加密密钥 RC4 加密 | §2.2.2.5、§5.1.3 |
| … | 4 | `EncryptedHWID` 头 | u16+u16 | MUST = `BB_ENCRYPTED_DATA_BLOB (0x0009)` | §2.2.2.5 |
| … | var | 同上 `.pBlob` | u8[] | `CLIENT_HARDWARE_ID`（20 字节）RC4 加密 | §2.2.2.5 |
| … | 16 | `MACData` | u8[16] | 对 "`PLATFORM_CHALLENGE_RESPONSE_DATA` + 解密后的 `CLIENT_HARDWARE_ID`" 计算 MD5 MAC | §2.2.2.5、§5.1.5 |

> `EncryptedHWID.pBlob` 长度恒为 **20**（= `CLIENT_HARDWARE_ID` 大小），RC4 是流密码故密文同长。
> §11.4 官方 dump 的 `wBlobLen = 0x0014` 正是 20，自校验通过。

#### 4.5.1 `PLATFORM_CHALLENGE_RESPONSE_DATA`

来源：[MS-RDPELE] §2.2.2.5.1。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 2 | `wVersion` | u16 LE | MUST = `0x0100` | §2.2.2.5.1 |
| 2 | 2 | `wClientType` | u16 LE | 见下表 | §2.2.2.5.1 |
| 4 | 2 | `wLicenseDetailLevel` | u16 LE | 见下表 | §2.2.2.5.1 |
| 6 | 2 | `cbChallenge` | u16 LE | `pbChallenge` 字节数 | §2.2.2.5.1 |
| 8 | var | `pbChallenge` | u8[] | **解密后**的服务器 platform challenge 原文（含 NUL 结尾） | §2.2.2.5.1 |

`wClientType`（§2.2.2.5.1）：

| 值 | 名称 | 含义 |
|---|---|---|
| `0x0100` | `WIN32_PLATFORMCHALLENGE_TYPE` | Win32 |
| `0x0200` | `WIN16_PLATFORMCHALLENGE_TYPE` | Win16 |
| `0x0300` | `WINCE_PLATFORMCHALLENGE_TYPE` | WinCE |
| `0xFF00` | `OTHER_PLATFORMCHALLENGE_TYPE` | 其它 |

`wLicenseDetailLevel`（§2.2.2.5.1）：

| 值 | 名称 | 含义 |
|---|---|---|
| `0x0001` | `LICENSE_DETAIL_SIMPLE` | 客户端许可证证书 + 许可服务器证书，不含签发者细节 |
| `0x0002` | `LICENSE_DETAIL_MODERATE` | 证书链到许可服务器证书的签发者 |
| `0x0003` | `LICENSE_DETAIL_DETAIL` | 证书链到根证书 |

规范要求：RDP 5.0+ 客户端 SHOULD 设 `0x0003` 以支持 ≥6.5 KB 的大许可证（§2.2.2.5.1）。
Appendix A `<14>`：除 WinCE 外所有微软客户端都用 `0x0100`。
§1.7 明确：整个许可扩展**没有能力协商**，唯一的能力广告就是这个 `wLicenseDetailLevel`。

### 4.6 `SERVER_NEW_LICENSE`（0x03）/ `SERVER_UPGRADE_LICENSE`（0x04）

来源：[MS-RDPELE] §2.2.2.7、§2.2.2.6。

§2.2.2.7 原文："The structure and the content of this message are the same as the Server Upgrade License message."
→ **两者字节结构完全一致**，仅 `bMsgType` 不同（0x03 = 新发，0x04 = 升级）。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `EncryptedLicenseInfo` 头 | u16+u16 | `wBlobType` SHOULD = `BB_ENCRYPTED_DATA_BLOB (0x0009)` | §2.2.2.6；Appendix A `<15>` |
| 4 | var | 同上 `.pBlob` | u8[] | `NEW_LICENSE_INFO` 用许可加密密钥 RC4 加密 | §2.2.2.6、§5.1.3 |
| … | 16 | `MACData` | u8[16] | 对**未加密**的 `NEW_LICENSE_INFO` 计算 MD5 MAC | §2.2.2.6、§5.1.5 |

Appendix A `<15>`：Server 2008/2008 R2/2012 发 `0x0009`；**Server 2003 的 `wBlobType` 未定义**。
→ 接收方 MUST 忽略该字段（与 `EncryptedHWID` 同理）。

#### 4.6.1 `NEW_LICENSE_INFO`

来源：[MS-RDPELE] §2.2.2.6.1。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `dwVersion` | u32 LE | 同 `PRODUCT_INFO.dwVersion`（高 16 = 主版本，低 16 = 次版本） | §2.2.2.6.1 |
| 4 | 4 | `cbScope` | u32 LE | `pbScope` 字节数 | §2.2.2.6.1 |
| 8 | var | `pbScope` | **ANSI** 字符串 | 许可证签发者名，NUL 结尾（例 `"TailSpin Toys"`） | §2.2.2.6.1 |
| … | 4 | `cbCompanyName` | u32 LE | 同 `PRODUCT_INFO.cbCompanyName` | §2.2.2.6.1 |
| … | var | `pbCompanyName` | **UTF-16LE** 字符串 | 同 `PRODUCT_INFO.pbCompanyName` | §2.2.2.6.1 |
| … | 4 | `cbProductId` | u32 LE | 同 `PRODUCT_INFO.cbProductId` | §2.2.2.6.1 |
| … | var | `pbProductId` | **UTF-16LE** 字符串 | 同 `PRODUCT_INFO.pbProductId` | §2.2.2.6.1 |
| … | 4 | `cbLicenseInfo` | u32 LE | `pbLicenseInfo` 字节数 | §2.2.2.6.1 |
| … | var | `pbLicenseInfo` | u8[] | **CAL 原始字节**：许可服务器生成的 X.509 证书链。对客户端**不透明**，只需原样存回并在下次连接时通过 `CLIENT_LICENSE_INFO.LicenseInfo` 发回 | §2.2.2.6.1 |

**编码混合陷阱（极易踩）**：同一个结构里 `pbScope` 是 **ANSI（单字节）**，而
`pbCompanyName` / `pbProductId` 是 **UTF-16LE（双字节）**。
§11.1 官方 `SERVER_LICENSE_REQUEST` 里 `pbCompanyName` 是 `4d 00 69 00 63 00 ...`（UTF-16LE，44 字节）；
§11.5 官方 `NEW_LICENSE_INFO` 解密结果里 `pbScope` 是 `6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00`
（ANSI，14 字节）——两者在同一 dump 内并存，是硬证据。

**存证索引键**：`dwVersion` + `pbScope` + `pbCompanyName` + `pbProductId`
（§2.2.2.6.1："The dwVersion, pbScope, pbCompanyName, and pbProductId fields are used by the client to index
the licenses in the client's license store"）。客户端 MAY 存盘（§3.3.5.6："The client then MAY store..."）。

#### 4.6.2 CAL 的语义（`LICENSED_PRODUCT_INFO` 扩展）

`pbLicenseInfo` 内部的 X.509 叶证书带扩展 OID `1.3.6.1.4.1.311.18.5`
（`szOID_PKIX_LICENSED_PRODUCT_INFO`），编码为 `LICENSED_PRODUCT_INFO`（§2.2.2.9.1）：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `Version` | u32 | 结构版本 |
| 4 | 4 | `LicenseCount` | u32 | 已发给该客户端的许可数量 |
| 8 | 4 | `PlatformId` | u32 | 客户端请求时的 `PlatformId` |
| 12 | 4 | `LicensedLanguageId` | u32 | 许可服务器活动语言 ID |
| 16 | 2 | `RequestedProductIdOffset` | u16 | 从结构首字节起算的偏移 |
| 18 | 2 | `RequestedProductIdByteCount` | u16 | |
| 20 | 2 | `AdjustedProductIdOffset` | u16 | |
| 22 | 2 | `AdjustedProductIdByteCount` | u16 | |
| 24 | 2 | `LicensedVersionInfoOffset` | u16 | |
| 26 | 2 | `LicensedVersionInfoCount` | u16 | MUST = `0x0001` |
| 28 | var | `RequestedProductId` | u8[] | |
| … | var | `AdjustedProductId` | u8[] | |
| … | 8 | `LicensedVersionInfo` | `LICENSED_VERSION_INFO` | 见下 |

`LICENSED_VERSION_INFO`（§2.2.2.9.1.1，8 字节）：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 2 | `ProductLicenseMajorVersion` | u16 | RDSH 产品主版本 |
| 2 | 2 | `ProductLicenseMinorVersion` | u16 | RDSH 产品次版本 |
| 4 | 4 | `ProductLicenseFlags` | u32 | 见下表 |

| 标志 | 值 | 含义 |
|---|---|---|
| `LICENSE_ENFORCED` | `0x00008000` | 许可被强制执行 |
| `RTM_LICENSE` | `0x00800000` | RTM 许可（未置位 = beta 许可） |
| `TEMPORARY_LICENSE` | `0x80000000` | 临时许可（未置位 = 永久许可） |

其余扩展 OID（§2.2.2.9）：`1.3.6.1.4.1.311.18.4`（`CERT_VERSION`）、`.18.2`（`MANUFACTURER`）、
`.18.6`（`MS_LICENSE_SERVER_INFO`）、`.18.7`（`PRODUCT_SPECIFIC_OID`）；证书用 OID `1.3.14.3.2.29`
（`sha1RSASign`）签名。**本项目不需要解析这些**（§10 说明），列出仅为完整性。

### 4.7 `LICENSE_ERROR_MESSAGE`（bMsgType = 0xFF，`ERROR_ALERT`）

来源：[MS-RDPBCGR] §2.2.1.12.1.3（MS-RDPELE §2.2.2.8 直接引用该节，无独立结构定义）。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `dwErrorCode` | u32 LE | 错误/状态码，见 §4.7.1 | §2.2.1.12.1.3 |
| 4 | 4 | `dwStateTransition` | u32 LE | 收到本消息后的状态迁移，见 §4.7.2 | §2.2.1.12.1.3 |
| 8 | 4 | `bbErrorInfo` 头 | u16+u16 | MUST = `BB_ERROR_BLOB (0x0004)` | §2.2.1.12.1.3 |
| 12 | var | `bbErrorInfo.blobData` | u8[] | 错误详情；无详情时 `wBlobLen=0`（此时无 blobData） | §2.2.1.12.1.3；§3.1.5.2 |

> `LICENSE_VALID_CLIENT_DATA`（§2.2.1.12.1）进一步收紧：`bMsgType` MUST = `0xFF`，
> `dwStateTransition` MUST = `ST_NO_TRANSITION(0x02)`，`bbErrorInfo` MUST 为**空** `BB_ERROR_BLOB`。
> 即 Valid Client PDU 恒为 **16 字节**（4 + 4 + 4 + 4）。

#### 4.7.1 全部错误码（含未定义空洞）

来源：[MS-RDPBCGR] §2.2.1.12.1.3。

**客户端发送**：

| 名称 | 值 | 语义 | 依据 |
|---|---|---|---|
| `ERR_INVALID_SERVER_CERTIFICATE` | `0x00000001` | 服务器证书验证失败 | §2.2.1.12.1.3；[MS-RDPELE] §3.3.5.1 |
| `ERR_NO_LICENSE` | `0x00000002` | 客户端主动放弃（无可用许可） | §2.2.1.12.1.3；[MS-RDPELE] §3.3.5.1 |

**服务器发送**：

| 名称 | 值 | 语义 | 依据 |
|---|---|---|---|
| `ERR_INVALID_SCOPE` | `0x00000004` | Scope 非法 | §2.2.1.12.1.3 |
| `ERR_NO_LICENSE_SERVER` | `0x00000006` | 无可用许可服务器 | §2.2.1.12.1.3 |
| `STATUS_VALID_CLIENT` | `0x00000007` | **成功**：客户端无需（或已有）许可 | §2.2.1.12.1.3；§2.2.1.12.1 |
| `ERR_INVALID_CLIENT` | `0x00000008` | 客户端非法 / 消息乱序 / 畸形 | §2.2.1.12.1.3；[MS-RDPELE] §3.2.5.8 |
| `ERR_INVALID_PRODUCTID` | `0x0000000B` | ProductId 非法 | §2.2.1.12.1.3 |
| `ERR_INVALID_MESSAGE_LEN` | `0x0000000C` | 消息长度非法 | §2.2.1.12.1.3 |

**双向**：

| 名称 | 值 | 语义 | 依据 |
|---|---|---|---|
| `ERR_INVALID_MAC` | `0x00000003` | MAC 校验失败 | §2.2.1.12.1.3；[MS-RDPELE] §3.1.5.1、§3.2.5.9、§3.3.5.9 |

**未定义空洞（必须显式处理为"未知错误码"）**：
`0x00000000`、`0x00000005`、`0x00000009`、`0x0000000A`、`0x0000000D` 及以上——
§2.2.1.12.1.3 的表里**没有**这些值。实现 MUST 把未知码当作"许可失败"但**不要**假定语义，
建议记录原始值后按 `dwStateTransition` 决定动作（推导，C 级）。

#### 4.7.2 全部状态迁移码

来源：[MS-RDPBCGR] §2.2.1.12.1.3；语义见 [MS-RDPELE] §3.1.5.3。

| 名称 | 值 | 语义 | 依据 |
|---|---|---|---|
| `ST_TOTAL_ABORT` | `0x00000001` | 中止许可协议；**MAY** 断开 RDP 连接（取决于服务器许可系统） | §2.2.1.12.1.3；[MS-RDPELE] §3.1.5.3、Appendix A `<16>` |
| `ST_NO_TRANSITION` | `0x00000002` | 无迁移 = **成功**（必须与 `STATUS_VALID_CLIENT` 配对） | §2.2.1.12.1.3；[MS-RDPELE] §3.1.5.3 |
| `ST_RESET_PHASE_TO_START` | `0x00000003` | 重置许可阶段到起点（客户端回 "Client Licensing Await"，服务器回 "Server Licensing Begin"） | §2.2.1.12.1.3；[MS-RDPELE] §3.1.5.3 |
| `ST_RESEND_LAST_MESSAGE` | `0x00000004` | 重发上一条消息 | §2.2.1.12.1.3；[MS-RDPELE] §3.1.5.3 |

Appendix A `<17>`：**所有微软实现都不发** `ST_RESET_PHASE_TO_START` 与 `ST_RESEND_LAST_MESSAGE`。
→ 本项目可以不实现这两个分支（只需能识别并记录）。

### 4.8 `CLIENT_HARDWARE_ID`

来源：[MS-RDPELE] §2.2.2.3.1。固定 **20 字节**。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `PlatformId` | u32 LE | 与 `CLIENT_NEW_LICENSE_REQUEST.PlatformId` **相同** | §2.2.2.3.1、§3.3.1.9 |
| 4 | 4 | `Data1` | u32 LE | 硬件相关数据 | §2.2.2.3.1 |
| 8 | 4 | `Data2` | u32 LE | 硬件相关数据 | §2.2.2.3.1 |
| 12 | 4 | `Data3` | u32 LE | 硬件相关数据 | §2.2.2.3.1 |
| 16 | 4 | `Data4` | u32 LE | 硬件相关数据 | §2.2.2.3.1 |

规范对 `Data1..Data4` 的**唯一**要求："MUST contain a number that helps the server uniquely identify the client"
（§2.2.2.3.1）。具体构造规则见 §7。

---

## 5. `LICENSE_BINARY_BLOB` 通用布局

来源：[MS-RDPBCGR] §2.2.1.12.1.2。

### 5.1 布局

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 2 | `wBlobType` | u16 LE | 数据类型；若 `wBlobLen==0` 则 SHOULD 忽略 |
| 2 | 2 | `wBlobLen` | u16 LE | `blobData` 字节数；若为 0 则 **`blobData` 字段不存在** |
| 4 | var | `blobData` | u8[] | 长度由 `wBlobLen` 给出 |

**两条硬规则**（§2.2.1.12.1.2）：

1. `wBlobLen == 0` → `blobData` **不出现在线上**（不是"存在但为空"），结构总长恒为 **4 字节**。
2. `wBlobLen == 0` → `wBlobType` 内容 SHOULD 被忽略（`SERVER_LICENSE_REQUEST.ServerCertificate` 靠这条省掉证书）。

### 5.2 全部 BLOB 类型（`wBlobType`）

来源：[MS-RDPBCGR] §2.2.1.12.1.2。

| 值 | 名称 | 使用位置 | 依据 |
|---|---|---|---|
| `0x0001` | `BB_DATA_BLOB` | `CLIENT_LICENSE_INFO.LicenseInfo`；`CLIENT_PLATFORM_CHALLENGE_RESPONSE`（表内注明）；官方 dump 里 `CLIENT_LICENSE_INFO.EncryptedHWID` 也用它 | §2.2.1.12.1.2 |
| `0x0002` | `BB_RANDOM_BLOB` | `EncryptedPreMasterSecret`（`CLIENT_NEW_LICENSE_REQUEST` / `CLIENT_LICENSE_INFO`） | §2.2.1.12.1.2 |
| `0x0003` | `BB_CERTIFICATE_BLOB` | `SERVER_LICENSE_REQUEST.ServerCertificate` | §2.2.1.12.1.2 |
| `0x0004` | `BB_ERROR_BLOB` | `LICENSE_ERROR_MESSAGE.bbErrorInfo` | §2.2.1.12.1.2 |
| `0x0009` | `BB_ENCRYPTED_DATA_BLOB` | `CLIENT_PLATFORM_CHALLENGE_RESPONSE` 两个字段；`SERVER_UPGRADE_LICENSE` / `SERVER_NEW_LICENSE.EncryptedLicenseInfo` | §2.2.1.12.1.2 |
| `0x000D` | `BB_KEY_EXCHG_ALG_BLOB` | `SERVER_LICENSE_REQUEST.KeyExchangeList` | §2.2.1.12.1.2 |
| `0x000E` | `BB_SCOPE_BLOB` | `SCOPE`（`SCOPE_LIST` 元素） | §2.2.1.12.1.2 |
| `0x000F` | `BB_CLIENT_USER_NAME_BLOB` | `CLIENT_NEW_LICENSE_REQUEST.ClientUserName` | §2.2.1.12.1.2 |
| `0x0010` | `BB_CLIENT_MACHINE_NAME_BLOB` | `CLIENT_NEW_LICENSE_REQUEST.ClientMachineName` | §2.2.1.12.1.2 |

**交叉引用（不在 §2.2.1.12.1.2 表内，但属同一 u16 类型空间）**：

| 值 | 名称 | 使用位置 | 依据 |
|---|---|---|---|
| `0x0006` | `BB_RSA_KEY_BLOB` | `PROPRIETARYSERVERCERTIFICATE.wPublicKeyBlobType` | [MS-RDPBCGR] §2.2.1.4.3.1.1 |
| `0x0008` | `BB_RSA_SIGNATURE_BLOB` | `PROPRIETARYSERVERCERTIFICATE.wSignatureBlobType` | [MS-RDPBCGR] §2.2.1.4.3.1.1 |

> 推导（C 级）：这两个值出现在服务器证书内部，不在许可消息的直接字段上；许可解析器**不需要**处理它们，
> 除非要验证 `PROPRIETARYSERVERCERTIFICATE` 签名（本项目可选，见 §10）。

### 5.3 服务器证书容器（仅在需要取 RSA 公钥时解析）

`SERVER_CERTIFICATE`（[MS-RDPBCGR] §2.2.1.4.3.1）：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `dwVersion` | u32 LE | bit31 = `t`（0=永久证书，1=临时证书）；bit30–0 = `certChainVersion` |
| 4 | var | `certData` | — | 由 `certChainVersion` 决定 |

`certChainVersion`（§2.2.1.4.3.1）：

| 值 | 名称 | `certData` 内容 |
|---|---|---|
| `0x00000001` | `CERT_CHAIN_VERSION_1` | `PROPRIETARYSERVERCERTIFICATE`（§5.3.1） |
| `0x00000002` | `CERT_CHAIN_VERSION_2` | X.509 证书（`X509_CERTIFICATE_CHAIN`，§5.3.2） |

#### 5.3.1 `PROPRIETARYSERVERCERTIFICATE`

来源：[MS-RDPBCGR] §2.2.1.4.3.1.1。

| 偏移 | 长度 | 字段 | 类型 | 值/说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `dwVersion` | u32 LE | MUST = `CERT_CHAIN_VERSION_1 (0x00000001)` | §2.2.1.4.3.1.1 |
| 4 | 4 | `dwSigAlgId` | u32 LE | MUST = `SIGNATURE_ALG_RSA (0x00000001)` | §2.2.1.4.3.1.1 |
| 8 | 4 | `dwKeyAlgId` | u32 LE | MUST = `KEY_EXCHANGE_ALG_RSA (0x00000001)` | §2.2.1.4.3.1.1 |
| 12 | 2 | `wPublicKeyBlobType` | u16 LE | MUST = `BB_RSA_KEY_BLOB (0x0006)` | §2.2.1.4.3.1.1 |
| 14 | 2 | `wPublicKeyBlobLen` | u16 LE | `PublicKeyBlob` 字节数 | §2.2.1.4.3.1.1 |
| 16 | var | `PublicKeyBlob` | `RSA_PUBLIC_KEY` | 见 §9.3 | §2.2.1.4.3.1.1.1 |
| … | 2 | `wSignatureBlobType` | u16 LE | 置为 `BB_RSA_SIGNATURE_BLOB (0x0008)` | §2.2.1.4.3.1.1 |
| … | 2 | `wSignatureBlobLen` | u16 LE | `SignatureBlob` 字节数 | §2.2.1.4.3.1.1 |
| … | var | `SignatureBlob` | u8[] | 用 Terminal Services Signing Key 对证书前 6 字段签名 | §2.2.1.4.3.1.1、§5.3.3.1.2 |

#### 5.3.2 `X509_CERTIFICATE_CHAIN`

来源：[MS-RDPELE] §2.2.1.4.2、§2.2.1.4.2.1。

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `NumCertBlobs` | u32 LE | `CertBlob` 个数；最小 2（自签许可服务器证书 + 终端服务器证书），最大 200 |
| 4 | var | `CertBlobArray` | `CERT_BLOB[NumCertBlobs]` | 根证书在前；倒数第二个 = 许可服务器证书；最后 = 终端服务器证书 |
| … | var | `Padding` | u8[] | 长度 = `8 + 4*NumCertBlobs` 字节 |

`CERT_BLOB`（§2.2.1.4.2.1）：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `cbCert` | u32 LE | `abCert` 字节数 |
| 4 | var | `abCert` | u8[] | 单个 X.509 证书的 DER 编码 |

> **本项目的 RSA 公钥来源优先级**（推导，C 级，由 §2.2.2.1 三个分支 + §2.2.1.4.3.1 推出）：
> ① 若 `ServerCertificate` BLOB 的 `wBlobLen > 0` → 从其中取；
> ② 否则从 Server MCS Connect Response 的 `TS_UD_SC_SEC1.serverCertificate` 取（`dwVersion` 的
> `certChainVersion` 决定是 proprietary 还是 X.509）；
> ③ 两者都没有 → 无法做 RSA，必须报错（此时服务器实际上也无法解密 premaster）。

---

## 6. 加密 / 完整性：许可阶段数据如何被保护

这一节要区分**三层**独立机制，实现时不能混淆：

| 层 | 名称 | 密钥来源 | 作用范围 | 依据 |
|---|---|---|---|---|
| L1 | 外部安全协议（TLS / CredSSP） | TLS 握手协商 | **整条 TCP 连接**（含 TPKT/X.224/MCS 全部字节） | [MS-RDPBCGR] §5.4、§5.4.5 |
| L2 | Standard RDP Security（RC4 + MAC） | `clientRandom` + `serverRandom`（§5.3.4/§5.3.5） | 许可 PDU 的 `securityHeader` 之后的数据（**可选**） | [MS-RDPBCGR] §5.3；[MS-RDPELE] §2.2.2 |
| L3 | 许可内部加密（RC4 + MD5 MAC） | `PremasterSecret` + 两个 random（§5.1.2） | 许可消息内部的 `Encrypted*` 字段 | [MS-RDPELE] §5.1.2–§5.1.5 |

### 6.1 L3 是**永远存在**的（与 TLS 无关）

这是最容易误判的一点。许可协议自身定义了独立的加密层，**只要走 `NEW_LICENSE_REQUEST` 路径就必须实现**：

| 被加密字段 | 所在消息 | 算法 | MAC 覆盖范围 | 依据 |
|---|---|---|---|---|
| `EncryptedPlatformChallenge` | `SERVER_PLATFORM_CHALLENGE` (0x02) | RC4(LicensingEncryptionKey) | 未加密的 challenge 明文 | [MS-RDPELE] §2.2.2.4 |
| `EncryptedHWID` | `CLIENT_LICENSE_INFO` (0x12) | RC4(LicensingEncryptionKey) | 未加密的 `CLIENT_HARDWARE_ID` | §2.2.2.3 |
| `EncryptedPlatformChallengeResponse` | `CLIENT_PLATFORM_CHALLENGE_RESPONSE` (0x15) | RC4(LicensingEncryptionKey) | — | §2.2.2.5 |
| `EncryptedHWID` | 同上 | RC4(LicensingEncryptionKey) | `PCR_DATA` + 解密后的 HWID | §2.2.2.5 |
| `EncryptedLicenseInfo` | `NEW_LICENSE` (0x03) / `UPGRADE_LICENSE` (0x04) | RC4(LicensingEncryptionKey) | 未加密的 `NEW_LICENSE_INFO` | §2.2.2.6 |

**L3 密钥派生链**（[MS-RDPELE] §5.1.2，逐字）：

```
SaltedHash(S, I)   = MD5(S + SHA-1(I + S + ClientRandom + ServerRandom))
PreMasterHash(I)   = SaltedHash(PremasterSecret, I)
MasterSecret       = PreMasterHash('A') + PreMasterHash('BB') + PreMasterHash('CCC')      // 48 字节

SaltedHash2(S, I)  = MD5(S + SHA-1(I + S + ServerRandom + ClientRandom))   // 注意顺序相反
MasterHash(I)      = SaltedHash2(MasterSecret, I)
SessionKeyBlob     = MasterHash('A') + MasterHash('BB') + MasterHash('CCC')               // 48 字节

MAC-salt-key              = First128Bits(SessionKeyBlob)     // 前 16 字节
LicensingEncryptionKey    = MD5(Second128Bits(SessionKeyBlob) + ClientRandom + ServerRandom)  // 16 字节
```

关键细节（全部来自 §5.1.2 原文）：

- `I` 是**字面字符串** `'A'`（1 字节 0x41）、`'BB'`（2 字节）、`'CCC'`（3 字节），**不是**重复字符。
- 第一轮 `SaltedHash` 的拼接顺序是 `I + S + ClientRandom + ServerRandom`；
  第二轮 `SaltedHash2` 是 `I + S + ServerRandom + ClientRandom`（**顺序相反**，极易写错）。
- `MasterSecret` 是 **48 字节**（3 × 16），不是 32 或 40。
- `LicensingEncryptionKey` 是 `MD5(...)` 的 **16 字节**全量，不是截断。

**L3 加密**（§5.1.3）：`EncryptedData = RC4(LicensingEncryptionKey, LicensingData)`。
RC4 是流密码，**密文长度 == 明文长度**（无填充）。每次加密都从**密钥流起点**开始（推导，C 级：
§5.1.3 未提状态延续，且 §11.3/§11.5 的密文长度与明文完全相等，无 IV/无链式结构）。

**L3 MAC**（§5.1.5，逐字）：

```
MACData = MD5(MAC-salt-key + pad2 + SHA-1(MAC-salt-key + pad1 + data-length + data-content))
```

- `pad1` = `0x36` 重复 **40** 次（320 bit）。
- `pad2` = `0x5C` 重复 **48** 次（384 bit）。
- `data-length` = 数据长度，**little-endian u32**。
- `data-content` = 完整待保护数据。
- 输出 **16 字节**全量 MD5（注意：与 Standard RDP Security 的 8 字节截断 MAC **不同**）。

### 6.2 L2：Standard RDP Security 下的行为

当协商结果为 `PROTOCOL_RDP`（Standard RDP Security）时（[MS-RDPBCGR] §5.3、[MS-RDPELE] §2.2.2）：

| 条件 | securityHeader 形态 | 是否加密 preamble+message |
|---|---|---|
| `ENCRYPTION_LEVEL_NONE(0)` 或 `LOW(1)` 且未置 `SEC_ENCRYPT` | Basic（4 字节） | 否 |
| `CLIENT_COMPATIBLE(2)` / `HIGH(3)` 且置 `SEC_ENCRYPT(0x0008)` | Non-FIPS（12 字节 = 4 + 8 字节 MAC） | 是（RC4 会话密钥） |
| `FIPS(4)` 且置 `SEC_ENCRYPT` | FIPS（16 字节 = 4 + 2 length + 1 version + 1 padlen + 8 MAC） | 是（3DES） |
| `CLIENT_COMPATIBLE`/`HIGH`/`FIPS` 但**未**置 `SEC_ENCRYPT` | Basic（4 字节） | 否 |

**Basic security header**（[MS-RDPBCGR] §2.2.8.1.1.2.1，4 字节）：

| 偏移 | 长度 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 2 | `flags` | u16 LE | 见下表 |
| 2 | 2 | `flagsHi` | u16 LE | 仅当 `SEC_FLAGSHI_VALID (0x8000)` 置位时有效 |

**Non-FIPS security header**（§2.2.8.1.1.2.2，12 字节）：Basic 4 字节 + `dataSignature` 8 字节（64-bit MAC）。

**FIPS security header**（§2.2.8.1.1.2.3，16 字节）：Basic 4 字节 + `length(2)=0x0010` +
`version(1)=0x01` + `padlen(1)` + `dataSignature(8)`。

与许可相关的 security header 标志位（§2.2.8.1.1.2.1）：

| 标志 | 值 | 语义 |
|---|---|---|
| `SEC_ENCRYPT` | `0x0008` | 本包已加密 |
| `SEC_LICENSE_PKT` | `0x0080` | **所有**许可 PDU MUST 置位 |
| `SEC_LICENSE_ENCRYPT_CS` | `0x0200` | 服务器→客户端：服务器**能处理**加密的许可包 |
| `SEC_LICENSE_ENCRYPT_SC` | `0x0200` | 客户端→服务器：客户端**能处理**加密的许可包（随 Security Exchange PDU 一起发） |
| `SEC_FLAGSHI_VALID` | `0x8000` | `flagsHi` 有效 |

> 注意 `SEC_LICENSE_ENCRYPT_CS` 与 `SEC_LICENSE_ENCRYPT_SC` **数值相同（都是 0x0200）**，
> 靠方向区分语义（[MS-RDPBCGR] §2.2.8.1.1.2.1 表内两行同值）。

**L2 与 L3 的叠加关系**（关键）：当 `SEC_ENCRYPT` 置位时，`preamble + LicensingMessage` 整体被会话密钥
RC4 加密；而 `LicensingMessage` 内部的 `Encrypted*` 字段**在此之前**已用 L3 密钥加密。
即线上是 **L3 密文套在 L2 密文里**（双层加密）。反过来，若 `SEC_ENCRYPT` 未置位，
则只有 L3 单层保护 `Encrypted*` 字段，`preamble`、`ClientRandom`、`ServerRandom`、`MACData` 全部明文。

### 6.3 L1：TLS / PROTOCOL_HYBRID_EX 路径下许可 PDU 是否仍加密

**结论（分三层回答，缺一不可）**：

| 层 | HYBRID_EX 下是否加密 | 依据 |
|---|---|---|
| L1（整条连接） | **是**。TLS 建立后"Traffic on the wire remains encrypted with TLS and is wrapped by TLS headers. There is no double-encryption of traffic" | [MS-RDPBCGR] §5.4.5.2 |
| L2（Standard RDP Security） | **不使用**。Enhanced RDP Security 下 `encryptionMethod` 与 `encryptionLevel` 都 MUST 为 0，Security Commencement 阶段不执行，客户端不发 Security Exchange PDU，因此**没有**会话密钥、**没有** `SEC_ENCRYPT` | [MS-RDPBCGR] §2.2.1.4.3、§5.4.2.3、§5.4.2.4 |
| L3（许可内部 RC4） | **仍然加密**。许可协议自身的 `Encrypted*` 字段与密钥派生流程与外部安全协议**无关**，规范没有任何"TLS 下可跳过 L3"的条款 | [MS-RDPELE] §2.2.2.3–§2.2.2.6、§5.1.2–§5.1.5 |

**securityHeader 在 HYBRID_EX 下的形态**（A 级）：

- 许可 PDU **仍然必须**带 security header —— [MS-RDPBCGR] §1.3.1.1 明确它是两个例外之一。
- 但只能是 **Basic（4 字节）**，且**不含** `SEC_ENCRYPT`：
  "If Enhanced RDP Security is in effect, the External Security Protocol MUST be used to encrypt the entire PDU
  and generate a verification digest. The securityHeader field MUST be present; however, it will contain a
  Basic Security Header structure." —— [MS-RDPBCGR] §3.3.5.3.12（发送侧）、§3.2.5.3.12（接收侧）。
- `SEC_LICENSE_ENCRYPT_CS` / `SEC_LICENSE_ENCRYPT_SC` **不需要**置位：
  "if an External Security Protocol is being used, then the server and client do not need to ever encrypt any
  licensing packets because the External Security Protocol will encrypt them. For this reason, the
  SEC_LICENSE_ENCRYPT_CS (0x0200) and SEC_LICENSE_ENCRYPT_SC (0x0200) flags do not need to be set"
  —— [MS-RDPBCGR] §5.4.2.4。
- `SEC_LICENSE_PKT (0x0080)` **仍然必须**置位（§2.2.2、§3.2.5.3.12）。

**由此推出 HYBRID_EX 路径下许可阶段的实现清单**（推导，C 级）：

1. 不需要 RC4 会话密钥、不需要 Standard RDP Security 的 8 字节 MAC。
2. 仍然需要 **RSA**（加密 premaster secret）—— 因为 L3 密钥由 premaster 派生。
3. 仍然需要 **RC4（16 字节密钥）** —— L3 加解密。
4. 仍然需要 **MD5 + SHA-1** —— L3 密钥派生与 MAC。
5. 仍然需要**服务器 RSA 公钥** —— 见 §6.4 的规范空白。

### 6.4 规范空白：HYBRID_EX 下 RSA 公钥从哪来（重要）

三段规范放在一起会产生冲突：

| 条款 | 原文要点 | 依据 |
|---|---|---|
| a | `ServerCertificate` BLOB "If encryption is in effect and is already protecting RDP traffic, the licensing protocol MAY choose not to send the server certificate" | [MS-RDPELE] §2.2.2.1 |
| b | "If the licensing protocol chooses not to send the server certificate, then the client uses the public key obtained from the server certificate sent as part of Server Security Data in the Server MCS Connect Response PDU" | [MS-RDPELE] §2.2.2.1 |
| c | Enhanced RDP Security 下 `encryptionMethod` / `encryptionLevel` MUST = 0，此时 `serverRandomLen` / `serverCertLen` **MUST NOT be present**，`serverCertificate` **MUST NOT be present** | [MS-RDPBCGR] §2.2.1.4.3 |

冲突点：HYBRID_EX 下 (a) 的条件"encryption is in effect"成立（TLS 在加密），服务器**可以**省略证书；
但 (b) 的兜底来源（Server Security Data）在 (c) 下**必然为空**。此时客户端拿不到公钥，无法加密 premaster，
L3 密钥无法派生，许可协议无法继续。

**可行的三种解释**（推导，C 级，需实测判定，见 §12 U1）：

1. **服务器实际总是发送证书**：即 (a) 的"MAY choose not to send"在 TLS 路径下不被采用，
   `ServerCertificate` BLOB 的 `wBlobLen > 0`。这是最可能的实现（否则协议不可用）。
2. 服务器在 TLS 路径下改用 X.509 链（`CERT_CHAIN_VERSION_2`）并**照常**放进 `ServerCertificate` BLOB。
3. 若 `wBlobLen == 0` 且 Server Security Data 也无证书 → 客户端只能报 `ERR_INVALID_SERVER_CERTIFICATE(0x01)`
   + `ST_TOTAL_ABORT(0x01)`，或直接断开。**这是规范允许但实际不可用的路径**。

> **实现要求**：解析 `SERVER_LICENSE_REQUEST` 时必须**同时**支持两条取公钥路径（BLOB 优先，Security Data 兜底），
> 并在两者都缺失时明确报错，禁止静默使用全零/伪造公钥（否则 MAC 必然失败，且掩盖真实原因）。

### 6.5 完整性校验的失败处理（A 级）

| 角色 | 检测到 MAC 不匹配 | 依据 |
|---|---|---|
| 服务器 | MAY 发 `ERROR_ALERT(ERR_INVALID_MAC 0x03, ST_TOTAL_ABORT 0x01)` | [MS-RDPELE] §3.1.5.1、§3.2.5.9 |
| 客户端 | MAY 发 `ERROR_ALERT(ERR_INVALID_MAC, ST_TOTAL_ABORT)`，然后 **MUST 断开 RDP 连接** | [MS-RDPELE] §3.3.5.9 |

> 注意不对称：客户端在 MAC 失败后**必须断开**（不是"可以断开"）。

---

## 7. HWID（`CLIENT_HARDWARE_ID.Data1..Data4`）计算

### 7.1 规范结论：**规范未定义**

[MS-RDPELE] §2.2.2.3.1 对四个数据字段的**全部**约束只有一句（逐字）：

> "A 32-bit unsigned integer containing client hardware-specific data.
> This field MUST contain a number that helps the server uniquely identify the client."

§3.3.1.9 给出的是**建议**而非规则（逐字）：

> "The other 16 bytes (fields Data1 through Data4) of the Client Hardware Identification are intended to be
> hardware specific. Clients SHOULD attempt to use operating system-specific or hardware-specific information
> that is easily and consistently retrievable. Examples include hard-wired processor IDs, Ethernet addresses of
> nonremovable Ethernet cards, and disk subsystem serial numbers. The client SHOULD cache the Client Hardware
> Identification for later retrieval after it is generated."

**因此**：

- **没有**任何规范化的哈希算法、输入集合、字节序、或 4×u32 的切分规则。
- **没有**任何互操作要求 —— 服务器只是把 20 字节当作不透明索引键存入许可数据库（§2.2.2.3.1 开头：
  "A license server uses the content of this structure as an index into the issued licenses in its database"）。
- 因此**任意稳定值都能工作**（推导，C 级：服务器只需"能区分客户端"，不校验构造方式）。
  这意味着本项目**不需要**复刻 mstsc 的算法即可通过许可阶段。

### 7.2 唯一硬约束

| 约束 | 依据 |
|---|---|
| `PlatformId`（偏移 0..3）MUST 与 `CLIENT_NEW_LICENSE_REQUEST.PlatformId` / `CLIENT_LICENSE_INFO.PlatformId` **完全相同** | §2.2.2.3.1、§3.3.1.9（"This ties a particular Client Hardware Identification to the client's operating system"） |
| 总长恒为 20 字节 | §2.2.2.3.1（4 + 4×4） |
| 同一客户端 SHOULD 缓存并在后续连接复用（否则服务器会把它当新设备，消耗额外 CAL） | §3.3.1.9 |

### 7.3 若要与 mstsc 行为一致：取证建议（不猜测）

以下为**可执行的取证方案**，按成本从低到高排列。**本文不给出"mstsc 用 XX 算法"的结论**，因为无官方依据。

**方案 H1（最强证据，推荐）：自建许可服务器 + 解密 HWID**

原理：HWID 用 L3 密钥加密，而 L3 密钥由 `PremasterSecret` 派生 —— 谁持有服务器 RSA 私钥谁就能解密。

1. 用本仓库的能力做"假服务器"：完成 X.224/MCS/Client Info 后，发 `SERVER_LICENSE_REQUEST`，
   `ServerCertificate` BLOB 里放**自己生成的** RSA 密钥对（proprietary 格式，见 §5.3.1/§9.3）。
2. 客户端（mstsc）回 `CLIENT_NEW_LICENSE_REQUEST` → 用私钥解密 `EncryptedPreMasterSecret` 得到 48 字节 premaster。
3. 按 §5.1.2 派生 `LicensingEncryptionKey`，解密客户端后续 `EncryptedHWID`（20 字节）。
4. 得到真实 HWID 明文。重复 N 次（换网卡 / 换盘 / 改机器名 / 改内存），观察哪 4 个 u32 变化 → 反推输入集合。
5. 若要进一步确认哈希，可用 §5.1.5 的 MAC 反推？不可行（MAC 是单向）。改为：构造候选输入，用候选算法算 16 字节，
   与实测 HWID 比对（离线穷举候选组合）。

**方案 H2（静态证据，成本低但只能给线索）**

对 `mstscax.dll` 做导入表 / 字符串 / 交叉引用分析，看它调用了哪些"硬件指纹"API。本仓库已有导入表快照
（`F:\rtsc\evidence\mstscax\imports.txt`），可读出以下**已确认存在**的导入：

| 导入 | 行号（L02） | 与 HWID 的可能关联（**推测，非结论**） |
|---|---|---|
| `GetVolumeInformationW` | 210 | 卷序列号（`lpVolumeSerialNumber`）—— 规范 §3.3.1.9 提到的 "disk subsystem serial numbers" |
| `FindFirstVolumeW` / `FindNextVolumeW` / `FindVolumeClose` | 183 / — / — | 枚举卷，配合上一行 |
| `GetVolumePathNamesForVolumeNameW` | — | 卷 → 路径映射 |
| `GetSystemFirmwareTable` | 262 | SMBIOS / 固件表（可含主板/BIOS 序列号） |
| `GetSystemInfo` / `GetNativeSystemInfo` | 447 / 397 | CPU 架构/核数（区分度低） |
| `IsProcessorFeaturePresent` | 395 | CPU 特性位（区分度低） |
| `GetComputerNameW` / `GetComputerNameExW` / `GetComputerNameA` | 368 / — / — | 机器名（但机器名已单独在 `ClientMachineName` BLOB 里） |
| `CryptGenRandom` | 990 | 随机数（用于 ClientRandom / 盐，**不是** HWID 输入） |
| `NCryptOpenStorageProvider` / `NCryptOpenKey` / `NCryptExportKey` / `NCryptSignHash` | 851 等 | 证书/密钥操作（许可相关，非 HWID） |

**已确认不存在**的相关导入（负证据，同样有价值）：

| 未出现的 API | 含义 |
|---|---|
| `GetAdaptersAddresses` / `GetAdaptersInfo` / `GetIfTable` | 在 `IPHLPAPI.DLL` 段（L02 第 1122 行起）中**没有**这些符号。该 DLL 只导入了 `CancelMibChangeNotify2` / `GetNetworkConnectivityHint` / `ParseNetworkString` / `CreateSortedAddressPairs` / `FreeMibTable`。→ 规范 §3.3.1.9 举的 "Ethernet addresses" 例子**并非**通过 iphlpapi 的常规枚举 API 获取（可能经 `setupapi` / `CFGMGR32` 设备枚举，或根本未使用） |

> **必须强调**：H2 只能给"候选输入集合"，**不能**证明算法。导入表存在 ≠ 该 API 被 HWID 路径调用
> （mstscax 是巨型 DLL，同一 API 可能服务于完全无关的功能，如 UI、设备重定向、打印）。
> 只有 H1 能得到可复现的字节级证据。

**方案 H3（差分实验，成本中）**

在同一台机器上：
1. 记录一次真实连接的 HWID（用 H1 的解密能力）；
2. 只改一个变量（例如拔掉一块非系统盘、或改机器名、或改内存容量），重连，再记录；
3. 对比 4 个 u32 哪些变了。
   - 若某字段完全不变 → 该输入未参与；
   - 若整块 16 字节全变 → 很可能是**整体哈希**（而非逐字段映射）；
   - 若只有 1 个 u32 变 → 可能是逐字段独立取值。
4. 若判定为整体哈希，再用 H1 的候选穷举确认具体算法（MD5/SHA-1 截断、输入拼接顺序、是否含盐）。

### 7.4 本项目的最小实现建议（可执行结论）

既然 §7.1 已证明"任意稳定值都能工作"，本项目**不需要**复刻 mstsc：

1. `PlatformId` 用与 `CLIENT_NEW_LICENSE_REQUEST` 相同的值（例如 `0x04010000`）。
2. `Data1..Data4` 用**确定性派生**的稳定值，例如：
   - 对 `PlatformId` + 机器名 + 用户名 做一次哈希，取前 16 字节按 LE 切成 4 个 u32；
   - 或直接使用固定的 4 个常量（最简，但同机多客户端会共享同一"设备"身份）。
3. **必须缓存**（写文件或注册表），保证同一机器多次连接 HWID 不变（§3.3.1.9 SHOULD）。
4. 若将来需要与 mstsc 对齐（例如做许可证迁移测试），再执行 §7.3 H1。

---

## 8. 客户端状态机

### 8.1 官方状态集合

来源：[MS-RDPELE] §3.3.1.11（Client Licensing States）、§3.2.1.11（Server Licensing States）。

**客户端 4 个状态**（§3.3.1.11）：

| 状态 | 进入条件 | 依据 |
|---|---|---|
| **Client Licensing Await** | 初始状态 | §3.3.1.11 |
| **Client Process Licensing** | 收到 `SERVER_LICENSE_REQUEST`（0x01） | §3.3.1.11、§3.3.5.1 |
| **Client Licensing Aborted** | 服务器发来乱序/未识别消息或无效 MAC（§3.2.5.8、§3.2.5.9） | §3.3.1.11 |
| **Client Licensing Completed** | 收到 `NEW_LICENSE` / `UPGRADE_LICENSE`，或收到 `STATUS_VALID_CLIENT` + `ST_NO_TRANSITION` | §3.3.1.11、§3.3.5.6、§3.3.5.7 |

> 规范原文在客户端状态描述里把 "Client Licensing Aborted" 的说明写成了 "the client goes into the
> 'Server Licensing Aborted' state"（§3.3.1.11）——这是**规范笔误**，客户端只有 Client 侧状态。
> 记录于此以免实现者困惑（推导，C 级）。

**服务器 4 个状态**（§3.2.1.11）：`Server Licensing Begin` → `Server Process Licensing` →
`Server Licensing Aborted` / `Server Licensing Completed`。

### 8.2 客户端完整迁移表（按收到的 bMsgType）

| # | 当前状态 | 收到 | 附加条件 | 动作 | 新状态 | 依据 |
|---|---|---|---|---|---|---|
| 1 | Await | `LICENSE_REQUEST(0x01)` | 服务器证书验证失败 | 发 `ERROR_ALERT(ERR_INVALID_SERVER_CERTIFICATE 0x01, ST_TOTAL_ABORT 0x01)` | Aborted | §3.3.5.1 第 1 条 |
| 2 | Await | `LICENSE_REQUEST(0x01)` | license store 有匹配 CAL | 派生密钥 → 发 `LICENSE_INFO(0x12)` | Process | §3.3.5.1 第 2 条、§3.3.5.3 |
| 3 | Await | `LICENSE_REQUEST(0x01)` | license store 无匹配 CAL | 派生密钥 → 发 `NEW_LICENSE_REQUEST(0x13)` | Process | §3.3.5.1 第 3 条、§3.3.5.2 |
| 4 | Await | `LICENSE_REQUEST(0x01)` | 客户端主动放弃（MAY） | 发 `ERROR_ALERT(ERR_NO_LICENSE 0x02, ST_TOTAL_ABORT 0x01)` | Aborted | §3.3.5.1 第 4 条 |
| 5 | Process | `PLATFORM_CHALLENGE(0x02)` | — | 解密 challenge → 校验 MAC → 构造 `PCR_DATA` → 发 `PLATFORM_CHALLENGE_RESPONSE(0x15)` | Process | §3.3.5.4、§3.3.5.5 |
| 6 | Process | `NEW_LICENSE(0x03)` | — | 解密 `NEW_LICENSE_INFO` → 校验 MAC → MAY 存 CAL | Completed | §3.3.5.7 |
| 7 | Process | `UPGRADE_LICENSE(0x04)` | — | 同上（替换旧 CAL） | Completed | §3.3.5.6 |
| 8 | Process | `ERROR_ALERT(0xFF)` | `code==STATUS_VALID_CLIENT(0x07)` 且 `transition==ST_NO_TRANSITION(0x02)` | 无（成功） | Completed | §3.1.5.3、§3.3.1.11 |
| 9 | Process | `ERROR_ALERT(0xFF)` | `transition==ST_TOTAL_ABORT(0x01)` | 中止；MAY 断开（Windows XP 实测不断开，见 Appendix A `<16>`） | Aborted | §3.1.5.3 |
| 10 | Process | `ERROR_ALERT(0xFF)` | `transition==ST_RESET_PHASE_TO_START(0x03)` | 回 Await（微软实现不发，见 Appendix A `<17>`） | Await | §3.1.5.3 |
| 11 | Process | `ERROR_ALERT(0xFF)` | `transition==ST_RESEND_LAST_MESSAGE(0x04)` | 重发上一条（微软实现不发） | 不变 | §3.1.5.3 |
| 12 | 任意 | 其它/乱序/畸形 | — | **MUST 断开 RDP 连接** | — | §3.3.5.8 |
| 13 | 任意 | 任意 | L3 MAC 校验失败 | MAY 发 `ERROR_ALERT(ERR_INVALID_MAC 0x03, ST_TOTAL_ABORT 0x01)`，然后 **MUST 断开** | Aborted | §3.3.5.9 |

### 8.3 状态图（ASCII）

```
                    ┌──────────────────────┐
                    │ Client Licensing     │
                    │ Await                │
                    └──────────┬───────────┘
                               │ 收到 0x01 LICENSE_REQUEST
                               │ （证书验证失败 → 发 0xFF(0x01,0x01) → Aborted）
                               ▼
                    ┌──────────────────────┐
        ┌──────────►│ Client Process       │◄──────────┐
        │           │ Licensing            │           │
        │           └──┬────────┬───────┬──┘           │
        │              │        │       │              │
        │  收到 0x02   │        │       │ 收到 0xFF    │
        │  发 0x15     │        │       │ (0x07,0x02)  │
        │              │        │       │              │
        │              │        │       ▼              │
        │              │        │  ┌──────────────────┐│
        │              │        └─►│ Client Licensing ││
        │              │           │ Completed        ││
        │              │           └──────────────────┘│
        │              │ 收到 0x03 / 0x04              │
        │              └───────────────────────────────┘
        │
        │ 收到 0xFF(ST_TOTAL_ABORT) 或 乱序 或 MAC 失败
        ▼
  ┌──────────────────────┐
  │ Client Licensing     │
  │ Aborted  (→ 断开)    │
  └──────────────────────┘
```

### 8.4 超时

`Client Packet Wait Timer`（[MS-RDPELE] §3.3.2.1）：客户端 MAY 实现可配置的等待计时器，
超时未收到服务器响应则 MAY 断开。Appendix A `<20>`：Windows Vista / Server 2008 客户端
默认 **300 秒**。

> 本项目建议：实现为可配置项（默认 300s），与规范产品行为一致；不要硬编码不可调。

---

## 9. RSA 密钥交换

### 9.1 算法编号

| 值 | 名称 | 出现位置 | 依据 |
|---|---|---|---|
| `0x00000001` | `KEY_EXCHANGE_ALG_RSA` | `SERVER_LICENSE_REQUEST.KeyExchangeList` 的 BLOB 内容（u32 数组元素） | [MS-RDPELE] §2.2.2.1 |
| `0x00000001` | `KEY_EXCHANGE_ALG_RSA` | `CLIENT_NEW_LICENSE_REQUEST.PreferredKeyExchangeAlg`（MUST） | §2.2.2.2、§3.3.1.3 |
| `0x00000001` | `KEY_EXCHANGE_ALG_RSA` | `CLIENT_LICENSE_INFO.PreferredKeyExchangeAlg`（同 §4.2） | §2.2.2.3 |
| `0x00000001` | `KEY_EXCHANGE_ALG_RSA` | `PROPRIETARYSERVERCERTIFICATE.dwKeyAlgId` | [MS-RDPBCGR] §2.2.1.4.3.1.1 |
| `0x00000001` | `SIGNATURE_ALG_RSA` | `PROPRIETARYSERVERCERTIFICATE.dwSigAlgId` | [MS-RDPBCGR] §2.2.1.4.3.1.1 |

> 五个位置共用同一个数值 `1`，但**语义不同**（密钥交换 / 签名）。实现时不要因为数值相同就复用常量名。

**密钥长度**：

| 场景 | 位数 | 依据 |
|---|---|---|
| 规范正文（`KEY_EXCHANGE_ALG_RSA` 定义） | "512-bit asymmetric key" | §2.2.2.1、§3.3.1.3 |
| **Windows 实际**（2008 及以后） | **2048-bit** | Appendix A `<2>`、`<8>`、`<19>`："Windows uses 2048-bit keys. Any client/server combinations that include Windows Server 2003 and Windows XP use 512-bit keys" |
| 交叉验证 | §11.2 官方 dump 的 `EncryptedPreMasterSecret.wBlobLen = 0x0108 = 264 = 256 + 8` → 2048-bit | 推导（C 级） |

> **实现 MUST 按 blob 里的 `bitlen` 动态处理**，不能硬编码 512 或 2048。

### 9.2 `KeyExchangeList` 的 BLOB 内容

`LICENSE_BINARY_BLOB`（§5.1）包一个 u32 数组：

| 偏移（BLOB 内） | 长度 | 字段 | 类型 | 值 |
|---|---|---|---|---|
| 0 | 2 | `wBlobType` | u16 LE | `BB_KEY_EXCHG_ALG_BLOB (0x000D)` |
| 2 | 2 | `wBlobLen` | u16 LE | `4`（单算法） |
| 4 | 4 | 算法 ID[0] | u32 LE | `0x00000001` |

§11.1 官方 dump 逐字节为 `0d 00 04 00 01 00 00 00`，完全吻合（自校验通过）。

### 9.3 RSA 公钥 blob 格式（逐字段）

#### 9.3.1 RDP 线上格式（`RSA_PUBLIC_KEY`，**这才是要解析的**）

来源：[MS-RDPBCGR] §2.2.1.4.3.1.1.1。

| 偏移 | 长度 | 字段 | 类型 | 说明 | 依据 |
|---|---|---|---|---|---|
| 0 | 4 | `magic` | u32 LE | MUST = `0x31415352`（ASCII "RSA1"） | §2.2.1.4.3.1.1.1 |
| 4 | 4 | `keylen` | u32 LE | `modulus` 字段字节数；MUST = `(bitlen / 8) + 8` | §2.2.1.4.3.1.1.1 |
| 8 | 4 | `bitlen` | u32 LE | 模数位数 | §2.2.1.4.3.1.1.1 |
| 12 | 4 | `datalen` | u32 LE | 该密钥可编码的最大字节数；MUST = `(bitlen / 8) - 1` | §2.2.1.4.3.1.1.1 |
| 16 | 4 | `pubExp` | u32 LE | 公开指数（通常 `0x00010001` = 65537） | §2.2.1.4.3.1.1.1 |
| 20 | var | `modulus` | u8[`keylen`] | **`(bitlen/8)` 字节模数 + 8 字节零填充**（零填充在模数**之后**） | §2.2.1.4.3.1.1.1 |

**关键点（三个都必须记住）**：

1. **没有** `bType` / `bVersion` / `reserved` / `aiKeyAlg`（那是 CryptoAPI 的 `PUBLICKEYSTRUC`）。
2. `modulus` 的**前 `bitlen/8` 字节是模数**，**后 8 字节是零填充**；`keylen` 包含这 8 字节。
3. 模数字节序是 **little-endian**（最低有效字节在前）——见 §9.4。

**尺寸自校验表**：

| `bitlen` | `bitlen/8` | `keylen` = `+8` | `datalen` = `-1` | 总结构长 = `20 + keylen` |
|---|---|---|---|---|
| 512 | 64 | 72 (`0x48`) | 63 (`0x3F`) | 92 (`0x5C`) |
| 1024 | 128 | 136 (`0x88`) | 127 (`0x7F`) | 156 (`0x9C`) |
| 2048 | 256 | 264 (`0x108`) | 255 (`0xFF`) | 284 (`0x11C`) |

#### 9.3.2 官方示例（512-bit）逐字节

[MS-RDPBCGR] §5.3.3.1.2 给出的 public key bytes（原文标注 "in little-endian format"）：

```
0x52 0x53 0x41 0x31: magic (0x31415352)
0x48 0x00 0x00 0x00: keylen (72 bytes)
0x00 0x02 0x00 0x00: bitlen (512 bits)
0x3f 0x00 0x00 0x00: datalen (63 bytes)
0x01 0x00 0x01 0x00: pubExp (0x00010001)
0xaf 0xfe 0x36 0xf2 ... 0x60 0xb7: modulus (64 字节) + 8 字节零填充
```

自校验：
- `magic` 线上是 `52 53 41 31` = LE 读作 `0x31415352` ✓（ASCII "RSA1"）
- `keylen` 线上 `48 00 00 00` = 72 = 64 + 8 ✓
- `bitlen` 线上 `00 02 00 00` = 512 ✓
- `datalen` 线上 `3f 00 00 00` = 63 = 64 − 1 ✓
- `pubExp` 线上 `01 00 01 00` = `0x00010001` = 65537 ✓

#### 9.3.3 与 CryptoAPI `PUBLICKEYBLOB` 的对照（任务书 C6 澄清）

| 偏移 | RDP `RSA_PUBLIC_KEY`（线上） | CryptoAPI `PUBLICKEYBLOB`（内存/Win32） |
|---|---|---|
| 0 | `magic` u32 = `0x31415352` | `bType` u8 = `0x06`（PUBLICKEYBLOB） |
| 1 | （同上，4 字节整体） | `bVersion` u8 = `0x02` |
| 2 | （同上） | `reserved` u16 = 0 |
| 4 | `keylen` u32 | `aiKeyAlg` u32（如 `CALG_RSA_KEYX 0xA400`） |
| 8 | `bitlen` u32 | `magic` u32 = `0x31415352` |
| 12 | `datalen` u32 | `bitlen` u32 |
| 16 | `pubExp` u32 | `pubexp` u32 |
| 20 | `modulus[keylen]`（模数 + 8 零） | `modulus[bitlen/8]`（**无**零填充） |

依据：RDP 侧 [MS-RDPBCGR] §2.2.1.4.3.1.1.1；CryptoAPI 侧 W01（`PUBLICKEYSTRUC` + `RSAPUBKEY` + `modulus`）、
W02（`bType/bVersion/reserved/aiKeyAlg`）、W03（`magic/bitlen/pubexp`）。

**两处必须注意的差异**：

1. RDP 的 `modulus` 比 CryptoAPI 多 **8 字节零填充**，且这 8 字节**计入 `keylen`**。
2. RDP **没有** `aiKeyAlg` 字段，所以不能直接把线上字节 `memcpy` 进 `PUBLICKEYBLOB` 结构体。

> 如果实现里用 Windows CNG/CryptoAPI 做 RSA，需要**手工重组**：
> 从 RDP blob 取 `bitlen` / `pubExp` / 模数前 `bitlen/8` 字节，再拼成 BCrypt 的 `BCRYPT_RSAKEY_BLOB`
> 或 CryptoAPI 的 `PUBLICKEYBLOB`（补齐 `PUBLICKEYSTRUC` + `RSAPUBKEY` 头，去掉 8 字节零填充）。
> 这是本项目**唯一**需要 blob 转换的地方。

### 9.4 client random / premaster secret 的加密方式

#### 9.4.1 填充方案：**无填充（raw RSA / textbook RSA）**

[MS-RDPBCGR] §5.3.4.1 给出的公式（逐字）：

```
c = r^e mod n
```

其中 `c` = 加密结果，`r` = 未加密随机数，`e` = public exponent，`n` = modulus。

**规范没有提到 PKCS#1 v1.5 或 OAEP**。原文只说"using RSA"，并给出裸模幂公式。
→ 结论：**不使用 RSA-OAEP，也不使用 PKCS#1 v1.5 填充**，是教科书式 raw RSA（推导，A 级公式 + 无填充描述）。

> 这一点非常重要：若实现里调用 `BCryptEncrypt(..., BCRYPT_PAD_PKCS1, ...)` 或 OpenSSL 的
> `RSA_public_encrypt(..., RSA_PKCS1_PADDING)`，**服务器将无法解密**（或解出垃圾 premaster，
> 导致后续所有 L3 MAC 失败）。

#### 9.4.2 字节序：**little-endian，且必须反向**

[MS-RDPBCGR] §5.3.4.1（逐字）：

> "The client random value is interpreted as an unsigned little-endian integer value when performing the encryption."

[MS-RDPBCGR] §4.8 的 Java 参考实现给出完整做法（逐字摘录关键三行）：

```java
ReverseByteArray(modulusBytes);
ReverseByteArray(exponentBytes);
ReverseByteArray(dataBytes);
// ... BigInteger.modPow(exponent, modulus) ...
byte[] cipherTextBytes = cipherText.toByteArray();
ReverseByteArray(cipherTextBytes);
```

**完整算法（可直接实现，5 步）**：

1. 取 `modulus`（**去掉尾部 8 字节零填充**，只留 `bitlen/8` 字节）。
2. 把 `modulus`、`pubExp`（4 字节 LE）、`data`（32 或 48 字节）**各自整段反转** → 变成 big-endian 视角的字节串。
3. 以 big-endian 解释成大整数，计算 `c = data^e mod n`。
4. 把 `c` 转回字节串（big-endian，**左侧补零到 `bitlen/8` 字节**），再**整段反转** → 得到 LE 密文。
5. 把 LE 密文放进**全零**的 `(bitlen/8) + 8` 字节缓冲区（密文占前 `bitlen/8` 字节，后 8 字节保持零）。

第 5 步依据 §5.3.4.1（逐字）：

> "The resultant encrypted client random is copied into a zeroed-out buffer, which is of size: (bitlen / 8) + 8.
> For example, if the public key of the server is 512 bits long, then the zeroed-out buffer is 72 bytes.
> This value can also be obtained from the keylen field in the public key structure."

**自校验**（用 §11.2 官方 dump）：

- `wBlobLen = 0x0108 = 264` = `(2048/8) + 8` = `256 + 8` ✓
- 密文尾部 8 字节为 `00 00 00 00 00 00 00 00`（dump 中 `0x130` 行末尾）✓

#### 9.4.3 premaster secret 的明文长度：**48 字节**

| 事实 | 依据 |
|---|---|
| `EncryptedPreMasterSecret` BLOB "contains an encrypted **48-byte** random number" | [MS-RDPELE] §2.2.2.2、§3.3.1.6 |
| 该 48 字节与 `ClientRandom`(32) + `ServerRandom`(32) 一起派生许可密钥 | §5.1.2 |

**注意区分两个 32 字节值**：

- `ClientRandom`（32 字节）：明文直接放在 `CLIENT_NEW_LICENSE_REQUEST` 偏移 8，**不加密**（只受 L2 保护）。
- `EncryptedPreMasterSecret`（48 字节明文）：RSA 加密后放在偏移 44，**必须加密**。
- 二者**不能混用**：`ClientRandom` 参与密钥派生（§5.1.2 的 `SaltedHash`），premaster 也参与，但角色不同。

#### 9.4.4 加密的是 48 字节 premaster，不是 32 字节 client random

这是与 **Standard RDP Security 的 Security Exchange PDU** 最容易混淆的点：

| | Security Exchange PDU（[MS-RDPBCGR] §2.2.1.10） | 许可 `EncryptedPreMasterSecret`（[MS-RDPELE] §2.2.2.2） |
|---|---|---|
| 明文长度 | **32** 字节（client random） | **48** 字节（premaster secret） |
| 填充 | 无（raw RSA） | 无（raw RSA） |
| 输出长度 | `(bitlen/8) + 8` | `(bitlen/8) + 8` |
| 用途 | 派生 RDP **会话密钥**（§5.3.5） | 派生**许可加密密钥**（§5.1.2） |
| 何时发 | 只在 Standard RDP Security + 加密生效时 | 只要走许可握手就发 |

> 同一个 2048-bit 服务器密钥，两处的密文长度都是 264 字节，但**明文长度不同**（32 vs 48）。
> 实现里如果复用同一个加密函数，务必用参数区分长度，不要写死 32。

### 9.5 服务器侧解密（用于自测）

[MS-RDPELE] §5.1.1.2 + [MS-RDPBCGR] §5.3.4.1 的逆运算：

1. 取 264（或 72）字节密文，**去掉尾部 8 字节零**，整段反转。
2. `m = c^d mod n`（`d` = 服务器私钥）。
3. 结果转字节串、左侧补零到 48 字节、整段反转 → 得到 LE 视角的 premaster。

> 若解出的 48 字节全零或明显随机噪声，通常是**填充方案用错**（见 §9.4.1）。

---

## 10. 最小可用路径（可执行结论）

### 10.1 目标与判据

**目标**：让服务器继续下发 `Demand Active PDU`（[MS-RDPBCGR] §2.2.1.13.1），即许可阶段"成功完成"。

**判据（可观测）**：收到 `bMsgType` 不属于许可集合、且 security header **不含** `SEC_LICENSE_PKT (0x0080)`
的服务器 PDU，其载荷以 `MCS Send Data Indication` 承载 `Demand Active PDU Data`（首字段
`shareId(4)` + `length(2)` + `pduType(2)`，`pduType` 低 4 bit = `PDUTYPE_DEMANDACTIVEPDU 0x1`）。

### 10.2 结论：两条路径，按服务器类型二选一

#### 路径 A（personal terminal server / 客户端 SKU / 远程管理模式）——**零许可消息**

| 步骤 | 客户端动作 | 依据 |
|---|---|---|
| A1 | 正常完成到 Client Info PDU | [MS-RDPBCGR] §1.3.1.1 |
| A2 | 收到 `ERROR_ALERT(0xFF)`，`dwErrorCode=0x07`、`dwStateTransition=0x02` | §2.2.1.12.1 |
| A3 | **不做任何回应**，直接等 Demand Active | §3.3.5.3.12（服务器发完即发 Demand Active） |

**实现量**：只需能解析 `LICENSE_PREAMBLE` + `LICENSE_ERROR_MESSAGE`（共 20 字节），
**不需要** RSA、RC4、MD5、SHA-1、HWID、任何 CAL 处理。

> 这是最小中的最小。但注意：**不能**假设服务器一定是 personal terminal server。
> 必须在运行时按收到的 `bMsgType` 分支，不能编译期写死。

#### 路径 B（终端服务器，application server mode）——**必须走完整握手**

| 步骤 | 客户端动作 | 必须实现的能力 | 依据 |
|---|---|---|---|
| B1 | 收 `LICENSE_REQUEST(0x01)`，解析 `ServerRandom` / `ProductInfo` / `KeyExchangeList` / `ServerCertificate` / `ScopeList` | TLV 解析 + `RSA_PUBLIC_KEY` 解析（§9.3） | §2.2.2.1 |
| B2 | 从 `ServerCertificate` BLOB 取 RSA 公钥（`wBlobLen>0`），或从 Server Security Data 兜底（§6.4） | 两种证书容器解析（proprietary / X.509） | §2.2.2.1、§5.3 |
| B3 | 生成 32 字节 `ClientRandom` + 48 字节 premaster | CSPRNG | §2.2.2.2 |
| B4 | **raw RSA** 加密 premaster（LE + 反向 + 8 字节零填充） | 大数模幂 | §5.1.1.1、[MS-RDPBCGR] §5.3.4.1 |
| B5 | 发 `NEW_LICENSE_REQUEST(0x13)`（含 `ClientUserName` / `ClientMachineName` ANSI BLOB） | 组包 | §2.2.2.2 |
| B6 | 按 §5.1.2 派生 `MAC-salt-key` + `LicensingEncryptionKey` | MD5 + SHA-1 | §5.1.2 |
| B7 | 收 `PLATFORM_CHALLENGE(0x02)`，RC4 解密 `EncryptedPlatformChallenge`，用 `MAC-salt-key` 校验 `MACData` | RC4 + MD5 MAC | §2.2.2.4、§5.1.4、§5.1.5 |
| B8 | 构造 `PLATFORM_CHALLENGE_RESPONSE_DATA`（`wVersion=0x0100`、`wClientType=0x0100`、`wLicenseDetailLevel=0x0003`、`pbChallenge`=解密后的 challenge 原文） | 组包 | §2.2.2.5.1 |
| B9 | 构造 20 字节 `CLIENT_HARDWARE_ID`，RC4 加密；对 `PCR_DATA` + 明文 HWID 算 MAC | RC4 + MD5 MAC + HWID 生成/缓存 | §2.2.2.3.1、§5.1.3、§5.1.5 |
| B10 | 发 `PLATFORM_CHALLENGE_RESPONSE(0x15)` | 组包 | §2.2.2.5 |
| B11 | 收 `NEW_LICENSE(0x03)` 或 `UPGRADE_LICENSE(0x04)`，RC4 解密 `EncryptedLicenseInfo`，校验 MAC | RC4 + MD5 MAC | §2.2.2.6 |
| B12 | 解析 `NEW_LICENSE_INFO`，**可选**存 CAL；**不做任何回应** | TLV 解析（注意 ANSI/UTF-16 混合） | §2.2.2.6.1、§3.3.5.6 |
| B13 | 等 Demand Active | — | §2.2.1.13.1 |

### 10.3 明确回答"最少需要正确实现哪些消息"

| 问题 | 答案 |
|---|---|
| 最少需要**发送**哪几条消息？ | **2 条**：`NEW_LICENSE_REQUEST(0x13)` + `PLATFORM_CHALLENGE_RESPONSE(0x15)`。若本地有 CAL 则改为 `LICENSE_INFO(0x12)` + `PLATFORM_CHALLENGE_RESPONSE(0x15)`，仍是 2 条 |
| 最少需要**正确解析**哪几条消息？ | **3 条**：`LICENSE_REQUEST(0x01)`（取公钥）、`PLATFORM_CHALLENGE(0x02)`（取 challenge）、`NEW_LICENSE/UPGRADE_LICENSE(0x03/0x04)`（确认结束）。外加 `ERROR_ALERT(0xFF)`（成功/失败判定，**必须**） |
| 哪些消息可以**完全不实现**？ | `LICENSE_INFO(0x12)`（若不做 CAL 缓存，永远不发）；`UPGRADE_LICENSE(0x04)` 的**独立**处理（与 `NEW_LICENSE` 同结构，同一解析器即可）；`ST_RESET_PHASE_TO_START` / `ST_RESEND_LAST_MESSAGE`（微软实现不发，Appendix A `<17>`） |
| 哪些**不能**省？ | ① L3 密钥派生（§5.1.2）—— 省了就无法解密/校验任何后续消息；② L3 MAC（§5.1.5）—— 省了服务器会 `ERR_INVALID_MAC` 并 abort；③ raw RSA 的**字节序与反向**（§9.4.2）—— 省了 premaster 解错，后续全错；④ `wMsgSize` 与 `SEC_LICENSE_PKT` 标志（§2、§1.3） |
| 能不能只做"路径 A"？ | **不能作为唯一实现**。若目标是真实终端服务器（application server mode），必须实现路径 B 全部 13 步。路径 A 只在服务器是 personal terminal server 时生效 |
| 最短代码路径（若允许"不存 CAL"） | `LICENSE_REQUEST` 解析 → RSA → `NEW_LICENSE_REQUEST` → 密钥派生 → `PLATFORM_CHALLENGE` 解密 → `PLATFORM_CHALLENGE_RESPONSE` → `NEW_LICENSE` 解密+校验 → 丢弃 CAL → 等 Demand Active |

### 10.4 常见"看起来能过但其实错"的路径（负例）

| 错误做法 | 后果 | 依据 |
|---|---|---|
| 用 PKCS#1 v1.5 / OAEP 加密 premaster | 服务器解出错误 premaster → L3 密钥错 → `MACData` 校验失败 → `ERR_INVALID_MAC` → abort | §9.4.1 |
| RSA 前不做字节反转（直接 big-endian 解释） | 同上 | §9.4.2 |
| 密文不补到 `(bitlen/8)+8`，或补在前面 | 服务器按固定长度解析，字段错位 | §9.4.2 第 5 步 |
| 派生密钥时把 `'A'/'BB'/'CCC'` 写成 `'AAA'` 之类 | 密钥错 | §5.1.2 |
| `SaltedHash2` 用了 `ClientRandom + ServerRandom`（而非相反的 `ServerRandom + ClientRandom`） | 密钥错 | §5.1.2 第 2 步 |
| `LicensingEncryptionKey` 只取 MD5 前 8 字节 | RC4 密钥错 | §5.1.2 第 5 步（16 字节全量） |
| MAC 用 8 字节截断（照搬 Standard RDP Security） | 服务器期望 16 字节 MD5 | §5.1.5（输出 16 字节） |
| `pad1` 用 48 次、`pad2` 用 40 次（写反） | MAC 错 | §5.1.5（pad1=40×0x36，pad2=48×0x5C） |
| `data-length` 用 big-endian | MAC 错 | §5.1.5（little-endian UINT32） |
| 把 `ERROR_ALERT(0x07,0x02)` 当失败断开 | 连接被自己掐断，永远到不了 Demand Active | §0.2 C4、§3.1.5.3 |
| 忽略 `SEC_LICENSE_PKT` 校验，把所有 PDU 都当许可包 | 收到 Demand Active 时解析崩溃 | §2.2.2、§3.2.5.3.12 |
| `NEW_LICENSE_INFO.pbScope` 按 UTF-16 解析 | 字段错位（该字段是 ANSI） | §2.2.2.6.1、§11.5 |
| `EncryptedHWID.wBlobType` 强校验为 0x0009 | 遇到发 0x0001 的服务器（官方 dump 即如此）直接失败 | §4.3 陷阱、§11.4 |

---

## 11. 十六进制 dump 逐字节注解

### 11.0 说明

本节含 **5 个官方 dump（A 级，逐字节抄录 + 注解）** 与 **3 个本地推导 dump（D 级，可复现）**。

- 官方 dump 来自 [MS-RDPELE] §4.1/§4.4/§4.5 与 [MS-RDPBCGR] §5.3.3.1.2，字节与注解均照抄，
  本文**额外**补充了偏移计算与自校验。
- 本地推导 dump 由 PowerShell 按 §4 的结构表逐字段拼装，用于验证"结构表 → 字节"的一致性。
  生成命令见 §11.9，可原样复现。

### 11.1 官方 dump：`SERVER_LICENSE_REQUEST`（[MS-RDPELE] §4.1，节选 0x00–0x70 与包尾 0x880–0x897）

来源：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/a870d76a-639b-4757-9370-a9bdfbfd6961

```
00000000  01 03 98 08 84 ef ae 20-b1 d5 9e 36 49 1a e8 2e   ....... ...6I...
00000010  0a 99 89 ac 49 a6 47 4f-33 9b 5a b9 95 03 a6 c6   ....I.GO3.Z.....
00000020  c2 3c 3f 61 00 00 06 00-2c 00 00 00 4d 00 69 00   .<?a....,...M.i.
00000030  63 00 72 00 6f 00 73 00-6f 00 66 00 74 00 20 00   c.r.o.s.o.f.t. .
00000040  43 00 6f 00 72 00 70 00-6f 00 72 00 61 00 74 00   C.o.r.p.o.r.a.t.
00000050  69 00 6f 00 6e 00 00 00-08 00 00 00 41 00 30 00   i.o.n.......A.0.
00000060  32 00 00 00 0d 00 04 00-01 00 00 00 03 00 12 08   2...............
00000070  02 00 00 80 02 00 00 00-f5 02 00 00 30 82 02 f1   ............0...
```

逐字节注解：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00` | `01` | `LICENSE_PREAMBLE.bMsgType` | `0x01` = `LICENSE_REQUEST` |
| `0x01` | `03` | `LICENSE_PREAMBLE.flags` | `0x03` = 版本 3（RDP 5.0+），**未**置 `EXTENDED_ERROR_MSG_SUPPORTED` |
| `0x02–0x03` | `98 08` | `LICENSE_PREAMBLE.wMsgSize` | LE → `0x0898` = **2200** 字节（整包长，含 preamble） |
| `0x04–0x23` | `84 ef ae 20 ... c2 3c 3f 61` | `ServerRandom[32]` | 32 字节，`0x04 + 0x20 = 0x24` 结束 |
| `0x24–0x27` | `00 00 06 00` | `PRODUCT_INFO.dwVersion` | LE → `0x00060000`（主版本 6，次版本 0） |
| `0x28–0x2B` | `2c 00 00 00` | `PRODUCT_INFO.cbCompanyName` | `0x2C` = **44** 字节 |
| `0x2C–0x57` | `4d 00 69 00 ... 6e 00 00 00` | `PRODUCT_INFO.pbCompanyName` | UTF-16LE "Microsoft Corporation\0"，44 字节 = 22 字符 × 2 ✓ |
| `0x58–0x5B` | `08 00 00 00` | `PRODUCT_INFO.cbProductId` | `0x08` = **8** 字节 |
| `0x5C–0x63` | `41 00 30 00 32 00 00 00` | `PRODUCT_INFO.pbProductId` | UTF-16LE "A02\0"，8 字节 ✓（§4.1.1 自校验成立） |
| `0x64–0x65` | `0d 00` | `KeyExchangeList.wBlobType` | `0x000D` = `BB_KEY_EXCHG_ALG_BLOB` ✓ |
| `0x66–0x67` | `04 00` | `KeyExchangeList.wBlobLen` | 4 字节 |
| `0x68–0x6B` | `01 00 00 00` | `KeyExchangeList.blobData` | `0x00000001` = `KEY_EXCHANGE_ALG_RSA` ✓ |
| `0x6C–0x6D` | `03 00` | `ServerCertificate.wBlobType` | `0x0003` = `BB_CERTIFICATE_BLOB` ✓ |
| `0x6E–0x6F` | `12 08` | `ServerCertificate.wBlobLen` | LE → `0x0812` = **2066** 字节 |
| `0x70–...` | `02 00 00 80 ...` | `ServerCertificate.blobData` | `SERVER_CERTIFICATE.dwVersion` = LE `0x80000002` → `certChainVersion=0x2`（X.509）+ `t=1`（临时证书） |

**包长自校验**：`0x6C + 4 + 0x0812 = 0x6C + 4 + 2066 = 108 + 4 + 2066 = 2178 = 0x882`。
再加 `ScopeList`（`ScopeCount(4)` + `Scope(4 + 14)` = 22 字节）→ `0x882 + 22 = 0x898` = `wMsgSize` ✓
（§4.1 官方注解明确 `0x882: ScopeList`、`0x898` 为包尾）。

`ScopeList` 部分（dump 尾部）：

```
00000880  00 00 01 00 00 00 0e 00-0e 00 6d 69 63 72 6f 73   ..........micros
00000890  6f 66 74 2e 63 6f 6d 00                           oft.com.
```

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x882–0x885` | `01 00 00 00` | `SCOPE_LIST.ScopeCount` | 1 |
| `0x886–0x887` | `0e 00` | `SCOPE.wBlobType` | `0x000E` = `BB_SCOPE_BLOB` ✓ |
| `0x888–0x889` | `0e 00` | `SCOPE.wBlobLen` | 14 字节 |
| `0x88A–0x897` | `6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00` | `SCOPE.blobData` | **ANSI** "microsoft.com\0"，14 字节 ✓（对比 `pbCompanyName` 的 UTF-16，编码不同，硬证据） |

### 11.2 官方 dump：`CLIENT_NEW_LICENSE_REQUEST`（[MS-RDPELE] §4.2，全文 0x155 字节）

来源：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/9b4e7ee7-9e85-46f0-9583-77cfd397864e

```
00000000:  13 83 55 01 01 00 00 00-00 00 01 04 dc 73 a0 c8  ..U..........s..
00000010:  69 25 6b 18 af 0b 94 7a-a9 a5 20 af 8b bc 0d cc  i%k....z.. .....
00000020:  a3 95 b7 b9 eb 81 5d be-0a 10 9c d8 02 00 08 01  ......].........
00000030:  da 9c 5d a6 68 9d a3 90-67 24 f3 3a ea a1 e2 68  ..].h...g$.:...h
00000040:  ad 12 f5 f6 0b 7a ac 92-b1 69 6f 42 55 8a a0 e2  .....z...ioBU...
00000050:  9b 2c d0 c7 ee 33 6c 47-79 c3 1e bf 03 8b 95 70  .,...3lGy......p
00000060:  07 a2 be ee 54 02 68 f8-90 d7 fe 2c 08 e1 6b 2d  ....T.h....,..k-
00000070:  ff 94 76 72 5f 7a 76 75-32 55 cc 58 61 63 a5 64  ..vr_zvu2U.Xac.d
00000080:  f1 6e c3 07 81 82 6f 88-73 62 fc 28 65 91 c2 c8  .n....o.sb.(e...
00000090:  9f 05 b0 d3 93 12 bf 6a-50 18 99 2d 4d c4 7f 74  .......jP..-M..t
000000A0:  d3 30 9f 16 78 a5 df aa-83 65 4f 77 30 42 e0 d7  .0..x....eOw0B..
000000B0:  69 c8 4d a5 73 11 59 35-b9 a7 e2 b0 f6 e3 b9 39  i.M.s.Y5.......9
000000C0:  c3 d4 e4 6b ca 40 9a ac-66 e6 1a a4 1b 39 7e 09  ...k.@..f....9~.
000000D0:  e3 72 99 dd 90 62 55 97-a9 04 c7 51 aa a2 01 cb  .r...bU....Q....
000000E0:  5a 63 4d 1a e5 99 c3 b1-2a 73 e8 9a 00 46 92 59  ZcM.....*s...F.Y
000000F0:  39 a3 80 a1 ac 90 52 ea-63 81 49 7d f3 2d 5c c3  9.....R.c.I}.-\.
00000100:  19 9f ed fe 81 1d 8c 04-1c d9 23 d2 6d 80 84 f3  ..........#.m...
00000110:  00 f2 b1 69 2f cd b3 9f-69 ee 60 3e 4b b5 be 5a  ...i/...i.`>K..Z
00000120:  09 83 0b bc 3d 3e 05 47-65 96 31 8c 6b c5 e6 a0  ....=>.Ge.1.k...
00000130:  00 00 00 00 00 00 00 00-0f 00 0e 00 41 64 6d 69  ............Admi
00000140:  6e 69 73 74 72 61 74 6f-72 00 10 00 07 00 52 4f  nistrator.....RO
00000150:  44 45 4e 54 00                                   DENT.
```

逐字节注解：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00` | `13` | `bMsgType` | `0x13` = `NEW_LICENSE_REQUEST` ✓ |
| `0x01` | `83` | `flags`（= `bVersion`） | `0x83` = `EXTENDED_ERROR_MSG_SUPPORTED(0x80)` \| 版本 3 ✓ |
| `0x02–0x03` | `55 01` | `wMsgSize` | LE → `0x0155` = **341** 字节 |
| `0x04–0x07` | `01 00 00 00` | `PreferredKeyExchangeAlg` | `0x00000001` = `KEY_EXCHANGE_ALG_RSA` ✓ |
| `0x08–0x0B` | `00 00 01 04` | `PlatformId` | LE → `0x04010000` = `CLIENT_OS_ID_WINNT_POST_52` \| `CLIENT_IMAGE_ID_MICROSOFT` \| 次版本 0 ✓ |
| `0x0C–0x2B` | `dc 73 a0 c8 ... 0a 10 9c d8` | `ClientRandom[32]` | 32 字节，`0x0C + 0x20 = 0x2C` ✓ |
| `0x2C–0x2D` | `02 00` | `EncryptedPreMasterSecret.wBlobType` | `0x0002` = `BB_RANDOM_BLOB` ✓ |
| `0x2E–0x2F` | `08 01` | `wBlobLen` | LE → `0x0108` = **264** = `(2048/8) + 8` → 服务器用 **2048-bit** 密钥 ✓ |
| `0x30–0x137` | `da 9c 5d a6 ... 00 00 00 00` | `pBlob[264]` | `0x30 + 0x108 = 0x138` ✓；尾部 8 字节全零（`0x130` 行）符合 §9.4.2 第 5 步 |
| `0x138–0x139` | `0f 00` | `ClientUserName.wBlobType` | `0x000F` = `BB_CLIENT_USER_NAME_BLOB` ✓ |
| `0x13A–0x13B` | `0e 00` | `wBlobLen` | 14 字节 |
| `0x13C–0x149` | `41 64 6d 69 6e 69 73 74 72 61 74 6f 72 00` | `blobData` | **ANSI** "Administrator\0"，14 字节 ✓ |
| `0x14A–0x14B` | `10 00` | `ClientMachineName.wBlobType` | `0x0010` = `BB_CLIENT_MACHINE_NAME_BLOB` ✓ |
| `0x14C–0x14D` | `07 00` | `wBlobLen` | 7 字节 |
| `0x14E–0x154` | `52 4f 44 45 4e 54 00` | `blobData` | ANSI "RODENT\0"，7 字节 ✓ |

**包长自校验**：`0x155` = 341。末字节偏移 `0x154` = 340，`340 + 1 = 341` ✓。

**该 dump 的额外价值**：它同时证明了 §4.2 的全部字段顺序与三个 BLOB 类型值，
并证明 `flags` 的 bit7 可以置位（`0x83`），而 `wMsgSize` 只算 preamble+message（不含 security header / MCS / X.224 / TPKT）。

### 11.3 官方 dump：`SERVER_PLATFORM_CHALLENGE`（[MS-RDPELE] §4.4，全文 0x26 字节）

来源：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/3e78e067-83a8-42b5-b5b3-054679ade7c7

```
00000000:  02 03 26 00 ff ff ff ff-50 f7 0a 00 46 37 85 54  ..&.....P...F7.T
00000010:  8e c5 91 34 97 5d 78 94-ad 3b 81 da 88 18 56 0f  ...4.]x..;....V.
00000020:  3a d1 f1 03 ef 35                                :....5
```

逐字节注解：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00` | `02` | `bMsgType` | `0x02` = `PLATFORM_CHALLENGE` ✓ |
| `0x01` | `03` | `flags` | 版本 3，无扩展错误位 |
| `0x02–0x03` | `26 00` | `wMsgSize` | `0x26` = **38** 字节 |
| `0x04–0x07` | `ff ff ff ff` | `ConnectFlags` | Reserved，**未初始化**（MUST 忽略）✓ |
| `0x08–0x09` | `50 f7` | `EncryptedPlatformChallenge.wBlobType` | 任意值（Appendix A `<12>`：unused）；官方注解标 `(ignored)` |
| `0x0A–0x0B` | `0a 00` | `wBlobLen` | 10 字节密文 |
| `0x0C–0x15` | `46 37 85 54 8e c5 91 34 97 5d` | `pBlob[10]` | RC4 密文；解密后 = `54 00 45 00 53 00 54 00 00 00`（UTF-16LE "TEST\0"，10 字节）✓ |
| `0x16–0x25` | `78 94 ad 3b 81 da 88 18 56 0f 3a d1 f1 03 ef 35` | `MACData[16]` | 对**明文** `54 00 45 00 53 00 54 00 00 00` 计算 MD5 MAC |

**自校验**：`4 + 4 + (2 + 2 + 10) + 16 = 38 = 0x26` ✓；密文长 == 明文长（RC4 流密码）✓。

**注意**：`wBlobType` 是 `50 f7`（垃圾值），证明**不能**对该字段做校验。
若实现里断言 `wBlobType == 0x0009`，这条官方 dump 会直接失败。

### 11.4 官方 dump：`CLIENT_PLATFORM_CHALLENGE_RESPONSE`（[MS-RDPELE] §4.5，全文 0x42 字节）

来源：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/58e79794-58f8-4607-a510-c0b5fef49c40

```
00000000:  15 83 42 00 01 00 12 00-fa b4 e8 24 cf 56 b2 4e  ..B........$.V.N
00000010:  80 02 bd b6 61 fc df e9-6c 44 01 00 14 00 f8 b5  ....a...lD......
00000020:  e8 25 3d 0f 3f 70 1d da-60 19 16 fe 73 1a 45 7e  .%=.?p..`...s.E~
00000030:  02 71 38 23 62 5d 10 8b-93 c3 f1 e4 67 1f 4a b6  .q8#b]......g.J.
00000040:  00 0a                                            ..
```

逐字节注解：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00` | `15` | `bMsgType` | `0x15` = `PLATFORM_CHALLENGE_RESPONSE` ✓ |
| `0x01` | `83` | `flags` | 扩展错误 \| 版本 3 |
| `0x02–0x03` | `42 00` | `wMsgSize` | `0x42` = **66** 字节 |
| `0x04–0x05` | `01 00` | `EncryptedPlatformChallengeResponse.wBlobType` | 官方注解标 `(ignored)`；此处值 `0x0001`（**不是** 0x0009）→ 又一处证明必须忽略 |
| `0x06–0x07` | `12 00` | `wBlobLen` | 18 字节 |
| `0x08–0x19` | `fa b4 e8 24 ... 6c 44` | `pBlob[18]` | 解密后 = `00 01 00 01 03 00 0a 00 54 00 45 00 53 00 54 00 00 00`（18 字节 `PCR_DATA`）✓ |
| `0x1A–0x1B` | `01 00` | `EncryptedHWID.wBlobType` | `0x0001`（官方注解 `(ignored)`） |
| `0x1C–0x1D` | `14 00` | `wBlobLen` | **20** 字节 = `CLIENT_HARDWARE_ID` 大小 ✓ |
| `0x1E–0x31` | `f8 b5 e8 25 ... 45 7e 02 71` | `pBlob[20]` | 解密后 = `02 00 00 00` + `f1 59 87 3e` + `c9 d8 98 af` + `24 02 f8 f3` + `29 3a f0 26` |
| `0x32–0x41` | `38 23 62 5d 10 8b 93 c3 f1 e4 67 1f 4a b6 00 0a` | `MACData[16]` | 覆盖 `PCR_DATA` + 明文 HWID |

解密后的 `PCR_DATA` 逐字段：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| 0 | `00 01` | `wVersion` | `0x0100` ✓ |
| 2 | `00 01` | `wClientType` | `0x0100` = `WIN32_PLATFORMCHALLENGE_TYPE` ✓ |
| 4 | `03 00` | `wLicenseDetailLevel` | `0x0003` = `LICENSE_DETAIL_DETAIL` ✓（RDP 5.0+ SHOULD 值） |
| 6 | `0a 00` | `cbChallenge` | 10 字节 |
| 8–17 | `54 00 45 00 53 00 54 00 00 00` | `pbChallenge` | UTF-16LE "TEST\0" —— 与 §11.3 服务器下发的 challenge 明文**完全相同** ✓（这是回显，不是新随机数） |

解密后的 `CLIENT_HARDWARE_ID` 逐字段：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| 0 | `02 00 00 00` | `PlatformId` | `0x00000002`（与 `PCR` 的 `PlatformId` 不同 —— 该示例为构造数据，见 §12 U5） |
| 4 | `f1 59 87 3e` | `Data1` | 任意硬件数据 |
| 8 | `c9 d8 98 af` | `Data2` | 任意 |
| 12 | `24 02 f8 f3` | `Data3` | 任意 |
| 16 | `29 3a f0 26` | `Data4` | 任意 |

**自校验**：`4 + (2+2+18) + (2+2+20) + 16 = 4 + 22 + 24 + 16 = 66 = 0x42` ✓。

### 11.5 官方 dump：`SERVER_NEW_LICENSE`（[MS-RDPELE] §4.6，节选头部）

来源：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpele/73c596f1-9550-4649-b880-2947c36c1bb6

```
00000000:  03 03 07 08 09 00 ef 07-db a3 13 30 79 a3 cd 9e  ...........0y...
00000010:  48 f4 8f 06 37 1b 45 dd-60 a9 2e 29 26 bf c1 96  H...7.E.`..)&...
...
000007F0:  96 e3 d4 bc 25 0b 56 ed-e8 bf d6 13 a0 f5 80 4a  ....%.V........J
00000800:  e5 ff 85 16 fa cb 1f                             .......
```

逐字节注解：

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00` | `03` | `bMsgType` | `0x03` = `NEW_LICENSE` ✓ |
| `0x01` | `03` | `flags` | 版本 3 |
| `0x02–0x03` | `07 08` | `wMsgSize` | LE → `0x0807` = **2055** 字节 |
| `0x04–0x05` | `09 00` | `EncryptedLicenseInfo.wBlobType` | `0x0009` = `BB_ENCRYPTED_DATA_BLOB` ✓ |
| `0x06–0x07` | `ef 07` | `wBlobLen` | LE → `0x07EF` = **2031** 字节 |
| `0x08–0x7F6` | `db a3 13 30 ... 25 0b 56` | `pBlob[2031]` | RC4 密文 |
| `0x7F7–0x806` | `ed e8 bf d6 13 a0 f5 80 4a e5 ff 85 16 fa cb 1f` | `MACData[16]` | 对明文 `NEW_LICENSE_INFO` 计算 |

**自校验（双重）**：

1. 包长：`4 + 4 + 2031 + 16 = 2055 = 0x807` ✓。
2. **RC4 密文长 == 明文长**：解密后的 `NEW_LICENSE_INFO` 各字段长度之和
   = `4 (dwVersion) + 4 (cbScope) + 14 (pbScope) + 4 (cbCompanyName) + 44 (pbCompanyName)
   + 4 (cbProductId) + 8 (pbProductId) + 4 (cbLicenseInfo) + 1945 (pbLicenseInfo)`
   = **2031** = `wBlobLen (0x07EF)` ✓ —— 这是 §6.1 "RC4 无填充" 的硬证据（A 级）。

官方 dump 同时给出解密后的 `NEW_LICENSE_INFO` 开头：

```
00 00 06 00   LicenseInfo::dwVersion = 0x060000
0e 00 00 00   LicenseInfo::cbScope
6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00   "microsoft.com\0"   ← ANSI，14 字节
2c 00 00 00   LicenseInfo::cbCompanyName
4d 00 69 00 ... 6e 00 00 00   "Microsoft Corporation\0"           ← UTF-16LE，44 字节
08 00 00 00   LicenseInfo::cbProductId
41 00 30 00 32 00 00 00   "A02\0"                                ← UTF-16LE，8 字节
99 07 00 00   LicenseInfo::cbLicenseInfo = 0x799 = 1945 字节
30 82 07 95 ...   CAL（X.509 链，DER 以 0x30 0x82 开头）
```

**这就是 §4.6.1"编码混合陷阱"的硬证据**：`cbScope` 段是单字节 ANSI（14 字节 = 14 字符），
`cbCompanyName` 段是双字节 UTF-16LE（44 字节 = 22 字符）。

### 11.6 本地推导 dump 1：`LICENSE_VALID_CLIENT_DATA`（最小成功 PDU）

**推导依据**：[MS-RDPBCGR] §2.2.1.12.1（结构）+ §2.2.1.12.1.3（错误码/迁移码表）。
**构造方法**：`preamble(bMsgType=0xFF, flags=0x03, wMsgSize=16)` + `dwErrorCode=0x07` +
`dwStateTransition=0x02` + `bbErrorInfo(wBlobType=0x0004, wBlobLen=0)`。

```
0000  ff 03 10 00 07 00 00 00 02 00 00 00 04 00 00 00
```

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00` | `ff` | `bMsgType` | `0xFF` = `ERROR_ALERT` |
| `0x01` | `03` | `flags` | 版本 3 |
| `0x02–0x03` | `10 00` | `wMsgSize` | **16** |
| `0x04–0x07` | `07 00 00 00` | `dwErrorCode` | `STATUS_VALID_CLIENT` |
| `0x08–0x0B` | `02 00 00 00` | `dwStateTransition` | `ST_NO_TRANSITION` |
| `0x0C–0x0D` | `04 00` | `bbErrorInfo.wBlobType` | `BB_ERROR_BLOB` |
| `0x0E–0x0F` | `00 00` | `bbErrorInfo.wBlobLen` | **0** → `blobData` 不存在（§5.1 硬规则 1） |

**自校验**：总长 `4 + 4 + 4 + 4 + 0 = 16` = `wMsgSize` ✓。这是路径 A（§10.2）唯一需要识别的 PDU。

### 11.7 本地推导 dump 2：`NEW_LICENSE_INFO` 明文（编码混合验证）

**推导依据**：[MS-RDPELE] §2.2.2.6.1 字段表 + §4.6 官方解密结果的字段顺序。
**构造方法**：`dwVersion=0x00060000`；`pbScope="microsoft.com\0"`（ANSI，14）；
`pbCompanyName="Microsoft Corporation\0"`（UTF-16LE，44）；`pbProductId="A02\0"`（UTF-16LE，8）；
`pbLicenseInfo` 用 16 字节占位（真实 CAL 是 X.509 链，此处仅验证布局）。

```
0000  00 00 06 00 0e 00 00 00 6d 69 63 72 6f 73 6f 66
0010  74 2e 63 6f 6d 00 2c 00 00 00 4d 00 69 00 63 00
0020  72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00
0030  6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00
0040  6f 00 6e 00 00 00 08 00 00 00 41 00 30 00 32 00
0050  00 00 11 00 00 00 30 82 00 10 02 01 02 30 0d 06
0060  09 2a 86 48 86 f7 0d
```

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| `0x00–0x03` | `00 00 06 00` | `dwVersion` | `0x00060000` |
| `0x04–0x07` | `0e 00 00 00` | `cbScope` | 14 |
| `0x08–0x15` | `6d 69 ... 6d 00` | `pbScope` | ANSI "microsoft.com\0"（14 字节，**单字节编码**） |
| `0x16–0x19` | `2c 00 00 00` | `cbCompanyName` | 44 |
| `0x1A–0x45` | `4d 00 69 00 ... 6e 00 00 00` | `pbCompanyName` | UTF-16LE "Microsoft Corporation\0"（44 字节，**双字节编码**） |
| `0x46–0x49` | `08 00 00 00` | `cbProductId` | 8 |
| `0x4A–0x51` | `41 00 30 00 32 00 00 00` | `pbProductId` | UTF-16LE "A02\0" |
| `0x52–0x55` | `11 00 00 00` | `cbLicenseInfo` | 17（占位） |
| `0x56–0x66` | `30 82 00 10 ... 0d` | `pbLicenseInfo` | 占位 DER 前缀（真实 CAL 以 `30 82 xx xx` 开头） |

**自校验**：`4 + 4 + 14 + 4 + 44 + 4 + 8 + 4 + 17 = 103 = 0x67` ✓（末字节偏移 `0x66`）。
**与官方 §11.5 对比**：`dwVersion`/`cbScope`/`pbScope`/`cbCompanyName`/`cbProductId` 完全一致，
仅 `cbLicenseInfo` 长度不同（官方 1945，本地 17 占位）—— 证明布局推导正确。

### 11.8 本地推导 dump 3：`PLATFORM_CHALLENGE_RESPONSE_DATA`

**推导依据**：[MS-RDPELE] §2.2.2.5.1 + §4.5 官方解密结果。

```
0000  00 01 00 01 03 00 0a 00 54 00 45 00 53 00 54 00
0010  00 00
```

| 偏移 | 字节 | 字段 | 解读 |
|---|---|---|---|
| 0 | `00 01` | `wVersion` | `0x0100` ✓ |
| 2 | `00 01` | `wClientType` | `0x0100` = WIN32 ✓ |
| 4 | `03 00` | `wLicenseDetailLevel` | `0x0003` = DETAIL ✓ |
| 6 | `0a 00` | `cbChallenge` | 10 |
| 8–17 | `54 00 45 00 53 00 54 00 00 00` | `pbChallenge` | UTF-16LE "TEST\0" |

**自校验**：`8 + 10 = 18` 字节；与 §11.4 官方解密结果**逐字节相同** ✓。

### 11.9 复现命令（D 级 dump）

在 `F:\rtsc` 下执行（全部临时文件走 `F:\rtsc\.tmp`，不写 C 盘）：

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
function HexDump([byte[]]$b, [int]$per=16){
  for($i=0;$i -lt $b.Length;$i+=$per){
    $n=[Math]::Min($per,$b.Length-$i)
    $hex=($b[$i..($i+$n-1)] | ForEach-Object { $_.ToString('x2') }) -join ' '
    '{0:x4}  {1}' -f $i,$hex
  }
}
# dump for 11.6
$ms=New-Object System.IO.MemoryStream; $bw=New-Object System.IO.BinaryWriter($ms)
$bw.Write([byte]0xFF); $bw.Write([byte]0x03); $bw.Write([uint16]16)
$bw.Write([uint32]7); $bw.Write([uint32]2); $bw.Write([uint16]0x0004); $bw.Write([uint16]0)
$bw.Flush(); HexDump $ms.ToArray()
```

输出与 §11.6 完全一致（已实测，见 §11.6 的 dump 即该命令输出）。

---

## 12. 不确定项清单

**以下条目在官方规范中无法得到确定答案，或规范内部存在冲突。本文不做猜测填充，
全部单列，并给出可执行的验证方法。**

### U1（高优先级）HYBRID_EX 路径下服务器 RSA 公钥的实际来源

**问题**：§6.4 已证明三段规范（[MS-RDPELE] §2.2.2.1 a/b 与 [MS-RDPBCGR] §2.2.1.4.3 c）在
"TLS 已加密 + 服务器省略证书"场景下互相冲突：兜底来源在 Enhanced RDP Security 下必然不存在。

**未确定**：真实 Windows 服务器在 `PROTOCOL_HYBRID_EX` 下，
`SERVER_LICENSE_REQUEST.ServerCertificate` 的 `wBlobLen` 是否为 0？若为 0，客户端从哪拿公钥？

**无法从规范确定的原因**：规范只写 "MAY choose not to send"，未说明在 Enhanced RDP Security 下
该 MAY 是否被采用；也没有"TLS 下用 X.509 证书公钥代替"的条款。

**验证方法（可执行）**：
1. 用 §7.3 H1 的假服务器思路反向操作 —— 抓取真实 `PROTOCOL_HYBRID_EX` 连接的
   `SERVER_LICENSE_REQUEST`（TLS 解密后），直接读 `ServerCertificate.wBlobLen`。
   本仓库 `F:\rtsc\evidence\handshake-001.md` 已证明目标 `192.168.1.7:3389` 协商为 `PROTOCOL_HYBRID_EX`，
   可用该目标做此实验。
2. 若 `wBlobLen > 0` → 解释 1 成立，实现只需支持"BLOB 里有证书"。
3. 若 `wBlobLen == 0` → 必须再检查 Server MCS Connect Response 的 `TS_UD_SC_SEC1.serverCertLen`；
   若也为 0，则该服务器实际不可完成许可（或存在规范未记载的第三来源）。

**当前实现的保守策略**（不猜测，只防御）：两条路径都实现，都缺失则明确报错（§6.4 末尾）。

### U2（中优先级）`ERROR_ALERT` 是否带 L3 加密

**问题**：`LICENSE_ERROR_MESSAGE` 结构里**没有** `Encrypted*` 字段，也没有 `MACData`。
但 §3.1.5.1 说"Both the server and client add a MAC checksum to licensing messages"，
而 §3.1.5.1 的 MAC 字段清单指向 §2.2.2.3–§2.2.2.6（**不含** §2.2.2.8 的 Error Message）。

**未确定**：`ERROR_ALERT` 的 `dwErrorCode` / `dwStateTransition` / `bbErrorInfo` 是否受
L3 保护？还是只受 L2（Standard RDP Security）或 L1（TLS）保护？

**规范证据**：§2.2.2.8 只说"Licensing Error Message ... can be used by both client and server"，
未提加密；§3.1.5.2 说 `bbErrorInfo` 可以是空 BLOB，未提 MAC。

**倾向性判断（非结论）**：结构里没有 MAC 字段 → 大概率**无 L3 保护**，仅靠 L1/L2。
但**不能据此断言**，因为规范未显式排除"对整个 LicensingMessage 做 L3 加密"。

**验证方法**：抓一个真实的 `ERROR_ALERT(0x07,0x02)`，看 `dwErrorCode` 字段是否是可读的 `07 00 00 00`
（明文）还是随机字节（密文）。本仓库已有 §11.6 的推导 dump 作为"明文形态"参照。

**实现建议**：按**明文**解析（与结构表一致）；若解析出的 `dwErrorCode` 不在 §4.7.1 表内且
`dwStateTransition` 不在 §4.7.2 表内，则记录原始字节并报"无法识别"，不要盲目猜测解密。

### U3（中优先级）`EncryptedHWID.wBlobType` 的正确值

**问题**：同一字段在两处规范给出不同要求（§4.3 已详述）：
- §2.2.2.3（`CLIENT_LICENSE_INFO`）：未指定类型；
- §2.2.2.5（`CLIENT_PLATFORM_CHALLENGE_RESPONSE`）：MUST = `0x0009`；
- [MS-RDPELE] §4.3 官方 dump（`CLIENT_LICENSE_INFO`）：实际是 `0x0001`；
- §11.4 官方 dump（`CLIENT_PLATFORM_CHALLENGE_RESPONSE`）：实际是 `0x0001`（**违反 MUST**）。

**未确定**：服务器是否**真的**校验这个字段？

**规范冲突**：§2.2.2.5 的 MUST 与 §11.4 官方示例直接矛盾（示例发的是 0x0001）。

**验证方法**：用 §7.3 H1 的假服务器接收 mstsc 的 `PLATFORM_CHALLENGE_RESPONSE`，
读 `EncryptedHWID.wBlobType` 实际值；再改服务器端"严格校验 0x0009"看是否导致失败。

**实现建议（当前最稳）**：接收时**完全忽略**该字段；发送时用 `0x0001`（与两个官方 dump 一致）。

### U4（中优先级）`SERVER_PLATFORM_CHALLENGE.EncryptedPlatformChallenge.wBlobType`

**问题**：Appendix A `<12>` 说 "The wBlobType field is unused"，§11.3 官方 dump 里是 `50 f7`（垃圾）。

**未确定**：服务器发送时是否**总是**填垃圾值？还是有时填 `0x0009`？

**规范证据**：只有 "unused" 一句，无更多约束。

**验证方法**：多次抓包统计该字段分布。

**实现建议**：接收时忽略（必须）；发送时填 `0x0009`（语义上最合理，且不影响兼容）。

### U5（低优先级）官方 dump 中 `PlatformId` 前后不一致

**问题**：§11.4 官方 `CLIENT_PLATFORM_CHALLENGE_RESPONSE` 的 `CLIENT_HARDWARE_ID.PlatformId`
解密后是 `0x00000002`，而规范 §2.2.2.3.1 / §3.3.1.9 明确要求它 MUST 与
`CLIENT_NEW_LICENSE_REQUEST.PlatformId` **相同**（该示例的 `PlatformId` 应为 `0x04010000` 类值）。

**未确定**：这是官方示例的构造数据（不是真实抓包），还是真实客户端确实会发不同值？

**规范证据**：§3.3.1.9 逐字："This ties a particular Client Hardware Identification to the client's operating system"，
语义上要求相同。

**验证方法**：用 §7.3 H1 解密真实 mstsc 的 HWID，检查前 4 字节是否等于它自己发的 `PlatformId`。

**实现建议**：**遵循规范的 MUST**（两处用同一个 `PlatformId`），不要模仿示例里的 `0x00000002`。

### U6（低优先级）`wMsgSize` 是否包含 security header

**问题**：§2.2.1.12.1.1 说 `wMsgSize` 是 "The size in bytes of the licensing packet (including the size
of the preamble)"。但"licensing packet"是否包含前面的 security header？

**规范证据**：§11.1–§11.5 的五个官方 dump 全部满足
`wMsgSize == 4 + len(LicensingMessage)`，**不包含** security header（也不含 MCS/X.224/TPKT）。
例：§11.1 `wMsgSize=0x898`，而 TPKT 总长远大于此。

**倾向性判断（接近结论）**：`wMsgSize` **不含** security header。
但规范措辞"licensing packet"有歧义，故列为不确定项。

**验证方法**：任一官方 dump 的长度算术（§11.1 已做，结论一致）。

**实现建议**：按"不含 security header"实现（`wMsgSize = 4 + LicensingMessage 长度`）。

### U7（低优先级）L3 RC4 是否在同一消息的多个字段间连续使用密钥流

**问题**：`CLIENT_PLATFORM_CHALLENGE_RESPONSE` 有两个加密字段
（`EncryptedPlatformChallengeResponse` 和 `EncryptedHWID`）。RC4 是流密码，
两次加密是**各自从密钥流起点开始**，还是**共用一条连续密钥流**？

**规范证据**：§5.1.3 只写 `EncryptedData = RC4(LicensingEncryptionKey, LicensingData)`，
未说明多字段场景下的状态管理。§5.1.4 同理。

**倾向性判断（推导，C 级）**：各自独立（每次调用重新初始化 RC4）。
理由：§5.1.3/§5.1.4 的公式把 `LicensingData` 当作**单个**输入，且没有"continue"/"state"之类的措辞；
若共用密钥流，规范必须明确说明字段顺序，但规范没有。

**验证方法**：用 §7.3 H1 的解密能力，对真实 `PLATFORM_CHALLENGE_RESPONSE` 分别用
"独立 RC4" 与 "连续 RC4" 解密，看哪种能得到合法的 `PCR_DATA`（`wVersion==0x0100` 且
`pbChallenge` 与服务器下发的 challenge 相同）。这是**可判定的红/绿实验**。

**实现建议**：先按"独立 RC4"实现（§5.1.3 字面语义），用上述实验验证。

### U8（低优先级）`CLIENT_HARDWARE_ID` 的 4×u32 是否需要非零

**问题**：§2.2.2.3.1 只说 "MUST contain a number that helps the server uniquely identify the client"。
全零是否合法？

**规范证据**：无任何非零约束。

**未确定**：服务器是否拒绝全零 HWID（例如把它当作"未提供"）？

**验证方法**：向真实服务器发全零 HWID，观察是否返回 `ERR_INVALID_CLIENT` 或正常发许可证。

**实现建议**：不要用全零（虽然规范未禁止），用 §7.4 的确定性派生值。

### U9（信息性）`LICENSE_DETAIL_DETAIL` 是否真的被服务器用于裁剪 CAL

**问题**：§2.2.2.5.1 说 `wLicenseDetailLevel` "represents the capability of the client to handle license data"，
RDP 5.0+ SHOULD 用 `0x0003`。但服务器是否**据此裁剪**证书链长度？

**规范证据**：§1.7 说这是唯一的能力广告，但未说明服务器如何消费。

**未确定**：发 `0x0001` 与 `0x0003` 收到的 CAL 是否不同（链长度）？

**验证方法**：同一服务器分别用两个值连接，比较 `NEW_LICENSE_INFO.cbLicenseInfo` 与链中证书数。

**实现建议**：直接发 `0x0003`（规范 SHOULD，且官方 dump 如此）。

### U10（信息性）`ST_TOTAL_ABORT` 后是否断开连接

**问题**：[MS-RDPELE] §3.1.5.3 说 "Aborting the licensing protocol MAY disconnect the RDP client connection"，
Appendix A `<16>` 说 Windows XP 收到 `ST_TOTAL_ABORT` **不**断开。

**未确定**：现代 Windows 客户端行为是否已改变？

**验证方法**：抓真实失败连接的后续字节（是否发 MCS Disconnect Provider Ultimatum）。

**实现建议**：本项目在 `ST_TOTAL_ABORT` 后主动断开（安全默认），并把该决策做成可配置项。

### U11（信息性）`Client Packet Wait Timer` 的现代默认值

**问题**：Appendix A `<20>` 只给 Vista/Server 2008 的 **300 秒**。

**未确定**：Windows 10/11 是否仍为 300 秒。

**验证方法**：构造"服务器不回任何许可消息"的场景，测量 mstsc 断开时间。

**实现建议**：默认 300 秒，可配置（§8.4）。

### U12（信息性）mstsc 的 HWID 具体算法

**问题**：见 §7.1 —— **规范未定义**，本文不给结论。

**验证方法**：§7.3 H1/H2/H3 三套方案（H1 是唯一能给出字节级证据的）。

**实现建议**：本项目不复刻（§7.4），用确定性派生值 + 缓存。

---

## 13. 实现检查清单（交付前逐项自检）

| # | 检查项 | 依据 | 判据 |
|---|---|---|---|
| 1 | `LICENSE_PREAMBLE` 按 4 字节解析，`wMsgSize` 含自身 | §2.1 | 5 个官方 dump 全部吻合 |
| 2 | `flags` 低 4 bit 版本 + bit7 扩展错误；发送 `0x83` | §2.2、§2.4 | §11.2/§11.4 一致 |
| 3 | `bMsgType` 用白名单（8 个值），无 `LICENSE_REQUEST_FAILED` | §3.1、§0.2 C3 | 收到未定义值 → 按 §3.2 处理 |
| 4 | 所有许可 PDU 带 security header，且 `SEC_LICENSE_PKT` 置位 | §1.3 | 收发双向检查 |
| 5 | `LICENSE_BINARY_BLOB` 的 `wBlobLen==0` → 无 `blobData` | §5.1 | 4 字节结构 |
| 6 | `PRODUCT_INFO` 字符串是 UTF-16LE，`cb` 含 NUL | §4.1.1 | `cbProductId==8` |
| 7 | `NEW_LICENSE_INFO.pbScope` 是 **ANSI**，其余字符串 UTF-16LE | §4.6.1 | §11.5/§11.7 对比 |
| 8 | `CLIENT_HARDWARE_ID` 恒 20 字节，`PlatformId` 与请求一致 | §4.8、§3.3.1.9 | 20 字节 |
| 9 | RSA 用 **raw**（无 PKCS#1/OAEP 填充），LE + 反向 + 8 零 | §9.4.1、§9.4.2 | §11.2 的 `wBlobLen=0x108` |
| 10 | premaster 明文 **48** 字节（不是 32） | §9.4.3 | 长度断言 |
| 11 | L3 密钥派生按 §5.1.2 五步，注意 `SaltedHash2` 顺序相反 | §6.1 | 单元测试用固定向量 |
| 12 | L3 MAC 16 字节，`pad1`=40×0x36，`pad2`=48×0x5C，length 为 LE u32 | §6.1 | 同上 |
| 13 | `EncryptedHWID.wBlobType` **不校验**；发送用 0x0001 | §4.3、U3 | 能接受 [MS-RDPELE] §4.3 / §11.4 |
| 14 | `ConnectFlags` **不校验**；`EncryptedPlatformChallenge.wBlobType` **不校验** | §4.4、U4 | 能接受 §11.3 的 `ff ff ff ff` / `50 f7` |
| 15 | `ERROR_ALERT(0x07,0x02)` 当**成功**，不断开 | §0.2 C4、§3.1.5.3 | 路径 A 能过 |
| 16 | `ERROR_ALERT` 未知错误码不假定语义，记录原始值 | §4.7.1 | 日志含原始 u32 |
| 17 | 乱序/畸形消息：客户端 MUST 断开 | §3.3.5.8 | 无"继续等"分支 |
| 18 | L3 MAC 失败：客户端 MAY 报错但 **MUST 断开** | §3.3.5.9 | 无"忽略继续"分支 |
| 19 | HYBRID_EX 下仍做 L3 加解密（TLS 不替代 L3） | §6.3 | 不能因"有 TLS"跳过 RC4 |
| 20 | RSA 公钥双来源（BLOB 优先 + Security Data 兜底），缺失即报错 | §6.4、U1 | 无静默降级 |
| 21 | `Client Packet Wait Timer` 可配置，默认 300s | §8.4 | 非硬编码 |
| 22 | 所有动态配置（超时、detail level、HWID 来源）走 env/options，不硬编码 | 项目约束 | 见 §10.3/§7.4 |

---

## 14. 附：结构名 ↔ 章节号 索引

| 结构 / 常量 | 定义章节 | 本文位置 |
|---|---|---|
| `TS_LICENSING_PDU` | [MS-RDPELE] §2.2.2 | §1.3 |
| `LICENSE_PREAMBLE` | [MS-RDPBCGR] §2.2.1.12.1.1 | §2 |
| `LICENSE_BINARY_BLOB` | [MS-RDPBCGR] §2.2.1.12.1.2 | §5 |
| `LICENSE_ERROR_MESSAGE` | [MS-RDPBCGR] §2.2.1.12.1.3 | §4.7 |
| `LICENSE_VALID_CLIENT_DATA` | [MS-RDPBCGR] §2.2.1.12.1 | §1.2、§11.6 |
| `SERVER_LICENSE_REQUEST` | [MS-RDPELE] §2.2.2.1 | §4.1 |
| `PRODUCT_INFO` | [MS-RDPELE] §2.2.2.1.1 | §4.1.1 |
| `SCOPE_LIST` | [MS-RDPELE] §2.2.2.1.2 | §4.1.2 |
| `SCOPE` | [MS-RDPELE] §2.2.2.1.2.1 | §4.1.2 |
| `CLIENT_NEW_LICENSE_REQUEST` | [MS-RDPELE] §2.2.2.2 | §4.2 |
| `CLIENT_LICENSE_INFO` | [MS-RDPELE] §2.2.2.3 | §4.3 |
| `CLIENT_HARDWARE_ID` | [MS-RDPELE] §2.2.2.3.1 | §4.8、§7 |
| `SERVER_PLATFORM_CHALLENGE` | [MS-RDPELE] §2.2.2.4 | §4.4 |
| `CLIENT_PLATFORM_CHALLENGE_RESPONSE` | [MS-RDPELE] §2.2.2.5 | §4.5 |
| `PLATFORM_CHALLENGE_RESPONSE_DATA` | [MS-RDPELE] §2.2.2.5.1 | §4.5.1 |
| `SERVER_UPGRADE_LICENSE` | [MS-RDPELE] §2.2.2.6 | §4.6 |
| `NEW_LICENSE_INFO` | [MS-RDPELE] §2.2.2.6.1 | §4.6.1 |
| `SERVER_NEW_LICENSE` | [MS-RDPELE] §2.2.2.7 | §4.6 |
| `LICENSED_PRODUCT_INFO` | [MS-RDPELE] §2.2.2.9.1 | §4.6.2 |
| `LICENSED_VERSION_INFO` | [MS-RDPELE] §2.2.2.9.1.1 | §4.6.2 |
| `SERVER_CERTIFICATE` | [MS-RDPBCGR] §2.2.1.4.3.1 | §5.3 |
| `PROPRIETARYSERVERCERTIFICATE` | [MS-RDPBCGR] §2.2.1.4.3.1.1 | §5.3.1 |
| `RSA_PUBLIC_KEY` | [MS-RDPBCGR] §2.2.1.4.3.1.1.1 | §9.3.1 |
| `X509_CERTIFICATE_CHAIN` | [MS-RDPELE] §2.2.1.4.2 | §5.3.2 |
| `CERT_BLOB` | [MS-RDPELE] §2.2.1.4.2.1 | §5.3.2 |
| `TS_SECURITY_HEADER` | [MS-RDPBCGR] §2.2.8.1.1.2.1 | §6.2 |
| `TS_SECURITY_HEADER1` | [MS-RDPBCGR] §2.2.8.1.1.2.2 | §6.2 |
| `TS_SECURITY_HEADER2` | [MS-RDPBCGR] §2.2.8.1.1.2.3 | §6.2 |
| 许可密钥派生 | [MS-RDPELE] §5.1.2 | §6.1 |
| 许可数据加解密 | [MS-RDPELE] §5.1.3 / §5.1.4 | §6.1 |
| 许可 MAC | [MS-RDPELE] §5.1.5 | §6.1 |
| 客户端状态机 | [MS-RDPELE] §3.3.1.11 / §3.1.5.3 | §8 |
| 错误码 / 迁移码 | [MS-RDPBCGR] §2.2.1.12.1.3 | §4.7.1 / §4.7.2 |
| Product Behavior 脚注 | [MS-RDPELE] §6（Appendix A） | 全文引用 |

