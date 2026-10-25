# MCS 域与通道建立阶段字段规格（Erect Domain / Attach User / Channel Join / Send Data / Disconnect Provider Ultimatum）

本文件是 RTSC 项目 MCS 域阶段（RDP Connection Sequence 的 Channel Connection 阶段及其后的
Send Data 封装）的实现依据。所有字段、字节值、枚举数值均来自**实际抓取的官方原文**，逐条给出
来源 URL（精确到小节页面）。

**来源等级约定**

| 等级 | 含义 |
|---|---|
| A | 微软官方规范 [MS-RDPBCGR] 网页原文（`Accept: text/markdown`）或官方 PDF 原文 |
| B | ITU-T 官方规范原文（T.125 / X.691 / T.123 / X.224 官方 PDF） |
| C | 由 A/B 原文推导（本文明确标"推导"，并给出推导链） |

**重要结论（先读）**

- RDP 使用 **MCS Version 2**：Connect MCSPDU 用 BER，**所有后续 Domain MCSPDU 用 PER（ALIGNED
  变体 of BASIC-PER）**（S1，A 级；T.125 §9，B 级）。因此本文件全部字段按 ALIGNED PER 解释，
  **不能**按 T.125 §8（Version 3）的 ASN.1 定义解释——两者在 `DataPriority` 上不同：Version 2
  是 `ENUMERATED`，Version 3 是 `CHOICE`。
- 每个 Domain MCSPDU 的**第一个字段是 `DomainMCSPDU` CHOICE 索引**，占 **6 bit**（43 个备选，
  range=43 → X.691 §10.5.7.1 的 "33 to 64 → 6 bits"），随后按 ALIGNED 规则补齐到字节边界。
- `UserId` = `DynamicChannelId` = `INTEGER (1001..65535)`，range=64535 → 两字节整数字段，
  **线上值是 `userId - 1001`**（例：UserId 1007 → `00 06`）。
- `ChannelId` = `INTEGER (0..65535)`，range=65536 = 64K → 两字节整数字段，**线上值就是原值**
  （例：1003 → `03 EB`）。
- 本文件 §12 的注解 dump **全部逐字节抄录**，并与 [MS-RDPBCGR] 官方 PDF（v20260309）独立比对，
  17 个字节块的字节序列**完全一致**（见 §12.0 校验表）。
- **任务前提有两处需要修正**（详见 §13）：(a) 2.2.2.1 / 2.2.2.2 不是 Send Data 封装，而是
  Shutdown Request / Shutdown Request Denied；(b) 通道 1002 是 **Server Channel**（固定
  `0x03EA`），不是用户通道；用户通道由服务器在 Attach User Confirm 中分配（dump 里是 1007）。

---

## 0. 规范来源清单（全部实际抓取）

### 0.1 抓取成功的 URL（HTTP 200）

均以 `Accept: text/markdown` 抓取，响应 `Content-Type: text/markdown; charset=utf-8`。

| 编号 | 小节 | URL | 状态 |
|---|---|---|---|
| S1 | 2.2 Message Syntax | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b61e1c76-5d7c-4285-b61a-b69f85e4a0e2 | 200 |
| S2 | 2.2.1.5 Client MCS Erect Domain Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/04c60697-0d9a-4afd-a0cd-2cc133151a9c | 200 |
| S3 | 2.2.1.6 Client MCS Attach User Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f5d6a541-9b36-4100-b78f-18710f39f247 | 200 |
| S4 | 2.2.1.7 Server MCS Attach User Confirm PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b3d850b-99b1-4a9a-852b-1eb2da5024e5 | 200 |
| S5 | 2.2.1.8 Client MCS Channel Join Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/64564639-3b2d-4d2c-ae77-1105b4cc011b | 200 |
| S6 | 2.2.1.9 Server MCS Channel Join Confirm PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/cfc938b5-041d-4c15-9909-81dd035b914e | 200 |
| S7 | 2.2.1.10 Client Security Exchange PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-ac8b-704db419b66f | 200 |
| S8 | 2.2.1.10.1 Security Exchange PDU Data (TS_SECURITY_PACKET) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ca73831d-3661-4700-9357-8f247640c02e | 200 |
| S9 | 2.2.1.11 Client Info PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/772d618e-b7d6-4cd0-b735-fa08af558f9d | 200 |
| S10 | 2.2.1.11.1 Client Info PDU Data (CLIENT_INFO_PDU) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/53e829df-29eb-44d4-8c70-e09f5a519be6 | 200 |
| S11 | 2.2.1.11.1.1 Info Packet (TS_INFO_PACKET) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/732394f5-e2b5-4ac5-8a0a-35345386b0d1 | 200 |
| S12 | 2.2.1.11.1.1.1 Extended Info Packet (TS_EXTENDED_INFO_PACKET) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/05ada9e4-a468-494b-8694-eb806a0ecc89 | 200 |
| S13 | 2.2.1.11.1.1.1.1 Time Zone Information (TS_TIME_ZONE_INFORMATION) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/526ed635-d7a9-4d3c-bbe1-4e3fb17585f4 | 200 |
| S14 | 2.2.1.11.1.1.1.1.1 System Time (TS_SYSTEMTIME) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/41b1f581-53c9-4f75-b9c2-9afc3cb9d08f | 200 |
| S15 | 2.2.2.1 Client Shutdown Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/910d408a-41d0-472d-bbe2-a59d237bc0da | 200 |
| S16 | 2.2.2.2 Server Shutdown Request Denied PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e86249c3-3825-43aa-a1ff-f635c2f5bbde | 200 |
| S17 | 2.2.2.3 MCS Disconnect Provider Ultimatum PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/53a2d2de-57a5-4bc9-9673-35d68d23d902 | 200 |
| S18 | 2.2.6.1 Virtual Channel PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6c074267-1b32-4ceb-9496-2eb941a23e6b | 200 |
| S19 | 2.2.6.1.1 Channel PDU Header (CHANNEL_PDU_HEADER) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f125c65e-6901-43c3-8071-d7d5aaee7ae4 | 200 |
| S20 | 2.2.8.1.1.2 Security Headers | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9865e0ce-a540-4eab-9409-2a25937c38d2 | 200 |
| S21 | 2.2.8.1.1.2.1 Basic (TS_SECURITY_HEADER) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e13405c5-668b-4716-94b2-1c2654ca1ad4 | 200 |
| S22 | 2.2.8.1.1.2.2 Non-FIPS (TS_SECURITY_HEADER1) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/768e12c4-7748-4005-b91d-790847e47025 | 200 |
| S23 | 2.2.8.1.2 Client Fast-Path Input Event PDU (TS_FP_INPUT_PDU) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b8e7c588-51cb-455b-bb73-92d480903133 | 200 |
| S24 | 2.2.9.1.2 Server Fast-Path Update PDU (TS_FP_UPDATE_PDU) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/68b5ee54-d0d5-4d65-8d81-e1c4025f7597 | 200 |
| S25 | 2.2.10.1 Server Save Session Info PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/885c1879-e0c8-4e2d-80c4-81acea9b51fb | 200 |
| S26 | 2.2.10.1.1.1 Logon Info Version 1 (TS_LOGON_INFO) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4407c337-fc39-4f01-87c6-e1f4c236fedb | 200 |
| S27 | 2.2.10.1.1.2 Logon Info Version 2 (TS_LOGON_INFO_VERSION_2) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a2e946b4-820c-4d11-b4c9-8029a7df558f | 200 |
| S28 | 2.2.1.4.3 Server Security Data (TS_UD_SC_SEC1) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e86b68d-3e2e-4433-b486-878875778f4b | 200 |
| S29 | 2.2.1.4.4 Server Network Data (TS_UD_SC_NET) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/89fa11de-5275-4106-9cf1-e5aa7709436c | 200 |
| S30 | 2.2.1.4.5 Server Message Channel Data (TS_UD_SC_MCS_MSGCHANNEL) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9269d58a-3d85-48a2-942a-bb0bbe5a55aa | 200 |
| S31 | 3.2.5.1 Constructing a Client-to-Server Slow-Path PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b27f8935-ac1f-47f7-b87b-32b92875b869 | 200 |
| S32 | 3.2.5.2 Processing a Server-to-Client Slow-Path PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dac03011-f059-44d3-a30b-26f238ad21aa | 200 |
| S33 | 3.2.5.3.5 Sending MCS Erect Domain Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/404413e8-1091-4eef-af1d-62d0fdc1efc4 | 200 |
| S34 | 3.2.5.3.6 Sending MCS Attach User Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f8f7c548-a3a0-4cb6-9be0-d2c404a0eb1b | 200 |
| S35 | 3.2.5.3.7 Processing MCS Attach User Confirm PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/4a2784d3-5a28-48c2-b233-120a886469c2 | 200 |
| S36 | 3.2.5.3.8 Sending MCS Channel Join Request PDU(s) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/c2bb6f47-779c-42d4-98f3-d7afa2a4906b | 200 |
| S37 | 3.2.5.3.9 Processing MCS Channel Join Confirm PDU(s) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ce4e3a4d-e0c5-42e0-a6ee-e920c2e8d0b8 | 200 |
| S38 | 3.2.5.3.10 Sending Security Exchange PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3815ccd7-e609-474b-acf6-7a53b191767b | 200 |
| S39 | 3.2.5.3.11 Sending Client Info PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/86313d86-377e-4bab-97cb-c541dd9370ea | 200 |
| S40 | 3.2.5.4 Disconnection Sequences | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f3ea90bc-d45d-40f4-813e-5f8e4520df94 | 200 |
| S41 | 3.2.5.4.1 Sending Shutdown Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7584f091-755a-4968-8af3-0d2639e10873 | 200 |
| S42 | 3.2.5.4.2 Processing Shutdown Request Denied PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3a6c7d80-62b1-4ca6-b2c2-410e61990041 | 200 |
| S43 | 3.2.5.5 Deactivation-Reconnection Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/625762c7-3713-410c-a9fc-63917be217f8 | 200 |
| S44 | 3.2.5.5.1 Processing Deactivate All PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e3dddf9e-ddc7-4622-a0d4-cc1d68f1f1ac | 200 |
| S45 | 3.2.5.6 Auto-Reconnect Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1e185348-2dbf-4b3a-8688-93b9a9ea33f6 | 200 |
| S46 | 3.2.5.6.1 Processing Auto-Reconnect Status PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/44ff69aa-d67f-4c8c-b965-42b0a091887a | 200 |
| S47 | 3.3.5.1 Constructing a Server-to-Client Slow-Path PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3592a9d1-a544-4891-a1f7-a696f0fcfe7c | 200 |
| S48 | 3.3.5.2 Processing a Client-to-Server Slow-Path PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3608c816-fb97-4b75-b925-7cb75deef21c | 200 |
| S49 | 3.3.5.3.5 Processing MCS Erect Domain Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/61c320cf-add7-40fb-8047-ce349d3c300f | 200 |
| S50 | 3.3.5.3.6 Processing MCS Attach User Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f4b6585b-7ea4-421e-b411-3014a7f035aa | 200 |
| S51 | 3.3.5.3.7 Sending MCS Attach User Confirm PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9a16e296-5ece-4186-a0d7-9b823586c22e | 200 |
| S52 | 3.3.5.3.8 Processing MCS Channel Join Request PDU(s) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/2cd07374-76de-4df9-b999-c796c84b6723 | 200 |
| S53 | 3.3.5.3.9 Sending MCS Channel Join Confirm PDU(s) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/c604522b-33cb-4416-9826-71992e51c1d6 | 200 |
| S54 | 3.3.5.3.10 Processing Security Exchange PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f1cde3b4-85c8-4e18-b73e-91ef58816c1b | 200 |
| S55 | 3.3.5.3.11 Processing Client Info PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ef9db6a5-36f4-4613-84b3-97501679d210 | 200 |
| S56 | 3.3.5.4 Disconnection Sequences | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/53cafabc-c082-4009-8f54-922021aa417f | 200 |
| S57 | 3.3.5.4.1 Processing Shutdown Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3c30d36f-ca41-47cf-b76b-733e388db8ae | 200 |
| S58 | 3.3.5.4.2 Sending Shutdown Request Denied PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7f05d96c-6a94-4527-b6f4-3ca929cae38d | 200 |
| S59 | 3.3.5.5 Deactivation-Reconnection Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7a8eacb9-bb52-444b-be4b-bd838ca851b4 | 200 |
| S60 | 3.3.5.5.1 Sending Deactivate All PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b307d88b-167d-4e1a-9d41-3ae39d657239 | 200 |
| S61 | 3.3.5.6 Auto-Reconnect Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8f558f6b-22a7-4394-b051-5ee17e484339 | 200 |
| S62 | 3.3.5.6.1 Sending Auto-Reconnect Status PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/c778e5fa-d7ec-47b0-9711-d01847a57f37 | 200 |
| S63 | 3.1.5.1.1 Sending of MCS Disconnect Provider Ultimatum PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3efcb3f7-8fa5-488b-8388-bf4d32004b8c | 200 |
| S64 | 3.1.5.1.2 Processing of MCS Disconnect Provider Ultimatum PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f10e972d-7b77-4fa5-999f-08406fe86284 | 200 |
| S65 | 3.2.1.5 User Channel ID（客户端存储） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a3725aa3-a07a-4742-884a-cc1d89c9c3a5 | 200 |
| S66 | 3.2.1.3 I/O Channel ID（客户端存储） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/97a697ab-e78b-4c5c-988e-3ece9495b781 | 200 |
| S67 | 3.2.1.6 Server Channel ID（客户端存储） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8910624b-7955-4a69-9980-d7b79f0269e1 | 200 |
| S68 | 3.2.1.2 Static Virtual Channel IDs（客户端存储） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/97a374ee-1359-4f7d-8810-15b8dc0d41a0 | 200 |
| S69 | 3.3.1.2 User Channel ID（服务端存储，含 1001..65536 范围原文） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/950cd069-252e-4c33-9988-cd5a6d3b5842 | 200 |
| S70 | 3.3.1.5 Server Channel ID（服务端存储，固定 0x03EA） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/55150fac-8dbe-40ee-82c1-ce546f6bcbf7 | 200 |
| S71 | 1.3.1.1 Connection Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee | 200 |
| S72 | 5.3.1 Encryption Levels | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f1c7c93b-94cc-4551-bb90-532a0185246a | 200 |
| S73 | 5.3.4.1 Encrypting Client Random | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/761e2583-6406-4a71-bfec-cca52294c099 | 200 |
| S74 | 5.3.5 Initial Session Key Generation | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9791c9e2-e5be-462f-8c23-3404c4af63b3 | 200 |
| S75 | 5.4.2.3 Changes to the Security Commencement Phase | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e0c6ad2-f1eb-42b8-ab20-4f4d889a3172 | 200 |
| S76 | 5.4.2.1 Negotiation-Based Approach | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db98be23-733a-4fd2-b086-002cd2ba02e5 | 200 |
| S77 | 5.4.2.2 Direct Approach | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2bd18fa-0066-4a57-ac25-9139c0df31e0 | 200 |
| S78 | 4.1.5 Annotated dump: Erect Domain Request | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7afba26d-52a5-4153-b1df-e21eca3b1b4f | 200 |
| S79 | 4.1.6 Annotated dump: Attach User Request | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5125dd86-1a99-46cd-bcae-d1c3c083eeb0 | 200 |
| S80 | 4.1.7 Annotated dump: Attach User Confirm | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3a33f738-a023-4178-bcc3-28f953a038fc | 200 |
| S81 | 4.1.8 Annotated dump: Channel Join Request and Confirm PDUs | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/388bac6b-39ff-4d85-8b72-4d11506e489b | 200 |
| S82 | 4.1.8.1 Channel 1007 | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/086fdf0e-8528-4a67-b371-1da3f0917e65 | 200 |
| S83 | 4.1.8.1.1 Client Join Request PDU for Channel 1007 (User Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8c14e16a-a556-4bcd-9e8f-5aa6ae360f45 | 200 |
| S84 | 4.1.8.1.2 Server Join Confirm PDU for Channel 1007 (User Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/48bac244-bf30-4df1-8516-6dd31d917128 | 200 |
| S85 | 4.1.8.2 Channel 1003 | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5830ba2e-bcc6-4d44-b203-0f674c54b8b6 | 200 |
| S86 | 4.1.8.2.1 Client Join Request PDU for Channel 1003 (I/O Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/921e5e9a-9346-4482-b6bf-97f0de3d2afa | 200 |
| S87 | 4.1.8.2.2 Server Join Confirm PDU for Channel 1003 (I/O Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/7443e65e-3482-4cec-823a-741eb1fe27b4 | 200 |
| S88 | 4.1.8.3 Channel 1004 | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6f60e78e-49e4-47ed-985f-7072aef6d3ed | 200 |
| S89 | 4.1.8.3.1 Client Join Request PDU for Channel 1004 (rdpdr Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/94d02f37-ea1d-4f80-bce5-c8a556349313 | 200 |
| S90 | 4.1.8.3.2 Server Join Confirm PDU for Channel 1004 (rdpdr Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/064b759a-4f60-4a08-a91e-c84abcaf40f5 | 200 |
| S91 | 4.1.8.4 Channel 1005 | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ec8de33c-ec94-4e9f-8cf4-92f24a5ab618 | 200 |
| S92 | 4.1.8.4.1 Client Join Request PDU for Channel 1005 (cliprdr Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f495eb02-d85e-44e0-807b-63992b6173cd | 200 |
| S93 | 4.1.8.4.2 Server Join Confirm PDU for Channel 1005 (cliprdr Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b00463c3-cd57-4e28-9608-8e39bb9d7c29 | 200 |
| S94 | 4.1.8.5 Channel 1006 | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a56aa07f-5282-4a1b-bef7-7ff912ec1da4 | 200 |
| S95 | 4.1.8.5.1 Client Join Request PDU for Channel 1006 (rdpsnd Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/87366171-46c9-48f0-b827-02a576e273ef | 200 |
| S96 | 4.1.8.5.2 Server Join Confirm PDU for Channel 1006 (rdpsnd Channel) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/fbb88576-40fc-4b20-a39b-042e75cb6f85 | 200 |
| S97 | 4.1.9 Annotated dump: Client Security Exchange PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b6075470-bbdd-465a-b6d9-ef15941ae358 | 200 |
| S98 | 4.1.10 Annotated dump: Client Info PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/ac6dc9ab-6f32-471e-8374-f80caab50069 | 200 |
| S99 | 4.2.3 Annotated dump: MCS Disconnect Provider Ultimatum PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/19a238a5-0455-46f0-a96b-31320d9a70a1 | 200 |
| S100 | 4.2.1 Annotated dump: Client Shutdown Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a759f382-bde2-4585-9c01-97263abc7e3b | 200 |
| S101 | 4.2.2 Annotated dump: Server Shutdown Request Denied PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d8701b65-4497-4b32-91c4-a08f62d76824 | 200 |
| S102 | [MS-RDPBCGR] 官方 PDF（v20260309，444 页） | https://winprotocoldoc.z19.web.core.windows.net/MS-RDPBCGR/%5bMS-RDPBCGR%5d.pdf | 200（14,539,712 B） |
| S103 | T.125 (02/98) 官方 PDF | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.125-199802-I!!PDF-E&type=items | 200（677,658 B） |
| S104 | X.691 (07/2002) 官方 PDF | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.691-200207-S!!PDF-E&type=items | 200（2,089,389 B） |
| S105 | T.123 (01/2007) 官方 PDF（TPKT §8） | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.123-200701-I!!PDF-E&type=items | 200（1,082,039 B） |
| S106 | X.224 (11/95) 官方 PDF（DT TPDU §13.7） | https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.224-199511-I!!PDF-E&type=items | 200（682,025 B） |
| S107 | 5.4.5.2 CredSSP | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8e11581d-094f-461a-9fde-ba51af90cf8b | 200 |
| S108 | 5.4.5 External Security Protocols Used By RDP | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/422e59a0-98c8-4a28-af9f-235a572b6e4d | 200 |
| S109 | 3.2.5.3.4 Processing MCS Connect Response PDU with GCC Conference Create Response | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d4fa5ef0-87c2-4256-b958-d50718a58d0b | 200 |
| S110 | 2.2.10.1.1 Save Session Info PDU Data (TS_SAVE_SESSION_INFO_PDU_DATA) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d892bc5b-aecd-4aee-99b6-5f43b5a63d75 | 200 |

> S102 的原始 URL `https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/...` 返回 **HTTP 308
> Permanent Redirect**，Location 指向 S102 的实际地址（跟随重定向后 200，已验证）。

### 0.2 抓取失败的 URL

| URL | 结果 |
|---|---|
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-acb0-9a0f8d9c1c4c | **HTTP 404**（任务提示给的 2.2.1.10 GUID 有误；正确 GUID 为 `...ac8b-704db419b66f`，见 S7） |
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9e9c9e29-9cd5-4b4c-a8e9-7e3c9e0b3c1a | **HTTP 404**（猜测的 CredSSP 小节 GUID，无此页；正确为 S107） |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.123-199602-I!!PDF-E&type=items | HTTP **200 但响应体是 "Document Not Found" HTML（9,125 B）**，非 PDF。改用 T.123 (01/2007) 成功（S105） |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.123-199602-S!!PDF-E&type=items | 同上（伪 200，HTML 9,125 B） |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.224-199411-I!!PDF-E&type=items | 同上（伪 200，HTML 9,125 B）。改用 X.224 (11/95) 成功（S106） |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.224-199411-S!!PDF-E&type=items | 同上（伪 200，HTML 9,125 B） |

> 教训：itu.int 的 `dologin_pub.asp` 对不存在的版本返回 **HTTP 200 + HTML 错误页**，必须校验响应体
> 是否以 `%PDF` 开头。

---

## 1. 封装栈与 PER 编码前提

### 1.1 慢路径（Slow-Path）封装

每个 MCS 域阶段 PDU 的线上封装（S2–S6、S9、S17，A 级）：

```
+--------------------------------------------------------+
| TPKT Header                     4 bytes  (offset 0)   |  [T123] §8
+--------------------------------------------------------+
| X.224 Class 0 Data TPDU         3 bytes  (offset 4)   |  [X224] §13.7
+--------------------------------------------------------+
| MCS Domain MCSPDU (PER aligned) 1..N bytes            |  [T125] §7+§9
+--------------------------------------------------------+
```

- **TPKT**（T.123 §8，S105，B 级）：octet1 = version `0x03`（二进制 `0000 0011`）；octet2 =
  reserved（for further study，RDP 用 `0x00`）；octet3..4 = **大端** u16，值 = 整个 packet 长度
  （含 4 字节头 + TPDU）。最小 7，最大 65535。
- **X.224 Data TPDU**（X.224 §13.7，S106，B 级，class 0 普通格式）：
  - octet1 `LI` = 后续字节数 = `0x02`
  - octet2 = `1111 000y`（DT code，bits 8..5=1111，bits 4..2=000，bit1=ROA=0）→ `0xF0`
  - octet3 = `EOT(bit8) | TPDU-NR(bits 7..1)` → `0x80`（EOT=1，NR=0，class 0 中 NR 恒 0）
  - 即固定三字节 **`02 F0 80`**。
- TPKT / X.224 的多字节长度是**大端**；其后的 MCS 与 RDP 字段按 S1「All multiple-byte fields
  within a message MUST be marshaled in little-endian byte order」——但 PER 的"two-octet
  bit-field"是**非负二进制整数的高字节在前**，两者不冲突（PER 字段不按 LE 解释）。

### 1.2 Domain MCSPDU 的 PER 编码骨架（本文件全部 PDU 共用）

`DomainMCSPDU ::= CHOICE { ... }` 共 **43 个备选**（T.125 §7 Part 10，S103，B 级）。按 X.691
§22.6（S104，B 级）编码索引；索引范围 0..42（range = 43），按 X.691 §10.5.7.1 落入
"33 to 64 → 6 bits"档，因此：

| 位 | 含义 |
|---|---|
| bit 8..3（6 bit） | `DomainMCSPDU` 选择索引 |
| bit 2..1 | 对齐填充（0），**除非**该备选首个字段是 1 bit 的 OPTIONAL 存在位 |

本文件涉及的索引（已与 §12 全部 dump 逐条对齐）：

| 索引 | 6-bit | 首字节 | 备选 |
|---|---|---|---|
| 1 | `000001` | `0x04` | erectDomainRequest |
| 8 | `001000` | `0x21`（含 reason 前 2 位） | disconnectProviderUltimatum |
| 10 | `001010` | `0x28` | attachUserRequest |
| 11 | `001011` | `0x2E`（含 presence 位） | attachUserConfirm |
| 14 | `001110` | `0x38` | channelJoinRequest |
| 15 | `001111` | `0x3E`（含 presence 位） | channelJoinConfirm |
| 25 | `011001` | `0x64` | sendDataRequest |
| 26 | `011010` | `0x68` | sendDataIndication |

完整 43 项索引（T.125 §7 Part 10，供校验）：0 plumbDomainIndication、1 erectDomainRequest、
2 mergeChannelsRequest、3 mergeChannelsConfirm、4 purgeChannelsIndication、5 mergeTokensRequest、
6 mergeTokensConfirm、7 purgeTokensIndication、8 disconnectProviderUltimatum、
9 rejectMCSPDUUltimatum、10 attachUserRequest、11 attachUserConfirm、12 detachUserRequest、
13 detachUserIndication、14 channelJoinRequest、15 channelJoinConfirm、16 channelLeaveRequest、
17 channelConveneRequest、18 channelConveneConfirm、19 channelDisbandRequest、
20 channelDisbandIndication、21 channelAdmitRequest、22 channelAdmitIndication、
23 channelExpelRequest、24 channelExpelIndication、25 sendDataRequest、26 sendDataIndication、
27 uniformSendDataRequest、28 uniformSendDataIndication、29 tokenGrabRequest、30 tokenGrabConfirm、
31 tokenInhibitRequest、32 tokenInhibitConfirm、33 tokenGiveRequest、34 tokenGiveIndication、
35 tokenGiveResponse、36 tokenGiveConfirm、37 tokenPleaseRequest、38 tokenPleaseIndication、
39 tokenReleaseRequest、40 tokenReleaseConfirm、41 tokenTestRequest、42 tokenTestConfirm。

### 1.3 本文件用到的 PER 编码规则（X.691，S104，B 级）

| 规则 | 出处 | 本文件用途 |
|---|---|---|
| 约束整数 range ≤255 → 最少位 bit-field | §10.5.7.1 | `Result`(16→4b)、`Reason`(5→3b)、`DataPriority`(4→2b) |
| 约束整数 range = 256 → 1 octet | §10.5.7.2 | 本文件未用 |
| 约束整数 257 ≤ range ≤ 64K → 2 octet | §10.5.7.3 | `ChannelId`(65536)、`UserId`(64535) |
| 半约束整数（lb 已知，ub=MAX）→ 长度决定因子 + 最少字节 | §10.7 | `subHeight`/`subInterval` |
| 长度决定因子 n≤127 → 1 octet（bit8=0） | §10.9.3.6 | `userData` ≤127 |
| 长度决定因子 127<n<16K → 2 octet（`10` + 14 bit） | §10.9.3.7 | `userData` 128..16383 |
| 长度决定因子 n≥16K → `11` + 6 bit 分片 | §10.9.3.8 | **RDP 禁止使用**（§7.4） |
| BIT STRING SIZE(2) → 2 bit，索引 0 先传 | §15.9 | `segmentation` |
| CHOICE 索引 → 最少位（本文件均 6 bit） | §22.6 | 所有 DomainMCSPDU |
| ENUMERATED 无扩展标记 → 按约束整数编码 | §13.2 | `Result` / `Reason` / `DataPriority` |
| SEQUENCE 的 OPTIONAL 前导位图按字段顺序 | §18.2 | `AttachUserConfirm`/`ChannelJoinConfirm` 的 OPTIONAL |

> **关键**：`DataPriority` 在 T.125 §7（Version 2）是 `ENUMERATED`（2 bit），在 T.125 §8
> （Version 3）是 `CHOICE`。RDP 用 Version 2（S1），故按 **2 bit 枚举**解释。

---

## 2. Erect Domain Request（`[APPLICATION 1]`）

### 2.1 字段定义

来源：S2（2.2.1.5，A 级）+ T.125 §7 Part 3（S103，B 级）：

```asn1
ErectDomainRequest  ::=  [APPLICATION 1] IMPLICIT SEQUENCE
{
    subHeight    INTEGER (0..MAX),
        --  height in domain of the MCSPDU transmitter
    subInterval    INTEGER (0..MAX)
        --  its throughput enforcement interval in milliseconds
}
```

| 偏移 | 大小 | 字段 | 编码 | 来源 |
|---|---|---|---|---|
| 0 | 4 | `tpktHeader` | `03 00 <len:BE16>` | S2 / [T123] §8 |
| 4 | 3 | `x224Data` | `02 F0 80` | S2 / [X224] §13.7 |
| 7 | 5 | `mcsEDrq` | 见下 | S2 / T.125 §11.8 |

`mcsEDrq` 逐字节（S78 dump，**规范字节图**）：

| 偏移 | 位 | 字段 | 编码 | 值 |
|---|---|---|---|---|
| 7 | bit8..3 | DomainMCSPDU 索引 | 6 bit | `000001` = 1 = erectDomainRequest |
| 7 | bit2..1 | 对齐填充 | 2 bit | `00` |
| 8 | — | `subHeight` 长度决定因子 | 1 octet | `01`（半约束整数，值占 1 字节） |
| 9 | — | `subHeight` 值 | 1 octet | `00` |
| 10 | — | `subInterval` 长度决定因子 | 1 octet | `01` |
| 11 | — | `subInterval` 值 | 1 octet | `00` |

→ 首字节 `0x04` = `000001 00`（S78 原文逐位标注）。

### 2.2 取值与约束

- `subHeight`：发送方在域层级中的高度（`INTEGER (0..MAX)`）。T.125 §11.8 Table 11-8 语义为
  "Height in Domain，Subordinate → Higher provider"。
- `subInterval`：吞吐量强制间隔，单位**毫秒**（T.125 §7 Part 3 注释
  `-- its throughput enforcement interval in milliseconds`）。
- 客户端取值（S33，A 级原文）："The client SHOULD initialize both the **subHeight** and
  **subinterval** fields of the MCS Erect Domain Request PDU to zero."
- 服务端校验（S49，A 级原文）："The server MUST ensure that the **subHeight** and
  **subinterval** fields are contained within the PDU. If this is not the case, the connection
  SHOULD be dropped."
- 发送时机（S2）：收到 MCS Connect Response PDU（2.2.1.4）之后。S109（3.2.5.3.4）补充：Connect
  Response 的 `result == rt-successful(0)` 才 MUST 发送 Erect Domain Request，否则 SHOULD 断链。
- Enhanced RDP Security 下整个 PDU 由外部安全协议加密并加校验摘要（S33）。
- 半约束整数的编码细节（推导，X.691 §10.7）：`lb = 0`、无 `ub` → 先 1 字节长度决定因子
  （值 n 的字节数），再是 n 字节非负二进制整数。n=0 时长度因子为 `01`、值为 `00`（不能用
  长度 `00` 表示零，因为 §10.7 的编码总是至少 1 字节值）。

### 2.3 完整 PDU 字节（规范字节图，S78）

```
03 00 00 0c 02 f0 80 04 01 00 01 00
```
总长 12 字节；TPKT `length` = `0x000C` = 12 = 实际长度 ✔

---

## 3. Attach User Request（`[APPLICATION 10]`）

### 3.1 字段定义

来源：S3（2.2.1.6，A 级）+ T.125 §7 Part 5（S103，B 级）：

```asn1
AttachUserRequest  ::=  [APPLICATION 10] IMPLICIT SEQUENCE
{
}
```

| 偏移 | 大小 | 字段 | 编码 | 来源 |
|---|---|---|---|---|
| 0 | 4 | `tpktHeader` | `03 00 <len:BE16>` | S3 |
| 4 | 3 | `x224Data` | `02 F0 80` | S3 |
| 7 | 1 | `mcsAUrq` | `0x28` | S3 / S79 |

`mcsAUrq` = `0x28` = `001010 00`：
- bit8..3 = `001010` = 10 → attachUserRequest
- bit2..1 = `00` 对齐填充
- SEQUENCE 为空（无任何字段，因此无 OPTIONAL 前导位）

**规范字节图**（S79）。

### 3.2 客户端 UserId 语义

- 客户端**不**在请求里携带 UserId；`AttachUserRequest` 只有 MCSPDU 类型本身。T.125 §11.17 原文：
  "AttachUserRequest contains no information other than its MCSPDU type."
- 客户端通过该请求**申请**一个 UserId（= User Channel ID）。新 id 由顶层 MCS provider 生成，
  "The only initial characteristic of the user id generated is its uniqueness"（T.125 §11.17）。
- 服务端收到后 MUST 回 Attach User Confirm（S50）。
- 客户端把 Confirm 里的 `initiator` 存入 **User Channel ID store**（S35 / S65）。
- T.125 §11.17 还要求 provider 记录每个未应答的 AttachUserRequest 及其到达的 MCS 连接，以便
  AttachUserConfirm 原路返回；应为 FIFO 队列。

### 3.3 完整 PDU 字节（规范字节图，S79）

```
03 00 00 08 02 f0 80 28
```
总长 8 字节；TPKT `length` = `0x0008` ✔

---

## 4. Attach User Confirm（`[APPLICATION 11]`）

### 4.1 字段定义

来源：S4（2.2.1.7，A 级）+ T.125 §7 Part 5（S103，B 级）：

```asn1
AttachUserConfirm  ::=  [APPLICATION 11] IMPLICIT SEQUENCE
{
    result       Result,
    initiator    UserId OPTIONAL
}
```

| 偏移 | 大小 | 字段 | 编码 | 来源 |
|---|---|---|---|---|
| 0 | 4 | `tpktHeader` | `03 00 <len:BE16>` | S4 |
| 4 | 3 | `x224Data` | `02 F0 80` | S4 |
| 7 | 4 | `mcsAUcf` | 见下 | S4 / S80 |

`mcsAUcf` 逐位（S80 dump，**规范字节图**）：

| 偏移 | 位 | 字段 | 编码 |
|---|---|---|---|
| 7 (`0x2E`) | bit8..3 | DomainMCSPDU 索引 = 11 | `001011` |
| 7 | bit2 | `initiator` OPTIONAL 存在位 | `1` = present |
| 7 | bit1 + 8.bit8..6 | `result`（Result 枚举，16 值 → 4 bit） | `0000` = rt-successful |
| 8 | bit5..1 | 对齐填充 | `00000` |
| 9..10 | — | `initiator`（UserId，1001..65535 → 2 octet，值 = id−1001） | `00 06` → 1007 |

> 位序说明（推导，X.691 §18.2 + §10.5.7.1）：`SEQUENCE` 的 OPTIONAL 前导位图只有 1 位（只有
> 一个 OPTIONAL 字段），按 §18.2 该位图**紧接在 CHOICE 索引之后**、且**位于各字段内容之前**，
> 故 `initiator present` 占 bit2，`result` 的 4 bit 从 bit1 开始跨到下一字节。S80 的逐位标注
> 与此完全一致。

### 4.2 `Result` 枚举完整取值表

来源：T.125 §7 Part 9 `Result ::= ENUMERATED`（S103，B 级），**全部 16 个取值**：

| 数值 | 枚举名 | 4-bit | 语境含义（T.125 §11.18/§11.22 语义） |
|---|---|---|---|
| 0 | `rt-successful` | `0000` | 成功 |
| 1 | `rt-domain-merging` | `0001` | 域正在合并 |
| 2 | `rt-domain-not-hierarchical` | `0010` | 域层级非法 |
| 3 | `rt-no-such-channel` | `0011` | 无此通道 |
| 4 | `rt-no-such-domain` | `0100` | 无此域 |
| 5 | `rt-no-such-user` | `0101` | 无此用户 |
| 6 | `rt-not-admitted` | `0110` | 未被接纳（私有通道） |
| 7 | `rt-other-user-id` | `0111` | 其他用户 id |
| 8 | `rt-parameters-unacceptable` | `1000` | 参数不可接受 |
| 9 | `rt-token-not-available` | `1001` | token 不可用 |
| 10 | `rt-token-not-possessed` | `1010` | 未持有 token |
| 11 | `rt-too-many-channels` | `1011` | 通道数超限 |
| 12 | `rt-too-many-tokens` | `1100` | token 数超限 |
| 13 | `rt-too-many-users` | `1101` | 用户数超限 |
| 14 | `rt-unspecified-failure` | `1110` | 未指明失败 |
| 15 | `rt-user-rejected` | `1111` | 用户被拒绝 |

编码：ENUMERATED 无扩展标记 → 4 bit（range 16 → X.691 §10.5.7.1 "9 to 16 → 4 bits"）。

RDP 侧取值规则（A 级）：

- 成功：`result = rt-successful (0)`，且 **`initiator` MUST be present**，其值即 User Channel ID
  （S51）。
- 失败：`result MUST be set to rt-unspecified-failure (14)`，且 `initiator` SHOULD NOT be present
  （S51）。→ **RDP 服务端实际只用 0 与 14 两个值。**
- 客户端校验（S35）：`result != 0` → SHOULD 断链；`result == 0` 但 `initiator` 缺失 → SHOULD
  断链；存在则存入 User Channel ID store，并立即发第一个 Channel Join Request（用户通道）。

### 4.3 `initiator` 的 PER 编码（DynamicChannelId 1001..65535 的 16 位规则）

- `ChannelId ::= INTEGER (0..65535)    -- range is 16 bits`
- `StaticChannelId ::= ChannelId (1..1000)`
- `DynamicChannelId ::= ChannelId (1001..65535)`
- `UserId ::= DynamicChannelId`
（以上均 T.125 §7 Part 1，S103，B 级）

编码规则（推导，X.691 §10.5.3 + §10.5.7.3）：

| 步骤 | 计算 | 结果 |
|---|---|---|
| range | 65535 − 1001 + 1 | **64535** |
| 档位 | 257 ≤ 64535 ≤ 64K | §10.5.7.3 两字节档 |
| 编码值 | `id − lb = id − 1001` | 0..64534 |
| 位宽 | 2 octet，octet-aligned，高位在前 | u16 |

因此 **UserId 的 16 位编码 = `(UserId − 1001)` 的 16 位大端表示**：

| UserId | 线上字节 |
|---|---|
| 1001 | `00 00` |
| 1002 | `00 01` |
| 1003 | `00 02` |
| 1007 | `00 06`（dump 实测） |
| 65535 | `FC 16`（推导：64534 = 0xFC16） |

- S80 原文注释 `AttachUserConfirm::initiator = 0x0006 + 1001 = 0x03ef = 1007` 与上式一致
  （**规范字节图 + 原文注释**）。
- 关键：`ChannelId` 的 lb=0、range=65536，**不加偏移**；只有 `UserId` 加 `−1001` 偏移。这是
  `initiator`（UserId）与 `channelId`（ChannelId）编码的**唯一差别**，但两者宽度都是 2 字节，
  从字节长度上看不出差别。

### 4.4 完整 PDU 字节（规范字节图，S80）

```
03 00 00 0b 02 f0 80 2e 00 00 06
```
总长 11 字节；TPKT `length` = `0x000B` = 11 ✔；`mcsAUcf` = 4 字节（与 S4 声明的
"mcsAUcf (4 bytes)" 一致）。

### 4.5 服务端 UserId 分配范围（规范内部冲突）

- S69（3.3.1.2，A 级）原文："This value MUST be in the range **1001 to 65536, inclusive**, as
  required by the T.125 ASN.1 definitions of the UserId and DynamicChannelId types"。
- 但 T.125 原文是 `DynamicChannelId ::= ChannelId (1001..65535)`（B 级），**上界应为 65535**。
- 处理：S69 的 "65536" 与 T.125 冲突，属规范笔误；实现应取 **1001..65535**（T.125 是 ASN.1
  权威定义，且 S1 明确以 T.125 定义为准）。本文件 §12 dump 里服务器分配的是 **1007**。

---

## 5. Channel Join Request（`[APPLICATION 14]`）

### 5.1 字段定义

来源：S5（2.2.1.8，A 级）+ T.125 §7 Part 6（S103，B 级）：

```asn1
ChannelJoinRequest  ::=  [APPLICATION 14] IMPLICIT SEQUENCE
{
    initiator    UserId,
    channelId    ChannelId
        --  may be zero
}
```

| 偏移 | 大小 | 字段 | 编码 | 来源 |
|---|---|---|---|---|
| 0 | 4 | `tpktHeader` | `03 00 <len:BE16>` | S5 |
| 4 | 3 | `x224Data` | `02 F0 80` | S5 |
| 7 | 5 | `mcsCJrq` | 见下 | S5 / S83 / S86 |

`mcsCJrq` 逐位（S83 dump，**规范字节图**）：

| 偏移 | 位 | 字段 | 编码 |
|---|---|---|---|
| 7 (`0x38`) | bit8..3 | 索引 = 14 | `001110` |
| 7 | bit2..1 | 对齐填充 | `00` |
| 8..9 | — | `initiator`（UserId，值 = id−1001） | `00 06` → 1007 |
| 10..11 | — | `channelId`（ChannelId，值 = 原值） | `03 EF` → 1007 |

### 5.2 两字段编码差异

| 字段 | 类型 | lb..ub | range | 编码 | 线上值 |
|---|---|---|---|---|---|
| `initiator` | `UserId` = `DynamicChannelId` | 1001..65535 | 64535 | 2 octet | `id − 1001` |
| `channelId` | `ChannelId` | 0..65535 | 65536 | 2 octet | `id`（不加偏移） |

- `channelId` 允许为 0：T.125 §11.21 说明，若请求上到顶层 provider 且 `channelId = 0`，顶层会
  分配一个新的 **assigned channel id** 并在成功 Confirm 中返回。

### 5.3 RDP 要求的加入顺序与 channelId 列表

S36（3.2.5.3.8，A 级）原文顺序：

1. **User Channel** — id 来自 User Channel ID store（即 Attach User Confirm 的 `initiator`）。
2. **I/O channel** — id 来自 I/O Channel ID store（即 Server Network Data 的 `MCSChannelId`）。
3. **Message channel** — 仅当 Message Channel ID 非 0（来自 Server Message Channel Data 的
   `MCSChannelID`；S30 原文 "If this value is zero, then the channel MUST NOT be joined"）。
4. **Static Virtual Channels** — id 来自 Static Virtual Channel IDs store（即 Server Network Data
   的 `channelIdArray`，与 Client Network Data 请求顺序一一对应，S29）。

时序约束（S36，A 级原文）：

- "The MCS Channel Join Request PDUs are sent **sequentially**. The first PDU is sent after
  receiving the MCS Attach User Confirm PDU and subsequent PDUs are sent after receiving the
  MCS Channel Join Confirm PDU for the previous request."
- "Sending of the MCS Channel Join Request PDUs MUST continue until all channels have been
  successfully joined."
- 例外一（S71）：RDP 8.1 / 10.0 / 10.1 客户端把全部 Join Request **一次性批量**发送，以缩短
  连接时间。
- 例外二（S36 / S52）：若客户端置 `RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN` 且服务器置
  `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED`（分别在 Client/Server Core Data 的
  `earlyCapabilityFlags`），则 SHOULD 跳过全部 Join Request/Confirm；收到 Attach User Confirm 后
  即视为全部通道已加入。
- 服务端对**已加入**通道的重复 Join Request：SHOULD 忽略且 SHOULD NOT 回 Confirm（S52）。

**实际 channelId 取值（示例 dump，非规范强制）**

| 通道 | dump 中的 id | 是否规范固定 | 依据 |
|---|---|---|---|
| Server Channel | 1002 (`0x03EA`) | **是，固定** | S70："defined as the arbitrarily chosen but fixed value 0x03EA (1002)" |
| I/O Channel | 1003 (`0x03EB`) | 否（服务器在 Server Network Data 指定） | S29 / S86 |
| Static VC #1 (rdpdr) | 1004 (`0x03EC`) | 否（`channelIdArray[0]`） | S29 / S89 |
| Static VC #2 (cliprdr) | 1005 (`0x03ED`) | 否 | S92 |
| Static VC #3 (rdpsnd) | 1006 (`0x03EE`) | 否 | S95 |
| User Channel | 1007 (`0x03EF`) | 否（Attach User Confirm 分配） | S83 / S84 |

> **注意**：上表列出 1002 只是为了完整对照下文 dump 里出现的 id；**客户端不会 join Server Channel**——S36 的加入清单只有 4 项（user / I/O / message / static VC），S71 也只说加入 user + I/O + static VC。

> **修正任务前提**：1002 不是用户通道，而是 **Server Channel**（固定 `0x03EA`），用作
> server→client Send Data Indication 的 `initiator`（S47 + S102 §4.1.12 dump 的
> `SendDataIndication::initiator = 0x01 + 1001 = 1002`）。用户通道是 1007。
> 此外任务提示的"各虚拟通道 1004+"只是本 dump 的取值，规范并不固定——虚拟通道 id 由服务器在
> Server Network Data 的 `channelIdArray` 里逐项指定，顺序与客户端请求一致。

### 5.4 完整 PDU 字节（规范字节图）

| 目标通道 | 字节 | 总长 | 来源 |
|---|---|---|---|
| 1007（用户） | `03 00 00 0c 02 f0 80 38 00 06 03 ef` | 12 | S83 |
| 1003（I/O） | `03 00 00 0c 02 f0 80 38 00 06 03 eb` | 12 | S86 |
| 1004（rdpdr） | `03 00 00 0c 02 f0 80 38 00 06 03 ec` | 12 | S89 |
| 1005（cliprdr） | `03 00 00 0c 02 f0 80 38 00 06 03 ed` | 12 | S92 |
| 1006（rdpsnd） | `03 00 00 0c 02 f0 80 38 00 06 03 ee` | 12 | S95 |

TPKT `length` 均为 `0x000C` = 12 = 实际长度 ✔；`mcsCJrq` = 5 字节（与 S5 声明的
"mcsCJrq (5 bytes)" 一致）。

---

## 6. Channel Join Confirm（`[APPLICATION 15]`）

### 6.1 字段定义

来源：S6（2.2.1.9，A 级）+ T.125 §7 Part 6（S103，B 级）：

```asn1
ChannelJoinConfirm  ::=  [APPLICATION 15] IMPLICIT SEQUENCE
{
    result       Result,
    initiator    UserId,
    requested    ChannelId,
        --  may be zero
    channelId    ChannelId OPTIONAL
}
```

| 偏移 | 大小 | 字段 | 编码 | 来源 |
|---|---|---|---|---|
| 0 | 4 | `tpktHeader` | `03 00 <len:BE16>` | S6 |
| 4 | 3 | `x224Data` | `02 F0 80` | S6 |
| 7 | 8 | `mcsCJcf` | 见下 | S6 / S84 |

`mcsCJcf` 逐位（S84 dump，**规范字节图**）：

| 偏移 | 位 | 字段 | 编码 |
|---|---|---|---|
| 7 (`0x3E`) | bit8..3 | 索引 = 15 | `001111` |
| 7 | bit2 | `channelId` OPTIONAL 存在位 | `1` = present |
| 7 | bit1 + 8.bit8..6 | `result`（4 bit） | `0000` = rt-successful |
| 8 | bit5..1 | 对齐填充 | `00000` |
| 9..10 | — | `initiator`（UserId，值 = id−1001） | `00 06` → 1007 |
| 11..12 | — | `requested`（ChannelId，原值） | `03 EF` → 1007 |
| 13..14 | — | `channelId`（ChannelId，原值，OPTIONAL） | `03 EF` → 1007 |

### 6.2 `result` 枚举

与 §4.2 **完全同一张表**（T.125 §7 Part 9 `Result`，16 个取值 0..15）。`ChannelJoinConfirm`
复用同一 `Result` 类型（T.125 §11.22 Table 11-22 的 "Result" 内容项）。为便于实现，重复列出：

| 数值 | 枚举名 | 4-bit |
|---|---|---|
| 0 | `rt-successful` | `0000` |
| 1 | `rt-domain-merging` | `0001` |
| 2 | `rt-domain-not-hierarchical` | `0010` |
| 3 | `rt-no-such-channel` | `0011` |
| 4 | `rt-no-such-domain` | `0100` |
| 5 | `rt-no-such-user` | `0101` |
| 6 | `rt-not-admitted` | `0110` |
| 7 | `rt-other-user-id` | `0111` |
| 8 | `rt-parameters-unacceptable` | `1000` |
| 9 | `rt-token-not-available` | `1001` |
| 10 | `rt-token-not-possessed` | `1010` |
| 11 | `rt-too-many-channels` | `1011` |
| 12 | `rt-too-many-tokens` | `1100` |
| 13 | `rt-too-many-users` | `1101` |
| 14 | `rt-unspecified-failure` | `1110` |
| 15 | `rt-user-rejected` | `1111` |

RDP 侧取值规则（A 级）：

- 成功：`result = rt-successful (0)`，且 **optional `channelId` MUST be included**（S53）。
- 失败（通道数超限 / 无此通道 / 内存分配失败等）：`result MUST be set to
  rt-unspecified-failure (14)`（S53）。→ RDP 服务端同样**只用 0 与 14**。
- 其余三字段初始化（S53 原文表格，本质是回抄请求）：

| 字段 | 取值 |
|---|---|
| `initiator` | 对应 Channel Join Request 里的 `initiator` |
| `requested` | 对应 Channel Join Request 里的 `channelId` |
| `channelId` | 对应 Channel Join Request 里的 `channelId` |

- 客户端校验（S37）：`channelId` 缺失 → SHOULD 断链；`result != 0` → SHOULD 断链；
  `initiator` / `requested` **MAY 被忽略**，但 `channelId` MUST 被检查，且必须等于上一个
  Join Request 里的 `channelId`，否则 SHOULD 断链。

### 6.3 四字段编码差异（含 OPTIONAL）

| 字段 | 类型 | lb..ub | range | 线上编码 | 偏移 |
|---|---|---|---|---|---|
| `result` | `Result` ENUMERATED | 0..15 | 16 | 4 bit | — |
| `initiator` | `UserId` | 1001..65535 | 64535 | 2 octet | `−1001` |
| `requested` | `ChannelId` | 0..65535 | 65536 | 2 octet | 无 |
| `channelId` | `ChannelId` OPTIONAL | 0..65535 | 65536 | 1 bit 存在位 + 2 octet | 无 |

**OPTIONAL 的编码差异**：`channelId` 是结构里唯一的 OPTIONAL 字段。按 X.691 §18.2（推导 +
S84 原文标注印证），`SEQUENCE` 的 OPTIONAL 前导位图（这里 1 bit）位于 CHOICE 索引之后、所有
字段内容之前，所以 `0x3E` 的 bit2 是 `channelId present`，`result` 的 4 bit 从 bit1 开始。
S84 原文逐位注释 `1 - ChannelJoinConfirm::channelId present` 与之一致。

推导：若 `channelId` 缺失，首字节应为 `0x3C`（`001111 0` + result `0000`…），PDU 缩短 2 字节。
本文件用自写 PER 编码器（§12.8）验证得到 `3c 00 00 06 03 ef`（`mcsCJcf` 5 字节）。但 RDP 要求
MUST 存在，故线上不会出现。

### 6.4 完整 PDU 字节（规范字节图）

| 目标通道 | 字节 | 总长 | 来源 |
|---|---|---|---|
| 1007（用户） | `03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef` | 15 | S84 |
| 1003（I/O） | `03 00 00 0f 02 f0 80 3e 00 00 06 03 eb 03 eb` | 15 | S87 |
| 1004（rdpdr） | `03 00 00 0f 02 f0 80 3e 00 00 06 03 ec 03 ec` | 15 | S90 |
| 1005（cliprdr） | `03 00 00 0f 02 f0 80 3e 00 00 06 03 ed 03 ed` | 15 | S93 |
| 1006（rdpsnd） | `03 00 00 0f 02 f0 80 3e 00 00 06 03 ee 03 ee` | 15 | S96 |

TPKT `length` 均为 `0x000F` = 15 = 实际长度 ✔；`mcsCJcf` = 8 字节（与 S6 声明一致）。

---

## 7. MCS Send Data Request（`[APPLICATION 25]`）/ Send Data Indication（`[APPLICATION 26]`）

### 7.1 定义与封装位置

T.125 §7 Part 7（S103，B 级）：

```asn1
SendDataRequest  ::=  [APPLICATION 25] IMPLICIT SEQUENCE
{
    initiator    UserId,
    channelId    ChannelId,
    dataPriority    DataPriority,
    segmentation   Segmentation,
    userData    OCTET STRING
}

SendDataIndication  ::=  [APPLICATION 26] IMPLICIT SEQUENCE
{
    initiator    UserId,
    channelId    ChannelId,
    dataPriority    DataPriority,
    segmentation   Segmentation,
    userData    OCTET STRING
}
```

[MS-RDPBCGR] 中的封装说明（A 级）：

- 客户端→服务器：`mcsSDrq`，SDrq = DomainMCSPDU **choice 25**（S31 / S39 / S7）。
- 服务器→客户端：`mcsSDin`，SDin = DomainMCSPDU **choice 26**（S47 / S25）。
- `initiator` / `channelId` 取值：
  - 客户端发送（S31）：`initiator` = User Channel ID（User Channel ID store，3.2.1.5）；
    `channelId` = MCS I/O channel ID（I/O Channel ID store，3.2.1.3）。
  - 服务器发送（S47）：`initiator` = MCS server channel ID（Server Channel ID store，固定
    `0x03EA`）；`channelId` = MCS I/O channel ID（I/O Channel ID store）。
  - 静态虚拟通道 PDU（S18）：同样用 SDrq/SDin 封装，`userData` 内是 Security Header +
    `channelPduHeader` + `virtualChannelData`。
- **任务前提修正**：Send Data 的封装说明**不在** 2.2.2.1 / 2.2.2.2。当前 [MS-RDPBCGR] 中
  2.2.2.1 = Client Shutdown Request PDU（S15）、2.2.2.2 = Server Shutdown Request Denied PDU
  （S16）。Send Data 封装规则在 3.2.5.1（S31，客户端侧）、3.3.5.1（S47，服务器侧），以及各
  PDU 小节里对 `mcsSDrq` / `mcsSDin` 字段的描述。

### 7.2 `mcsSDrq` / `mcsSDin` 头部逐位

以 S97 dump 的 `64 00 06 03 eb 70 50` 为例（**规范字节图**）：

| 偏移 | 位 | 字段 | 编码 | 值 |
|---|---|---|---|---|
| 0 (`0x64`) | bit8..3 | DomainMCSPDU 索引 | 6 bit | `011001` = 25 = sendDataRequest |
| 0 | bit2..1 | 对齐填充 | 2 bit | `00` |
| 1..2 | — | `initiator`（UserId，值 = id−1001） | 2 octet | `00 06` → 1007 |
| 3..4 | — | `channelId`（ChannelId，原值） | 2 octet | `03 EB` → 1003 |
| 5 (`0x70`) | bit8..7 | `dataPriority`（DataPriority 枚举，4 值 → 2 bit） | 2 bit | `01` = high(1) |
| 5 | bit6..5 | `segmentation`（BIT STRING SIZE(2)，索引 0 先传） | 2 bit | `11` = begin+end |
| 5 | bit4..1 | 对齐填充 | 4 bit | `0000` |
| 6 (`0x50`) | — | `userData` 长度决定因子 | 1 octet | `0x50` = 80（≤127 形态） |

`0x70` 的完整位图：`0111 0000` = `dataPriority(01) | segmentation(11) | padding(0000)`。

`SendDataIndication` 同理，只是首字节索引为 26 → `0x68`（S102 §4.1.12 dump：
`68 00 01 03 eb 70 81 73`，`initiator = 1002`）。

**`dataPriority` 取值**（T.125 §7 Part 1 `DataPriority ::= ENUMERATED`，B 级）：

| 值 | 枚举名 | 2-bit |
|---|---|---|
| 0 | `top` | `00` |
| 1 | `high` | `01` |
| 2 | `medium` | `10` |
| 3 | `low` | `11` |

**`segmentation` 位定义**（T.125 §7 Part 1，B 级）：

```asn1
Segmentation ::= BIT STRING
{
    begin     (0),
    end       (1)
} (SIZE (2))
```

按 X.691 §15.9（定长 BIT STRING，`ub = lb = 2 < 16`，直接放进 bit-field，无长度前缀）与 §15.5
（"the leading bit of the bitstring value shall coincide with the most significant bit of the
first octet"，S104 原文）：

| 位 | 含义 |
|---|---|
| bit6（字段最高位） | `begin`（索引 0） |
| bit5 | `end`（索引 1） |

→ `segmentation` 的 2-bit 值与位的关系（**推导**）：

| 值 | begin | end | 含义 |
|---|---|---|---|
| 0 (`00`) | 0 | 0 | 中间分片 |
| 1 (`01`) | 0 | 1 | 仅结束（末片） |
| 2 (`10`) | 1 | 0 | 仅开始（首片，未结束） |
| 3 (`11`) | 1 | 1 | 单片（begin + end） |

> 标注：S97 原文只写 `SendDataRequest::segmentation = 0x03 = (0x02 | 0x01) = (begin | end)`，
> 未逐位指认哪一位是 begin。上表的 bit6=begin / bit5=end 是依据 X.691 §15.5 + §15.9 的**推导**。
> 若只关心 `begin|end` 的合成值 `0x03`，该值本身来自规范字节图。

**结论**：RDP 慢路径 PDU 一律 `dataPriority = 1 (high)`、`segmentation = 3 (begin|end)`（S97 /
S98 / S100 与 S102 §4.1.12 全部如此），即 **`0x70` 是固定值**。

### 7.3 `userData` 长度决定因子

`userData` 是无约束 `OCTET STRING` → 走 X.691 §10.9.3.5–10.9.3.7（S104）：

| n = len(userData) | 编码形态 | 例 |
|---|---|---|
| 0 ≤ n ≤ 127 | 1 octet，bit8=0，bits7..1 = n | 80 → `0x50` |
| 128 ≤ n ≤ 16383 | 2 octet，bit8=1、bit7=0，bits6..1 + next octet = n（14 bit） | 412 → `0x81 0x9C`；371 → `0x81 0x73` |
| n ≥ 16384 | 3+ octet，bit8=1、bit7=1，bits6..1 = 分片数（1..4） | **RDP 禁止** |

校验（逐位推导）：

- 412 = `0x19C` = `01 1001 1100`（14 bit）→ `1000 0001 1001 1100` → `81 9C` ✔（S98）
- 371 = `0x173` = `01 0111 0011`（14 bit）→ `1000 0001 0111 0011` → `81 73` ✔（S102 §4.1.12）
- 80 = `0x50` = `101 0000` → `0101 0000` → `50` ✔（S97）

### 7.4 16383 字节上限的规范原文依据

S1（2.2 Message Syntax，A 级）原文：

> "Version 2 MCS Encoding Rules (defined in [T125] section 9) are used when encoding MCS structures
> defined in T125. The MCS Send Data Request (T125 section 11.32) and MCS Send Data Indication
> (T125 section 11.33) structures **MUST be restricted to 16,383 or fewer bytes in length** to
> avoid implementing ASN.1 Packed Encoding Rules (PER) extended size determinant encoding
> ([ITUX691] section 10.9.3, **excluding 10.9.3.8**)."

- 含义：长度决定因子只能用 §10.9.3.6（1 octet）与 §10.9.3.7（2 octet，最大 16383），
  **禁止** §10.9.3.8（≥16K 分片）。
- 因此 `userData` 最大 **16383** 字节；`mcsSDrq` / `mcsSDin` 头部最多 1+2+2+1+2 = 8 字节。
- 注意区分：Fast-Path 的 "The overall PDU length SHOULD be less than or equal to 16,383 bytes"
  （S23 / S24）是**另一个独立约束**，且 Fast-Path 不上 MCS。
- 另注：`maxMCSPDUsize` 是域参数（Connect Initial/Response 的 `DomainParameters`），RDP 协商值
  可为 65535 / 1056 / 65528 等（S102 §4.1.3 / §4.1.4 dump 实测：`02 02 ff ff` = 65535、
  `02 02 04 20` = 1056、`02 03 00 ff f8` = 65528），**但 16383 是 RDP 对 SDrq/SDin 的硬约束**，
  与 `maxMCSPDUsize` 无关。

### 7.5 `userData` 的内容（RDP 层）

| PDU | `userData` 内容 | 来源 |
|---|---|---|
| Security Exchange | `basicSecurityHeader` + `TS_SECURITY_PACKET` | S7 / S8 |
| Client Info | `securityHeader` + `TS_INFO_PACKET` | S9 / S10 |
| 静态虚拟通道 | `securityHeader`(可选) + `CHANNEL_PDU_HEADER` + 通道数据 | S18 / S19 |
| 一般慢路径 PDU | `securityHeader`(可选) + `shareDataHeader` + PDU 内容 | S31 / S47 |

- Enhanced RDP Security 下：整包由外部安全协议加密并生成校验摘要，`securityHeader`
  **MUST NOT** 出现（S31 / S47）。
- Standard RDP Security 下：`securityHeader` 存在；加密时其 `flags` MUST 含
  `SEC_ENCRYPT (0x0008)`（S31 / S47）。
- `shareDataHeader` 的 `pduSource`：客户端发送时 = User Channel ID（S31），服务器发送时 =
  Server Channel ID（S47）。

### 7.6 Fast-Path（不上 MCS）

S23（2.2.8.1.2）、S24（2.2.9.1.2），A 级原文：

> "The TPKT Header (T123 section 8), X.224 Class 0 Data TPDU (X224 section 13.7), and MCS Send Data
> Request (T125 section 11.32) **are replaced**; the Security Header is collapsed into the
> fast-path input header, and the Share Data Header is replaced by a new fast-path format."

- Fast-Path **没有** TPKT / X.224 / MCS 三层；`fpInputHeader` / `fpOutputHeader` 的首字节就是
  原 TPKT 首字节的位置。
- `fpInputHeader`（1 字节，S23，A 级）：

| 位 | 字段 | 取值 |
|---|---|---|
| bit8..7 | `action`（2 bit） | `0x0` = FASTPATH_INPUT_ACTION_FASTPATH；`0x3` = FASTPATH_INPUT_ACTION_X224（此时整字节 MUST 为 `0x03`，即慢路径 TPKT 版本字节） |
| bit6..3 | `numEvents`（4 bit） | 1..15；>15 时置 0 并用后续 `numEvents` 字节（最多 255） |
| bit2..1 | `flags`（2 bit） | `0x1` = FASTPATH_INPUT_SECURE_CHECKSUM；`0x2` = FASTPATH_INPUT_ENCRYPTED |

- `length1`：bit8=0 → 长度 1..127，`length2` 不存在；bit8=1 → 长度 = `length1[7:1]` 与 `length2`
  拼成 **big-endian** 16 位（`length2` 是低 8 位）。
- `fpOutputHeader`（S24）位域为 `action(2) | reserved(4) | flags(2)`（无 `numEvents`）。
- 结论：**通道建立阶段（Erect Domain → Client Info）全程走慢路径**；Fast-Path 只在 Capabilities
  Exchange 之后按能力协商启用。

---

## 8. Disconnect Provider Ultimatum（`[APPLICATION 8]`）

### 8.1 字段定义

来源：S17（2.2.2.3，A 级）+ T.125 §7 Part 4（S103，B 级）：

```asn1
DisconnectProviderUltimatum  ::=  [APPLICATION 8] IMPLICIT SEQUENCE
{
    reason    Reason
}
```

| 偏移 | 大小 | 字段 | 编码 | 来源 |
|---|---|---|---|---|
| 0 | 4 | `tpktHeader` | `03 00 <len:BE16>` | S17 |
| 4 | 3 | `x224Data` | `02 F0 80` | S17 |
| 7 | 2 | `mcsDPum` | `21 80` | S17 / S99 |

`mcsDPum` 逐位（S99 dump，**规范字节图**）：

| 偏移 | 位 | 字段 | 编码 |
|---|---|---|---|
| 7 (`0x21`) | bit8..3 | 索引 = 8 | `001000` |
| 7 | bit2..1 + 8.bit8 | `reason`（Reason 枚举 5 值 → 3 bit） | `01` + `1` = `011` = 3 |
| 8 | bit7..1 | 对齐填充 | `0000000` |

→ `21 80` = `001000 01` + `1 0000000`。

> **规范内部不一致（必须记录）**：S17 声明 `mcsDPum (8 bytes)`，但 S99 注解 dump 的 TPKT
> `length` 是 9、实际载荷只有 **2 字节**（`21 80`），且 `4 + 3 + 2 = 9` 自洽。若按 8 字节则
> TPKT 应为 15。**以 dump 与 T.125 结构为准：`mcsDPum` = 2 字节**。S17 的 "8 bytes" 是规范
> 笔误（推测从 `mcsCJcf (8 bytes)` 复制而来）。

### 8.2 `Reason` 枚举完整取值表

T.125 §7 Part 9（S103，B 级）：

```asn1
Reason  ::=  ENUMERATED  --  in DisconnectProviderUltimatum, DetachUserRequest, DetachUserIndication
{
    rn-domain-disconnected  (0),
    rn-provider-initiated   (1),
    rn-token-purged         (2),
    rn-user-requested       (3),
    rn-channel-purged       (4)
}
```

| 数值 | 枚举名 | 3-bit |
|---|---|---|
| 0 | `rn-domain-disconnected` | `000` |
| 1 | `rn-provider-initiated` | `001` |
| 2 | `rn-token-purged` | `010` |
| 3 | `rn-user-requested` | `011` |
| 4 | `rn-channel-purged` | `100` |

编码：5 值 → range 5 → X.691 §10.5.7.1 "5, 6, 7, 8 → 3 bits"。

RDP 侧取值规则（A 级）：

- S63（3.1.5.1.1）："Only the **rn-provider-initiated (1)** or **rn-user-requested (3)** reason
  codes MUST be used in the reason field."
  - 客户端主动断开（1.3.1.4.1）→ `rn-user-requested (3)`
  - 服务器侧用户主动断开（1.3.1.4.2）→ `rn-user-requested (3)`
  - 服务器侧管理员断开（1.3.1.4.3）→ `rn-provider-initiated (1)`
- S63：发完 DPU 后网络连接 **MUST** 关闭。
- S64（3.1.5.1.2）：服务器 **MUST 忽略** `reason`；客户端 MAY 用它提示用户，若值不是 1 或 3
  则 **MUST 忽略**；收到 DPU 后 MUST 预期对端关闭连接。
- S44（3.2.5.5.1）：收到 Deactivate All PDU 后，客户端 MUST 准备好处理**可选**的 DPU，然后才是
  真正断开。
- S42（3.2.5.4.2）：客户端处理完 Shutdown Request Denied 后若用户选择断开，SHOULD 发 DPU 并
  随后 MUST 断开。

### 8.3 完整 PDU 字节（规范字节图，S99）

```
03 00 00 09 02 f0 80 21 80
```
总长 9 字节；TPKT `length` = `0x0009` = 9 ✔

---

## 9. Client Security Exchange PDU（2.2.1.10）

### 9.1 何时发送

| 场景 | 是否发送 | 依据 |
|---|---|---|
| Standard RDP Security 且 Encryption Level > 0 且 Encryption Method > 0 | **发送** | S37 / S71 第 4 段 |
| Standard RDP Security 但 Encryption Level 或 Method 为 0 | 不发送，直接 Client Info | S37 |
| Enhanced RDP Security（TLS / CredSSP(HYBRID, HYBRID_EX) / RDSTLS / RDSAAD） | **不发送** | S75 |

S75（5.4.2.3，A 级）原文：

> "If Standard RDP Security mechanisms are not being used in conjunction with an External Security
> protocol (that is, the selected Encryption Level described in section 5.3.2 is
> ENCRYPTION_LEVEL_NONE (0)), then the Security Commencement phase of the RDP Connection Sequence
> is not executed, with the result that the client **does not send the Security Exchange PDU**.
> This PDU can be dropped because the Client Random is redundant in this case because encryption for
> the connection is only provided by the External Security Protocol."

S37（3.2.5.3.9，A 级）给出二选一判据：所有通道 join 完成后，若 Encryption Level 与 Encryption
Method **都大于 0** → 发 Security Exchange PDU；若**都为 0** → 直接发 Client Info PDU。

> **NLA（HYBRID / HYBRID_EX）结论：不发送。** 这是"推导"，推导链：
> ① S107（5.4.5.2）：CredSSP 由 `PROTOCOL_HYBRID (0x00000002)` / `PROTOCOL_HYBRID_EX
> (0x00000008)` 表示，属 External Security Protocol（S108）；
> ② S28（2.2.1.4.3）：使用 Enhanced RDP Security 时 `encryptionMethod` 与 `encryptionLevel`
> MUST 均为 0；
> ③ S75：Encryption Level 为 0 时 Security Commencement 阶段不执行，不发 Security Exchange PDU。
> 另：S108 明确 "There is no double-encryption of traffic because the Kerberos (or NTLM) session is
> securely bound to the TLS session"。

### 9.2 结构

来源：S7（2.2.1.10）+ S8（2.2.1.10.1）。

| 层 | 字段 | 大小（本例） | 来源 |
|---|---|---|---|
| TPKT | `tpktHeader` | 4 | S7 |
| X.224 | `x224Data` | 3 | S7 |
| MCS | `mcsSDrq` | 7 | S7 / T.125 §11.32 |
| RDP | `securityExchangePduData` = `TS_SECURITY_PACKET` | 80 | S8 |

`TS_SECURITY_PACKET`（S8，A 级）：

| 偏移（相对 `userData`） | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | `basicSecurityHeader` | `TS_SECURITY_HEADER`：`flags`(2) + `flagsHi`(2)。`flags` MUST 含 `SEC_EXCHANGE_PKT (0x0001)`；若客户端能处理加密 licensing 包且用 Standard RDP Security，SHOULD 再含 `SEC_LICENSE_ENCRYPT_SC (0x0200)`（S38） |
| 4 | 4 | `length` | u32。`encryptedClientRandom` 缓冲区的字节数，**不含**本 4 字节头，也**不含**前 4 字节 `basicSecurityHeader` |
| 8 | variable | `encryptedClientRandom` | 用服务器公钥 RSA 加密的 32 字节 client random；缓冲区大小 = `(bitlen/8) + 8` |

`encryptedClientRandom` 的缓冲区大小（S73，A 级原文）：

```
(bitlen / 8) + 8
```

> "For example, if the public key of the server is 512 bits long, then the zeroed-out buffer is
> 72 bytes. This value can also be obtained from the **keylen** field in the public key structure
> (section 2.2.1.4.3.1.1.1)."

- 即 `length` = `(bitlen/8) + 8`，末尾 8 字节是**必须存在且填 0 的 rear padding**。S38 原文：
  "After the encrypted client random has been copied into the **encryptedClientRandom** buffer,
  **8 bytes of padding (which MUST be filled with zeroes)** will remain."
- 加密算法（S73）：`c = r^e mod n`；`r` 按 **unsigned little-endian** 整数解释；结果拷入已清零的
  缓冲区（长度 `(bitlen/8)+8`）。
- 与 Standard RDP Security 的关系（S74）：client random 与 Server Security Data 里的 32 字节
  server random 一起派生**三个**对称会话密钥（client→server 加密键 / server→client 加密键 /
  MAC 键），长度 40 / 56 / 128 bit。本 PDU 是 Standard RDP Security 的 **Security
  Commencement** 阶段唯一报文。
- `flags` 位定义（S21，A 级）：`SEC_EXCHANGE_PKT = 0x0001`（"This packet type is sent from client
  to server only. The client only sends this packet if it will be encrypting further communication
  and Standard RDP Security mechanisms are in effect."）；`SEC_LICENSE_ENCRYPT_SC = 0x0200`
  （"It is sent by the client together with the SEC_EXCHANGE_PKT flag when sending a Security
  Exchange PDU"）；`SEC_FLAGSHI_VALID = 0x8000` 控制 `flagsHi` 是否有效。
- 服务端校验（S54）：`flags` 必须含 `SEC_EXCHANGE_PKT (0x0001)`，否则无法解释为 Security
  Exchange PDU，SHOULD 断链；若含 `SEC_LICENSE_ENCRYPT_SC (0x0200)`，记入 Client Licensing
  Encryption Ability store；用 `length` 判断 `encryptedClientRandom` 大小，与实收数据不符则
  SHOULD 断链。

### 9.3 完整 PDU 字节（规范字节图，S97）

```
03 00 00 5e 02 f0 80 64 00 06 03 eb 70 50 01 02
00 00 48 00 00 00 91 ac 0c 8f 64 8c 39 f4 e7 ff
0a 3b 79 11 5c 13 51 2a cb 72 8f 9d b7 42 2e f7
08 4c 8e ae 55 99 62 d2 81 81 e4 66 c8 05 ea d4
73 06 3f c8 5f af 2a fd fc f1 64 b3 3f 0a 15 1d
db 2c 10 9d 30 11 00 00 00 00 00 00 00 00
```
总长 94 字节；TPKT `length` = `0x005E` = 94 ✔

自洽校验：

- `mcsSDrq` 头 7 字节（`64 00 06 03 eb 70 50`），`userData length = 0x50 = 80`
- `4 + 3 + 7 + 80 = 94` ✔
- `userData` 内部：`flags(2) + flagsHi(2) + length(4) + encryptedClientRandom(72) = 80` ✔
- `TS_SECURITY_PACKET::length = 0x48 = 72` = `(512/8) + 8` = 64 + 8 ✔（服务器公钥 512 bit）
- 末尾 8 字节 `00 00 00 00 00 00 00 00` = rear padding ✔
- `flags = 0x0201 = SEC_LICENSE_ENCRYPT_SC | SEC_EXCHANGE_PKT`；`flagsHi = 0x0000` 因
  `SEC_FLAGSHI_VALID` 未置而应被忽略 ✔

---

## 10. Client Info PDU（2.2.1.11）

### 10.1 外层结构

来源：S9（2.2.1.11）+ S10（2.2.1.11.1）。

| 层 | 字段 | 大小（本例） | 来源 |
|---|---|---|---|
| TPKT | `tpktHeader` | 4 | S9 |
| X.224 | `x224Data` | 3 | S9 |
| MCS | `mcsSDrq` | 8 | S9 |
| RDP | `clientInfoPduData` = `CLIENT_INFO_PDU` | 412 | S10 |

`CLIENT_INFO_PDU`（S10，A 级）：

| 字段 | 大小 | 说明 |
|---|---|---|
| `securityHeader` | variable | **始终存在**。Encryption Level = NONE(0) → Basic Security Header；Encryption Method = 40/56/128bit → Non-FIPS；= FIPS → FIPS。Enhanced RDP Security 下也 MUST 存在，但内容是 Basic Security Header（S39） |
| `infoPacket` | variable | `TS_INFO_PACKET` |

- `securityHeader.flags` **MUST** 含 `SEC_INFO_PKT (0x0040)`（S39 / S55）。
- Standard RDP Security 且要加密时，`flags` 还 MUST 含 `SEC_ENCRYPT (0x0008)`（S39）。
- S55 补充：若 Encryption Level 为 `ENCRYPTION_LEVEL_NONE (0)`，客户端可能**错误地**置
  `SEC_ENCRYPT`；此时 MUST 以 Encryption Level 为准并**忽略**该 flag。
- S55：解析前必须先测 `INFO_UNICODE` 决定字符编码；字符数据超过上限时应截断存储；变长字段
  数据不足时 SHOULD 断链。
- S39：自动重连时把 cookie 填进 `TS_EXTENDED_INFO_PACKET.autoReconnectCookie`。

### 10.2 `TS_INFO_PACKET` 完整字段表

来源：S11（2.2.1.11.1.1，A 级）。

| 偏移 | 大小 | 字段 | 类型/编码 | 约束与语义 |
|---|---|---|---|---|
| 0 | 4 | `CodePage` | u32 LE | 无 `INFO_UNICODE` → ANSI code page；有 `INFO_UNICODE` → **低 16 位**是 active language identifier，高 16 位 MUST 被服务器忽略；若 Client Core Data 的 `keyboardLayout = 0`，服务器 SHOULD 忽略之 |
| 4 | 4 | `flags` | u32 LE | 见 §10.3 |
| 8 | 2 | `cbDomain` | u16 LE | `Domain` 字节数，**不含**强制 NULL 终止符 |
| 10 | 2 | `cbUserName` | u16 LE | `UserName` 字节数，**不含** NULL |
| 12 | 2 | `cbPassword` | u16 LE | `Password` 字节数，**不含** NULL |
| 14 | 2 | `cbAlternateShell` | u16 LE | `AlternateShell` 字节数，**不含** NULL |
| 16 | 2 | `cbWorkingDir` | u16 LE | `WorkingDir` 字节数，**不含** NULL |
| 18 | variable | `Domain` | 字符数组 | 长度 = `cbDomain`；**MUST** 至少含一个 NULL 终止符；上限：RDP 4.0/5.0 = 52 B（含 NULL），其它版本 512 B |
| — | variable | `UserName` | 字符数组 | 长度 = `cbUserName`；上限：RDP 4.0 = 44 B，其它 512 B；若 `INFO_PASSWORD_IS_SC_PIN` 置位则 SHOULD 被忽略 |
| — | variable | `Password` | 字符数组 | 长度 = `cbPassword`；上限：RDP 4.0/5.0 = 32 B，其它 512 B |
| — | variable | `AlternateShell` | 字符数组 | 长度 = `cbAlternateShell`；上限 512 B；仅在请求非默认 shell 时初始化 |
| — | variable | `WorkingDir` | 字符数组 | 长度 = `cbWorkingDir`；上限 512 B；MAY 初始化 |
| — | variable | `extraInfo` | `TS_EXTENDED_INFO_PACKET` | **可选**（RDP 4.0 除外） |

关键点（都是实现易错处）：

1. **五个 `cb*` 都"不含 NULL"**，但每个字符串字段**实际占用 `cb + 终止符长度`**：
   - `INFO_UNICODE` 置位 → 终止符 2 字节（UTF-16LE `00 00`），字段总长 = `cb + 2`
   - 否则 → 终止符 1 字节（ANSI `00`），字段总长 = `cb + 1`
   - 所以 `cbDomain = 0` 的字段仍占 2（或 1）字节。
2. `CodePage` 在 Unicode 模式下**不是** code page，而是语言 ID（低 16 位），高 16 位忽略。
3. 字符集由 `INFO_UNICODE` 单点决定，同时作用于 `TS_INFO_PACKET` 与 `TS_EXTENDED_INFO_PACKET`。
4. dump 实测（§12.6.2）：`CodePage = 0x04090409`（低字 `0x0409` = 1033 = en-US）、
   `flags = 0x000043B3`、`cbDomain = 10`、`cbUserName = 12`，随后 `Domain` 占 12 字节
   （10 + 2 字节 NULL）、`UserName` 占 14 字节（12 + 2 字节 NULL）。

### 10.3 `TS_INFO_PACKET.flags` 完整取值表

来源：S11，A 级。

| 值 | 名称 | 含义 |
|---|---|---|
| 0x00000001 | `INFO_MOUSE` | 客户端机器有鼠标 |
| 0x00000002 | `INFO_DISABLECTRLALTDEL` | 登录提示不要求 CTRL+ALT+DEL（或等价）安全访问序列 |
| 0x00000008 | `INFO_AUTOLOGON` | 用所给用户名/密码/域自动登录 |
| 0x00000010 | `INFO_UNICODE` | 字符串为 Unicode；否则按 `CodePage` 指定的 ANSI |
| 0x00000020 | `INFO_MAXIMIZESHELL` | 备用 shell 最大化启动 |
| 0x00000040 | `INFO_LOGONNOTIFY` | 要求服务器回送 Save Session Info（用户名/域/session id） |
| 0x00000080 | `INFO_COMPRESSION` | `CompressionTypeMask` 有效，含客户端支持的最高压缩包类型 |
| 0x00001E00 | `CompressionTypeMask` | 4-bit 枚举，最高压缩包类型（见下表） |
| 0x00000100 | `INFO_ENABLEWINDOWSKEY` | 客户端使用 Windows 键 |
| 0x00002000 | `INFO_REMOTECONSOLEAUDIO` | 音频在服务器端播放 |
| 0x00004000 | `INFO_FORCE_ENCRYPTED_CS_PDU` | 加密生效时所有 client→server 流量加密（防 MITM） |
| 0x00008000 | `INFO_RAIL` | 该连接用于 RemoteApp |
| 0x00010000 | `INFO_LOGONERRORS` | 要求 logon error 通知 |
| 0x00020000 | `INFO_MOUSE_HAS_WHEEL` | 鼠标有滚轮 |
| 0x00040000 | `INFO_PASSWORD_IS_SC_PIN` | `Password` 字段是智能卡 PIN |
| 0x00080000 | `INFO_NOAUDIOPLAYBACK` | 禁止音频重定向 |
| 0x00100000 | `INFO_USING_SAVED_CREDS` | 凭据来自凭据存储 |
| 0x00200000 | `INFO_AUDIOCAPTURE` | 支持客户端音频输入重定向 |
| 0x00400000 | `INFO_VIDEO_DISABLE` | 禁止视频重定向/回放 |
| 0x00800000 | `INFO_RESERVED1` | 保留，MUST NOT 置位 |
| 0x01000000 | `INFO_RESERVED2` | 保留，MUST NOT 置位 |
| 0x02000000 | `INFO_HIDEF_RAIL_SUPPORTED` | 支持 Enhanced RemoteApp；`INFO_RAIL` 未置时 MUST 忽略 |

`CompressionTypeMask` 取值（S11）：

| 值 | 名称 | 含义 |
|---|---|---|
| 0x0 | `PACKET_COMPR_TYPE_8K` | RDP 4.0 bulk compression |
| 0x1 | `PACKET_COMPR_TYPE_64K` | RDP 5.0 bulk compression |
| 0x2 | `PACKET_COMPR_TYPE_RDP6` | RDP 6.0 bulk compression |
| 0x3 | `PACKET_COMPR_TYPE_RDP61` | RDP 6.1 bulk compression |

S11 附加约束："If a client supports compression package *n* then it MUST support packages
*0...(n - 1)*."

### 10.4 `TS_EXTENDED_INFO_PACKET` 完整字段表

来源：S12（2.2.1.11.1.1.1，A 级）。**存在性严格链式**：后一字段存在 ⇒ 前一字段必须存在；
前一字段不存在 ⇒ 其后全部不存在。

| 顺序 | 大小 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 1 | 2 | `clientAddressFamily` | u16 | `AF_INET (0x0002)` → IPv4；`AF_INET6 (0x0017)` → IPv6 |
| 2 | 2 | `cbClientAddress` | u16 | `clientAddress` 字节数，**含** NULL 终止符 |
| 3 | variable | `clientAddress` | 字符数组 | 文本 IP；上限含 NULL：RDP 5.0/5.1/5.2/6.0 = 64 B，其它 80 B |
| 4 | 2 | `cbClientDir` | u16 | `clientDir` 字节数，**含** NULL |
| 5 | variable | `clientDir` | 字符数组 | 客户端软件所在目录或模块全路径；上限 512 B（含 NULL） |
| 6 | 172 | `clientTimeZone` | `TS_TIME_ZONE_INFORMATION` | 可选；RDP 5.0/5.1 服务器不读。**缺失则其后全部缺失** |
| 7 | 4 | `clientSessionId` | u32 | RDP 5.1 加入，服务器当前忽略，SHOULD 置 0。存在 ⇒ `clientTimeZone` 必须存在 |
| 8 | 4 | `performanceFlags` | u32 | 桌面特性开关（见下）。RDP 5.0 服务器不读。存在 ⇒ `clientSessionId` 必须存在 |
| 9 | 2 | `cbAutoReconnectCookie` | u16 | MUST 为 0 或 `0x001C`。RDP 5.0/5.1 不读。存在 ⇒ `performanceFlags` 必须存在 |
| 10 | 28 | `autoReconnectCookie` | `ARC_CS_PRIVATE_PACKET` | 当且仅当 `cbAutoReconnectCookie` 非 0 时存在 |
| 11 | 2 | `reserved1` | u16 | 保留，SHOULD 置 0。存在 ⇒ `cbAutoReconnectCookie` 与 `reserved2` 必须存在 |
| 12 | 2 | `reserved2` | u16 | 保留，**MUST** 置 0。存在 ⇒ `reserved1` 必须存在 |
| 13 | 2 | `cbDynamicDSTTimeZoneKeyName` | u16 | `dynamicDSTTimeZoneKeyName` 字节数。存在 ⇒ `reserved2` 与 `dynamicDaylightTimeDisabled` 必须存在 |
| 14 | variable | `dynamicDSTTimeZoneKeyName` | Unicode 字符数组 | **无终止 NULL**；上限 254 B；当且仅当 `cbDynamicDSTTimeZoneKeyName` 非 0 时存在 |
| 15 | 2 | `dynamicDaylightTimeDisabled` | u16 | `0x0000` = FALSE（若支持则启用 Dynamic DST）；`0x0001` = TRUE（禁用）。存在 ⇒ `cbDynamicDSTTimeZoneKeyName` 必须存在 |

`performanceFlags` 取值（S12）：

| 值 | 名称 | 含义 |
|---|---|---|
| 0x00000001 | `PERF_DISABLE_WALLPAPER` | 禁用桌面壁纸 |
| 0x00000002 | `PERF_DISABLE_FULLWINDOWDRAG` | 禁用全窗口拖动 |
| 0x00000004 | `PERF_DISABLE_MENUANIMATIONS` | 禁用菜单动画 |
| 0x00000008 | `PERF_DISABLE_THEMING` | 禁用主题 |
| 0x00000010 | `PERF_RESERVED1` | 保留，服务器 SHOULD 忽略 |
| 0x00000020 | `PERF_DISABLE_CURSOR_SHADOW` | 禁用光标阴影 |
| 0x00000040 | `PERF_DISABLE_CURSORSETTINGS` | 禁用光标闪烁 |
| 0x00000080 | `PERF_ENABLE_FONT_SMOOTHING` | 启用字体平滑 |
| 0x00000100 | `PERF_ENABLE_DESKTOP_COMPOSITION` | 启用 Desktop Composition（需 32 bpp） |
| 0x80000000 | `PERF_RESERVED2` | 保留，服务器 SHOULD 忽略 |

### 10.5 `TS_TIME_ZONE_INFORMATION`（172 字节，S13）

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | `Bias` | i32；分钟；`UTC = local time + bias` |
| 4 | 64 | `StandardName` | 32 个 Unicode 字符 |
| 68 | 16 | `StandardDate` | `TS_SYSTEMTIME` |
| 84 | 4 | `StandardBias` | i32；加到 `Bias` 上 |
| 88 | 64 | `DaylightName` | 32 个 Unicode 字符 |
| 152 | 16 | `DaylightDate` | `TS_SYSTEMTIME` |
| 168 | 4 | `DaylightBias` | i32；加到 `Bias` 上 |

- 若 `StandardDate` / `DaylightDate` 的所有 `w*` 字段全 0 → 客户端不支持夏令时，对应
  `StandardBias` / `DaylightBias` MUST 被忽略。
- 两个日期字段互相约束：一个有效则另一个也 MUST 有效。
- 偏移列由字段大小累加得出（**推导**）；S13 只给出字段顺序与大小。

### 10.6 `TS_SYSTEMTIME`（16 字节，S14）

| 偏移 | 大小 | 字段 | 约束 |
|---|---|---|---|
| 0 | 2 | `wYear` | **MUST 为 0** |
| 2 | 2 | `wMonth` | 1..12 |
| 4 | 2 | `wDayOfWeek` | 0=Sunday .. 6=Saturday |
| 6 | 2 | `wDay` | 1..4 = 第 N 个，5 = 最后一个 |
| 8 | 2 | `wHour` | 0..23 |
| 10 | 2 | `wMinute` | 0..59 |
| 12 | 2 | `wSecond` | 0..59 |
| 14 | 2 | `wMilliseconds` | 0..999 |

### 10.7 完整 PDU 字节（规范字节图，S98）

线上（加密后）427 字节，见 §12.6 逐字节抄录。结构校验：

- TPKT `length = 0x01AB = 427` = 实际长度 ✔
- `mcsSDrq` 头 8 字节（`64 00 06 03 eb 70 81 9c`），`userData length = 0x19C = 412`
- `4 + 3 + 8 + 412 = 427` ✔
- `userData` 内部：`flags(2) + flagsHi(2) + dataSignature(8) + 密文(400) = 412` ✔
- 解密后 `TS_INFO_PACKET` = 400 字节，与 `userData` 里密文长度一致 ✔

### 10.8 `TS_LOGON_INFO` / `TS_LOGON_INFO_VERSION_2`（澄清：不属于 Client Info）

任务把 `TS_LOGON_INFO` 列在 Client Info 下，但规范原文显示它是 **Save Session Info PDU**（server→client，2.2.10.1）的载荷，**不在** Client Info PDU（client→server）里。两者容易混淆，故在此澄清并给出结构，避免实现时误接。

`TS_SAVE_SESSION_INFO_PDU_DATA`（S110，A 级）：`shareDataHeader (18 bytes)` + `infoType (4 bytes)` + `infoData`。`infoType` 取值：

| 值 | 名称 | `infoData` 内容 |
|---|---|---|
| 0x00000000 | `INFOTYPE_LOGON` | `TS_LOGON_INFO`（Logon Info Version 1） |
| 0x00000001 | `INFOTYPE_LOGON_LONG` | `TS_LOGON_INFO_VERSION_2`（Logon Info Version 2） |
| 0x00000002 | `INFOTYPE_LOGON_PLAINNOTIFY` | Plain Notify（576 字节 padding） |
| 0x00000003 | `INFOTYPE_LOGON_EXTENDED_INFO` | Logon Info Extended |

`TS_LOGON_INFO`（S26，A 级，定长）：

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | `cbDomain` | u32；`Domain` 里 Unicode 字符数据的字节数（**含** NULL） |
| 4 | 52 | `Domain` | 26 个 Unicode 字符（定长），NULL 结尾 |
| 56 | 4 | `cbUserName` | u32；`UserName` 里 Unicode 数据字节数（**含** NULL） |
| 60 | 512 | `UserName` | 256 个 Unicode 字符（定长），NULL 结尾 |
| 572 | 4 | `SessionId` | u32；可选（RDP 4.0 以外都发） |

（偏移列为字段大小累加推导。）

`TS_LOGON_INFO_VERSION_2`（S27，A 级，变长）：

| 偏移 | 大小 | 字段 | 说明 |
|---|---|---|---|
| 0 | 2 | `Version` | u16；`SAVE_SESSION_PDU_VERSION_ONE (0x0001)` = Version 1 |
| 2 | 4 | `Size` | u32；本结构总字节数，**不含** `Domain` / `UserName` 变长部分 |
| 6 | 4 | `SessionId` | u32 |
| 10 | 4 | `cbDomain` | u32；`Domain` 字节数（**含** NULL） |
| 14 | 4 | `cbUserName` | u32；`UserName` 字节数（**含** NULL） |
| 18 | 558 | `Pad` | 填充，值 MUST 被忽略 |
| 576 | variable | `Domain` | NULL 结尾 Unicode 字符串 |
| — | variable | `UserName` | NULL 结尾 Unicode 字符串 |

（偏移列为推导；`Size` 应为 576 = 2+4+4+4+4+558。）

结论：Client Info PDU 的载荷只有 `securityHeader` + `TS_INFO_PACKET`（§10.1–§10.4）；`TS_LOGON_INFO*` 属于反向的 Save Session Info PDU，实现时不要放进 Client Info。

---

## 11. 完整时序（Connect Response 之后 → Client Info）

来源：S71（1.3.1.1 Connection Sequence，A 级）+ S109/S35/S36/S37/S39 + S2–S6 各小节首段。

```
        Client                                          Server
          |                                                |
          |<----------- (1) MCS Connect Response ----------|   2.2.1.4
          |                                                |
          |------------ (2) MCS Erect Domain Request ----->|   2.2.1.5
          |------------ (3) MCS Attach User Request ------>|   2.2.1.6
          |<----------- (4) MCS Attach User Confirm -------|   2.2.1.7
          |------------ (5) Channel Join Request (user) -->|   2.2.1.8
          |<----------- (6) Channel Join Confirm (user) ---|   2.2.1.9
          |------------ (5) Channel Join Request (I/O) --->|
          |<----------- (6) Channel Join Confirm (I/O) ----|
          |------------ (5) Channel Join Request (msg) --->|   仅当 msg id != 0
          |<----------- (6) Channel Join Confirm (msg) ----|
          |------------ (5) Channel Join Request (VC k) -->|   每个静态虚拟通道
          |<----------- (6) Channel Join Confirm (VC k) ---|
          |                                                |
          |------------ (7) Security Exchange PDU -------->|   2.2.1.10（可选）
          |------------ (8) Client Info PDU -------------->|   2.2.1.11
          |                                                |
          |<----------- (9) License Error PDU (Valid Client)| 2.2.1.12
          |<----------- (10) Demand Active PDU ------------|   2.2.1.13.1
          |------------ (11) Confirm Active PDU ---------->|   2.2.1.13.2
```

| # | PDU | 发送方 | 是否可选 | 依据 |
|---|---|---|---|---|
| 1 | MCS Connect Response | Server | **必须** | S109 |
| 2 | MCS Erect Domain Request | Client | **必须**（且仅当 Connect Response `result == 0`） | S2 / S109 / S33 |
| 3 | MCS Attach User Request | Client | **必须** | S3 / S34 |
| 4 | MCS Attach User Confirm | Server | **必须** | S4 / S50 / S51 |
| 5 | MCS Channel Join Request ×N | Client | **必须**（除非双方均置 skip-channel-join 能力） | S5 / S36 |
| 6 | MCS Channel Join Confirm ×N | Server | **必须**（同上） | S6 / S52 / S53 |
| 7 | Client Security Exchange | Client | **可选**（Standard RDP Security 且加密生效时才发） | S7 / S37 / S75 |
| 8 | Client Info | Client | **必须** | S9 / S39 |

补充时序规则：

- (1) 之前已完成 X.224 Connection Request/Confirm 与（若协商）外部安全协议握手（S71）。
- (2) 只在 Connect Response `result == rt-successful (0)` 时发送；否则客户端 SHOULD 断链（S109）。
- (3) 在 (2) 之后发送（S3 首段："It is sent after transmitting the MCS Erect Domain Request PDU"）。
- (4) 是对 (3) 的应答（S4 首段）。
- (5)(6) 的**第一个** Join Request 在收到 (4) 之后发送；后续每个 Join Request 在上一个 Join
  Confirm 之后发送（S36）。通道顺序：user → I/O → message（若 id≠0）→ 各静态虚拟通道（S36）。
- (7) 在**全部** Join Confirm 收到之后发送（S7 首段："It is sent after all of the requested MCS
  Channel Join Confirm PDUs have been received"）。
- (8) 在 (7) 之后发送；若 (7) 未发送，则在**全部** Join Confirm 收到之后发送（S9 首段）。
- (8) 之后服务器可进入 Licensing 阶段（S55 末段），随后是 Capabilities Exchange（S71 第 7 步）。
- 若启用 `RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN` + `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED`，(5)(6)
  整体省略，客户端收到 (4) 后直接进入 (7)/(8)（S36 / S52）。

---

## 12. 注解 dump（逐字节完整抄录）

### 12.0 抄录与独立校验说明

- 所有 dump 均来自 S78–S84、S86–S87、S89–S90、S92–S93、S95–S96、S97–S99 的
  `Accept: text/markdown` 响应，代码块内为官方 hexdump 原文。
- **独立校验**：另从 [MS-RDPBCGR] 官方 PDF（S102，v20260309，444 页）抽取 §4.1.5–§4.1.10、
  §4.2.3 的对应 hexdump，逐字节比对。结果：

| dump | 小节 | 字节数 | 与 PDF 原文逐字节一致 |
|---|---|---|---|
| Erect Domain Request | 4.1.5 | 12 | ✔ |
| Attach User Request | 4.1.6 | 8 | ✔ |
| Attach User Confirm | 4.1.7 | 11 | ✔ |
| Channel Join Request (1007) | 4.1.8.1.1 | 12 | ✔ |
| Channel Join Confirm (1007) | 4.1.8.1.2 | 15 | ✔ |
| Channel Join Request (1003) | 4.1.8.2.1 | 12 | ✔ |
| Channel Join Confirm (1003) | 4.1.8.2.2 | 15 | ✔ |
| Channel Join Request (1004) | 4.1.8.3.1 | 12 | ✔ |
| Channel Join Confirm (1004) | 4.1.8.3.2 | 15 | ✔ |
| Channel Join Request (1005) | 4.1.8.4.1 | 12 | ✔ |
| Channel Join Confirm (1005) | 4.1.8.4.2 | 15 | ✔ |
| Channel Join Request (1006) | 4.1.8.5.1 | 12 | ✔ |
| Channel Join Confirm (1006) | 4.1.8.5.2 | 15 | ✔ |
| Security Exchange | 4.1.9 | 94 | ✔ |
| Client Info（线上） | 4.1.10 | 427 | ✔ |
| Client Info（解密） | 4.1.10 | 400 | ✔ |
| Disconnect Provider Ultimatum | 4.2.3 | 9 | ✔ |

（17 个字节块，全部一致。PDF 与 markdown 两侧均按同一规则抽取：行首 8 位 hex 偏移后的两字符 hex token 序列。）

> **自洽检查口径**：下文 17 个 hexdump 块中，**16 块是完整的线上 PDU**（TPKT 封装），已逐块验证 `TPKT.length == 实际字节数` 全部成立；第 17 块（§12.6.2，400 字节）是 **解密后的 `TS_INFO_PACKET` 明文**，不含 TPKT 封装，因此不适用 TPKT 长度校验（它的长度已在 §12.6.1 里通过 `userData length = 0x19C` 与 `2+2+8+400` 校验）。

### 12.1 Erect Domain Request（S78，12 字节）

```
 00000000 03 00 00 0c 02 f0 80 04 01 00 01 00
```

```
 03 00 00 0c -> TPKT Header (length = 12 bytes)
 02 f0 80 -> X.224 Data TPDU

 PER encoded (ALIGNED variant of BASIC-PER) PDU contents:
 04 01 00 01 00

 0x04:
 0 - --\
 0 -   |
 0 -   | CHOICE: From DomainMCSPDU select erectDomainRequest (1)
 0 -   | of type ErectDomainRequest
 0 -   |
 1 - --/
 0 - padding
 0 - padding

 0x01:
 0 - --\
 0 -   |
 0 -   |
 0 -   | ErectDomainRequest::subHeight length = 1 byte
 0 -   |
 0 -   |
 0 -   |
 1 - --/

 0x00:
 0 - --\
 0 -   |
 0 -   |
 0 -   | ErectDomainRequest::subHeight = 0
 0 -   |
 0 -   |
 0 -   |
 0 - --/

 0x01:
 0 - --\
 0 -   |
 0 -   |
 0 -   | ErectDomainRequest::subInterval length = 1 byte
 0 -   |
 0 -   |
 0 -   |
 1 - --/

 0x00:
 0 - --\
 0 -   |
 0 -   |
 0 -   | ErectDomainRequest::subInterval = 0
 0 -   |
 0 -   |
 0 -   |
 0 - --/
```

自洽检查：总长 12 字节；TPKT `length = 0x000C` = 12 ✔；`4 + 3 + 5 = 12` ✔。

### 12.2 Attach User Request（S79，8 字节）

```
 00000000 03 00 00 08 02 f0 80 28
```

```
 03 00 00 08 -> TPKT Header (length = 8 bytes)
 02 f0 80 -> X.224 Data TPDU

 PER encoded (ALIGNED variant of BASIC-PER) PDU contents:
 28

 0x28:
 0 - --\
 0 -   |
 1 -   | CHOICE: From DomainMCSPDU select attachUserRequest (10)
 0 -   | of type AttachUserRequest
 1 -   |
 0 - --/
 0 - padding
 0 - padding
```

自洽检查：总长 8 字节；TPKT `length = 0x0008` = 8 ✔；`4 + 3 + 1 = 8` ✔。

### 12.3 Attach User Confirm（S80，11 字节）

```
 00000000 03 00 00 0b 02 f0 80 2e 00 00 06
```

```
 03 00 00 0b -> TPKT Header (length = 11 bytes)
 02 f0 80 -> X.224 Data TPDU

 PER encoded (ALIGNED variant of BASIC-PER) PDU contents:
 2e 00 00 06

 0x2e:
 0 - --\
 0 -   |
 1 -   | CHOICE: From DomainMCSPDU select attachUserConfirm (11)
 0 -   | of type AttachUserConfirm
 1 -   |
 1 - --/
 1 - AttachUserConfirm::initiator present
 0 - --\
       |
 0x00: | AttachUserConfirm::result = rt-successful (0)
 0 -   |
 0 -   |
 0 - --/
 0 - padding
 0 - padding
 0 - padding
 0 - padding
 0 - padding

 0x00:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
       | AttachUserConfirm::initiator = 0x0006 + 1001 = 0x03ef = 1007 (user channel)
 0x06: |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
 0 - --/
```

自洽检查：总长 11 字节；TPKT `length = 0x000B` = 11 ✔；`4 + 3 + 4 = 11` ✔。

### 12.4 Channel Join Request / Confirm（S83/S84/S86/S87/S89/S90/S92/S93/S95/S96）

#### 12.4.1 Channel 1007（User Channel）— Join Request（S83，12 字节）

```
 00000000 03 00 00 0c 02 f0 80 38 00 06 03 ef
```

```
 03 00 00 0c -> TPKT Header (length = 12 bytes)
 02 f0 80 -> X.224 Data TPDU

 PER encoded (ALIGNED variant of BASIC-PER) PDU contents:
 38 00 06 03 ef

 0x38:
 0 - --\
 0 -   |
 1 -   | CHOICE: From DomainMCSPDU select channelJoinRequest (14)
 1 -   | of type ChannelJoinRequest
 1 -   |
 0 - --/
 0 - padding
 0 - padding

 0x00:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
       | ChannelJoinRequest::initiator = 0x06 + 1001 = 1007 (0x03ef)
 0x06: |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
 0 - --/

 0x03:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
       | ChannelJoinRequest::channelId = 0x03ef = 1007
 0xef: |
 1 -   |
 1 -   |
 1 -   |
 0 -   |
 1 -   |
 1 -   |
 1 -   |
 1 - --/
```

自洽检查：12 字节；TPKT `length = 0x000C` ✔；`4 + 3 + 5 = 12` ✔。

#### 12.4.2 Channel 1007（User Channel）— Join Confirm（S84，15 字节）

```
 00000000 03 00 00 0f 02 f0 80 3e 00 00 06 03 ef 03 ef
```

```
 03 00 00 0f -> TPKT Header (length = 15 bytes)
 02 f0 80 -> X.224 Data TPDU

 PER encoded (ALIGNED variant of BASIC-PER) PDU contents:
 3e 00 00 06 03 ef 03 ef

 0x3e:
 0 - --\
 0 -   |
 1 -   | CHOICE: From DomainMCSPDU select channelJoinConfirm (15)
 1 -   | of type ChannelJoinConfirm
 1 -   |
 1 - --/
 1 - ChannelJoinConfirm::channelId present
 0 - --\
       |
 0x00: | ChannelJoinConfirm::result = rt-successful (0)
 0 -   |
 0 -   |
 0 - --/
 0 - padding
 0 - padding
 0 - padding
 0 - padding
 0 - padding

 0x00:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
       | ChannelJoinConfirm::initiator = 0x06 + 1001 = 1007 (0x03ef)
 0x06: |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
 0 - --/

 0x03:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
       | ChannelJoinConfirm::requested = 0x03ef = 1007
 0xef: |
 1 -   |
 1 -   |
 1 -   |
 0 -   |
 1 -   |
 1 -   |
 1 -   |
 1 - --/

 0x03:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
       | ChannelJoinConfirm::channelId = 0x03ef = 1007
 0xef: |
 1 -   |
 1 -   |
 1 -   |
 0 -   |
 1 -   |
 1 -   |
 1 -   |
 1 - --/
```

自洽检查：15 字节；TPKT `length = 0x000F` ✔；`4 + 3 + 8 = 15` ✔。

#### 12.4.3 Channel 1003（I/O Channel）— Join Request（S86，12 字节）

```
 00000000 03 00 00 0c 02 f0 80 38 00 06 03 eb
```

```
 ChannelJoinRequest::initiator = 6 + 1001 = 1007
 ChannelJoinRequest::channelId = 0x03eb = 1003
```

自洽检查：12 字节；TPKT `length = 0x000C` ✔。

#### 12.4.4 Channel 1003（I/O Channel）— Join Confirm（S87，15 字节）

```
 00000000 03 00 00 0f 02 f0 80 3e 00 00 06 03 eb 03 eb
```

```
 ChannelJoinConfirm::result = rt-successful (0)
 ChannelJoinConfirm::initiator = 6 + 1001 = 1007
 ChannelJoinConfirm::requested = 0x03eb = 1003
 ChannelJoinConfirm::channelId = 0x03eb = 1003
```

自洽检查：15 字节；TPKT `length = 0x000F` ✔。

#### 12.4.5 Channel 1004（rdpdr）— Join Request（S89，12 字节）

```
 00000000 03 00 00 0c 02 f0 80 38 00 06 03 ec
```

```
 ChannelJoinRequest::initiator = 6 + 1001 = 1007
 ChannelJoinRequest::channelId = 0x03ec = 1004
```

自洽检查：12 字节；TPKT `length = 0x000C` ✔。

#### 12.4.6 Channel 1004（rdpdr）— Join Confirm（S90，15 字节）

```
 00000000 03 00 00 0f 02 f0 80 3e 00 00 06 03 ec 03 ec
```

```
 ChannelJoinConfirm::result = rt-successful (0)
 ChannelJoinConfirm::initiator = 6 + 1001 = 1007
 ChannelJoinConfirm::requested = 0x03ec = 1004
 ChannelJoinConfirm::channelId = 0x03ec = 1004
```

自洽检查：15 字节；TPKT `length = 0x000F` ✔。

#### 12.4.7 Channel 1005（cliprdr）— Join Request（S92，12 字节）

```
 00000000 03 00 00 0c 02 f0 80 38 00 06 03 ed
```

```
 ChannelJoinRequest::initiator = 6 + 1001 = 1007
 ChannelJoinRequest::channelId = 0x03ed = 1005
```

自洽检查：12 字节；TPKT `length = 0x000C` ✔。

#### 12.4.8 Channel 1005（cliprdr）— Join Confirm（S93，15 字节）

```
 00000000 03 00 00 0f 02 f0 80 3e 00 00 06 03 ed 03 ed
```

```
 ChannelJoinConfirm::result = rt-successful (0)
 ChannelJoinConfirm::initiator = 6 + 1001 = 1007
 ChannelJoinConfirm::requested = 0x03ed = 1005
 ChannelJoinConfirm::channelId = 0x03ed = 1005
```

自洽检查：15 字节；TPKT `length = 0x000F` ✔。

#### 12.4.9 Channel 1006（rdpsnd）— Join Request（S95，12 字节）

```
 00000000 03 00 00 0c 02 f0 80 38 00 06 03 ee
```

```
 ChannelJoinRequest::initiator = 6 + 1001 = 1007
 ChannelJoinRequest::channelId = 0x03ee = 1006
```

自洽检查：12 字节；TPKT `length = 0x000C` ✔。

#### 12.4.10 Channel 1006（rdpsnd）— Join Confirm（S96，15 字节）

```
 00000000 03 00 00 0f 02 f0 80 3e 00 00 06 03 ee 03 ee
```

```
 ChannelJoinConfirm::result = rt-successful (0)
 ChannelJoinConfirm::initiator = 6 + 1001 = 1007
 ChannelJoinConfirm::requested = 0x03ee = 1006
 ChannelJoinConfirm::channelId = 0x03ee = 1006
```

自洽检查：15 字节；TPKT `length = 0x000F` ✔。

### 12.5 Client Security Exchange PDU（S97，94 字节）

```
 00000000 03 00 00 5e 02 f0 80 64 00 06 03 eb 70 50 01 02
 00000010 00 00 48 00 00 00 91 ac 0c 8f 64 8c 39 f4 e7 ff
 00000020 0a 3b 79 11 5c 13 51 2a cb 72 8f 9d b7 42 2e f7
 00000030 08 4c 8e ae 55 99 62 d2 81 81 e4 66 c8 05 ea d4
 00000040 73 06 3f c8 5f af 2a fd fc f1 64 b3 3f 0a 15 1d
 00000050 db 2c 10 9d 30 11 00 00 00 00 00 00 00 00
```

```
 03 00 00 5e -> TPKT Header (length = 94 bytes)
 02 f0 80 -> X.224 Data TPDU

 PER encoded (ALIGNED variant of BASIC-PER) SendDataRequest PDU:
 64 00 06 03 eb 70 50

 0x64:
 0 - --\
 1 -   |
 1 -   | CHOICE: From DomainMCSPDU select sendDataRequest (25)
 0 -   | of type SendDataRequest
 0 -   |
 1 - --/
 0 - padding
 0 - padding

 0x00:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
       | SendDataRequest::initiator = 0x06 + 1001 = 1007
 0x06: |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
 0 - --/

 0x03:
 0 - --\
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 0 -   |
 1 -   |
 1 -   |
       | SendDataRequest::channelId = 0x03eb = 1003
 0xeb: |
 1 -   |
 1 -   |
 1 -   |
 0 -   |
 1 -   |
 0 -   |
 1 -   |
 1 - --/

 0x70:
 0 - --\ SendDataRequest::dataPriority = 0x01 = high
 1 - --/
 1 - --\ SendDataRequest::segmentation = 0x03 = (0x02 | 0x01) = (begin | end)
 1 - --/
 0 - padding
 0 - padding
 0 - padding
 0 - padding

 0x50:
 0 - --\
 1 -   |
 0 -   |
 1 -   | SendDataRequest::userData length = 80 bytes
 0 -   |
 0 -   |
 0 -   |
 0 - --/

 01 02 -> TS_SECURITY_HEADER::flags = 0x0201
 0x0201
 = 0x0200 | 0x0001
 = SEC_LICENSE_ENCRYPT_SC | SEC_EXCHANGE_PKT

 00 00 -> TS_SECURITY_HEADER::flagsHi = 0x0000

 48 00 00 00 -> TS_SECURITY_PACKET::length = 0x48 = 72 bytes

 91 ac 0c 8f 64 8c 39 f4 e7 ff 0a 3b 79 11 5c 13
 51 2a cb 72 8f 9d b7 42 2e f7 08 4c 8e ae 55 99
 62 d2 81 81 e4 66 c8 05 ea d4 73 06 3f c8 5f af
 2a fd fc f1 64 b3 3f 0a 15 1d db 2c 10 9d 30 11 ->
 TS_SECURITY_PACKET::encryptedClientRandom

 00 00 00 00 00 00 00 00 -> 8-bytes of rear padding (always present)
```

自洽检查：总长 94 字节；TPKT `length = 0x005E` = 94 ✔；`4 + 3 + 7 + 80 = 94` ✔；
`4 + 4 + 72 = 80` = `userData length` ✔；`72 = (512/8) + 8` ✔。

### 12.6 Client Info PDU（S98，线上 427 字节 + 解密 400 字节）

#### 12.6.1 线上字节（427）

```
 00000000 03 00 01 ab 02 f0 80 64 00 06 03 eb 70 81 9c 48
 00000010 00 00 00 45 ca 46 fa 5e a7 be bc 74 21 d3 65 e9
 00000020 ba 76 12 7c 55 4b 9d 84 3b 3e 07 29 20 73 25 7b
 00000030 e6 9a bb e8 41 8a a0 69 3f 26 9a cd bc a6 03 27
 00000040 f5 ce bb a8 c2 ff 0f 38 a3 bf 74 81 ac cb c9 08
 00000050 49 0a 43 cf 91 31 36 cd ba 3d 16 4f 11 d7 69 12
 00000060 c8 e9 57 c0 b8 0f c4 72 66 79 bd 86 ba 30 60 76
 00000070 b4 cd 52 5e 79 8e 88 95 f0 9a 43 20 d9 96 74 1d
 00000080 5c 8a 9a e3 8a 5d d2 55 17 8c f2 66 6b 3f 3d 3a
 00000090 e3 2a d4 ff d5 11 30 30 e2 ff e2 e4 11 0c 7f 6a
 000000a0 1e a3 f4 2f dd 4f 89 8c c0 ca d3 8a 49 d7 00 d9
 000000b0 09 40 ab 79 1a 72 f9 89 42 af 20 aa 50 c7 cd d0
 000000c0 b8 1e ab d3 eb 10 01 82 68 9f f5 c9 05 fe 20 bb
 000000d0 7c 68 b4 72 cd 37 53 df 43 0a 6d de cb be 5f 80
 000000e0 05 1e b8 f3 5d 04 0c c6 66 3b 39 5f 5d a2 da b9
 000000f0 ea c9 da ba 7c 9d 4e 4a 4f 4a 16 04 ea 4e 23 d3
 00000100 6d 2c 2b 42 58 19 69 10 23 d4 e1 af 46 34 fc 23
 00000110 81 59 54 65 5f 6c 67 57 14 62 57 94 f1 81 86 00
 00000120 fe 1c 27 f6 76 e2 00 ea c5 f7 b5 e9 b2 ad ef 7f
 00000130 87 8b 8a b0 d3 1e 43 54 4b ab f6 ba 7f 5a b9 e5
 00000140 2d 5f 81 ab 2a 15 c4 97 bc d3 92 9a da be 8a b0
 00000150 fb a4 1a a0 96 26 86 23 10 1b 21 0a 91 05 22 4d
 00000160 6c 4d 01 4c 84 f3 50 56 4f 3a e4 c0 24 bf 35 f6
 00000170 f5 8b 3f 20 55 98 91 05 4d ee 46 95 44 6d 06 33
 00000180 42 1f 9f 84 91 e7 c5 9f 04 11 de cf a5 07 5f 27
 00000190 dd c0 ac b1 a7 98 9d 6d 79 00 70 33 bf 4e 16 23
 000001a0 57 f5 c7 88 82 d1 c6 a3 b4 0b 29
```

```
 03 00 01 ab -> TPKT Header (length = 427 bytes)
 02 f0 80 -> X.224 Data TPDU

 64 00 06 03 eb 70 81 9c -> PER encoded (ALIGNED variant of BASIC-PER) SendDataRequest
 initiator = 1007 (0x03ef)
 channelId = 1003 (0x03eb)
 dataPriority = high
 segmentation = begin | end
 userData length = 0x19c = 412 bytes

 48 00 -> TS_SECURITY_HEADER::flags = 0x0048
 0x0048
 = 0x0040 | 0x0008
 = SEC_INFO_PKT | SEC_ENCRYPT

 00 00 -> TS_SECURITY_HEADER::flagsHi - ignored as flags field does
 not contain SEC_FLAGSHI_VALID (0x8000)
 45 ca 46 fa 5e a7 be bc -> TS_SECURITY_HEADER1::dataSignature

 74 21 d3 65 e9 ba 76 12 7c 55 4b 9d 84 3b 3e 07
 29 20 73 25 7b e6 9a bb e8 41 8a a0 69 3f 26 9a
 cd bc a6 03 27 f5 ce bb a8 c2 ff 0f 38 a3 bf 74
 81 ac cb c9 08 49 0a 43 cf 91 31 36 cd ba 3d 16
 4f 11 d7 69 12 c8 e9 57 c0 b8 0f c4 72 66 79 bd
 86 ba 30 60 76 b4 cd 52 5e 79 8e 88 95 f0 9a 43
 20 d9 96 74 1d 5c 8a 9a e3 8a 5d d2 55 17 8c f2
 66 6b 3f 3d 3a e3 2a d4 ff d5 11 30 30 e2 ff e2
 e4 11 0c 7f 6a 1e a3 f4 2f dd 4f 89 8c c0 ca d3
 8a 49 d7 00 d9 09 40 ab 79 1a 72 f9 89 42 af 20
 aa 50 c7 cd d0 b8 1e ab d3 eb 10 01 82 68 9f f5
 c9 05 fe 20 bb 7c 68 b4 72 cd 37 53 df 43 0a 6d
 de cb be 5f 80 05 1e b8 f3 5d 04 0c c6 66 3b 39
 5f 5d a2 da b9 ea c9 da ba 7c 9d 4e 4a 4f 4a 16
 04 ea 4e 23 d3 6d 2c 2b 42 58 19 69 10 23 d4 e1
 af 46 34 fc 23 81 59 54 65 5f 6c 67 57 14 62 57
 94 f1 81 86 00 fe 1c 27 f6 76 e2 00 ea c5 f7 b5
 e9 b2 ad ef 7f 87 8b 8a b0 d3 1e 43 54 4b ab f6
 ba 7f 5a b9 e5 2d 5f 81 ab 2a 15 c4 97 bc d3 92
 9a da be 8a b0 fb a4 1a a0 96 26 86 23 10 1b 21
 0a 91 05 22 4d 6c 4d 01 4c 84 f3 50 56 4f 3a e4
 c0 24 bf 35 f6 f5 8b 3f 20 55 98 91 05 4d ee 46
 95 44 6d 06 33 42 1f 9f 84 91 e7 c5 9f 04 11 de
 cf a5 07 5f 27 dd c0 ac b1 a7 98 9d 6d 79 00 70
 33 bf 4e 16 23 57 f5 c7 88 82 d1 c6 a3 b4 0b 29 -> Encrypted
 TS_INFO_PACKET
```

自洽检查：总长 427 字节；TPKT `length = 0x01AB` = 427 ✔；`4 + 3 + 8 + 412 = 427` ✔；
`2 + 2 + 8 + 400 = 412` = `userData length` ✔。

#### 12.6.2 解密后的 `TS_INFO_PACKET`（400 字节）

> 注：本块是 `TS_INFO_PACKET` 明文，**不含 TPKT / X.224 / MCS 封装**，所以前 4 字节不是 TPKT 头（对应 `CodePage = 0x04090409`）。它的长度由外层的 `userData length` 和密文长度决定。

```
 00000000 09 04 09 04 b3 43 00 00 0a 00 0c 00 00 00 00 00
 00000010 00 00 4e 00 54 00 44 00 45 00 56 00 00 00 65 00
 00000020 6c 00 74 00 6f 00 6e 00 73 00 00 00 00 00 00 00
 00000030 00 00 02 00 1e 00 31 00 35 00 37 00 2e 00 35 00
 00000040 39 00 2e 00 32 00 34 00 32 00 2e 00 31 00 35 00
 00000050 36 00 00 00 84 00 43 00 3a 00 5c 00 64 00 65 00
 00000060 70 00 6f 00 74 00 73 00 5c 00 77 00 32 00 6b 00
 00000070 33 00 5f 00 31 00 5c 00 74 00 65 00 72 00 6d 00
 00000080 73 00 72 00 76 00 5c 00 6e 00 65 00 77 00 63 00
 00000090 6c 00 69 00 65 00 6e 00 74 00 5c 00 6c 00 69 00
 000000a0 62 00 5c 00 77 00 69 00 6e 00 33 00 32 00 5c 00
 000000b0 6f 00 62 00 6a 00 5c 00 69 00 33 00 38 00 36 00
 000000c0 5c 00 6d 00 73 00 74 00 73 00 63 00 61 00 78 00
 000000d0 2e 00 64 00 6c 00 6c 00 00 00 e0 01 00 00 50 00
 000000e0 61 00 63 00 69 00 66 00 69 00 63 00 20 00 53 00
 000000f0 74 00 61 00 6e 00 64 00 61 00 72 00 64 00 20 00
 00000100 54 00 69 00 6d 00 65 00 00 00 00 00 00 00 00 00
 00000110 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00000120 0a 00 00 00 05 00 02 00 00 00 00 00 00 00 00 00
 00000130 00 00 50 00 61 00 63 00 69 00 66 00 69 00 63 00
 00000140 20 00 44 00 61 00 79 00 6c 00 69 00 67 00 68 00
 00000150 74 00 20 00 54 00 69 00 6d 00 65 00 00 00 00 00
 00000160 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 00000170 00 00 00 00 04 00 00 00 01 00 02 00 00 00 00 00
 00000180 00 00 c4 ff ff ff 00 00 00 00 01 00 00 00 00 00
```

官方注解（S98 原文）：

```
 09 04 09 04 -> TS_INFO_PACKET::CodePage = 0x04090409
 Low word = 0x0409 = 1033 = English (US)
 Since the INFO_UNICODE flag is set, this is the active language identifier.

 b3 43 00 00 -> TS_INFO_PACKET::flags = 0x000043b3
 0x000043b3
 = 0x00000001 |
   0x00000002 |
   0x00000010 |
   0x00000020 |
   0x00000080 |
   0x00000100 |
   0x00000200 |
   0x00004000
 = INFO_MOUSE |
   INFO_DISABLECTRLALTDEL |
   INFO_UNICODE |
   INFO_MAXIMIZESHELL |
   INFO_COMPRESSION |
   INFO_ENABLEWINDOWSKEY |
   PACKET_COMPR_TYPE_64K << 9 |
   INFO_FORCE_ENCRYPTED_CS_PDU

 0a 00 -> TS_INFO_PACKET::cbDomain = 0x0a = 10 bytes (not including
 the size of the mandatory NULL terminator)
 0c 00 -> TS_INFO_PACKET::cbUserName = 0x0c = 12 bytes (not including
 the size of the mandatory NULL terminator)
 00 00 -> TS_INFO_PACKET::cbPassword = 0 bytes
 00 00 -> TS_INFO_PACKET::cbAlternateShell = 0 bytes
 00 00 -> TS_INFO_PACKET::cbWorkingDir = 0 bytes

 4e 00 54 00 44 00 45 00 56 00 00 00 -> TS_INFO_PACKET::Domain = "NTDEV"
 65 00 6c 00 74 00 6f 00 6e 00 73 00 00 00 ->
 TS_INFO_PACKET::UserName = "eltons"
 00 00 -> TS_INFO_PACKET::Password = ""
 00 00 -> TS_INFO_PACKET::AlternateShell = ""
 00 00 -> TS_INFO_PACKET::WorkingDir = ""

 02 00 -> TS_EXTENDED_INFO_PACKET::clientAddressFamily = AF_INET (2)
 1e 00 -> TS_EXTENDED_INFO_PACKET::cbClientAddress = 0x1e = 30 bytes
 (including the size of the mandatory NULL terminator)

 31 00 35 00 37 00 2e 00 35 00 39 00 2e 00 32 00
 34 00 32 00 2e 00 31 00 35 00 36 00 00 00 ->
 TS_EXTENDED_INFO_PACKET::clientAddress = "157.59.242.156"

 84 00 -> TS_EXTENDED_INFO_PACKET::cbClientDir = 0x84 = 132 bytes (including the size of the mandatory NULL terminator)

 43 00 3a 00 5c 00 64 00 65 00 70 00 6f 00 74 00
 73 00 5c 00 77 00 32 00 6b 00 33 00 5f 00 31 00
 5c 00 74 00 65 00 72 00 6d 00 73 00 72 00 76 00
 5c 00 6e 00 65 00 77 00 63 00 6c 00 69 00 65 00
 6e 00 74 00 5c 00 6c 00 69 00 62 00 5c 00 77 00
 69 00 6e 00 33 00 32 00 5c 00 6f 00 62 00 6a 00
 5c 00 69 00 33 00 38 00 36 00 5c 00 6d 00 73 00
 74 00 73 00 63 00 61 00 78 00 2e 00 64 00 6c 00
 6c 00 00 00 -> TS_EXTENDED_INFO_PACKET::clientDir =
 "C:\depots\w2k3_1\termsrv\newclient\lib\win32\obj\i386\mstscax.dll"

 e0 01 00 00 -> TS_TIME_ZONE_INFORMATION::Bias = 0x01e0 = 480 mins = 8 hrs

 50 00 61 00 63 00 69 00 66 00 69 00 63 00 20 00
 53 00 74 00 61 00 6e 00 64 00 61 00 72 00 64 00
 20 00 54 00 69 00 6d 00 65 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ->
 TS_TIME_ZONE_INFORMATION::StandardName = "Pacific Standard Time"

 00 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wYear = 0
 0a 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wMonth = 0x0a =
 October (10)
 00 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wDayOfWeek = Sunday (0)
 05 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wDay = 5 (last Sunday)
 02 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wHour = 2am
 00 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wMinute = 0
 00 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wSecond = 0
 00 00 -> TS_TIME_ZONE_INFORMATION::StandardDate::wMilliseconds = 0

 00 00 00 00 -> TS_TIME_ZONE_INFORMATION::StandardBias = 0

 50 00 61 00 63 00 69 00 66 00 69 00 63 00 20 00
 44 00 61 00 79 00 6c 00 69 00 67 00 68 00 74 00
 20 00 54 00 69 00 6d 00 65 00 00 00 00 00 00 00
 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ->
 TS_TIME_ZONE_INFORMATION::DaylightName = "Pacific Daylight Time"

 00 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wYear = 0
 04 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wMonth = April (4)
 00 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wDayOfWeek = Sunday (0)
 01 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wDay = 1 (first Sunday)
 02 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wHour = 2am
 00 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wMinute = 0
 00 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wSecond = 0
 00 00 -> TS_TIME_ZONE_INFORMATION::DaylightDate::wMilliseconds = 0

 c4 ff ff ff -> TS_TIME_ZONE_INFORMATION::DaylightBias = 0xffffffc4 =
 -60 (two's complement)

 00 00 00 00 -> TS_EXTENDED_INFO_PACKET::clientSessionId = 0
 01 00 00 00 -> TS_EXTENDED_INFO_PACKET::performanceFlags = 0x01 =
 TS_PERF_DISABLE_WALLPAPER
 00 00 -> TS_EXTENDED_INFO_PACKET:: cbAutoReconnectCookie = 0
```

自洽检查（逐段累加，均以 `INFO_UNICODE` 置位、UTF-16LE 2 字节终止符为前提）：

| 段 | 字节数 | 累计 |
|---|---|---|
| 固定头 `CodePage..cbWorkingDir`（4+4+2×5） | 18 | 18 |
| `Domain`（`cbDomain` 10 + NULL 2） | 12 | 30 |
| `UserName`（`cbUserName` 12 + NULL 2） | 14 | 44 |
| `Password`（0 + 2） | 2 | 46 |
| `AlternateShell`（0 + 2） | 2 | 48 |
| `WorkingDir`（0 + 2） | 2 | 50 |
| `clientAddressFamily` + `cbClientAddress` | 4 | 54 |
| `clientAddress`（30，含 NULL） | 30 | 84 |
| `cbClientDir` | 2 | 86 |
| `clientDir`（132，含 NULL） | 132 | 218 |
| `clientTimeZone` | 172 | 390 |
| `clientSessionId` | 4 | 394 |
| `performanceFlags` | 4 | 398 |
| `cbAutoReconnectCookie` | 2 | **400** |

→ 400 字节 ✔（与 `TS_INFO_PACKET` 总长、`userData` 里密文长度一致）。

### 12.7 Disconnect Provider Ultimatum（S99，9 字节）

```
 00000000 03 00 00 09 02 f0 80 21 80
```

```
 03 00 00 09 -> TPKT Header (length = 9 bytes)
 02 f0 80 -> X.224 Data TPDU

 PER encoded (ALIGNED variant of BASIC-PER) PDU contents:
 21 80

 0x21:
 0 - --\
 0 -   |
 1 -   | CHOICE: From DomainMCSPDU select disconnectProviderUltimatum (8)
 0 -   | of type DisconnectProviderUltimatum
 0 -   |
 0 - --/
 0 - --\
 1 -   |
       | DisconnectProviderUltimatum::reason = rn-user-requested (3)
 0x80: |
 1 - --/
 0 - padding
 0 - padding
 0 - padding
 0 - padding
 0 - padding
 0 - padding
 0 - padding
```

自洽检查：总长 9 字节；TPKT `length = 0x0009` = 9 ✔；`4 + 3 + 2 = 9` ✔。

### 12.8 独立 PER 编码器交叉验证（红/绿）

为避免"只抄录不理解"，本文件另用独立实现的 ALIGNED-PER 编码器（仅依据 X.691 §10.5.7.1 /
§10.5.7.3 / §10.9.3.6 / §10.9.3.7 / §15.9 / §18.2 / §22.6 与 T.125 §7 的 ASN.1）重新生成上述
全部 PDU，并与规范字节图逐字节比对：

| 生成的 PDU | 参数 | 编码器输出 | 规范 dump | 一致 |
|---|---|---|---|---|
| AttachUserRequest | — | `28` | `28` | ✔ |
| ErectDomainRequest | subHeight=0, subInterval=0 | `04 01 00 01 00` | `04 01 00 01 00` | ✔ |
| AttachUserConfirm | result=0, initiator=1007 | `2e 00 00 06` | `2e 00 00 06` | ✔ |
| ChannelJoinRequest | initiator=1007, channel=1007 | `38 00 06 03 ef` | `38 00 06 03 ef` | ✔ |
| ChannelJoinRequest | initiator=1007, channel=1003 | `38 00 06 03 eb` | `38 00 06 03 eb` | ✔ |
| ChannelJoinConfirm | 0, 1007, 1007, 1007 | `3e 00 00 06 03 ef 03 ef` | `3e 00 00 06 03 ef 03 ef` | ✔ |
| ChannelJoinConfirm | 0, 1007, 1006, 1006 | `3e 00 00 06 03 ee 03 ee` | `3e 00 00 06 03 ee 03 ee` | ✔ |
| DisconnectProviderUltimatum | reason=3 | `21 80` | `21 80` | ✔ |
| SendDataRequest | 1007, 1003, high, begin+end, 80 B | `64 00 06 03 eb 70 50`（+80 B 载荷） | `64 00 06 03 eb 70 50` | ✔ |
| SendDataRequest | 1007, 1003, high, begin+end, 412 B | `64 00 06 03 eb 70 81 9c`（+412 B） | `64 00 06 03 eb 70 81 9c` | ✔ |
| SendDataIndication | 1002, 1003, high, begin+end, 371 B | `68 00 01 03 eb 70 81 73`（+371 B） | `68 00 01 03 eb 70 81 73` | ✔ |

结论：本文件对 PER 位域、`UserId` 的 `−1001` 偏移、`ChannelId` 的无偏移、`userData` 长度
决定因子三种形态的解释，均可**从规范字节图反向复现**，不是猜测。

另外验证了几条**未在官方 dump 中出现**的路径（用于确认 §6.3 与 §14.2 的推导）：

| 生成的 PDU | 参数 | 编码器输出 |
|---|---|---|
| ChannelJoinConfirm | result=0, initiator=1007, requested=1007, `channelId` **缺失** | `3c 00 00 06 03 ef`（`mcsCJcf` 5 字节） |
| AttachUserConfirm | result=14, `initiator` **缺失** | `2d c0`（`mcsAUcf` 2 字节） |
| ChannelJoinConfirm | result=14, `channelId` present | `3f c0 00 06 03 ef 03 ef` |
| ChannelJoinConfirm | result=14, `channelId` **缺失** | `3d c0 00 06 03 ef` |

读法说明：
- `channelId` 缺失 → 首字节从 `0x3E` 变为 `0x3C`，PDU 比正常形态短 2 字节，与 §6.3 的推导一致。
- `result=14` → `result` 位域变为 `1110`，使首字节低位变化：`0x2E→ 0x2D`（AUcf，因 `initiator` 缺失而更短）、`0x3E→ 0x3F`（CJcf 带 channelId）、`0x3C→ 0x3D`（CJcf 无 channelId）。
- 上述四行**均未与官方字节图核对**（官方无失败形态 dump），仅作为编码器自一致性证据。

---

## 13. 任务前提修正（必须记录）

| # | 任务提示的说法 | 规范原文事实 | 依据 |
|---|---|---|---|
| 1 | "2.2.2.1 (MCS Send Data Request / Indication 封装) 与 2.2.2.2（Fast-Path 相关若在此）" | 当前 [MS-RDPBCGR] 2.2.2.1 = **Client Shutdown Request PDU**；2.2.2.2 = **Server Shutdown Request Denied PDU**；2.2.2.3 = MCS Disconnect Provider Ultimatum。Send Data 封装规则在 **3.2.5.1**（客户端侧）与 **3.3.5.1**（服务器侧）；Fast-Path 在 **2.2.8.1.2** / **2.2.9.1.2** | S15 / S16 / S17 / S31 / S47 / S23 / S24 |
| 2 | "用户通道 1002、I/O 通道 1003、各虚拟通道 1004+" | **1002 是 Server Channel，固定 `0x03EA`**（server→client SDin 的 `initiator`）；**用户通道由 Attach User Confirm 分配**，dump 中是 **1007**；I/O = 1003、静态 VC = 1004/1005/1006 只是本 dump 的取值，规范只要求它们来自 Server Network Data 的 `MCSChannelId` / `channelIdArray` | S70 / S71 / S83 / S84 / S29 / S47 |
| 3 | 2.2.1.10 GUID `9cde84cd-5055-475a-acb0-9a0f8d9c1c4c` | 该 GUID 返回 **404**；正确 GUID 为 `9cde84cd-5055-475a-ac8b-704db419b66f` | §0.2 |
| 4 | "3.2.5.4 / 3.2.5.5 / 3.2.5.6（发送侧时序与取值）" | 这 3 个小节是 **Disconnection / Deactivation-Reconnection / Auto-Reconnect**，**不含**通道建立阶段时序。通道建立时序在 **3.2.5.3.5–3.2.5.3.11** | S33–S39 / S40–S46 |
| 5 | "3.3.5.4 / 3.3.5.5 / 3.3.5.6（处理侧规则）" | 同上，这 3 个小节是断开/去激活/自动重连；通道建立处理规则在 **3.3.5.3.5–3.3.5.3.11** | S49–S55 / S56–S62 |
| 6 | "`TS_EXTENDED_INFO` 与 `TS_LOGON_INFO` 结构"（列在 Client Info 下） | `TS_LOGON_INFO` / `TS_LOGON_INFO_VERSION_2` 是 **Save Session Info PDU（server→client，2.2.10.1）** 的载荷，**不在** Client Info PDU（client→server）里。已在 §10.8 单独给出结构与澄清 | S25 / S26 / S27 / S110 |

---

## 14. 未验证项

### 14.1 抓取失败 / 未获取原文的 URL

| URL | HTTP 状态 | 说明 |
|---|---|---|
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9cde84cd-5055-475a-acb0-9a0f8d9c1c4c | 404 | 任务给的 GUID 有误；已用正确 GUID 替代（S7） |
| https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9e9c9e29-9cd5-4b4c-a8e9-7e3c9e0b3c1a | 404 | 猜测的 CredSSP GUID；已用 S107 替代 |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.123-199602-I!!PDF-E&type=items | 200（实为 HTML 错误页，9,125 B） | T.123 (10/96) 版本不存在；改用 T.123 (01/2007)（S105） |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-T.123-199602-S!!PDF-E&type=items | 200（实为 HTML 错误页） | 同上 |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.224-199411-I!!PDF-E&type=items | 200（实为 HTML 错误页） | X.224 (11/94) 版本不存在；改用 X.224 (11/95)（S106） |
| https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.224-199411-S!!PDF-E&type=items | 200（实为 HTML 错误页） | 同上 |
| https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-RDPBCGR/%5bMS-RDPBCGR%5d.pdf | **308** Permanent Redirect | 已跟随到 S102，200 |

### 14.2 内容层面的未验证项（明确标注为推导或无法验证）

| # | 项 | 状态 | 原因 |
|---|---|---|---|
| 1 | `AttachUserConfirm` 失败形态（`result=14`、`initiator` 缺失）的线上字节 | **未获取原文 dump** | 官方 §4.1.7 只给了成功形态。本文件 §4.2 的"`result=14` 且 `initiator` 缺失"来自 S51 的 MUST 文本，**无字节级测试向量**。若按本文件编码规则推导，`mcsAUcf` 应为 2 字节 `2d c0`（位序：`001011`(choice 11) + `0`(initiator absent) + `1110`(result 14) = 11 bit，补齐为 `0010 1101 1100 0000`）——**该推导值已用 §12.8 的独立编码器算出，但未与任何官方字节图核对** |
| 2 | `ChannelJoinConfirm` 失败形态（`result=14`）的线上字节 | **未获取原文 dump** | 同上；S53 只给规则，无 dump。推导值（§12.8 编码器）：`result=14 + channelId 存在` → `3f c0 00 06 03 ef 03 ef`；`result=14 + channelId 缺失` → `3d c0 00 06 03 ef`，均**未与官方字节图核对** |
| 3 | `ChannelJoinConfirm` 中 `channelId` **缺失**时的字节 | **仅推导**（§6.3 / §12.8） | 官方无此 dump；RDP 要求 MUST 存在，故实际不会出现 |
| 4 | `segmentation` 的 begin/end 具体位归属（bit6=begin、bit5=end） | **仅推导** | S97 原文只标注合成值 `0x03 = begin|end`，未逐位指认。推导依据 X.691 §15.5 + §15.9 |
| 5 | `subHeight` / `subInterval` 的半约束整数编码（长度因子 `01` + 值 `00`） | **仅推导** | 官方 dump 的注解只说 "length = 1 byte" 与 "= 0"，未引用 X.691 §10.7。推导依据 X.691 §10.7 |
| 6 | `TS_TIME_ZONE_INFORMATION` 各字段偏移（0/4/68/84/88/152/168） | **仅推导** | S13 只给字段顺序与大小，无偏移列；偏移由累加得出，与 §12.6.2 dump 的逐字段注解一致 |
| 7 | S17 声明 `mcsDPum (8 bytes)` 与 dump 实测 2 字节冲突 | **规范内部不一致，已记录** | §8.1；以 dump 与 T.125 结构（`reason` 仅 3 bit）为准 |
| 8 | S69 声明 UserId 范围 `1001..65536` 与 T.125 `1001..65535` 冲突 | **规范内部不一致，已记录** | §4.5；取 T.125 |
| 9 | TPKT octet2（reserved）在 RDP 中的取值 | **由 dump 确认，非规范正文** | T.123 §8 只说 "reserved for further study"，未规定必须为 0；RDP 全部 dump 实测为 `0x00` |
| 10 | `AttachUserRequest` 的 "客户端 UserId 语义" | 部分未验证 | T.125 §11.17 只说 id 由顶层 provider 生成、唯一性是其唯一初始特征；**没有**"客户端建议 id"的机制。本文已按原文陈述，未扩展 |
| 11 | Fast-Path 与 NLA 的具体交互（何时切换） | **未获取原文** | 本文只验证到"Fast-Path 替换 TPKT/X.224/MCS"（S23/S24）与"通道建立阶段全程慢路径"；Fast-Path 启用时机的完整规则在 3.2.5.8.1.2 / 3.3.5.8.1.2 等小节，本次未抓取 |
| 12 | `TS_EXTENDED_INFO_PACKET` 之后是否还有字段 | 已验证为"无" | S12 的字段表以 `dynamicDaylightTimeDisabled` 结束，且 dump（§12.6.2）在 `cbAutoReconnectCookie = 0` 处正好结束，二者一致 |

### 14.3 未抓取（任务未要求，明确声明）

- [MS-CSSP] 原文（CredSSP 细节）——本文件只用到"CredSSP 属 External Security Protocol"这一点
  （S107 / S108）。
- [MS-RDPELE]（Licensing）、[MS-RDPERP]、[MS-RDPEA] 等——仅作为交叉引用出现，未抓取原文。
- T.125 §8（Version 3 MCSPDU）与 §13（协议版本互操作）——本文件只用 §7 / §9 / §11，
  Version 3 仅用于说明 `DataPriority` 定义差异。
- X.691 §16（octetstring）之外的类型编码细节——本文件用到的规则见 §1.3。

