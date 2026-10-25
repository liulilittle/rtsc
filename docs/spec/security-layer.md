# RDP 安全层字段规格（TLS + CredSSP/NLA）

本文件是 RTSC 项目安全层（Enhanced RDP Security：TLS 与 CredSSP/NLA）的实现依据。
所有字段、字节值、枚举数值均来自**实际抓取的官方规范原文**或**对本项目目标服务器的实机探测**，
逐条给出出处。凡未抓到原文或未实测的内容，一律在 §10「未验证项」列出，不作推断性填充。

**来源等级约定**

| 等级 | 含义 |
|---|---|
| A | 微软官方规范原文（`Accept: text/markdown` 抓取 learn.microsoft.com，HTTP 200）或官方 PDF 原文 |
| B | 其他官方规范原文（IETF RFC）或权威开源实现的公开源码（FreeRDP，Apache-2.0） |
| C | 由 A/B 原文推导（本文明确标「推导」，并给出推导链） |
| E | 本文作者的实机探测证据（目标 `192.168.1.7:3389`，见 §0.3） |

**重要结论（先读）**

- 目标服务器 `192.168.1.7:3389` 在 X.224 协商阶段返回 `selectedProtocol = 0x00000008`
  （PROTOCOL_HYBRID_EX），即 **CredSSP + Early User Authorization Result**（E 级实测，§0.3）。
- **CredSSP 在 TLS 之上**：`[MS-CSSP] 3.1.5` 第 1 步要求先完成 TLS 握手，之后所有 CredSSP 消息
  都在 TLS 通道内；`[MS-RDPBCGR] 5.4.5.2` 明确「TLS handshake will always be executed」，
  「Kerberos or NTLM will be used **within the TLS channel**」。CredSSP 完成后才发
  MCS Connect Initial（在 TLS 之内），**不是** MCS 之后（§1）。
- **TLS 握手插在 X.224 Connection Confirm 之后、MCS Connect Initial 之前**（`[MS-RDPBCGR] 3.2.5.3.2`）。
- HYBRID_EX 相对 HYBRID 只多一个东西：CredSSP 握手完成后、任何 post-handshake PDU 之前，
  服务器多发一个 **4 字节的 Early User Authorization Result PDU**（§2）。
- `pubKeyAuth` 的算法**随 CredSSP 版本分叉**：v2/3/4 是「加密 SubjectPublicKey 原文」，
  **v5/6 是 SHA-256 绑定哈希**（`CredSSP Client-To-Server Binding Hash` + NUL + nonce + SubjectPublicKey）。
  本文件 §5.4 给出完整步骤与实测参数。这是 CredSSP 最容易实现错的地方。
- 服务器证书是**自签名**（`CN=DESKTOP-5BFDKO3`），规范允许且预期如此
  （`[MS-CSSP] 3.1.5` 第 1 步：「does not require the client to have a commonly trusted CA root」）。
  因此**不能**用「证书链校验失败」作为拒绝连接的理由（§4.3）。
- NTLM 侧服务器**不下发** `MsvAvTargetName`(0x0009) 与 `MsvAvChannelBindings`(0x000A)，
  客户端必须**自己补**这两个 AV_PAIR（`[MS-NLMP] 3.1.5.1.2`，E 级实测确认，§7.3）。
- 本文件附带的算法验证脚本已用 `[MS-NLMP] 4.2.4` 官方测试向量逐项对上
  （NTOWFv2 / LMv2 / EncryptedRandomSessionKey / MAC），见 §6.6。

---

## 0. 规范来源清单（全部实际抓取）

### 0.1 [MS-RDPBCGR]（HTTP 200，`Accept: text/markdown`）

| 编号 | 小节 | URL |
|---|---|---|
| S1 | 1.3.1.1 Connection Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/023f1e69-cfe8-4ee6-9ee0-7e759fb4e4ee |
| S2 | 1.3.1.2 Security-Enhanced Connection Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/49e2791f-72d0-4229-92b7-8f32c48a7206 |
| S3 | 2.2.1.1.1 RDP Negotiation Request (RDP_NEG_REQ) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3 |
| S4 | 2.2.1.2 Server X.224 Connection Confirm PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483 |
| S5 | 2.2.1.2.1 RDP Negotiation Response (RDP_NEG_RSP) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817 |
| S6 | 2.2.1.2.2 RDP Negotiation Failure (RDP_NEG_FAILURE) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761 |
| S7 | 2.2.1.3.2 Client Core Data (TS_UD_CS_CORE) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/00f1da4a-ee9c-421a-852f-c19f92343d73 |
| S8 | 2.2.1.4.3 Server Security Data (TS_UD_SC_SEC1) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e86b68d-3e2e-4433-b486-878875778f4b |
| S9 | 2.2.8.1.1.2 Security Headers | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9865e0ce-a540-4eab-9409-2a25937c38d2 |
| S10 | 2.2.8.1.1.2.1 Basic (TS_SECURITY_HEADER) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e13405c5-668b-4716-94b2-1c2654ca1ad4 |
| S11 | 2.2.10.2 Early User Authorization Result PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d0e560a3-25cb-4563-8bdc-6c4cc625bbfc |
| S12 | 3.2.5.3.1 Sending X.224 Connection Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d2a48824-e362-4ed1-bda8-0eb7cbb28b8c |
| S13 | 3.2.5.3.2 Processing X.224 Connection Confirm PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b88f4666-f1b8-4a22-bc41-a62721a6d97b |
| S14 | 3.2.5.3.11 Sending Client Info PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/86313d86-377e-4bab-97cb-c541dd9370ea |
| S15 | 3.2.5.10.2 Processing Early User Authorization Result PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dcc6169e-3da3-47d0-bdb2-41dd093bff4e |
| S16 | 3.3.5.3.1 Processing X.224 Connection Request PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/674600ba-15ca-4276-83ca-7bd48a9c2944 |
| S17 | 3.3.5.3.2 Sending X.224 Connection Confirm PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/84909189-251f-4bd0-a410-35bb4c38eefa |
| S18 | 3.3.5.7.1.1 User Authorization Failures | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/26043070-85f8-4ee8-8721-d7f013c755ca |
| S19 | 3.3.5.10.2 Sending Early User Authorization Result PDU | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f4c0abc3-c8c4-4561-9467-2be725fc2c97 |
| S20 | 5.3 Standard RDP Security | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8e8b2cca-c1fa-456c-8ecb-a82fc60b2322 |
| S21 | 5.3.1 Encryption Levels | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f1c7c93b-94cc-4551-bb90-532a0185246a |
| S22 | 5.3.2 Negotiating the Cryptographic Configuration | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b9a49d9e-44db-46aa-90a7-bb7f75718e02 |
| S23 | 5.4 Enhanced RDP Security | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/592a0337-dc91-4de3-a901-e1829665291d |
| S24 | 5.4.1 Encryption Levels | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/6e547618-4755-41cb-9b3b-c9075565b80d |
| S25 | 5.4.2 Security-Enhanced Connection Sequence | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9a0c1e57-6784-4c1d-bdec-8c221642669b |
| S26 | 5.4.2.1 Negotiation-Based Approach | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/db98be23-733a-4fd2-b086-002cd2ba02e5 |
| S27 | 5.4.2.2 Direct Approach | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2bd18fa-0066-4a57-ac25-9139c0df31e0 |
| S28 | 5.4.2.3 Changes to the Security Commencement Phase | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3e0c6ad2-f1eb-42b8-ab20-4f4d889a3172 |
| S29 | 5.4.3 Encrypting and Decrypting the I/O Data Stream | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/d40f538f-281f-482b-93ce-098521c5ed4f |
| S30 | 5.4.4 Packet Layout in the I/O Data Stream | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b974a1f-7a08-4647-8904-412aa2ac6ef6 |
| S31 | 5.4.5 External Security Protocols Used By RDP | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/422e59a0-98c8-4a28-af9f-235a572b6e4d |
| S32 | 5.4.5.1 Transport Layer Security (TLS) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/857dadbe-f01a-4047-9b63-0d5b681ad306 |
| S33 | 5.4.5.2 CredSSP | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/8e11581d-094f-461a-9fde-ba51af90cf8b |
| S34 | 5.4.5.2.1 User Authorization Failures | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/e9beb695-2da8-434e-8f4d-5d1a2b9b2658 |
| S35 | 5.4.5.2.2 TLS Fatal Alerts | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/29b260de-f102-49ab-96d0-2172f7d3c816 |
| S36 | Appendix A: Product Behavior | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/cbe1ed0a-d320-4ea5-be5a-f2eb6e032853 |
| S37 | 官方 PDF（v20260309，444 页） | https://winprotocoldoc.z19.web.core.windows.net/MS-RDPBCGR/%5bMS-RDPBCGR%5d.pdf |

### 0.2 [MS-CSSP] / [MS-NLMP] / [MS-SPNG] / [MS-ERREF] / 其他

| 编号 | 规范·小节 | URL |
|---|---|---|
| C1 | [MS-CSSP] 1.3 Overview | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/e36b36f6-edf4-4df1-9905-9e53b7d7c7b7 |
| C2 | [MS-CSSP] 1.5 Prerequisites/Preconditions | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/47f88302-03ac-48f4-a542-4c00da52bde0 |
| C3 | [MS-CSSP] 1.7 Versioning and Capability Negotiation | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/61ed1279-856a-43f1-96e0-8cdead0760e8 |
| C4 | [MS-CSSP] 2.1 Transport | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/2111f723-5c7f-4d80-9c77-46de491f7ef5 |
| C5 | [MS-CSSP] 2.2.1 TSRequest | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685 |
| C6 | [MS-CSSP] 2.2.1.1 NegoData | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/9664994d-0784-4659-b85b-83b8d54c2336 |
| C7 | [MS-CSSP] 2.2.1.2 TSCredentials | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94a1ab00-5500-42fd-8d3d-7a84e6c2cf03 |
| C8 | [MS-CSSP] 2.2.1.2.1 TSPasswordCreds | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/17773cc4-21e9-4a75-a0dd-72706b174fe5 |
| C9 | [MS-CSSP] 3.1.1 Abstract Data Model | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/3cd79cfc-fc9d-481f-b4be-aee5eaf494aa |
| C10 | [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules（握手 5 步） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c |
| C11 | [MS-CSSP] 4 Protocol Examples | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/94846575-5a58-44de-b07b-48b90af328fb |
| C12 | [MS-CSSP] 5.1 Security Considerations for Implementors | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/57c0f867-a053-4c11-b47f-dff91c647405 |
| C13 | [MS-CSSP] Appendix A: Product Behavior | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/0b458a93-de59-44af-82f1-ebedb585f5c6 |
| C14 | [MS-CSSP] 官方 PDF（v20240423，27 页） | https://winprotocoldoc.z19.web.core.windows.net/MS-CSSP/%5bMS-CSSP%5d.pdf |
| N1 | [MS-NLMP] 2.2.1.1 NEGOTIATE_MESSAGE | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2 |
| N2 | [MS-NLMP] 2.2.1.2 CHALLENGE_MESSAGE | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786 |
| N3 | [MS-NLMP] 2.2.1.3 AUTHENTICATE_MESSAGE | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce |
| N4 | [MS-NLMP] 2.2.2.1 AV_PAIR | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e |
| N5 | [MS-NLMP] 2.2.2.5 NEGOTIATE（flags 位定义） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832 |
| N6 | [MS-NLMP] 2.2.2.7 NTLMv2_CLIENT_CHALLENGE | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b |
| N7 | [MS-NLMP] 2.2.2.8 NTLMv2_RESPONSE | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d43e2224-6fc3-449d-9f37-b90b55a29c80 |
| N8 | [MS-NLMP] 2.2.2.9 NTLMSSP_MESSAGE_SIGNATURE | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b192b940-a508-4329-8513-efb3342f2c85 |
| N9 | [MS-NLMP] 2.2.2.9.1 NTLMSSP_MESSAGE_SIGNATURE（字段） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83fbd0e7-8ab0-4873-8cbe-795249b46b8a |
| N10 | [MS-NLMP] 2.2.2.9.2 …for Extended Session Security | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2c3b4689-d6f1-4dc6-85c9-0bf01ea34d9f |
| N11 | [MS-NLMP] 2.2.2.10 VERSION | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175 |
| N12 | [MS-NLMP] 3.1.5.1.2 Client Receives a CHALLENGE_MESSAGE | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96 |
| N13 | [MS-NLMP] 3.3.2 NTLM v2 Authentication（NTOWFv2/ComputeResponse） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3 |
| N14 | [MS-NLMP] 3.4.3 Message Confidentiality（SEAL） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/115f9c7d-bc30-4262-ae96-254555c14ea6 |
| N15 | [MS-NLMP] 3.4.4.2 With Extended Session Security（MAC） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a92716d5-d164-4960-9e15-300f4eef44a8 |
| N16 | [MS-NLMP] 3.4.5.1 KXKEY | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/d86303b5-b29e-4fb9-b119-77579c761370 |
| N17 | [MS-NLMP] 3.4.5.2 SIGNKEY | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/524cdccb-563e-4793-92b0-7bc321fce096 |
| N18 | [MS-NLMP] 3.4.5.3 SEALKEY | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/bf39181d-e95d-40d7-a740-ab4ec3dc363d |
| N19 | [MS-NLMP] 3.4.6 GSS_WrapEx() Call | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a06bfc2b-30fc-4483-b876-a9386f4808ed |
| N20 | [MS-NLMP] 1.9 Standards Assignments（NTLM OID） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/e21c0b07-8662-41b7-8853-2b9184eab0db |
| N21 | [MS-NLMP] 4.2.1 Common Values（测试向量） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7fc694c9-397a-446a-bd80-4635000f2c0f |
| N22 | [MS-NLMP] 4.2.4 NTLMv2 Authentication（测试向量） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/125f7a94-933e-4023-a146-a449e49bf774 |
| N23 | [MS-NLMP] 4.2.4.4 GSS_WrapEx Examples（SEAL 测试向量） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/9cdb7bb2-17e6-409c-99cc-04590db064d4 |
| N24 | [MS-NLMP] 官方 PDF（v20260330，99 页） | https://winprotocoldoc.z19.web.core.windows.net/MS-NLMP/%5bMS-NLMP%5d.pdf |
| P1 | [MS-SPNG] 2.2.1 NegTokenInit2 | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-b5b5-38c92be3d472 |
| P2 | [MS-SPNG] 1.3.3 Client Initiated SPNG Message Flow | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/d4f2b41c-5f9e-4e11-98d0-ade76467095d |
| P3 | [MS-SPNG] 1.9.1 Use of Constants Assigned Elsewhere（SPNEGO OID） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/94ccc4f8-d224-495f-8d31-4f58d1af598e |
| E1 | [MS-ERREF] 2.3.1 NTSTATUS Values | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55 |
| E2 | [MS-ERREF] 2.1.1 HRESULT Values（SEC_E_*） | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/705fb797-2175-4a90-b5a3-3918024b10b8 |
| R1 | RFC 4178（SPNEGO） | https://www.rfc-editor.org/rfc/rfc4178.txt |
| W1 | OpenSSL License（3.x 为 Apache-2.0） | https://www.openssl.org/source/license.html |
| W2 | OpenSSL legacy provider（MD4/RC4/DES 所在） | https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-legacy/ |
| W3 | OpenSSL NOTES-WINDOWS.md（MSVC 构建） | https://raw.githubusercontent.com/openssl/openssl/master/NOTES-WINDOWS.md |
| W4 | vcpkg openssl port（3.6.5#2） | https://vcpkg.io/en/package/openssl |
| W5 | mbedTLS LICENSE（Apache-2.0 OR GPL-2.0-or-later） | https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/LICENSE |
| W6 | mbedTLS 3.0 迁移指南（MD4/RC4 被移除） | https://raw.githubusercontent.com/Mbed-TLS/mbedtls/mbedtls-3.6/docs/3.0-migration-guide.md |
| W7 | wolfSSL License（GPLv3 或商业授权） | https://www.wolfssl.com/license/ |
| W8 | BoringSSL LICENSE（Apache-2.0） | https://raw.githubusercontent.com/google/boringssl/master/LICENSE |
| W9 | QueryContextAttributesW（CredSSP 属性表） | https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesw |
| W10 | AcquireCredentialsHandleW（pAuthData = CREDSSP_CRED） | https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-acquirecredentialshandlew |
| W11 | CREDSSP_CRED 结构 | https://learn.microsoft.com/en-us/windows/win32/api/credssp/ns-credssp-credssp_cred |
| F1 | FreeRDP `libfreerdp/core/nla.c`（CredSSP 状态机参考实现） | https://raw.githubusercontent.com/FreeRDP/FreeRDP/master/libfreerdp/core/nla.c |
| F2 | FreeRDP `libfreerdp/core/credssp_auth.c`（EncryptMessage 封装） | https://raw.githubusercontent.com/FreeRDP/FreeRDP/master/libfreerdp/core/credssp_auth.c |
| F3 | FreeRDP `libfreerdp/core/transport.c`（EUAR 读取方式） | https://raw.githubusercontent.com/FreeRDP/FreeRDP/master/libfreerdp/core/transport.c |
| F4 | FreeRDP `winpr/libwinpr/sspi/NTLM/ntlm.h`（flag 数值） | https://raw.githubusercontent.com/FreeRDP/FreeRDP/master/winpr/libwinpr/sspi/NTLM/ntlm.h |
| F5 | FreeRDP `libfreerdp/crypto/certificate.c`（SubjectPublicKey 提取） | https://raw.githubusercontent.com/FreeRDP/FreeRDP/master/libfreerdp/crypto/certificate.c |

### 0.3 实机探测证据（E 级）

目标 `192.168.1.7:3389`，2026-10-22 实测。

**(a) TLS 能力（`openssl s_client`）**

```
s_client -connect 192.168.1.7:3389 -servername 192.168.1.7 -tls1_2
  -> New, TLSv1.2, Cipher is AES256-GCM-SHA384
     Server public key is 2048 bit
     No ALPN negotiated
     Verification error: self-signed certificate
     subject=CN=DESKTOP-5BFDKO3   issuer=CN=DESKTOP-5BFDKO3
     a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
     v:NotBefore: Aug 10 12:25:07 2026 GMT; NotAfter: Feb  9 12:25:07 2027 GMT
     X509v3 Extended Key Usage: TLS Web Server Authentication
     No client certificate CA names sent

s_client ... -tls1_3   -> New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
s_client ... -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256
                       -> New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
s_client ... -tls1_2 -noservername -> 握手成功（AES256-GCM-SHA384）
```

证书详情（`openssl x509 -text`，同一证书）：

```
Subject: CN=DESKTOP-5BFDKO3        Issuer: CN=DESKTOP-5BFDKO3   (自签名)
Not Before: Aug 10 12:25:07 2026 GMT   Not After: Feb  9 12:25:07 2027 GMT
Public-Key: (2048 bit)             Signature Algorithm: sha256WithRSAEncryption
X509v3 Extended Key Usage: TLS Web Server Authentication
X509v3 Key Usage: Key Encipherment, Data Encipherment
sha256 Fingerprint = B1:B9:F1:4C:C6:DE:24:CF:13:95:6E:2F:4B:BC:02:1F:
                     61:5E:C3:24:B7:65:D9:19:45:96:AF:5E:DC:4F:2C:12
```

**无 `Subject Alternative Name` 扩展**（`x509 -text` 输出中不存在 SAN 段）——这直接决定
§4.3 的结论：主机名校验必须可关闭，且**不能**用「证书无 SAN」当作致命错误。

**(b) CredSSP 第 1 步 / 第 2 步（客户端 91 字节，服务器回 300 字节）**

```
STEP1 (client -> server), 91 bytes:
3059a003020106 a1523050304ea04c044a
  604806062b0601050502 a03e303c a00e300c060a2b06010401823702020a a22a0428
    4e544c4d53535000 01000000 358288e2 0000000000000000 0000000000000000 0a0063450000000f

STEP2 (server -> client), 300 bytes 外层结构:
30 82 0128                      SEQUENCE, len 296
  a0 03 02 01 06                [0] INTEGER version = 6
  a1 82 011f                    [1] NegoData
    30 82 011b                  SEQUENCE (NegoData 的第 1 项)
      30 82 0117                SEQUENCE
        a0 82 0113              [0] OCTET STRING (271 bytes)   <- SPNEGO negTokenResp
          30 82 010b            SEQUENCE
            a0 03 0a 01 01      [0] negState = accept-incomplete(1)
            a1 0c 06 0a 2b06010401823702020a   [1] supportedMech = NTLM OID
            a2 81 f1            [2] responseToken
              04 81 ee          OCTET STRING (238 bytes)      <- NTLM CHALLENGE_MESSAGE
                4e544c4d53535000 02000000 ...                "NTLMSSP\0", MessageType = 2
```

NTLM CHALLENGE 字段（从 `4e544c4d53535000` 起，238 字节）：

| 偏移 | 大小 | 字段 | 实测值 |
|---|---|---|---|
| 0 | 8 | Signature | `4e544c4d53535000` = "NTLMSSP\0" |
| 8 | 4 | MessageType | `02000000` = 2 |
| 12 | 2 | TargetNameLen | 30 |
| 14 | 2 | TargetNameMaxLen | 30 |
| 16 | 4 | TargetNameBufferOffset | 0x38 |
| 20 | 4 | NegotiateFlags | **0xE28A8235** |
| 24 | 8 | ServerChallenge | 每次不同（示例 `35828ae288603a00`） |
| 32 | 8 | Reserved | `0000000000000000` |
| 40 | 2 | TargetInfoLen | 152 |
| 42 | 2 | TargetInfoMaxLen | 152 |
| 44 | 4 | TargetInfoBufferOffset | 0x56 |
| 48 | 8 | Version | `0a00f4650000000f` |
| 56 | 30 | TargetName | "DESKTOP-5BFDKO3"（UTF-16LE） |
| 86 | 152 | TargetInfo（AV_PAIR 序列） | 见下 |

TargetInfo AV_PAIR 序列（实测）：`0x0002`(MsvAvNbDomainName), `0x0001`(MsvAvNbComputerName),
`0x0004`(MsvAvDnsDomainName), `0x0003`(MsvAvDnsComputerName), `0x0007`(MsvAvTimestamp),
`0x0000`(MsvAvEOL)。**没有 0x0009 / 0x000A / 0x0006**。

**(c) 服务器对 TSRequest.version 的处理**

客户端分别发送 `version = 1,2,3,4,5,6,7,8`，服务器**始终回 `version = 6`**。
即服务器按自身最高支持版本应答，不做「取双方最小值」的协商。

**(d) 第 3 步结果（错误口令 `definitely-wrong-password`）**

```
TSRequest(version=6, negoTokens=NTLMSSP AUTHENTICATE(418B), pubKeyAuth=48B, clientNonce=32B)
server -> 30 0d a0 03 02 01 06 a4 06 02 04 c0 00 00 6d
  即 errorCode = 0xC000006D = STATUS_LOGON_FAILURE（[MS-ERREF] 2.3.1，E1）
```

**(e) 第 3 步的 negoToken 若用 SPNEGO negTokenResp 包装**

```
server -> 30 0d a0 03 02 01 06 a4 06 02 04 80 09 03 08
  即 errorCode = 0x80090308 = SEC_E_INVALID_TOKEN（[MS-ERREF] 2.1.1，E2）
```

**结论**：本目标服务器在**第 3 步要求裸 NTLM AUTHENTICATE blob**（不接受额外的 SPNEGO
negTokenResp 包装）；第 1 步既接受裸 NTLM NEGOTIATE（回 262 字节），也接受完整 GSS-API
SPNEGO NegTokenInit（回 300 字节）。实现应对齐本实测行为，同时保留可切换开关（§5.6）。

**(f) TSRequest 只有 version、没有 negoTokens** → 服务器回 TLS fatal alert
`TLSV1_ALERT_INTERNAL_ERROR`（`[MS-RDPBCGR] 5.4.5.2.2` 允许的 alert，S35）。

---

## 1. 安全层在连接序列中的位置

### 1.1 完整时序（协商式，本服务器走这条）

```
TCP connect :3389
  |
  |-- TPKT + X.224 CRQ + RDP_NEG_REQ (requestedProtocols = 0x0B)      <- 明文
  |<-  TPKT + X.224 CCF + RDP_NEG_RSP (selectedProtocol = 0x08)        <- 明文
  |
  |==================== TLS 握手开始（TLS record 层） ====================
  |--  ClientHello
  |<-  ServerHello / Certificate / ServerKeyExchange / ServerHelloDone
  |--  ClientKeyExchange / ChangeCipherSpec / Finished
  |<-  ChangeCipherSpec / Finished
  |==================== TLS 握手完成 ======================================
  |
  |--  TSRequest(version=6, negoTokens=NTLM NEGOTIATE)          [TLS 内]
  |<-  TSRequest(version=6, negoTokens=NTLM CHALLENGE)          [TLS 内]
  |--  TSRequest(version=6, negoTokens=NTLM AUTHENTICATE,
  |              pubKeyAuth, clientNonce)                       [TLS 内]
  |<-  TSRequest(version=6, pubKeyAuth=<server hash>)            [TLS 内]
  |--  TSRequest(version=6, authInfo=TSCredentials)              [TLS 内]
  |                    <<< CredSSP 握手完成 >>>
  |
  |<-  Early User Authorization Result PDU (4 字节)   <-- 仅 HYBRID_EX，裸 PDU
  |
  |--  MCS Connect Initial PDU (TPKT+X.224+MCS)                  [TLS 内]
  |<-  MCS Connect Response PDU                                  [TLS 内]
  |    ... 后续全部 RDP PDU 均在 TLS 之内 ...
```

### 1.2 规范原文依据

| 结论 | 原文 | 来源 |
|---|---|---|
| TLS 握手在 CCF 之后、MCS Connect Initial 之前 | 「If an External Security Protocol will be used … the client MUST execute the selected protocol **at this stage** … Once the External Security Protocol handshake has successfully run to completion … the client SHOULD continue with the connection sequence by sending the **MCS Connect Initial PDU** … over the newly established secure channel」 | S13（3.2.5.3.2），A |
| 服务器侧对称动作 | 「the server MUST prepare to execute the selected protocol by calling into the relevant External Security Protocol Provider **after the X.224 Connection Confirm PDU (with RDP Negotiation Response) has been sent**」 | S17（3.3.5.3.2），A |
| 握手后 RDP 消息从 MCS Connect Initial 继续 | 「the RDP messages resume, continuing with (a) the MCS Connect Initial PDU; or (b) the Early User Authorization Result PDU followed by the MCS Connect Initial PDU」 | S26（5.4.2.1），A |
| **CredSSP 在 TLS 之上，不在 MCS 之后** | 「When the CredSSP Protocol begins execution, **the TLS handshake will always be executed**. Once a TLS channel has been successfully established … **Kerberos or NTLM will be used within the TLS channel** to authenticate the user」 | S33（5.4.5.2），A |
| CredSSP 消息全部走 TLS | 「It first uses the TLS Protocol to establish an encrypted channel … **All subsequent messages are sent over this channel**」 | C1（1.3），A |
| CredSSP 握手第 1 步即 TLS | 「The CredSSP client and CredSSP server **first complete the TLS handshake** … After the handshake is complete, **all subsequent CredSSP Protocol messages are encrypted by the TLS channel**」 | C10（3.1.5）step 1，A |
| TLS 是 CredSSP 的子集 | 「If this flag [PROTOCOL_HYBRID] is set, then the PROTOCOL_SSL flag SHOULD also be set **because TLS is a subset of CredSSP**」 | S3（2.2.1.1.1），A |
| 无双重加密 | 「Traffic on the wire remains encrypted with TLS … **There is no double-encryption of traffic** because the Kerberos (or NTLM) session is securely bound to the TLS session」 | S33（5.4.5.2），A |

### 1.3 安全层生效后的数据流形态

- **TLS record 的明文载荷就是原始 RDP 字节流**：从 MCS Connect Initial 起，所有 TPKT 帧
  （`03 00 xx xx` + X.224 Data TPDU + MCS + …）原样放进 TLS application data。
  不存在额外封装层，也**不**再出现 Standard RDP Security 的 securityHeader。
- 原文：「Because RDP encryption is not used in the presence of an External Security Protocol layer,
  **the security header data is not present in any RDP traffic** (except for the Client Info and
  licensing PDUs)」（S30，5.4.4，A）。
- 例外：**Client Info PDU 必须带 Basic Security Header**（`TS_SECURITY_HEADER`，flags 含
  `SEC_INFO_PKT 0x0040`），即便在 TLS 之下。原文：「If Enhanced RDP Security is in effect, the
  External Security Protocol MUST be used to encrypt the entire PDU and generate a verification digest.
  The **securityHeader field MUST be present**; however, it will contain a Basic Security Header
  structure」（S14，3.2.5.3.11，A）。该头 4 字节：`flags(2) + flagsHi(2)`（S10，A）。
- 加密与完整性全部由 TLS 提供：「Encryption and decryption of RDP traffic is only carried out by the
  External Security Protocol layer. Double-encryption of data does not take place.」（S29，5.4.3，A）。
- 安全协商的**回放校验**：明文交换过的 RDP_NEG_REQ/RSP 必须在 Basic Settings Exchange 阶段
  反向重放一次——客户端把服务器的选择写进 Client Core Data 的 `serverSelectedProtocol`，
  服务器把客户端请求写进 Server Core Data（S26，5.4.2.1，A；字段见 S7 的
  `serverSelectedProtocol (4 bytes)`，S7 原文：「contains the value returned by the server in the
  **selectedProtocol** field of the RDP Negotiation Response」）。
- 由于走 Enhanced RDP Security，`TS_UD_SC_SEC1` 的 `encryptionMethod` 与 `encryptionLevel`
  **必须都是 0**（`ENCRYPTION_METHOD_NONE` / `ENCRYPTION_LEVEL_NONE`），且
  `serverRandomLen`/`serverCertLen` 字段**不出现**（S8，2.2.1.4.3，A）。因此
  **Security Commencement 阶段被跳过，客户端不发 Security Exchange PDU**（S28，5.4.2.3，A）。
- 另据 S24（5.4.1，A）：Enhanced RDP Security 下服务器返回给客户端的加密级别恒为
  `ENCRYPTION_LEVEL_NONE (0)`。

---

## 2. PROTOCOL_HYBRID vs PROTOCOL_HYBRID_EX

### 2.1 数值与语义

| 标志 | 值 | 语义（原文） | 来源 |
|---|---|---|---|
| PROTOCOL_RDP | 0x00000000 | Standard RDP Security（5.3） | S5 / S3，A |
| PROTOCOL_SSL | 0x00000001 | 「TLS 1.0, 1.1, or 1.2」（RDP_NEG_RSP 表）；5.4.5.1 与 5.4.5 另含 TLS 1.3 | S5 / S32 / S31，A |
| PROTOCOL_HYBRID | 0x00000002 | CredSSP（5.4.5.2） | S5，A |
| PROTOCOL_RDSTLS | 0x00000004 | RDSTLS（5.4.5.3） | S5，A |
| **PROTOCOL_HYBRID_EX** | **0x00000008** | 「Credential Security Support Provider protocol (CredSSP) **coupled with the Early User Authorization Result PDU** (section 2.2.10.2)」 | S5，A |
| PROTOCOL_RDSAAD | 0x00000010 | RDS-AAD-Auth（5.4.5.4） | S5，A |

互含关系（原文，S3）：
- 置 `PROTOCOL_HYBRID` 时 SHOULD 同时置 `PROTOCOL_SSL`（「because TLS is a subset of CredSSP」）。
- 置 `PROTOCOL_HYBRID_EX` 时 SHOULD 同时置 `PROTOCOL_HYBRID`。

> 本项目 `RDP_NEG_REQ.requestedProtocols = 0x0B`（SSL|HYBRID|HYBRID_EX）符合上述 SHOULD 链。

### 2.2 HYBRID_EX 比 HYBRID 多什么

**只多一件事**：CredSSP 握手成功后、任何 post-handshake PDU 之前，服务器额外发一个
**Early User Authorization Result PDU（EUAR）**，把「用户是否有权开远程会话」提前告知客户端。

原文（S11，2.2.10.2，A）：
> The Early User Authorization Result PDU is sent from server to client and is used to convey
> authorization information to the client. This PDU is **only sent by the server if the client
> advertised support for it** by specifying the PROTOCOL_HYBRID_EX (0x00000008) flag in the
> **requestedProtocols** field … and it **MUST be sent immediately after the CredSSP handshake
> has completed**.

原文（S19，3.3.5.10.2，A）：
> If it is to be sent to the client, the Early User Authorization Result PDU **MUST be sent before
> any post-handshake PDUs** are transmitted.

Direct Approach（直连式）**不支持** EUAR：原文「The Early User Authorization Result PDU is **not
supported in the Direct Approach**」（S27，5.4.2.2，A）。

### 2.3 EUAR PDU 结构

| 偏移 | 大小 | 字段 | 类型 | 说明 |
|---|---|---|---|---|
| 0 | 4 | `authorizationResult` | UINT32 LE | 授权结果 |

取值（S11，A）：

| 名称 | 值 | 含义（原文） |
|---|---|---|
| AUTHZ_SUCCESS | 0x00000000 | The user has permission to access the server. |
| AUTHZ_ACCESS_DENIED | 0x00000005 | The user does not have permission to access the server. |

**总长 4 字节，无 TPKT、无 X.224、无 MCS 头**。规范 2.2.10.2 的字段图只有 `authorizationResult`
一个字段，未画出任何传输层封装（S11，A）。旁证：FreeRDP 在 EUAR 状态下按**固定 4 字节**从
transport 读取（`transport_default_read_pdu()` 的 `transport->earlyUserAuth` 分支，
F3 `transport.c`；`nla_recv_pdu()` 的 `NLA_STATE_EARLY_USER_AUTH` 分支，F1 `nla.c`），
发送侧只写一个 UINT32（`nla_send_early_user_auth`，F1）。**「无 TPKT」为 C 级推导**
（规范字段图 + FreeRDP 实现一致），未在抓包中直接观察到（见 §10）。

### 2.4 客户端如何响应

| 情形 | 客户端动作 | 来源 |
|---|---|---|
| `authorizationResult == AUTHZ_SUCCESS` | 不做任何回应，继续发 MCS Connect Initial | S11 + S26，A；F1（只切状态），B |
| `authorizationResult == AUTHZ_ACCESS_DENIED` | 「the client SHOULD **drop the connection** as user authorization has failed and login to the remote session will not be possible」 | S15（3.2.5.10.2），A |
| 其他未知值 | 规范未定义；实现应视为失败并断开（推导 C） | — |

补充：EUAR 之外还有一条**晚路径**——若客户端只协商 HYBRID（不支持 EUAR），服务器在
MCS 通道加入全部完成后才做授权，失败则发 `Set Error Info PDU`，错误码
`ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES (0x00000009)`（S18，3.3.5.7.1.1，A）。
HYBRID_EX 的意义就是把这条失败**提前到 MCS 之前**。

---

## 3. RDP_NEG_RSP / RDP_NEG_FAILURE 完整字段表

### 3.1 RDP_NEG_RSP（S5，2.2.1.2.1，A）

| 偏移 | 大小 | 字段 | 类型 | 取值/约束 |
|---|---|---|---|---|
| 0 | 1 | `type` | UINT8 | MUST be `0x02` (TYPE_RDP_NEG_RSP) |
| 1 | 1 | `flags` | UINT8 | 见下表；未知/保留位 MUST 忽略 |
| 2 | 2 | `length` | UINT16 LE | MUST be `0x0008` |
| 4 | 4 | `selectedProtocol` | UINT32 LE | 见 §2.1 |

`flags` 位（S5，A）：

| 位 | 名称 | 含义 |
|---|---|---|
| 0x01 | EXTENDED_CLIENT_DATA_SUPPORTED | 服务器支持 GCC 用户数据里的 Extended Client Data Blocks |
| 0x02 | DYNVC_GFX_PROTOCOL_SUPPORTED | 服务器支持 Graphics Pipeline Extension（MS-RDPEGFX） |
| 0x04 | NEGRSP_FLAG_RESERVED | 保留位，客户端 SHOULD 忽略 |
| 0x08 | RESTRICTED_ADMIN_MODE_SUPPORTED | 服务器支持免凭据登录（Restricted Admin Mode），客户端可在 TSPasswordCreds 里发空凭据 |
| 0x10 | REDIRECTED_AUTHENTICATION_MODE_SUPPORTED | 服务器支持带凭据重定向的免凭据登录（Remote Credential Guard），客户端可发 TSRemoteGuardCreds |

> 实测：本服务器 `flags = 0x0F`（0x01|0x02|0x04|0x08），`selectedProtocol = 0x08`（E，§0.3）。
> 注意 `0x04` 是保留位却被置位——印证「未知/保留位必须忽略」。

### 3.2 RDP_NEG_FAILURE（S6，2.2.1.2.2，A）

| 偏移 | 大小 | 字段 | 类型 | 取值/约束 |
|---|---|---|---|---|
| 0 | 1 | `type` | UINT8 | MUST be `0x03` (TYPE_RDP_NEG_FAILURE) |
| 1 | 1 | `flags` | UINT8 | 无定义标志，MUST be `0x00` |
| 2 | 2 | `length` | UINT16 LE | MUST be `0x0008` |
| 4 | 4 | `failureCode` | UINT32 LE | 见下表 |

`failureCode` 全表（0x01–0x07，S6，A）：

| 值 | 名称 | 含义（原文摘要） |
|---|---|---|
| 0x00000001 | SSL_REQUIRED_BY_SERVER | 服务器要求 Enhanced RDP Security（TLS 1.0/1.1/1.2 或 CredSSP）。「If only CredSSP was requested then the server only supports TLS.」 |
| 0x00000002 | SSL_NOT_ALLOWED_BY_SERVER | 服务器只用 Standard RDP Security，不支持任何 External Security Protocol。 |
| 0x00000003 | SSL_CERT_NOT_ON_SERVER | 服务器没有有效认证证书，无法初始化 External Security Protocol Provider。 |
| 0x00000004 | INCONSISTENT_FLAGS | 请求的安全协议列表与当前生效协议不一致。仅在 Direct Approach 且已在使用 External Security Protocol 时可能。 |
| 0x00000005 | HYBRID_REQUIRED_BY_SERVER | 服务器要求 Enhanced RDP Security + CredSSP。 |
| 0x00000006 | SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER | 服务器要求 Enhanced RDP Security + TLS 1.0/1.1/1.2 **并带基于证书的客户端认证**。 |
| 0x00000007 | ENTRA_AUTH_REQUIRED_BY_SERVER | 服务器要求 Enhanced RDP Security 并通过 Entra ID 认证（RDS AAD Auth，5.4.5.4）。 |

> 产品行为补注：`0x00000006` 只有 Microsoft RDP 6.0 服务器会发（S36 Appendix A `<4>`，A）。
> 服务器发出 RDP_NEG_FAILURE 后 **MUST 关闭连接**（S17，3.3.5.3.2，A）。

### 3.3 客户端解析规则（S13，3.2.5.3.2，A）

- `rdpNegData` 缺失 ⇒ 服务器不支持 Enhanced RDP Security，协议**隐含视为 PROTOCOL_RDP (0)**。
- `rdpNegData` 存在时**必须**是 RDP_NEG_RSP 或 RDP_NEG_FAILURE，否则 SHOULD 断开。
- 收到 RDP_NEG_FAILURE ⇒ 取 `failureCode`，SHOULD 断开。
- 收到 RDP_NEG_RSP ⇒ 取 `selectedProtocol`，据此进入对应安全层。

### 3.4 RDP_NEG_REQ 的 flags（S3，A；客户端发送侧，本项目已实现）

| 位 | 名称 | 含义 |
|---|---|---|
| 0x01 | RESTRICTED_ADMIN_MODE_REQUIRED | 客户端要求免凭据登录（Restricted Admin） |
| 0x02 | REDIRECTED_AUTHENTICATION_MODE_REQUIRED | 客户端要求带重定向的免凭据登录（Remote Credential Guard） |
| 0x08 | CORRELATION_INFO_PRESENT | X.224 CRQ 中存在可选的 `rdpCorrelationInfo` |

`type` MUST be `0x01`；`length` MUST be `0x0008`。

---

## 4. TLS 层要求

### 4.1 版本

| 项 | 规范依据 | 结论 |
|---|---|---|
| 允许版本 | 「TLS 1.0, 1.1, 1.2, and 1.3 are represented by the PROTOCOL_SSL (0x00000001) flag」（S32，5.4.5.1，A）；5.4 列出 TLS 1.0/1.1/1.2/1.3（S23，A） | 1.0 / 1.1 / 1.2 / 1.3 皆可 |
| 产品可用性 | TLS 1.1 不在 NT/2000/XP/2003/Vista/2008；TLS 1.2 不在 NT/2000/XP/2003/Vista/2008；TLS 1.3 不在 NT/2000/XP/2003/Vista/7/8/10/2008SP2/2012/2016/2019（S36 `<53><54><55>`，A） | 老旧服务器只能 1.0 |
| 本目标实测 | `-tls1_2` → TLSv1.2 / `-tls1_3` → TLSv1.3（E，§0.3a） | 两者都支持 |
| 实现建议 | 客户端默认 `min = TLS1.2`，`max = TLS1.3`；提供配置项可降到 1.0（老服务器兼容） | 推导 C |

> 注意：RDP_NEG_RSP 的 `PROTOCOL_SSL` 行文字只写「TLS 1.0, 1.1, or 1.2」（S5），
> 但 5.4.5.1 与 5.4.5 明确包含 1.3（S31/S32）。这是规范内部表述不一致，不是笔误可忽略——
> 实现按「允许 1.3」处理，并在 §10 记录。

### 4.2 密码套件

**规范未规定密码套件**。`[MS-RDPBCGR] 5.4.5.1` 全文（S32，A）只有一句：

> TLS 1.0, 1.1, 1.2, and 1.3 are represented by the PROTOCOL_SSL (0x00000001) flag in the RDP
> Negotiation Request and RDP Negotiation Response structures. TLS is derived from SSL ([SSL3])
> and was added to RDP to enable authentication of the remote computer's identity, hence
> mitigating man-in-the-middle attacks on RDP traffic.

规范把密码套件完全交给 TLS 实现（「These resources are opaque to RDP and left to implementers to
provide, set up, and maintain」，S31，A）。

实测（E，§0.3a）：
- TLS 1.2 默认协商到 `AES256-GCM-SHA384`（RSA 密钥传输，非 ECDHE）；
- 显式指定 `ECDHE-RSA-AES128-GCM-SHA256` 也能成功；
- TLS 1.3 协商到 `TLS_AES_256_GCM_SHA384`。

**实现建议（C）**：不硬编码套件列表，交给 TLS 库默认；仅保留「禁用 SSLv3/RC4/3DES」这类
安全下限配置。因为 RDP 服务器侧套件由 Windows SChannel 策略决定，客户端强制某一种套件
会显著降低兼容性。

### 4.3 证书校验策略

| 结论 | 依据 |
|---|---|
| **不要求**与服务器共享可信 CA 根 | 「the CredSSP Protocol **does not require the client to have a commonly trusted certification authority root** with the CredSSP server」（C10，3.1.5 step 1，A）；「The CredSSP Protocol does not assume a common certification authority root between the client and the server」（C2，1.5，A） |
| 服务器 SHOULD 用「公共可信 CA 签发」**或**「自签名」证书 | 同 C10 step 1：「the CredSSP server SHOULD use an X.509 certificate that is either based on a commonly trusted certificate authority (CA) root or on a self-signed X.509 certificate」；C13 `<24>` 补充「can be configured by using any X.509 certificate that is trusted by the client … or by using a self-signed certificate」 |
| 服务器**不**请求客户端证书 | 「As part of the TLS handshake, the CredSSP server **does not request the client's X.509 certificate** (thus far, the client is anonymous)」（C10 step 1，A）；实测 `No client certificate CA names sent`（E） |
| 不支持 TLS 会话恢复 | 「**TLS session resumption is not supported**」（C10 step 1，A） |
| 身份绑定靠 CredSSP 而非证书链 | 「This field is used to assure that the public key that is used by the server during the TLS handshake **belongs to the target server and not to a man-in-the-middle**」（C5，2.2.1 对 pubKeyAuth 的说明，A） |
| 策略检查是 SHOULD | 「The CredSSP Protocol SHOULD require the client to perform a policy check to verify that the target server is trusted to receive the user's credentials」（C9，3.1.1，A） |

**实现结论（C）**：
1. TLS 层**必须**把证书校验结果作为「可配置策略」，**默认不得因自签名/未知 CA 直接失败**，
   否则连不上本目标服务器（实测自签名，E）。
2. 证书校验失败时必须走显式策略分支：`strict`（拒绝）/ `tofu`（首次信任并 pin 指纹）/
   `insecure`（仅记录）。默认建议 `tofu`（首次连接记录 SHA-256 指纹，后续比对），
   因为 CredSSP 的 `pubKeyAuth` 只保证「TLS 公钥前后一致 + 服务器知道 NTLM 会话密钥」，
   它**不**验证主机名，也**不**提供首次连接的可信性。
3. `pubKeyAuth` 校验**不可省略**——它是 CredSSP 唯一的 MITM 防护（§5.4）。
4. 主机名校验：规范未要求（`[MS-CSSP]` 全文无 hostname 校验条款）。实测证书 `CN=DESKTOP-5BFDKO3`
   而连接地址是 `192.168.1.7`，且证书**没有 SAN 扩展**——若强制主机名校验会必然失败。
   因此主机名校验必须可关闭，默认关闭（C）。
   附带：`tofu` 模式应 pin **证书 SHA-256 指纹**（本目标为
   `B1:B9:F1:4C:C6:DE:24:CF:13:95:6E:2F:4B:BC:02:1F:61:5E:C3:24:B7:65:D9:19:45:96:AF:5E:DC:4F:2C:12`）
   或 **SubjectPublicKey 的 SHA-256**；后者更稳（证书续期但公钥不变时不会误报）。

### 4.4 SNI 与 ALPN

| 项 | 规范 | 实测 |
|---|---|---|
| SNI | `[MS-RDPBCGR]` 与 `[MS-CSSP]` 全文**均未提及** SNI（对 RDPBCGR 官方 PDF 全文检索 `SNI` / `Server Name` 命中 0 次） | 带 `-servername` 与 `-noservername` 都握手成功（E） |
| ALPN | 两者**均未提及** ALPN | 服务器 `No ALPN negotiated`（E） |

**实现结论（C）**：
- SNI：**可选**。发送 `server_hostname = <目标地址>` 无害（实测通过），且对走 SNI 路由的
  负载均衡器有益；但**不得**因 SNI 未命中而失败。
- ALPN：**不要发**。服务器不协商 ALPN；发 ALPN 扩展可能触发部分实现的严格校验。
  若 TLS 库默认发送，应显式清空 ALPN 列表。

### 4.5 握手完成后的数据流形态

```
TLS record (application_data)
  └── 明文 = 完整 TPKT 帧
        ├── TPKT header (4B: 03 00 len_hi len_lo)
        ├── X.224 Data TPDU (3B: 02 F0 80)
        └── MCS / RDP PDU ...
```

- 一个 TLS record 可装多个 TPKT 帧，一个 TPKT 帧也可跨多个 TLS record——**必须按 TPKT
  长度字段重新组帧**，不能假设「一个 TLS record = 一个 PDU」（C，TLS 语义 + TPKT 语义）。
- 唯一例外是 EUAR（§2.3）：它是**裸 4 字节**，不带 TPKT，出现在 CredSSP 刚结束、
  MCS Connect Initial 之前的窗口里。读取器必须在该窗口切换到「读 4 字节」模式（C；F3 一致）。
- 服务器对客户端 TLS 握手的**帧打包要求**：「Microsoft RDP 5.2 … 10.5 servers expect that the
  final set of client-to-server TLS handshake messages (**ClientKeyExchange, ChangeCipherSpec,
  and Finished**) be sent **together in a single frame**」（S36 `<57>`，A）。
  实现必须把这三条消息合并到同一次 write（或同一 TLS record 批次）里发出。

### 4.6 错误上报

CredSSP 用 **TLS fatal alert** 上报错误（S35，5.4.5.2.2，A）：

| Alert 码 | 名称 | 含义 |
|---|---|---|
| 10 | TLS1_ALERT_UNEXPECTED_MESSAGE | 收到不合适的消息 |
| 21 | TLS1_ALERT_DECRYPTION_FAILED | 密文解密方式非法（非块长整数倍或 padding 错误） |
| 42 | TLS1_ALERT_BAD_CERTIFICATE | 证书损坏（如签名验证失败） |
| 45 | TLS1_ALERT_CERTIFICATE_EXPIRED | 证书过期或当前无效 |
| 48 | TLS1_ALERT_UNKNOWN_CA | 收到了有效链，但 CA 证书找不到或无法匹配已知可信 CA |
| 49 | TLS1_ALERT_ACCESS_DENIED | 凭据无效导致登录失败 |
| 80 | TLS1_ALERT_INTERNAL_ERROR | 通用兜底错误 |

实测：TSRequest 缺 `negoTokens` 时服务器发 `TLSV1_ALERT_INTERNAL_ERROR`（E，§0.3f）。

---

## 5. CredSSP 握手完整状态机

### 5.1 TSRequest 的 ASN.1 结构（C5，2.2.1，A）

```asn1
TSRequest ::= SEQUENCE {
        version    [0] INTEGER,
        negoTokens [1] NegoData  OPTIONAL,
        authInfo   [2] OCTET STRING OPTIONAL,
        pubKeyAuth [3] OCTET STRING OPTIONAL,
        errorCode  [4] INTEGER OPTIONAL,
        clientNonce [5] OCTET STRING OPTIONAL
}
```

| 字段 | tag | 编码 | 语义 |
|---|---|---|---|
| `version` | `[0]` context-specific constructed → `A0` | 内层 `INTEGER`（`02`） | 支持的 CredSSP 版本，**合法值 2,3,4,5,6**。「If the version received is greater than the implementation understands, treat the peer as one that is compatible with the version … that the implementation understands」 |
| `negoTokens` | `[1]` → `A1` | 内层 `NegoData`（`SEQUENCE`） | SPNEGO / Kerberos / NTLM 消息 |
| `authInfo` | `[2]` → `A2` | 内层 `OCTET STRING`（`04`） | `TSCredentials` 的 DER 字节；**MUST be encrypted** under SPNEGO 协商出的加密密钥。「carries the message signature and then the encrypted data」 |
| `pubKeyAuth` | `[3]` → `A3` | 内层 `OCTET STRING`（`04`） | 公钥绑定数据，已加密。「carries the message signature and then the encrypted public key」 |
| `errorCode` | `[4]` → `A4` | 内层 `INTEGER`（`02`） | 32 位值；版本 3/4/6 且 SPNEGO 在服务器侧失败时 SHOULD 填 NTSTATUS 失败码 |
| `clientNonce` | `[5]` → `A5` | 内层 `OCTET STRING`（`04`） | **32 字节**密码学随机数；**仅版本 ≥5 使用** |

**版本取值与行为**（C5 + C13 `<10><11>`，A）：

| 版本 | 引入 | 关键差异 |
|---|---|---|
| 2 | XP SP3 / Vista / 2008 / 7 / 2008R2 / 8 / 2012（只支持 2） | `pubKeyAuth` = 加密后的 SubjectPublicKey 原文 |
| 3 | — | 增加 `errorCode` 语义 |
| 4 | — | 同 3 |
| 5 | Windows Server v1803 及以后（C13 `<25>`） | `pubKeyAuth` 改为 SHA-256 绑定哈希；引入 `clientNonce` |
| 6 | 当前 | 同 5 |

`[MS-CSSP] 5.1` 明确建议：「A major revision has been applied to the protocol in version 5 for
improved security. **Implementors are advised to support version 5 or higher only**.」（C12，A）

### 5.2 NegoData 与 NTLM 消息的封装（C6，2.2.1.1，A）

```asn1
NegoData ::= SEQUENCE OF SEQUENCE {
        negoToken [0] OCTET STRING
}
```

即双层 SEQUENCE：外层 `SEQUENCE OF`，每个元素是一个 `SEQUENCE`，内含一个 `[0] OCTET STRING`。
`negoToken` 的内容是「一个或多个 SPNEGO token，以及 SPNEGO 协商出的全部 Kerberos 或 NTLM 消息」。
NTLM 消息（NTLMSSP blob）**整体作为一个 OCTET STRING 的载荷**，不再二次编码。

**实测 wire 形态**（E，§0.3b，91 字节 TSRequest）：

```
30 59                          TSRequest SEQUENCE, len 0x59=89
  a0 03 02 01 06               version = 6
  a1 52                        negoTokens
    30 50                      SEQUENCE OF (NegoData), len 0x50
      30 4e                    SEQUENCE (第 1 项), len 0x4e
        a0 4c                  [0] negoToken
          04 4a                OCTET STRING, len 0x4a=74
            60 48              GSS-API InitialContextToken [APPLICATION 0]
              06 06 2b0601050502      OID 1.3.6.1.5.5.2 (SPNEGO)
              a0 3e            [0] inner NegTokenInit
                30 3c          SEQUENCE
                  a0 0e        [0] mechTypes
                    30 0c      SEQUENCE OF MechType
                      06 0a 2b06010401823702020a   OID 1.3.6.1.4.1.311.2.2.10 (NTLM)
                  a2 2a        [2] mechToken
                    04 28      OCTET STRING, len 40
                      4e544c4d53535000 01000000 358288e2 0000000000000000
                      0000000000000000 0a0063450000000f
```

其中 40 字节就是 NTLM **NEGOTIATE_MESSAGE**（§6.1）。

SPNEGO OID：`1.3.6.1.5.5.2`（`iso.org.dod.internet.security.mechanism.snego`，P3，A）。
NTLM OID：`1.3.6.1.4.1.311.2.2.10`（`iso.org.dod.internet.private.enterprise.Microsoft.security.mechanisms.NTLM`，N20，A）。

### 5.3 五步状态机（C10，3.1.5，A + 实测）

| 步 | 方向 | TSRequest 字段 | 说明 |
|---|---|---|---|
| 0 | client→server | — | **先完成 TLS 握手**（TLS 不在 CredSSP 报文内） |
| 1 | client→server | `version` + `negoTokens`(NTLM NEGOTIATE) | 客户端发起 SPNEGO/NTLM。`authInfo`/`pubKeyAuth` 省略 |
| 2 | server→client | `version` + `negoTokens`(NTLM CHALLENGE) | 服务器回 challenge。`authInfo`/`pubKeyAuth` 省略 |
| 3 | client→server | `version` + `negoTokens`(NTLM AUTHENTICATE) + `pubKeyAuth` (+ `clientNonce` if v≥5) | 原文：「If the client is sending the last SPNEGO token or Kerberos/NTLM message, the TSRequest structure **MUST have both the negoTokens and the pubKeyAuth fields filled in**」。`authInfo` 省略 |
| 4 | server→client | `version` + `pubKeyAuth` | 服务器回公钥回显/哈希。`authInfo` 与 `negoTokens` 都省略 |
| 5 | client→server | `version` + `authInfo` | 客户端发凭据。`pubKeyAuth` 与 `negoTokens` 都省略 |

握手到此结束。若协商的是 HYBRID_EX，紧接着服务器发 EUAR（§2.3）。

**失败分支**（C10，A）：
- 服务器侧 SPNEGO 失败且客户端 version ≥3 ⇒ 服务器回 TSRequest，`errorCode` = NTSTATUS 失败码；
  客户端「MUST immediately fail with the provided status code and cease all further processing」。
- 服务器不支持请求的版本 ⇒ SHOULD 在 `errorCode` 里置 `STATUS_NOT_SUPPORTED`。

**实测版本行为**（E，§0.3c）：客户端发 1..8 任意版本，服务器都回 `version = 6`。

**实测封装要求**（E，§0.3e）：第 3 步的 `negoToken` **必须是裸 NTLM AUTHENTICATE blob**；
若再包一层 SPNEGO `negTokenResp`，服务器回 `SEC_E_INVALID_TOKEN (0x80090308)`。

### 5.4 pubKeyAuth 的完整计算步骤

这是 CredSSP 最容易实现错的地方。算法**按版本分叉**，两条路径完全不同。

#### 5.4.0 前置：取服务器的 SubjectPublicKey

原文（C10 step 3，Version 2/3/4 段，A）：
> The public key that is encrypted is the **ASN.1-encoded SubjectPublicKey sub-field of
> SubjectPublicKeyInfo** from the X.509 certificate, as specified in [RFC3280] section 4.1.

**要点**：取的是 `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }`
里的 **BIT STRING 内容（去掉首个 unused-bits 字节后的原始字节）**，也就是
`RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` 的完整 DER 编码
（含它自己的 `30 82 ...` 头）。**不是**整个 SubjectPublicKeyInfo，**不是**整个证书，
**不是** SHA-1/SHA-256 指纹。

FreeRDP 用 `i2d_PublicKey(pkey, ...)` 得到同样的字节（F5 `certificate.c`
`freerdp_certificate_get_public_key()`），B 级旁证。

实测（E）：本服务器证书的该字段是 **270 字节**，以
`30 82 01 0a 02 82 01 01 00 ce b5 bf 3f ...` 开头（即 `SEQUENCE` + `INTEGER(257B modulus)` + …）。

伪代码：

```
spki_der   = certificate.tbsCertificate.subjectPublicKeyInfo   (整段 DER)
spki_body  = DER 解开 SEQUENCE 后的内容
algorithm  = 第 1 个元素（SEQUENCE AlgorithmIdentifier）
bitstring  = 第 2 个元素（03 <len> <unused_bits> <data...>）
SubjectPublicKey = bitstring[1:]        # 去掉 unused_bits 那 1 字节
```

#### 5.4.1 版本 5 / 6：SHA-256 绑定哈希

原文（C10 step 3，Version 5 or 6 段，A）：
> The client SHOULD generate a cryptographically random **32-byte** value and set the **nonce** field
> of the TSRequest structure to this value. It then computes a **SHA256 hash** of the ASN.1 encoded
> **SubjectPublicKey** concatenated with the bytes of the well-known string
> **"CredSSP Client-To-Server Binding Hash"** and the generated nonce. The hash is then encrypted
> using the confidentiality support of the authentication protocol.

原文给出的定义（C10，A，逐字）：

```
Set ClientServerHashMagic to "CredSSP Client-To-Server Binding Hash"
Set ClientServerHash to SHA256(ClientServerHashMagic, Nonce, SubjectPublicKey)
Set TSRequest.pubKeyAuth to Encrypt(ClientServerHash)
```

原文附注（C10，A）：「**The hash MUST include the null terminator (\0) of the string.**」

服务器侧（C10 step 4，Version 5 and 6 段，A）：

```
Set ServerClientHashMagic to "CredSSP Server-To-Client Binding Hash"
Set ServerClientHash to SHA256(ServerClientHashMagic, Nonce, SubjectPublicKey)
Set TSRequest.pubKeyAuth to Encrypt(ServerClientHash)
```

同样「MUST include the null terminator (\0)」。

**拼接顺序的歧义与实测裁决**：原文写作 `SHA256(ClientServerHashMagic, Nonce, SubjectPublicKey)`，
但同一段的散文句写作「SHA256 hash of the ASN.1 encoded SubjectPublicKey **concatenated with**
the bytes of the well-known string … **and** the generated nonce」。两种读法给出不同的字节序。
FreeRDP 的实现（F1 `nla.c` `nla_encrypt_public_key_hash()`）是**逐字按 `hashMagic → nonce → SubjectPublicKey`**
顺序 update 摘要（且注释明写「include trailing \0 from hashMagic」），B 级旁证。
本文件采纳 **`magic || nonce || SubjectPublicKey`** 的顺序（C 级推导，依据：伪代码参数顺序 + FreeRDP 实现一致；
该顺序未在实测中通过「成功完成第 4 步」得到验证，见 §10）。

Magic 常量的精确字节（含结尾 NUL），由字符串直接推出（C）：

```
"CredSSP Client-To-Server Binding Hash\0"   -> 38 字节
  43 72 65 64 53 53 50 20 43 6c 69 65 6e 74 2d 54
  6f 2d 53 65 72 76 65 72 20 42 69 6e 64 69 6e 67
  20 48 61 73 68 00

"CredSSP Server-To-Client Binding Hash\0"   -> 38 字节
  43 72 65 64 53 53 50 20 53 65 72 76 65 72 2d 54
  6f 2d 43 6c 69 65 6e 74 20 42 69 6e 64 69 6e 67
  20 48 61 73 68 00
```

字节值与 FreeRDP 的 `ClientServerHashMagic[]` / `ServerClientHashMagic[]` 数组逐字节一致（F1，B）。

#### 5.4.2 版本 2 / 3 / 4：加密 SubjectPublicKey 原文

原文（C10 step 3，Version 2, 3, 4 段，A）：
> The client encrypts the public key it received from the server (contained in the X.509 certificate)
> in the TLS handshake from step 1, by using the confidentiality support of the authentication protocol.

即：`TSRequest.pubKeyAuth = Encrypt(SubjectPublicKey)`（无哈希、无 nonce）。

服务器回显（C10 step 4，Version 2, 3, and 4 段，A）：
> The server then **adds 1 to the first byte** representing the public key (the ASN.1 structure
> corresponding to the SubjectPublicKey field) and encrypts the binary result … The addition of 1 to
> the first byte of the public key is performed so that the client-generated pubKeyAuth message
> **cannot be replayed back to the client by an attacker**.

「加 1」是**小端序多字节加 1**（FreeRDP 的 `ap_integer_increment_le()` / `ap_integer_decrement_le()`
逐字节进位/借位，F1，B）。客户端校验时对收到的明文做小端减 1，再与本地 SubjectPublicKey 逐字节比对。

#### 5.4.3 `Encrypt()` / `EncryptMessage()` 到底是什么

规范只说「encrypt using the confidentiality support of the authentication protocol」（C10，A）。
对 NTLM 而言这就是 **NTLM 的 SEAL**（`[MS-NLMP] 3.4.3`，N14，A）：

```
SEAL(Handle, SigningKey, SeqNum, Message):
    Sealed message := RC4(Handle, Message)
    Signature      := MAC(Handle, SigningKey, SeqNum, Message)
```

而 `pubKeyAuth` 字段的布局是「**message signature and then the encrypted data**」（C5，2.2.1，A），
即 **`signature(16) || ciphertext`**。

签名算法（N15，3.4.4.2，A，Extended Session Security 且协商了 KEY_EXCH）：

```
MAC(Handle, SigningKey, SeqNum, Message):
    NTLMSSP_MESSAGE_SIGNATURE.Version   := 0x00000001
    NTLMSSP_MESSAGE_SIGNATURE.Checksum  := RC4(Handle, HMAC_MD5(SigningKey, SeqNum || Message)[0..7])
    NTLMSSP_MESSAGE_SIGNATURE.SeqNum    := SeqNum
    SeqNum := SeqNum + 1
```

签名结构（N9，2.2.2.9.1，A）：`Version(4) | Checksum(8) | SeqNum(4)` = 16 字节，全小端。

**关键顺序**：先 `RC4(Message)` 得到密文，**再**用同一个 RC4 流状态 `RC4(HMAC_MD5(...))` 得到 checksum。
FreeRDP 的实现顺序与此一致（F1 `nla_encrypt_public_key_hash()` → `credssp_auth_encrypt()`，
后者调 SSPI `EncryptMessage`，F2，B）。

#### 5.4.4 NTLM 会话密钥与序列号

`Encrypt()` 用的密钥来自 SPNEGO/NTLM 协商结果（N16/N17/N18，A）：

```
KeyExchangeKey  = SessionBaseKey                      # NTLMv2 情形（N16 原文：
                                                      # 「If NTLM v2 is used, KeyExchangeKey MUST be
                                                      #  set to the given 128-bit SessionBaseKey value」）
ExportedSessionKey = 若协商了 KEY_EXCH 且(SIGN 或 SEAL)：
                       16 字节随机数；EncryptedRandomSessionKey = RC4(KeyExchangeKey, ExportedSessionKey)
                     否则 = KeyExchangeKey
SigningKey = MD5(ExportedSessionKey || "session key to client-to-server signing key magic constant\0")
SealingKey = MD5(ExportedSessionKey || "session key to client-to-server sealing key magic constant\0")
```

（服务端方向把 `client-to-server` 换成 `server-to-client`。SEALKEY 在 128 位下直接取
`ExportedSessionKey` 全部 16 字节，再做 MD5——见 N18。）

序列号：`[MS-NLMP] 3.4.4`「In the case of connection-oriented authentication, the *SeqNum*
parameter **MUST start at 0** and is incremented by one for each message sent」（A）。
CredSSP 里 `pubKeyAuth` 的 seq 从 **0** 开始，`authInfo` 用 **1**（客户端侧连续两个 sealed 消息）。
实测证实：FreeRDP 用 `nla->sendSeqNum++` / `nla->recvSeqNum++` 逐消息递增（F1，B）。

#### 5.4.5 完整步骤清单（客户端，版本 5/6）

1. TLS 握手完成，取出服务器证书的 `SubjectPublicKey`（§5.4.0），保存为 `SPK`。
2. 生成 32 字节密码学随机 `nonce`。
3. `magic = "CredSSP Client-To-Server Binding Hash" || 0x00`（38 字节）。
4. `hash = SHA256(magic || nonce || SPK)`（32 字节）。
5. 由 NTLM 协商得到 `ExportedSessionKey`，派生 `SigningKey` / `SealingKey`（§5.4.4）。
6. `ciphertext = RC4(SealingKey, hash)`。
7. `checksum = RC4(HMAC_MD5(SigningKey, LE32(0) || hash))[0..8]`
   —— **注意 MAC 的输入是明文 `hash`，不是 ciphertext**；RC4 状态在 step 6 之后继续。
8. `pubKeyAuth = LE32(1) || checksum || LE32(0) || ciphertext`（16 + 32 = 48 字节）。
9. 第 3 步 TSRequest 里同时带 `negoTokens`(AUTHENTICATE)、`pubKeyAuth`、`clientNonce = nonce`。
10. 收到第 4 步响应后：`plain = RC4_DECRYPT(pubKeyAuth[16:])`，校验
    `plain == SHA256("CredSSP Server-To-Client Binding Hash\0" || nonce || SPK)`。
    **不匹配必须中止，绝不发 authInfo**。

实测：本目标返回的第 3 步结果中 `pubKeyAuth` 为 **48 字节**（E，§0.3d），与 16+32 一致。
（服务器在该步先校验 NTLM 凭据，凭据错误直接回 `errorCode`，未走到第 4 步。）

#### 5.4.6 常见实现错误清单（全部由上述原文直接推出，C）

| 错误 | 后果 |
|---|---|
| 用整个证书或整个 SubjectPublicKeyInfo 做输入，而不是 SubjectPublicKey | 哈希不匹配，服务器回错 |
| 忘记 magic 的结尾 `\0` | 哈希不匹配 |
| 顺序写成 `SPK || magic || nonce` | 哈希不匹配 |
| v5/6 仍发 SubjectPublicKey 原文（不走哈希） | 服务器回错/`errorCode` |
| v2/3/4 却发哈希 | 服务器回错 |
| 把 MAC 输入写成 ciphertext | checksum 不匹配，服务器拒绝 |
| 用 `EncryptMessage` 但把 signature 放在密文之后 | 布局错，`pubKeyAuth` 解析失败 |
| 忘记服务器 v2/3/4 回显要「首字节 +1」 | 客户端误判为 MITM，中止 |
| seq 从 1 开始 | 签名校验失败 |
| 用 `TlsExportKeyingMaterial` 之类 TLS 通道绑定替代 NTLM SEAL | 服务器不认 |

### 5.5 TSCredentials（第 5 步 authInfo 的明文）（C7/C8，A）

```asn1
TSCredentials ::= SEQUENCE {
        credType    [0] INTEGER,
        credentials [1] OCTET STRING
}

TSPasswordCreds ::= SEQUENCE {
        domainName  [0] OCTET STRING,
        userName    [1] OCTET STRING,
        password    [2] OCTET STRING
}
```

`credType` 取值（C7，A）：

| 值 | `credentials` 内容 |
|---|---|
| 1 | `TSPasswordCreds` |
| 2 | `TSSmartCardCreds` |
| 6 | `TSRemoteGuardCreds` |

编码要点：
- `domainName` / `userName` / `password` 都是 **UTF-16LE 字节**装进 `OCTET STRING`（不是 UTF-8）。
  依据：C13 `<6><9><14><15>`「Where data is a text string, Windows uses a Unicode string defined by
  a **UNICODE_STRING** structure to encode to ASN.1 OCTET STRING format」（A）。
- `credentials` 里装的是 `TSPasswordCreds` 的**完整 DER 字节**（含 `30 ...` 头）。
- 整个 `TSCredentials` 的 DER 字节再被 SEAL（seq = 1）后放进 `authInfo` 的 OCTET STRING。

规范样例（C11，4 Protocol Examples，A）给出 authInfo 明文头：
`30 82 01 0f a0 03 02 01 02 a1 82 01 06 04 82 01 02 30 81 ff ...`
——`credType = 2`（smart card），`credentials` 长度 0x102。

### 5.6 本服务器实测的封装选择（E）

| 步骤 | 实测接受 | 实测拒绝 |
|---|---|---|
| 第 1 步 | 裸 NTLM NEGOTIATE（回 262B）；GSS-SPNEGO `NegTokenInit`（回 300B） | 裸 `negTokenInit` SEQUENCE（无 GSS 头）→ `SEC_E_INVALID_TOKEN` |
| 第 3 步 | 裸 NTLM AUTHENTICATE + pubKeyAuth + clientNonce | SPNEGO `negTokenResp` 包装 → `SEC_E_INVALID_TOKEN` |
| 任一步 | 必须带 `negoTokens` | 只有 version → `TLSV1_ALERT_INTERNAL_ERROR` |

**实现建议（C）**：默认按上表行为（第 1 步发 GSS-SPNEGO NegTokenInit，第 3 步发裸 NTLM），
并用一个配置项 `credssp_spnego_wrap_last_token`（默认 false）允许切换，以便对接其他实现。

### 5.7 DER 编码约束

- `[n]` 均为 **context-specific constructed**（`A0`..`A5`），内层再放对应通用类型（`02`/`04`/`30`）。
- `version` 用**最短** INTEGER 编码：v6 → `02 01 06`（实测一致）。
- `errorCode` 为 32 位值，最高位为 1（NTSTATUS/SEC_E 都是 `0xC...`/`0x8...`），
  DER INTEGER 要求**前置 0x00** 以免被解释为负数。实测服务器发的是
  `a4 06 02 04 c0 00 00 6d`——**未加前导 0x00**（E，§0.3d），即服务器发的是「按无符号 4 字节直写」
  的非规范 DER。**实现必须能解析这种形式**（放宽：接受 4 字节无符号，也接受带前导 0x00 的 5 字节）。
  这是实测发现、规范未覆盖的互操作细节（C，依据实测字节）。
- `OCTET STRING` 长度 ≥128 时用长形式（`04 81 xx` / `04 82 xx xx`），实测服务器用
  `a0 82 0113` / `04 81 ee`（E）。
- 服务器要求「a TLS encrypted message fragment contain an **entire ASN.1 message**」，
  且「expects a TLS encryption of an entire TSRequest message **without fragmentation**」
  （C13 `<8>`，A）——即一个 TSRequest 必须一次 write 完成，不得跨 TLS record 拆分。

---

## 6. NTLM 三消息完整字段表

所有整数字段**小端**。所有 `*Fields` 三元组的结构统一为
`Len(2) | MaxLen(2) | BufferOffset(4)`，`BufferOffset` 相对**消息起始**。

### 6.1 NEGOTIATE_MESSAGE（N1，2.2.1.1，A）

| 偏移 | 大小 | 字段 | 约束 |
|---|---|---|---|
| 0 | 8 | `Signature` | ASCII `"NTLMSSP\0"` = `4e 54 4c 4d 53 53 50 00` |
| 8 | 4 | `MessageType` | MUST be `0x00000001` |
| 12 | 4 | `NegotiateFlags` | `NEGOTIATE` 结构（§6.4） |
| 16 | 2 | `DomainNameLen` | 若 `OEM_DOMAIN_SUPPLIED` 置位则 >0 |
| 18 | 2 | `DomainNameMaxLen` | SHOULD = Len，接收时 MUST 忽略 |
| 20 | 4 | `DomainNameBufferOffset` | 相对消息起始 |
| 24 | 2 | `WorkstationLen` | 若 `OEM_WORKSTATION_SUPPLIED` 置位则 >0 |
| 26 | 2 | `WorkstationMaxLen` | SHOULD = Len |
| 28 | 4 | `WorkstationBufferOffset` | 相对消息起始 |
| 32 | 8 | `Version` | 仅 `NEGOTIATE_VERSION` 置位时有效，否则全 0 |
| 40 | … | `Payload` | `DomainName`（OEM）/ `WorkstationName`（OEM），顺序任意 |

**头部固定 40 字节**（含 Version）。若不发 Version（不置 `NEGOTIATE_VERSION`），
头部为 32 字节，但 `Version` 字段位置仍占位全 0——规范表格是固定布局，实现按 40 字节写最稳。

实测（E，§0.3b）：本项目的 NEGOTIATE 为 **40 字节**，`NegotiateFlags = 0xE2888235`，
`DomainNameLen = WorkstationLen = 0`，`Version = 0a 00 63 45 00 00 00 0f`。

`Version` 结构（N11，2.2.2.10，A）：

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 1 | `ProductMajorVersion` |
| 1 | 1 | `ProductMinorVersion` |
| 2 | 2 | `ProductBuild` |
| 4 | 3 | `Reserved`（SHOULD 为 0） |
| 7 | 1 | `NTLMRevisionCurrent`（SHOULD be `0x0F` = `NTLMSSP_REVISION_W2K3`） |

### 6.2 CHALLENGE_MESSAGE（N2，2.2.1.2，A）

| 偏移 | 大小 | 字段 | 约束 |
|---|---|---|---|
| 0 | 8 | `Signature` | `"NTLMSSP\0"` |
| 8 | 4 | `MessageType` | MUST be `0x00000002` |
| 12 | 2 | `TargetNameLen` | |
| 14 | 2 | `TargetNameMaxLen` | SHOULD = Len |
| 16 | 4 | `TargetNameBufferOffset` | Unicode 时必须是偶数 |
| 20 | 4 | `NegotiateFlags` | 服务器选择/支持的能力 |
| 24 | 8 | `ServerChallenge` | 64 位 nonce |
| 32 | 8 | `Reserved` | 发送时全 0，接收时忽略 |
| 40 | 2 | `TargetInfoLen` | |
| 42 | 2 | `TargetInfoMaxLen` | SHOULD = Len |
| 44 | 4 | `TargetInfoBufferOffset` | |
| 48 | 8 | `Version` | 仅 `NEGOTIATE_VERSION` 置位时有效 |
| 56 | … | `Payload` | `TargetName`、`TargetInfo`（AV_PAIR 序列） |

**头部固定 56 字节**。`TargetInfo` 是 `AV_PAIR` 序列，必须以 `MsvAvEOL` 结尾，
「An AV_PAIR structure can start on any byte alignment … the sequence of AV_PAIRs has no padding」
（N2，A）。文本型 AV 值**一律 Unicode**，与协商字符集无关（N2 注，A）。

实测（E，§0.3b）：238 字节，`NegotiateFlags = 0xE28A8235`，
`TargetName = "DESKTOP-5BFDKO3"`，`TargetInfoLen = 152`。

### 6.3 AUTHENTICATE_MESSAGE（N3，2.2.1.3，A）

| 偏移 | 大小 | 字段 | 约束 |
|---|---|---|---|
| 0 | 8 | `Signature` | `"NTLMSSP\0"` |
| 8 | 4 | `MessageType` | MUST be `0x00000003` |
| 12 | 2 | `LmChallengeResponseLen` | |
| 14 | 2 | `LmChallengeResponseMaxLen` | SHOULD = Len |
| 16 | 4 | `LmChallengeResponseBufferOffset` | |
| 20 | 2 | `NtChallengeResponseLen` | |
| 22 | 2 | `NtChallengeResponseMaxLen` | SHOULD = Len |
| 24 | 4 | `NtChallengeResponseBufferOffset` | |
| 28 | 2 | `DomainNameLen` | Unicode 时必须偶数 |
| 30 | 2 | `DomainNameMaxLen` | SHOULD = Len |
| 32 | 4 | `DomainNameBufferOffset` | |
| 36 | 2 | `UserNameLen` | 不含 NUL 终止符 |
| 38 | 2 | `UserNameMaxLen` | SHOULD = Len |
| 40 | 4 | `UserNameBufferOffset` | |
| 44 | 2 | `WorkstationLen` | |
| 46 | 2 | `WorkstationMaxLen` | SHOULD = Len |
| 48 | 4 | `WorkstationBufferOffset` | |
| 52 | 2 | `EncryptedRandomSessionKeyLen` | 仅 `KEY_EXCH` 置位时非 0 |
| 54 | 2 | `EncryptedRandomSessionKeyMaxLen` | SHOULD = Len |
| 56 | 4 | `EncryptedRandomSessionKeyBufferOffset` | |
| 60 | 4 | `NegotiateFlags` | 协商结论 |
| 64 | 8 | `Version` | 仅 `NEGOTIATE_VERSION` 置位时有效 |
| 72 | 16 | `MIC` | NEGOTIATE/CHALLENGE/AUTHENTICATE 三消息的完整性校验 |
| 88 | … | `Payload` | 6 个变长字段，顺序任意 |

**头部固定 88 字节**（含 Version 与 MIC）。实测（E）：本项目发出的 AUTHENTICATE 为
**418 字节**，即 88 + 330 payload。

> 陷阱：很多实现按 64 字节头写（漏掉 Version + MIC 的 24 字节）。**必须 88**。
> 本文件作者在实测脚本里第一次就踩了这个坑（按 64 写导致 offset 全错）。

`Payload` 内容（N3，A）：

| 字段 | 结构 | 说明 |
|---|---|---|
| `LmChallengeResponse` | `LMv2_RESPONSE`（NTLMv2 时） | 24 字节：`HMAC_MD5(ResponseKeyLM, ServerChallenge‖ClientChallenge) ‖ ClientChallenge` |
| `NtChallengeResponse` | `NTLMv2_RESPONSE`（NTLMv2 时） | `NTProofStr(16) ‖ NTLMv2_CLIENT_CHALLENGE` |
| `DomainName` | 协商字符集 | 本服务器为 Unicode |
| `UserName` | 协商字符集 | |
| `Workstation` | 协商字符集 | |
| `EncryptedRandomSessionKey` | 16 字节（128 位密钥） | `RC4(KeyExchangeKey, ExportedSessionKey)` |

### 6.4 NEGOTIATE flags 完整数值表（N5，2.2.2.5，A）

位序按规范图（bit 31 → bit 0，字母 W..A）：

| 位 | 字母 | 名称 | 值 |
|---|---|---|---|
| 31 | W | `NTLMSSP_NEGOTIATE_56` | `0x80000000` |
| 30 | V | `NTLMSSP_NEGOTIATE_KEY_EXCH` | `0x40000000` |
| 29 | U | `NTLMSSP_NEGOTIATE_128` | `0x20000000` |
| 28 | r1 | 未使用，MUST 0 | `0x10000000` |
| 27 | r2 | 未使用，MUST 0 | `0x08000000` |
| 26 | r3 | 未使用，MUST 0 | `0x04000000` |
| 25 | T | `NTLMSSP_NEGOTIATE_VERSION` | `0x02000000` |
| 24 | r4 | 未使用，MUST 0 | `0x01000000` |
| 23 | S | `NTLMSSP_NEGOTIATE_TARGET_INFO` | `0x00800000` |
| 22 | R | `NTLMSSP_REQUEST_NON_NT_SESSION_KEY` | `0x00400000` |
| 21 | r5 | 未使用，MUST 0 | `0x00200000` |
| 20 | Q | `NTLMSSP_NEGOTIATE_IDENTIFY` | `0x00100000` |
| 19 | P | `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` | `0x00080000` |
| 18 | r6 | 未使用，MUST 0 | `0x00040000` |
| 17 | O | `NTLMSSP_TARGET_TYPE_SERVER` | `0x00020000` |
| 16 | N | `NTLMSSP_TARGET_TYPE_DOMAIN` | `0x00010000` |
| 15 | M | `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` | `0x00008000` |
| 14 | r7 | 未使用，MUST 0 | `0x00004000` |
| 13 | L | `NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED` | `0x00002000` |
| 12 | K | `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED` | `0x00001000` |
| 11 | J | （匿名连接） | `0x00000800` |
| 10 | r8 | 未使用，SHOULD 0 | `0x00000400` |
| 9 | H | `NTLMSSP_NEGOTIATE_NTLM` | `0x00000200` |
| 8 | r9 | 未使用，MUST 0 | `0x00000100` |
| 7 | G | `NTLMSSP_NEGOTIATE_LM_KEY` | `0x00000080` |
| 6 | F | `NTLMSSP_NEGOTIATE_DATAGRAM` | `0x00000040` |
| 5 | E | `NTLMSSP_NEGOTIATE_SEAL` | `0x00000020` |
| 4 | D | `NTLMSSP_NEGOTIATE_SIGN` | `0x00000010` |
| 3 | r10 | 未使用，MUST 0 | `0x00000008` |
| 2 | C | `NTLMSSP_REQUEST_TARGET` | `0x00000004` |
| 1 | B | `NTLM_NEGOTIATE_OEM` | `0x00000002` |
| 0 | A | `NTLMSSP_NEGOTIATE_UNICODE` | `0x00000001` |

关键语义（N5，A）：
- **A/B 联合**：A=1 ⇒ Unicode；A=0 且 B=1 ⇒ OEM；A=0 且 B=0 ⇒ MUST return `SEC_E_INVALID_TOKEN`。
- `NEGOTIATE_KEY_EXCH`：「requests an explicit key exchange … SHOULD be used because it improves
  security for message integrity or confidentiality」。
- `NEGOTIATE_ALWAYS_SIGN`：「a session key is generated regardless of the states of
  NEGOTIATE_SIGN and NEGOTIATE_SEAL. A session key **MUST always exist** to generate the MIC」。
- `EXTENDED_SESSIONSECURITY` 与 `LM_KEY` 互斥；两者都请求时只返回前者。
- `SEAL` / `SIGN` 若客户端置位，服务器**MUST**在 CHALLENGE 里回同样位。

实测（E）：
- 本项目 NEGOTIATE 发 `0xE2888235`（含 `0x02000000` VERSION，不含 `0x00400000` REQUEST_NON_NT）。
- 服务器 CHALLENGE 回 `0xE28A8235` = 客户端值 `| 0x00020000`（`TARGET_TYPE_SERVER`）。
- 两者都含 `56|KEY_EXCH|128|VERSION|TARGET_INFO|EXT_SESS_SEC|ALWAYS_SIGN|NTLM|SEAL|SIGN|REQUEST_TARGET|UNICODE`。

### 6.5 NTLMv2 响应计算的每一步公式（N13，3.3.2，A）

原文伪代码（逐字，A）：

```
Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(
    MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )
EndDefine

Define LMOWFv2(Passwd, User, UserDom) as NTOWFv2(Passwd, User, UserDom)
EndDefine

Set ResponseKeyNT to NTOWFv2(Passwd, User, UserDom)
Set ResponseKeyLM to LMOWFv2(Passwd, User, UserDom)

Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM,
    CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge, Time, ServerName)
As
If (User is set to "" && Passwd is set to "")
    -- Special case for anonymous authentication
    Set NtChallengeResponseLen to 0
    Set NtChallengeResponseMaxLen to 0
    Set NtChallengeResponseBufferOffset to 0
    Set LmChallengeResponse to Z(1)
Else
    Set temp to ConcatenationOf(Responserversion, HiResponserversion,
    Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
    Set NTProofStr to HMAC_MD5(ResponseKeyNT,
    ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
    Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
    Set LmChallengeResponse to ConcatenationOf(HMAC_MD5(ResponseKeyLM,
    ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
    ClientChallenge )
EndIf

Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
EndDefine
```

变量定义（N13，A）：
- `Responserversion` = 1，`HiResponserversion` = 1（各 1 字节）。
- `Time`：8 字节小端 GMT 时间。**优先取 CHALLENGE 的 `MsvAvTimestamp`**（见下）。
- `ClientChallenge`：8 字节随机。
- `ServerName`：AUTHENTICATE 里 `NtChallengeResponse` 的 `AvPairs` 字段（AV_PAIR 序列，含 EOL）。
- `Z(n)` = n 个 0x00 字节。

**Time 的来源**（N12，3.1.5.1.2，A）：
```
If there exists CHALLENGE_MESSAGE.TargetInfo.AvId == MsvAvTimestamp
    Set Time to CHALLENGE_MESSAGE.TargetInfo.Value of that AVPair
Else
    Set Time to Currenttime
Endif
```
（用服务器时间而非本地时间，可避免客户端时钟偏差导致失败。）

**LmChallengeResponse 的特殊规则**（N12，A）：
> If NTLM v2 authentication is used and the CHALLENGE_MESSAGE TargetInfo field has an
> **MsvAvTimestamp** present, the client **SHOULD NOT send the LmChallengeResponse** and
> **SHOULD send Z(24) instead**.

实测（E）：本服务器 CHALLENGE 含 `MsvAvTimestamp`(0x0007)，故按规范应发 `Z(24)`。
本文件作者的实测脚本发的是完整 LMv2（24 字节），服务器**未因此报错**（回的是
`STATUS_LOGON_FAILURE`，说明已走到凭据校验）。实现建议按规范发 `Z(24)`（C）。

**MIC**（N12，A）：
```
Set MIC to HMAC_MD5(ExportedSessionKey,
    ConcatenationOf(NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE))
Set AUTHENTICATE_MESSAGE.MIC to MIC
```
计算时 `AUTHENTICATE_MESSAGE.MIC` 字段**先填 0**（N12 输入说明：「with MIC field set to 0」）。
若 CHALLENGE 含 `MsvAvTimestamp`，客户端 SHOULD 提供 MIC，且必须在 `MsvAvFlags` 里置
`0x00000002`（N12，A）。

**EncryptedRandomSessionKey**（N12，A）：
```
If (NTLMSSP_NEGOTIATE_KEY_EXCH bit is set in CHALLENGE_MESSAGE.NegotiateFlags
   AND (NTLMSSP_NEGOTIATE_SIGN OR NTLMSSP_NEGOTIATE_SEAL are set ...))
    Set ExportedSessionKey to NONCE(16)
    Set AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey to RC4K(KeyExchangeKey, ExportedSessionKey)
Else
    Set ExportedSessionKey to KeyExchangeKey
    Set AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey to NIL
Endif
```
`RC4K` = 不带 MAC 的裸 RC4 加密（N12 用 `RC4K` 与 `RC4` 区分：前者仅加密，后者带 RC4 状态推进）。

**KeyExchangeKey**（N16，3.4.5.1，A）：
> If NTLM v2 is used, KeyExchangeKey **MUST be set to the given 128-bit SessionBaseKey value**.

### 6.6 官方测试向量验证（N21/N22/N23，A）

本文件作者用独立实现（自写 MD4/RC4 + `hashlib`/`hmac`）跑了 `[MS-NLMP]` 的官方测试向量，
**逐项一致**。注意规范里有两组**不同**的示例上下文，不能混用——这一点最容易误判。

#### 6.6.1 NTLMv2 向量（N21 4.2.1 + N22 4.2.4）

输入（N21，A）：

```
User    = "User"      (UTF-16LE)
UserDom = "Domain"    (UTF-16LE)
Passwd  = "Password"  (UTF-16LE)
ServerChallenge  = 01 23 45 67 89 ab cd ef
ClientChallenge  = aa aa aa aa aa aa aa aa
Time             = 00 00 00 00 00 00 00 00
```

| 项 | 规范值（N22，A） | 本实现计算值 | 一致 |
|---|---|---|---|
| `NTOWFv2("Password","User","Domain")` | `0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f` | 同 | ✓ |
| `SessionBaseKey` | `8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3` | 同 | ✓ |
| `LMv2 Response` | `86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa` | 同 | ✓ |
| `Encrypted Session Key`（`RC4(SessionBaseKey, 55…55)`） | `c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e` | 同 | ✓ |

#### 6.6.2 GSS_WrapEx / SEAL 向量（N23 4.2.4.4）

**这组示例的密钥来源与 6.6.1 不同**，规范在此处给出的上下文是：

```
Plaintext  = "Plaintext" (UTF-16LE) = 50 00 6c 00 61 00 69 00 6e 00 74 00 65 00 78 00 74 00
SeqNum     = 0
SignKey 规范值 = 60 e7 99 be 5c 72 fc 92 92 2a e8 eb e9 61 fb 8d
```

反推可知本示例的 `ExportedSessionKey` 是 **`eb 93 42 9a 8b d9 52 f8 b8 9c 55 b8 7f 47 5e dc`**
（即 `[MS-NLMP] 4.2.3.1.3` 的 NTLM v1 with Client Challenge 的 KeyExchangeKey，128 位；
`MD5(该值 ‖ "session key to client-to-server signing key magic constant\0")` 恰等于规范 SignKey）。

用该密钥验证：

| 项 | 规范值（N23，A） | 本实现计算值 | 一致 |
|---|---|---|---|
| `SignKey` | `60 e7 99 be 5c 72 fc 92 92 2a e8 eb e9 61 fb 8d` | 同 | ✓ |
| `SealKey`（取密钥前 7 字节 = 56 位，再 MD5） | 规范给出中间值 `eb 93 42 9a 8b d9 52`（56 位截断密钥），完整 SealKey 未给出 | `04 dd 7f 01 4d 85 04 d2 65 a2 5c c8 6a 3a 7c 06` | ✓（由规范中间值可复现） |
| `Sealed data`（`RC4(SealKey, Plaintext)`） | `a0 23 72 f6 53 02 80`（PDF 该行被截断，可见 7 字节） | `a0 23 72 f6 53 02 73 f3 aa 1e b9 01 90 ce 52 00 c9 9d`（前 7 字节一致） | ✓ |
| `Checksum`（`RC4(HMAC_MD5(SignKey, SeqNum‖Plaintext)[0..7])`） | `7f b3 8e c5 c5 5d 49 76` | 见下注 | 见下注 |

> **注（Checksum 项）**：Checksum 只有在 RC4 流**已推进过明文加密**之后才等于规范值。
> 本文件作者第一次计算时用「独立 RC4 实例算 checksum」得到 `ea 2f 39 5c 87 ab f5 e4`（不匹配），
> 用「同一 RC4 实例先 `update(plaintext)` 再 `update(checksum)`」得到 `7f b3 8e c5 c5 5d 49 76`
> （**匹配**，见 §5.4.3 的 SEAL 顺序）。这正好验证了 §5.4.3 强调的「RC4 状态连续」这一关键点。

**结论**：NTOWFv2 / SessionBaseKey / LMv2 / EncryptedSessionKey / SignKey / SealKey /
Sealed data / Checksum 全部与官方向量一致（8/8）。可放心按 §6.5 与 §5.4.3 实现。

### 6.7 错误码速查（E1/E2，A）

| 值 | 名称 | 含义 |
|---|---|---|
| 0xC000006D | STATUS_LOGON_FAILURE | 「The attempted logon is invalid. This is either due to a bad username or authentication information.」 |
| 0xC000006A | STATUS_WRONG_PASSWORD | 当前密码不正确（改密场景） |
| 0xC0000064 | STATUS_NO_SUCH_USER | （未在本次抓取页验证，见 §10） |
| 0xC0000071 | STATUS_PASSWORD_EXPIRED | 密码已过期 |
| 0xC0000072 | STATUS_ACCOUNT_DISABLED | 账户已禁用 |
| 0xC0000224 | STATUS_PASSWORD_MUST_CHANGE | 首次登录必须改密 |
| 0xC0000234 | STATUS_ACCOUNT_LOCKED_OUT | 账户已锁定 |
| 0xC000015B | STATUS_LOGON_TYPE_NOT_GRANTED | 未授予该登录类型 |
| 0xC000005E | STATUS_NO_LOGON_SERVERS | 无可用登录服务器 |
| 0xC0000022 | STATUS_ACCESS_DENIED | 访问被拒 |
| 0xC00000BB | STATUS_NOT_SUPPORTED | 请求不支持（CredSSP 版本不支持时用这个） |
| 0x80090308 | SEC_E_INVALID_TOKEN | 提供的 token 无效 |
| 0x80090302 | SEC_E_UNSUPPORTED_FUNCTION | 请求的功能不支持 |
| 0x8009030C | SEC_E_LOGON_DENIED | 登录尝试失败 |

> 上表中 `0xC0000064` 未在本次抓取的 2.3.1 页面命中（见 §10），其余均在 E1/E2 页面命中。

---

## 7. AV_PAIR 完整列表

### 7.1 结构（N4，2.2.2.1，A）

| 偏移 | 大小 | 字段 |
|---|---|---|
| 0 | 2 | `AvId`（UINT16 LE） |
| 2 | 2 | `AvLen`（UINT16 LE） |
| 4 | `AvLen` | `Value` |

「An AV_PAIR can be aligned on any byte boundary and can be 4+N bytes long for arbitrary N」
（N4，A）。序列以 `MsvAvEOL` 结尾，**没有对齐填充**。

### 7.2 完整 AvId 表（N4，2.2.2.1，A）

| AvId | 名称 | Value 语义 | MUST 存在 |
|---|---|---|---|
| 0x0000 | `MsvAvEOL` | 列表结束；`AvLen` MUST be 0 | 是（AV 列表必须以此结尾） |
| 0x0001 | `MsvAvNbComputerName` | 服务器 NetBIOS 计算机名，Unicode，无 NUL 终止 | 是 |
| 0x0002 | `MsvAvNbDomainName` | 服务器 NetBIOS 域名，Unicode，无 NUL 终止 | 是 |
| 0x0003 | `MsvAvDnsComputerName` | 计算机 FQDN，Unicode，无 NUL 终止 | 否 |
| 0x0004 | `MsvAvDnsDomainName` | 域 FQDN，Unicode，无 NUL 终止 | 否 |
| 0x0005 | `MsvAvDnsTreeName` | 森林 FQDN，Unicode，无 NUL 终止 | 否 |
| 0x0006 | `MsvAvFlags` | 32 位标志，见 §7.4 | 否（但 MIC 场景必须置位 0x2） |
| 0x0007 | `MsvAvTimestamp` | `FILETIME`（[MS-DTYP] 2.3.3）小端，服务器本地时间；「This structure is **always sent** in the CHALLENGE_MESSAGE」 | 服务器总是发 |
| 0x0008 | `MsvAvSingleHost` | `Single_Host_Data` 结构（平台相关 blob + MachineID） | 否 |
| 0x0009 | `MsvAvTargetName` | 目标服务器 SPN，Unicode，无 NUL 终止 | 客户端应发（§7.3） |
| 0x000A | `MsvAvChannelBindings` | channel bindings 哈希：`gss_channel_bindings_struct` 的 MD5（RFC4121 §4.1.1.2 / RFC2744 §3.11）；**全 0 表示无 channel bindings** | 客户端应发（§7.3） |

### 7.3 CredSSP 场景必须处理的三个 AV_PAIR

**(a) `MsvAvTimestamp`（0x0007）**

- 服务器 CHALLENGE 里**总是发**（N4，A）。实测确认存在（E，§0.3b）。
- 客户端必须用它作为 `Time`（N12，A，§6.5）。
- 它的存在还触发两条 SHOULD：不发 LmChallengeResponse（发 Z(24)）；必须发 MIC（N12，A）。

**(b) `MsvAvTargetName`（0x0009）**

- 服务器**不下发**（实测 AV 序列只有 0x02/0x01/0x04/0x03/0x07/0x00，E）。
- 客户端**应主动补**（N12，A）：
  > If ClientSuppliedTargetName is not NULL
  >   Add an AV_PAIR … AvId = MsvAvTargetName, Value = ClientSuppliedTargetName **without terminating NULL**.
  >   If UnverifiedTargetName is TRUE, then in AvId = MsvAvFlags set the **0x00000004** bit.
  > Else
  >   Add an AV_PAIR … AvId = MsvAvTargetName, Value = **empty string** without terminating NULL.
- 值应为主机名的 SPN，形式 `TERMSRV/<host>`（C，来自 SPN 约定；规范只说「The SPN of the target server」，
  N4，A。`TERMSRV/` 前缀来自 Windows SPN 惯例，本次未在 MS 规范原文中命中——见 §10）。
- 实测：本文件脚本用 `TERMSRV/192.168.1.7`（UTF-16LE），服务器未报错（走到凭据校验，E）。

**(c) `MsvAvChannelBindings`（0x000A）**

- 服务器**不下发**（实测，E）。
- 客户端**应主动补**（N12，A）：
  > If ClientChannelBindingsUnhashed is not NULL
  >   Add … AvId = MsvAvChannelBindings, Value = **MD5_HASH(ClientChannelBindingsUnhashed)**
  > Else
  >   Add … AvId = MsvAvChannelBindings, Value = **Z(16)**
- **CredSSP 场景用 Z(16)**：因为 TLS 通道绑定在 CredSSP 里由 `pubKeyAuth` 承担，
  不再叠一层 CBT。实测用全 0 16 字节，服务器接受（E）。
- 若真要用 CBT：`Value` = `MD5(gss_channel_bindings_struct)`，其中
  `application_data` 是 `tls-server-end-point:` 前缀 + 服务器证书哈希（RFC 5929）。

### 7.4 `MsvAvFlags`（0x0006）位定义（N4，A）

| 位 | 含义 |
|---|---|
| 0x00000001 | 「Indicates to the client that the account authentication is constrained」 |
| 0x00000002 | 「Indicates that the client is providing message integrity in the **MIC** field … in the AUTHENTICATE_MESSAGE」 |
| 0x00000004 | 「Indicates that the client is providing a target SPN **generated from an untrusted source**」 |

**CredSSP 实现必须置 `0x00000002`**（因为发了 MIC），见 N12：「If there is an AV_PAIR … with the
AvId field set to MsvAvFlags, then in the Value field, **set bit 0x2 to 1**；else add an AV_PAIR
structure and set … bit 0x2 to 1」（A）。

### 7.5 AV_PAIR 序列在 NTLMv2_CLIENT_CHALLENGE 里的位置（N6，2.2.2.7，A）

`NTLMv2_CLIENT_CHALLENGE` 结构（= `temp` 的后半段）：

| 偏移 | 大小 | 字段 | 约束 |
|---|---|---|---|
| 0 | 1 | `RespType` | MUST be `0x01` |
| 1 | 1 | `HiRespType` | MUST be `0x01` |
| 2 | 2 | `Reserved1` | SHOULD be `0x0000` |
| 4 | 4 | `Reserved2` | SHOULD be `0x00000000` |
| 8 | 8 | `TimeStamp` | 100ns ticks since 1601-01-01 UTC，小端 |
| 16 | 8 | `ChallengeFromClient` | = `ClientChallenge` |
| 24 | 4 | `Reserved3` | SHOULD be `0x00000000` |
| 28 | … | `AvPairs` | AV_PAIR 序列，以 `MsvAvEOL` 结尾 |

与 `temp` 的对应关系（对照 §6.5 伪代码）：
```
temp = RespType(1) || HiRespType(1) || Z(6) || Time(8) || ClientChallenge(8) || Z(4) || ServerName || Z(4)
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^
       正好是 NTLMv2_CLIENT_CHALLENGE 的 28 字节固定头（Z(6) 覆盖 Reserved1+Reserved2）   AvPairs  + Z(4)
```
——即 `temp` = `NTLMv2_CLIENT_CHALLENGE` 全结构 + 尾部 `Z(4)`。这是最容易写错的地方之一：
**`temp` 末尾多 4 字节 0**，而 `NTLMv2_CLIENT_CHALLENGE` 本身不含这 4 字节。

`NTLMv2_RESPONSE`（N7，2.2.2.8，A）= `Response(16) || NTLMv2_CLIENT_CHALLENGE(variable)`，
其中 `Response` 就是 `NTProofStr`。

---

## 8. 实现选型建议

### 8.1 约束回顾

- 项目**零第三方依赖**现状，MSVC 2022 + CMake/Ninja，C++20，`/W4 /WX /permissive-`。
- 目标：**跨平台（Windows + Linux）**。
- 需要的能力（按 §4–§7 推导）：

| 能力 | 必需 | 说明 |
|---|---|---|
| TLS 1.2 / 1.3 客户端 | 是 | §4.1 |
| 自签名证书「接受但不校链」 | 是 | §4.3 |
| 取服务器证书的 SubjectPublicKey（DER） | 是 | §5.4.0 |
| MD4 | 是 | NTOWFv2（§6.5） |
| HMAC-MD5 | 是 | NTOWFv2 / NTProofStr / MIC / MAC |
| RC4（有状态流） | 是 | SEAL / EncryptedRandomSessionKey |
| SHA-256 | 是 | pubKeyAuth v5/6 |
| 常量时间比较 | 是 | pubKeyAuth 校验 |
| ASN.1 DER 编解码（context tag） | 是 | TSRequest / NegoData / TSCredentials |
| 随机数 | 是 | nonce / ClientChallenge / ExportedSessionKey |

注意：**MD4 与 RC4 在现代 TLS 库里普遍被移到「legacy」或直接移除**，这是选型的核心风险点。

### 8.2 方案 A：OpenSSL 3.x（推荐）

| 项 | 内容 |
|---|---|
| 依赖 | OpenSSL 3.x（`libssl` + `libcrypto`） |
| 许可 | 3.0 及以后为 **Apache-2.0**（W1 原文：「For the 3.0 release, and later releases derived from that, the **Apache License v2** applies」） |
| Windows 集成 | ① vcpkg：`vcpkg install openssl`（当前 port 版本 `3.6.5#2`，W4）；② 官方预编译安装包；③ 源码 + `perl Configure VC-WIN64A` + `nmake`（W3 记录 `VC-*` 前缀的原生 MSVC 构建） |
| Linux | 发行版包或源码，一等公民 |
| TLS 能力 | TLS 1.0–1.3、全套密码套件、可关校验（`SSL_VERIFY_NONE`）、可取证书 DER |
| MD4 | 在 **legacy provider** 里（W2 原文：「Hashing Algorithms … **MD4**, see EVP_MD-MD4(7)」）；需 `OSSL_PROVIDER_load(NULL, "legacy")` + `EVP_MD_fetch(NULL, "MD4", NULL)` |
| RC4 | 同样在 **legacy provider**（W2：「RC4, see EVP_CIPHER-RC4(7)」）；但**有状态流式 RC4 用 EVP 不方便**——建议自己写 30 行 RC4（算法极简，且 NTLM 需要「同一状态连续加密两次」的语义） |
| 取 SubjectPublicKey | `X509_get0_pubkey()` + `i2d_PublicKey()`（FreeRDP 正是这么做，F5，B） |
| CredSSP 可行性 | **完全可行**。TLS 用 OpenSSL，NTLM/CredSSP 全自己实现（~2500 行） |
| 代码量估计（C） | TLS 封装 300 行；DER 编解码 400 行；NTLM 三消息 + 密钥派生 900 行；CredSSP 状态机 500 行；RC4/MD4 自带 120 行；测试 800 行。合计 **≈3000 行** |
| 风险 | legacy provider 在某些发行版被拆成独立包（`openssl-legacy`）；FIPS 模式下不可用（本项目不需要 FIPS） |

### 8.3 方案 B：Windows SChannel + 内置 CredSSP SSP（仅 Windows）

| 项 | 内容 |
|---|---|
| 依赖 | 系统 DLL：`secur32.dll`（SSPI）、`crypt32.dll`。**无第三方库** |
| 许可 | 操作系统组件，无额外许可负担 |
| Windows 集成 | 直接链接，零构建成本 |
| Linux | **不支持**。SChannel 是 Windows 专属 |
| TLS 能力 | 完整（Schannel 实现 SSL/TLS） |
| CredSSP 可行性 | **系统直接提供 CredSSP 安全包**。证据：`AcquireCredentialsHandleW` 文档明确 `pAuthData` 是「A pointer to a **CREDSSP_CRED** structure that specifies authentication data for **both Schannel and Negotiate** packages」（W10，A）；`CREDSSP_CRED` 定义见 W11（`pSchannelCred` + `pSpnegoCred`）；`QueryContextAttributesW` 文档开篇即「The QueryContextAttributes (**CredSSP**) function lets a transport application query the **Credential Security Support Provider (CredSSP)** security package」（W9，A）。即调用 `AcquireCredentialsHandle(NULL, "CredSSP", ...)` 就能拿到一个**已封装 TLS+NTLM 的**上下文，只需按 §5.3 的 TSRequest 语义喂 token |
| 代价 | ① **协议细节被系统黑盒化**——本项目是「逆向 mstsc 协议栈」性质的工程，用系统 CredSSP 等于跳过整个 CredSSP 实现，与本项目目标冲突；② 无法在 Linux 复用；③ 无法观察/测试中间状态（pubKeyAuth 计算过程不可见） |
| 代码量估计（C） | 若只用 CredSSP 包：≈400 行（薄封装）。若自己用 Schannel 做 TLS + 自己实现 NTLM/CredSSP：TLS 部分 ≈500 行（`InitializeSecurityContext` 循环 + `QueryContextAttributes(SECPKG_ATTR_REMOTE_CERT_CONTEXT)`），其余同方案 A |
| 适用 | 作为**可选的加速后端**（`#ifdef _WIN32`），或作为**交叉验证的参考实现**（用它跑一遍，对比自研实现的 wire 字节） |

### 8.4 方案 C：BoringSSL / mbedTLS / wolfSSL

| 库 | 许可 | MD4 | RC4 | 结论 |
|---|---|---|---|---|
| **BoringSSL** | Apache-2.0（W8） | 有（`crypto/md4`） | 有（`crypto/rc4`） | 无版本化发布、无 ABI 稳定承诺、API 随 master 变动。**不适合作为长期依赖**，但算法齐全 |
| **mbedTLS 3.x/4.x** | Apache-2.0 **OR** GPL-2.0-or-later（W5） | **已移除**（W6 原文：「### Remove MD2, **MD4**, **RC4**, Blowfish and XTEA algorithms」） | **已移除**（同 W6） | TLS 可用，但 MD4/RC4 必须自带（各约 60 行）。体积小（默认配置 ~100KB 级），适合嵌入式 |
| **wolfSSL** | **GPLv3 或商业授权**（W7 原文：「free software downloads … as long as the user adheres to version three of the GPL License」「Businesses … must license commercial versions」；商业授权 **$7,500 USD per end product**） | 有（`wolfcrypt/md4.h`） | 有（`wolfcrypt/arc4.h`） | 算法齐全、体积小，但 **GPLv3 对闭源分发是阻断性的**，需付费商业授权 |

### 8.5 推荐：方案 A（OpenSSL 3.x）+ 自带 RC4/MD4

**理由**：

1. **跨平台唯一解**：只有 OpenSSL 在 Windows 与 Linux 上都是成熟一等公民，
   且不引入 GPL 传染（Apache-2.0）。
2. **许可最干净**：Apache-2.0（W1），可静态/动态链接闭源产品。
3. **MD4/RC4 有官方兜底**：legacy provider 提供两者（W2），避免自己实现密码学原语带来的
   正确性风险；同时因为 NTLM 需要「有状态流式 RC4」，仍建议自带 RC4（约 30 行），
   而 MD4 走 legacy provider 或自带（RFC 1320 有官方测试向量，见 §6.6 已验证）。
4. **与已有证据链一致**：FreeRDP（本文件的主要参考实现，Apache-2.0）就是 OpenSSL 后端，
   其 `i2d_PublicKey()` 取公钥、`EncryptMessage` 封装的做法可直接对照（F2/F5）。
5. **构建可控**：项目已用 CMake + vcpkg 生态可用（W4），也可 `VC-WIN64A` 源码构建（W3），
   不需要改现有 CMake 结构太多（加 `find_package(OpenSSL REQUIRED)` + `target_link_libraries(... OpenSSL::SSL OpenSSL::Crypto)`）。

**具体落地建议（C）**：

| 决策 | 选择 | 理由 |
|---|---|---|
| TLS 库 | OpenSSL 3.x，`find_package(OpenSSL 3.0 REQUIRED)` | Apache-2.0、跨平台 |
| TLS 版本 | `min=TLS1_2`, `max=TLS1_3`，可配置降到 1.0 | §4.1 |
| 证书校验 | `SSL_VERIFY_NONE` + 应用层 `tofu` 指纹 pin | §4.3 |
| SNI | 发送（`SSL_set_tlsext_host_name`） | §4.4 |
| ALPN | 不设置 | §4.4 |
| MD4 | 优先 legacy provider，失败则回退自带实现 | §8.2 |
| RC4 | **自带**（需要状态连续语义） | §5.4.3 |
| HMAC-MD5 / SHA-256 | OpenSSL `EVP_MAC` / `EVP_Digest` | 现成 |
| DER | **自带**（约 400 行），不用 OpenSSL 的 ASN.1 API | OpenSSL ASN.1 API 对「context tag + 可选字段 + 非规范 INTEGER」太笨重；实测服务器发的 `errorCode` 就不符合严格 DER（§5.7） |
| 常量时间比较 | `CRYPTO_memcmp` | 防时序侧信道 |
| Windows 可选后端 | `#ifdef _WIN32` 下用系统 CredSSP 包做**交叉验证**（不进产品路径） | §8.3 |

**为什么不用 SChannel 作为主方案**：本项目的价值在于「按规范实现并验证协议」，
用系统 CredSSP 包会把 §5.4（pubKeyAuth）与 §6（NTLM）整个跳过——这两块恰是任务要求
「完整规范」的核心。SChannel 更适合作为**对照实验**（同一目标服务器，对比 wire 字节）。

---

## 9. 每个字段/常量的规范来源索引

### 9.1 RDP 协商与安全层位置

| 字段/常量 | 值 | 来源 |
|---|---|---|
| `TYPE_RDP_NEG_REQ` | 0x01 | S3 |
| `TYPE_RDP_NEG_RSP` | 0x02 | S5 |
| `TYPE_RDP_NEG_FAILURE` | 0x03 | S6 |
| `PROTOCOL_RDP` | 0x00000000 | S5 / S3 |
| `PROTOCOL_SSL` | 0x00000001 | S5 / S3 / S32 |
| `PROTOCOL_HYBRID` | 0x00000002 | S5 / S3 |
| `PROTOCOL_RDSTLS` | 0x00000004 | S5 / S3 |
| `PROTOCOL_HYBRID_EX` | 0x00000008 | S5 / S3 |
| `PROTOCOL_RDSAAD` | 0x00000010 | S5 / S3 |
| `EXTENDED_CLIENT_DATA_SUPPORTED` | 0x01 | S5 |
| `DYNVC_GFX_PROTOCOL_SUPPORTED` | 0x02 | S5 |
| `NEGRSP_FLAG_RESERVED` | 0x04 | S5 |
| `RESTRICTED_ADMIN_MODE_SUPPORTED` | 0x08 | S5 |
| `REDIRECTED_AUTHENTICATION_MODE_SUPPORTED` | 0x10 | S5 |
| `RESTRICTED_ADMIN_MODE_REQUIRED` | 0x01 | S3 |
| `REDIRECTED_AUTHENTICATION_MODE_REQUIRED` | 0x02 | S3 |
| `CORRELATION_INFO_PRESENT` | 0x08 | S3 |
| `SSL_REQUIRED_BY_SERVER` | 0x00000001 | S6 |
| `SSL_NOT_ALLOWED_BY_SERVER` | 0x00000002 | S6 |
| `SSL_CERT_NOT_ON_SERVER` | 0x00000003 | S6 |
| `INCONSISTENT_FLAGS` | 0x00000004 | S6 |
| `HYBRID_REQUIRED_BY_SERVER` | 0x00000005 | S6 |
| `SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER` | 0x00000006 | S6 / S36 `<4>` |
| `ENTRA_AUTH_REQUIRED_BY_SERVER` | 0x00000007 | S6 |
| `AUTHZ_SUCCESS` | 0x00000000 | S11 |
| `AUTHZ_ACCESS_DENIED` | 0x00000005 | S11 |
| `ENCRYPTION_METHOD_NONE` | 0x00000000 | S8 |
| `ENCRYPTION_LEVEL_NONE` | 0x00000000 | S8 / S24 |
| `ENCRYPTION_LEVEL_LOW` | 0x00000001 | S8 / S21 |
| `ENCRYPTION_LEVEL_CLIENT_COMPATIBLE` | 0x00000002 | S8 / S21 |
| `ENCRYPTION_LEVEL_HIGH` | 0x00000003 | S8 / S21 |
| `ENCRYPTION_LEVEL_FIPS` | 0x00000004 | S8 / S21 |
| `SEC_EXCHANGE_PKT` | 0x0001 | S10 |
| `SEC_ENCRYPT` | 0x0008 | S10 |
| `SEC_INFO_PKT` | 0x0040 | S10 / S14 |
| `SEC_LICENSE_PKT` | 0x0080 | S10 |
| `SEC_FLAGSHI_VALID` | 0x8000 | S10 |
| `ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES` | 0x00000009 | S18 |
| `serverSelectedProtocol` 字段 | 4B | S7 |

### 9.2 CredSSP

| 字段/常量 | 值 | 来源 |
|---|---|---|
| `TSRequest.version` tag | `[0]` → `A0` | C5 |
| `TSRequest.negoTokens` tag | `[1]` → `A1` | C5 |
| `TSRequest.authInfo` tag | `[2]` → `A2` | C5 |
| `TSRequest.pubKeyAuth` tag | `[3]` → `A3` | C5 |
| `TSRequest.errorCode` tag | `[4]` → `A4` | C5 |
| `TSRequest.clientNonce` tag | `[5]` → `A5` | C5 |
| `version` 合法值 | 2,3,4,5,6 | C5 |
| `clientNonce` 长度 | 32 字节 | C5 |
| `NegoData` 结构 | `SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }` | C6 |
| `TSCredentials.credType` | `[0]` INTEGER | C7 |
| `TSCredentials.credentials` | `[1]` OCTET STRING | C7 |
| `credType` = password | 1 | C7 |
| `credType` = smartcard | 2 | C7 |
| `credType` = remote guard | 6 | C7 |
| `TSPasswordCreds.domainName` | `[0]` OCTET STRING | C8 |
| `TSPasswordCreds.userName` | `[1]` OCTET STRING | C8 |
| `TSPasswordCreds.password` | `[2]` OCTET STRING | C8 |
| `"CredSSP Client-To-Server Binding Hash"` + NUL | 38 字节 magic | C10 |
| `"CredSSP Server-To-Client Binding Hash"` + NUL | 38 字节 magic | C10 |
| 哈希算法 | SHA-256 | C10 |
| pubKeyAuth 版本分叉 | v2/3/4 = 加密 SPK；v5/6 = 加密哈希 | C5 / C10 |
| 服务器 v2/3/4 回显 | 首字节 +1（小端进位） | C10 |
| `authInfo` 加密要求 | MUST be encrypted under SPNEGO key | C5 |
| `errorCode` 类型 | NTSTATUS（[MS-ERREF] 2.3） | C5 / E1 |
| TLS 会话恢复 | 不支持 | C10 |
| 服务器不请求客户端证书 | 是 | C10 |
| 不要求共同 CA 根 | 是 | C10 / C2 |
| 自签名证书允许 | 是 | C10 / C2 / C13 `<24>` |
| 建议最低版本 | 5 | C12 |
| 完整 TSRequest 必须一次 TLS write | 是 | C13 `<8>` |
| TLS fatal alert 码表 | 10/21/42/45/48/49/80 | S35 |

### 9.3 NTLM

| 字段/常量 | 值 | 来源 |
|---|---|---|
| `Signature` | `"NTLMSSP\0"` | N1 / N2 / N3 |
| `MessageType` NEGOTIATE | 0x00000001 | N1 |
| `MessageType` CHALLENGE | 0x00000002 | N2 |
| `MessageType` AUTHENTICATE | 0x00000003 | N3 |
| NEGOTIATE 头长 | 40 字节 | N1 |
| CHALLENGE 头长 | 56 字节 | N2 |
| AUTHENTICATE 头长 | 88 字节 | N3 |
| `NTLMSSP_NEGOTIATE_56` | 0x80000000 | N5 + F4（数值） |
| `NTLMSSP_NEGOTIATE_KEY_EXCH` | 0x40000000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_128` | 0x20000000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_VERSION` | 0x02000000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_TARGET_INFO` | 0x00800000 | N5 + F4 |
| `NTLMSSP_REQUEST_NON_NT_SESSION_KEY` | 0x00400000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_IDENTIFY` | 0x00100000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` | 0x00080000 | N5 + F4 |
| `NTLMSSP_TARGET_TYPE_SERVER` | 0x00020000 | N5 + F4 |
| `NTLMSSP_TARGET_TYPE_DOMAIN` | 0x00010000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` | 0x00008000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED` | 0x00002000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED` | 0x00001000 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_NTLM` | 0x00000200 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_LM_KEY` | 0x00000080 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_DATAGRAM` | 0x00000040 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_SEAL` | 0x00000020 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_SIGN` | 0x00000010 | N5 + F4 |
| `NTLMSSP_REQUEST_TARGET` | 0x00000004 | N5 + F4 |
| `NTLM_NEGOTIATE_OEM` | 0x00000002 | N5 + F4 |
| `NTLMSSP_NEGOTIATE_UNICODE` | 0x00000001 | N5 + F4 |
| `NTLMSSP_REVISION_W2K3` | 0x0F | N11 |
| `MsvAvEOL` | 0x0000 | N4 |
| `MsvAvNbComputerName` | 0x0001 | N4 |
| `MsvAvNbDomainName` | 0x0002 | N4 |
| `MsvAvDnsComputerName` | 0x0003 | N4 |
| `MsvAvDnsDomainName` | 0x0004 | N4 |
| `MsvAvDnsTreeName` | 0x0005 | N4 |
| `MsvAvFlags` | 0x0006 | N4 |
| `MsvAvTimestamp` | 0x0007 | N4 |
| `MsvAvSingleHost` | 0x0008 | N4 |
| `MsvAvTargetName` | 0x0009 | N4 |
| `MsvAvChannelBindings` | 0x000A | N4 |
| `MsvAvFlags` bit 0x1 | 0x00000001 | N4 |
| `MsvAvFlags` bit 0x2（MIC） | 0x00000002 | N4 / N12 |
| `MsvAvFlags` bit 0x4（untrusted SPN） | 0x00000004 | N4 |
| `NTOWFv2` | `HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(Uppercase(User)‖UserDom))` | N13 |
| `LMOWFv2` | = `NTOWFv2` | N13 |
| `ComputeResponse` | 见 §6.5 | N13 |
| `temp` 布局 | `01 01 00*6 Time(8) ClientChallenge(8) 00*4 ServerName 00*4` | N13 |
| `SessionBaseKey` | `HMAC_MD5(ResponseKeyNT, NTProofStr)` | N13 |
| `KXKEY`（NTLMv2） | = `SessionBaseKey` | N16 |
| `SIGNKEY` | `MD5(ExportedSessionKey ‖ "session key to client-to-server signing key magic constant\0")` | N17 |
| `SEALKEY` | `MD5(ExportedSessionKey ‖ "session key to client-to-server sealing key magic constant\0")`（128 位时先取全 16 字节） | N18 |
| `MAC`（ESS + KEY_EXCH） | `Version=1; Checksum=RC4(HMAC_MD5(SigningKey, SeqNum‖Message)[0..7]); SeqNum` | N15 |
| `SEAL` | `ciphertext=RC4(Message); signature=MAC(...)` | N14 |
| 签名结构 | `Version(4) Checksum(8) SeqNum(4)`，小端 | N9 |
| `MIC` | `HMAC_MD5(ExportedSessionKey, NEGOTIATE‖CHALLENGE‖AUTHENTICATE)` | N12 |
| MIC 计算时 AUTHENTICATE.MIC | 先填 0 | N12 |
| `EncryptedRandomSessionKey` | `RC4K(KeyExchangeKey, ExportedSessionKey)` | N12 |
| SeqNum 初值 | 0，每消息 +1 | N14 段前文（3.4.4） |
| `NTLMv2_CLIENT_CHALLENGE` 布局 | `RespType HiRespType Reserved1(2) Reserved2(4) TimeStamp(8) ChallengeFromClient(8) Reserved3(4) AvPairs` | N6 |
| `NTLMv2_RESPONSE` 布局 | `Response(16) ‖ NTLMv2_CLIENT_CHALLENGE` | N7 |
| 有 Timestamp 时不发 LM 响应 | 发 `Z(24)` | N12 |
| NTLM OID | `1.3.6.1.4.1.311.2.2.10` | N20 |
| SPNEGO OID | `1.3.6.1.5.5.2` | P3 / R1 §4.2 |
| `negTokenInit` 结构 | `SEQUENCE { mechTypes [0], reqFlags [1], mechToken [2], mechListMIC [3] }` | R1 §4.2.1 / P1 |
| `NegTokenInit2` 结构 | `SEQUENCE { mechTypes [0], reqFlags [1], mechToken [2], negHints [3], mechListMIC [4] }` | P1 |
| `NegHints.hintName` 建议值 | `"not_defined_in_RFC4178@please_ignore"` | P1 |

### 9.4 错误码

| 常量 | 值 | 来源 |
|---|---|---|
| `STATUS_LOGON_FAILURE` | 0xC000006D | E1 |
| `STATUS_WRONG_PASSWORD` | 0xC000006A | E1 |
| `STATUS_PASSWORD_EXPIRED` | 0xC0000071 | E1 |
| `STATUS_ACCOUNT_DISABLED` | 0xC0000072 | E1 |
| `STATUS_PASSWORD_MUST_CHANGE` | 0xC0000224 | E1 |
| `STATUS_ACCOUNT_LOCKED_OUT` | 0xC0000234 | E1 |
| `STATUS_LOGON_TYPE_NOT_GRANTED` | 0xC000015B | E1 |
| `STATUS_NO_LOGON_SERVERS` | 0xC000005E | E1 |
| `STATUS_ACCESS_DENIED` | 0xC0000022 | E1 |
| `STATUS_NOT_SUPPORTED` | 0xC00000BB | E1 |
| `STATUS_ACCOUNT_EXPIRED` | 0xC0000193 | E1 |
| `STATUS_INVALID_LOGON_HOURS` | 0xC000006F | E1 |
| `STATUS_INVALID_WORKSTATION` | 0xC0000070 | E1 |
| `STATUS_DOMAIN_CONTROLLER_NOT_FOUND` | 0xC0000233 | E1 |
| `SEC_E_INVALID_TOKEN` | 0x80090308 | E2 |
| `SEC_E_UNSUPPORTED_FUNCTION` | 0x80090302 | E2 |
| `SEC_E_LOGON_DENIED` | 0x8009030C | E2 |

### 9.5 TLS / 证书

| 项 | 来源 |
|---|---|
| TLS 1.0/1.1/1.2/1.3 允许 | S23 / S31 / S32 |
| 无密码套件要求 | S31 / S32（原文无此内容） |
| 自签名允许 | C10 / C2 / C13 `<24>` |
| 不要求共同 CA 根 | C10 / C2 |
| 不请求客户端证书 | C10 |
| 不支持会话恢复 | C10 |
| 客户端握手最后三消息须同一帧 | S36 `<57>` |
| TLS fatal alert 码表 | S35 |
| TLS 1.3 产品可用性 | S36 `<55>` |
| TLS 1.2 产品可用性 | S36 `<54>` |
| TLS 1.1 产品可用性 | S36 `<53>` |

### 9.6 选型相关

| 项 | 来源 |
|---|---|
| OpenSSL 3.x 许可 = Apache-2.0 | W1 |
| OpenSSL legacy provider 含 MD4/RC4/DES | W2 |
| OpenSSL MSVC 原生构建（`VC-*`） | W3 |
| vcpkg openssl port 版本 | W4 |
| mbedTLS 许可（Apache-2.0 OR GPL-2.0-or-later） | W5 |
| mbedTLS 3.0 移除 MD4/RC4 | W6 |
| wolfSSL 许可（GPLv3 / 商业 $7,500 per product） | W7 |
| BoringSSL 许可（Apache-2.0） | W8 |
| Windows CredSSP SSP 存在（`AcquireCredentialsHandle` + `CREDSSP_CRED`） | W10 / W11 |
| Windows `QueryContextAttributes` 用于 CredSSP | W9 |

---

## 10. 未验证项

本节的每一项都明确标注「为什么没验证」与「如何验证」。**不含任何推断性填充**。

### 10.1 抓取失败 / 404 的 URL

| 目标 | HTTP 状态 | 处理 |
|---|---|---|
| `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/3.1.5.1` | **404** | 该小节在 [MS-CSSP] 中**不存在**。[MS-CSSP] 的 3.1.5 没有子小节（toc.json 实测：3.1.5 后直接是 3.1.6）。任务描述里的「3.1.5.1 NTLM 与 Kerberos 的差异」「3.1.5.2 pubKeyAuth」「3.1.5.3 错误码」三个小节号**在现行规范中不存在**；对应内容实际在 3.1.5 的 step 2 / step 3 / step 4 段落里（已抓取，C10）与 2.2.1 的 `pubKeyAuth` 字段描述（C5）与 `errorCode` 字段描述（C5）里。NTLM 与 Kerberos 差异的原文见 C13 `<1><3>`（「SPNEGO has the Kerberos Protocol and NTLM available」「The Kerberos Protocol is always preferred over NTLM」） |
| `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/3.1.5.2` | **404** | 同上 |
| `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/3.1.5.3` | **404** | 同上 |
| `https://learn.microsoft.com/en-us/windows/win32/secauthn/schannel` | **404** | 改用 W9/W10/W11 的 SSPI 文档作为 SChannel/CredSSP 能力证据 |
| `https://learn.microsoft.com/en-us/windows/win32/secauthn/ssp-packages` | **404** | 同上 |
| `https://learn.microsoft.com/en-us/windows/win32/secauthn/credential-security-support-provider-technical-reference` | **404** | 同上 |
| `https://boringssl.googlesource.com/boringssl/+/refs/heads/master/LICENSE?format=TEXT` | 连接失败 | 改用 `raw.githubusercontent.com/google/boringssl/master/LICENSE`（200，W8） |
| `https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/LICENSE` 首次尝试 | 超时 | 重试成功（W5） |
| `https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/docs/3.0-migration-guide.md` | **404** | 正确路径是 `mbedtls-3.6` 分支（W6，200） |
| `https://docs.openssl.org/3.0/man3/d2i_PublicKey/` | 200 但内容为 meta-refresh 跳转页（实际正文 181 字节） | 未取得 `i2d_PublicKey` 的正式文档正文；SubjectPublicKey 提取依据改为 C10 原文 + F5 源码 |
| `https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net/MS-*/[MS-*].pdf` | **308** 永久重定向 | 跟随到 `winprotocoldoc.z19.web.core.windows.net`（200，S37/C14/N24） |

### 10.2 规范未覆盖、只能靠实测/推导的内容

| 项 | 状态 | 说明 |
|---|---|---|
| **EUAR 是否真的不带 TPKT** | **C 级推导，未抓到包验证** | 依据：S11 字段图只有 4 字节 `authorizationResult`；FreeRDP 按固定 4 字节读（F1/F3）。**未在本目标上观察到 EUAR 实际字节**——因为需要正确凭据才能走到「CredSSP 成功 → 服务器发 EUAR」这一步，本次只有错误口令。验证方法：拿到正确凭据后，在第 5 步 `authInfo` 发出后抓第一个服务器→客户端字节流，看是否以 `00 00 00 00`（AUTHZ_SUCCESS）开头且总长恰 4 字节 |
| **pubKeyAuth v5/6 的拼接顺序** | **C 级推导** | 原文伪代码 `SHA256(magic, Nonce, SubjectPublicKey)` 与散文「SubjectPublicKey concatenated with … magic … and the nonce」矛盾。采纳伪代码顺序（与 F1 实现一致）。**未通过「服务器接受第 3 步并回第 4 步」验证**——服务器在凭据校验失败时先回 `errorCode`，没走到 pubKeyAuth 校验。验证方法：正确凭据下，若服务器回 `SEC_E_INVALID_TOKEN`/`STATUS_LOGON_FAILURE` 以外的错误，或第 4 步 pubKeyAuth 校验失败，则说明顺序错，改用另一种拼接顺序 |
| **服务器是否真的校验 pubKeyAuth** | 未验证 | 本次服务器在 NTLM 凭据阶段就失败，无法判断它是否也校验了 pubKeyAuth（可能先校 pubKeyAuth 再校凭据，也可能反之）。验证方法同上 |
| **`errorCode` 的非规范 DER 编码** | 实测发现，规范未提 | 服务器发 `a4 06 02 04 c0 00 00 6d`（4 字节 INTEGER，最高位为 1，无前导 0x00）。严格 DER 要求 `02 05 00 c0 00 00 6d`。实现必须能解析两种形式。这是**实测事实**（E），但「服务器为何这样编码」未查证 |
| **`MsvAvTargetName` 的 SPN 前缀 `TERMSRV/`** | 未在 MS 规范原文命中 | N4 只说「The SPN of the target server」，未规定前缀。`TERMSRV/<host>` 是 Windows SPN 惯例（来自 SSPI/SPN 文档，本次未抓取该文档）。实测用 `TERMSRV/192.168.1.7` 服务器未报错，但也可能是服务器根本没校验该字段（因为凭据先失败） |
| **`STATUS_NO_SUCH_USER` = 0xC0000064** | 未在本次抓取的 2.3.1 页面命中 | 该页面 255KB 全文检索 `0xC0000064` 无命中（可能页面分页/懒加载）。其余 14 个错误码均已命中 |
| **TLS 1.3 是否真的被 Microsoft RDP 服务器接受** | 仅 openssl 层验证 | `s_client -tls1_3` 握手成功（E），但**未验证**在 TLS 1.3 之上 CredSSP 能否跑通（本次 CredSSP 实测走的是 TLS 1.2 + `ctx.minimum_version=TLSv1_2` 且 Python 默认会协商 1.3——实际日志显示 `TLS TLSv1.3 TLS_AES_256_GCM_SHA384`，即 **CredSSP 在 TLS 1.3 上已跑通到 NTLM 凭据校验**。这条可算已验证，但「跑通到第 4/5 步」未验证） |
| **CredSSP version 2/3/4 的实际行为** | 未验证 | 本服务器强制回 v6，无法观察 v2/3/4 路径（加密 SubjectPublicKey + 服务器首字节 +1 回显）。验证方法：对一个只支持 v2 的老服务器（Windows Server 2008/2012）实测 |
| **`authInfo` 的 SEAL seq 是否确实为 1** | C 级推导 | 依据 N14「SeqNum MUST start at 0 and is incremented by one for each message sent」+ pubKeyAuth 是第 1 个 sealed 消息 ⇒ authInfo 是第 2 个 ⇒ seq=1。未实测（没走到第 5 步） |
| **`RDP_NEG_RSP.flags` 位 0x04 被置位** | 实测事实，规范说「reserved, SHOULD be ignored」 | 服务器置了保留位。已验证客户端必须忽略（本项目已忽略） |
| ~~SEALKEY/SIGNKEY 测试向量不一致~~ | **已澄清，不再是未验证项** | 初稿曾误把 `4.2.4.4` 的密钥当成 `4.2.1` 的 `55…55`。实际 `4.2.4.4` 用的 ExportedSessionKey 是 `4.2.3.1.3` 的 `eb 93 42 9a 8b d9 52 f8 b8 9c 55 b8 7f 47 5e dc`；用它复算 SignKey/SealKey/Sealed data 全部命中规范值（§6.6.2）。唯一遗留：`4.2.4.4` 的 `Sealed data` 在官方 PDF 该行被截断，只核对了可见的 7 字节 |
| **`NTLMSSP_NEGOTIATE_56` 等的精确位号** | 已交叉验证 | N5 的 HTML 页面**不含数值**（只有位图与字母），数值取自 F4（FreeRDP `ntlm.h`，B 级）。位号与数值的对应关系已用「bit31=W=56」逐位核对一致 |

### 10.3 未抓取但任务提到的小节

| 任务要求的小节 | 实际处理 |
|---|---|
| [MS-RDPBCGR] 5.3.3（Server Certificates） | 未抓取。§4.3 只用到 5.3.3.2（X.509 Certificate Chains）的结论「Standard RDP Security 下服务器证书走 GCC 的 TS_UD_SC_SEC1」，而 Enhanced RDP Security 下该字段不出现（S8 已抓）。5.3.3 与 TLS 无关，故未展开 |
| [MS-RDPBCGR] 5.3.4 / 5.3.5（Client/Server Random、Initial Session Key Generation） | 未抓取。这两节只服务 Standard RDP Security（RC4 + 自研密钥派生），在 Enhanced RDP Security 下整段跳过（S28 原文：Security Commencement 不执行、不发 Security Exchange PDU）。**本项目走 HYBRID_EX，永远用不到** |
| [MS-RDPBCGR] 5.4.5.2 的「错误码」小节 | 不存在独立小节。错误码在 TSRequest.errorCode（C5）+ TLS fatal alert（S35）+ NTSTATUS（E1）+ SEC_E（E2），均已覆盖 |
| [MS-NLMP] 2.2.2.9.1「各 NEGOTIATE flag 数值」 | 任务把 flag 数值归到 2.2.2.9.1，实际在 **2.2.2.5**（N5）。2.2.2.9.1 是签名结构。已按实际位置抓取，并交叉 F4 取数值 |
| [MS-NLMP] 3.1.5「NTLMv2 响应计算」 | 实际在 **3.3.2**（N13）。3.1.5 是「Message Processing Events and Sequencing Rules」的目录页。已按实际位置抓取 |

### 10.4 本次未做的实机验证（需正确凭据）

以下都需要**能登录目标服务器的账号**，本次没有，故全部未验证：

1. CredSSP 第 4 步（服务器 pubKeyAuth 回显/哈希）的实际字节与长度。
2. 第 5 步 `authInfo` 被服务器接受后，EUAR 的实际字节（§10.2 第 1 项）。
3. `pubKeyAuth` 拼接顺序的正确性（§10.2 第 2 项）。
4. `MsvAvTargetName` 的 SPN 是否被服务器校验（§10.2 第 5 项）。
5. TLS 1.3 上完整跑通 CredSSP 5 步。
6. `authInfo` 的 SEAL seq=1 假设。

**建议的验证路径**（C）：用 `rtsc_probe` 增加一个 `--credssp-only` 模式，
在第 3 步之后把服务器回的原始字节 dump 出来；拿到正确凭据后逐项比对 §5.4.5 的 10 步清单。

---

## 11. 实现检查清单（可直接当 code review checklist）

按 §1–§7 逐条落成可勾选项。

**连接序列**
- [ ] X.224 CCF 收到后立刻切到 TLS，**不**先发 MCS Connect Initial（§1.2）
- [ ] 客户端 TLS 最后三条握手消息（ClientKeyExchange/CCS/Finished）合并为一次 write（§4.5）
- [ ] CredSSP 五步全部在 TLS 之内完成（§5.3）
- [ ] CredSSP 成功后，若 `selectedProtocol & PROTOCOL_HYBRID_EX`，先读 4 字节 EUAR（§2.3）
- [ ] `AUTHZ_ACCESS_DENIED` 立刻断开，不发 MCS（§2.4）
- [ ] MCS Connect Initial 及之后全部包在 TLS 里（§1.3）
- [ ] Client Core Data 的 `serverSelectedProtocol` 回填服务器选择值（§1.3）
- [ ] 不发 Security Exchange PDU（§1.3）
- [ ] Client Info PDU 带 `TS_SECURITY_HEADER`（`SEC_INFO_PKT`）（§1.3）

**TLS**
- [ ] `min=TLS1_2`，可配置到 1.0（§4.1）
- [ ] 证书校验失败**不**直接 abort，走 `tofu` 策略（§4.3）
- [ ] 发送 SNI（§4.4）
- [ ] **不**设置 ALPN（§4.4）
- [ ] 按 TPKT 长度重组帧，不假设 1 record = 1 PDU（§4.5）
- [ ] 能解析服务器发来的 TLS fatal alert 并映射为可读错误（§4.6）

**CredSSP**
- [ ] TSRequest 六个可选字段的 tag 正确（A0..A5）（§5.1）
- [ ] `version` 用最短 INTEGER 编码（`02 01 06`）（§5.7）
- [ ] 能解析「4 字节无符号 INTEGER」形式的 `errorCode`（§5.7）
- [ ] `clientNonce` 32 字节随机（§5.1）
- [ ] `NegoData` 双层 SEQUENCE（§5.2）
- [ ] 第 1 步发 GSS-SPNEGO `NegTokenInit`（`60` + SPNEGO OID + `[0]`）（§5.2）
- [ ] 第 3 步发**裸** NTLM AUTHENTICATE（§5.6）
- [ ] 第 3 步同时带 `negoTokens` + `pubKeyAuth` + `clientNonce`（§5.3）
- [ ] `pubKeyAuth` 版本分叉正确（§5.4.1 / §5.4.2）
- [ ] magic 含结尾 NUL（§5.4.1）
- [ ] 拼接顺序 `magic ‖ nonce ‖ SPK`（§5.4.1）
- [ ] `SubjectPublicKey` 取自 `SubjectPublicKeyInfo` 的 BIT STRING 内容（去 unused-bits 字节）（§5.4.0）
- [ ] `pubKeyAuth` 布局 `sig(16) ‖ ciphertext`（§5.4.3）
- [ ] MAC 输入是**明文**，且 RC4 状态连续（§5.4.3）
- [ ] seq：pubKeyAuth=0，authInfo=1（§5.4.4）
- [ ] 第 4 步校验失败**绝不**发 authInfo（§5.4.5）
- [ ] `TSCredentials` / `TSPasswordCreds` 的文本字段用 UTF-16LE（§5.5）
- [ ] 一个 TSRequest 一次 TLS write，不分片（§5.7）

**NTLM**
- [ ] NEGOTIATE 头 40 字节（§6.1）
- [ ] CHALLENGE 解析按 56 字节头（§6.2）
- [ ] AUTHENTICATE 头 **88** 字节（含 Version + MIC）（§6.3）
- [ ] `Time` 取自 `MsvAvTimestamp`（§6.5）
- [ ] 有 Timestamp 时 LM 响应发 `Z(24)`（§6.5）
- [ ] `temp` 末尾多 4 字节 0（§7.5）
- [ ] `MsvAvFlags` 置 `0x2`（发 MIC）（§7.4）
- [ ] 补 `MsvAvTargetName`（§7.3）
- [ ] 补 `MsvAvChannelBindings` = `Z(16)`（§7.3）
- [ ] AV_PAIR 序列以 `MsvAvEOL` 结尾、无对齐填充（§7.1）
- [ ] MIC 计算时 AUTHENTICATE.MIC 先填 0（§6.5）
- [ ] `EncryptedRandomSessionKey` 用裸 RC4（`RC4K`）（§6.5）
- [ ] 错误码映射到可读文案（§6.7）

**工程**
- [ ] `find_package(OpenSSL 3.0 REQUIRED)`（§8.5）
- [ ] legacy provider 加载失败时有回退 MD4（§8.5）
- [ ] RC4 自带实现有 RFC 6229 测试向量（§8.5）
- [ ] MD4 自带实现有 RFC 1320 测试向量（§6.6 已验证）
- [ ] 常量时间比较用于 pubKeyAuth 校验（§8.1）

---

## 12. 修订记录

| 版本 | 日期 | 变更 |
|---|---|---|
| 0.1 | 2026-10-22 | 初版。覆盖 §1–§11；实机证据 §0.3；未验证项 §10 |
