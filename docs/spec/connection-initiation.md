# 连接初始化阶段规格（证据汇编）

来源：[MS-RDPBCGR]（Microsoft Open Specifications，官方）
- 2.2.1.1 Client X.224 Connection Request PDU
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
- 2.2.1.1.1 RDP Negotiation Request (RDP_NEG_REQ)
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3
- 2.2.1.2 Server X.224 Connection Confirm PDU
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483
- 2.2.1.2.1 RDP Negotiation Response (RDP_NEG_RSP)
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
- 2.2.1.2.2 RDP Negotiation Failure (RDP_NEG_FAILURE)
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761
- 2.2.1.2 CC 注解 dump
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/49095420-c6ef-4256-a262-3800e1e233a7
- 底层：[T123] §8 TPKT、[X224] §13.3 CRQ、§13.4 CCF

---

## 1. TPKT 头（[T123] §8）

| 偏移 | 大小 | 字段 | 值 |
|---|---|---|---|
| 0 | 1 | version | 3 |
| 1 | 1 | reserved | 0 |
| 2 | 2 | length（大端） | 含 4 字节头在内的总长 |

约束：
- length 最小 4；最大 65535（u16 上限）。
- X.224 数据 PDU 载荷上限 65528（65535 - 4 - 3），因 CRQ 不携带 TPDU size 参数，取默认最大 65528。

## 2. X.224 Class 0 TPDU（[X224] §13.3/§13.4）

公共结构：`LI(1) | code(1) | dst-ref(2) | src-ref(2) | class+options(1)` = 7 字节
- LI = 其后续字节数（CRQ/CCF/DR 均为 6）。

| TPDU | code | 说明 |
|---|---|---|
| Connection Request (CRQ) | 0xE0 | 客户端发起，dst-ref=0、src-ref=0、class=0 |
| Connection Confirm (CCF) | 0xD0 | 服务端响应，dst-ref=0、src-ref=0x1234、class=0 |
| Disconnect Request (DR) | 0x80 | 后随 reason(1)，LI=6 |

Data TPDU（DT，用于 MCS Send Data Request 的 `x224Data`）：`02 F0 80`
- LI=2、code=0xF0、TPDU-NR/EOT=0x80（EOT 置位）。

## 3. RDP_NEG_REQ（2.2.1.1.1，8 字节）

| 偏移 | 大小 | 字段 | 值 |
|---|---|---|---|
| 0 | 1 | type | 0x01 (TYPE_RDP_NEG_REQ) |
| 1 | 1 | flags | 见下 |
| 2 | 2 | length | 0x0008 |
| 4 | 4 | requestedProtocols（LE32） | 见下 |

flags：
- 0x01 RESTRICTED_ADMIN_MODE_REQUIRED
- 0x02 REDIRECTED_AUTHENTICATION_MODE_REQUIRED
- 0x08 CORRELATION_INFO_PRESENT

requestedProtocols：
- 0x00000000 PROTOCOL_RDP（标准 RDP 安全）
- 0x00000001 PROTOCOL_SSL（TLS）
- 0x00000002 PROTOCOL_HYBRID（CredSSP/NLA；SHOULD 同时置 SSL）
- 0x00000004 PROTOCOL_RDSTLS
- 0x00000008 PROTOCOL_HYBRID_EX（CredSSP + Early User Auth Result）
- 0x00000010 PROTOCOL_RDSAAD（Entra ID）

## 4. RDP_NEG_RSP（2.2.1.2.1，8 字节）

| 偏移 | 大小 | 字段 | 值 |
|---|---|---|---|
| 0 | 1 | type | 0x02 (TYPE_RDP_NEG_RSP) |
| 1 | 1 | flags | 见下 |
| 2 | 2 | length | 0x0008 |
| 4 | 4 | selectedProtocol（LE32） | 同 requestedProtocols 取值 |

flags：
- 0x01 EXTENDED_CLIENT_DATA_SUPPORTED
- 0x02 DYNVC_GFX_PROTOCOL_SUPPORTED
- 0x04 NEGRSP_FLAG_RESERVED（客户端 SHOULD 忽略）
- 0x08 RESTRICTED_ADMIN_MODE_SUPPORTED
- 0x10 REDIRECTED_AUTHENTICATION_MODE_SUPPORTED

## 5. RDP_NEG_FAILURE（2.2.1.2.2，8 字节）

| 偏移 | 大小 | 字段 | 值 |
|---|---|---|---|
| 0 | 1 | type | 0x03 (TYPE_RDP_NEG_FAILURE) |
| 1 | 1 | flags | 0x00 |
| 2 | 2 | length | 0x0008 |
| 4 | 4 | failureCode（LE32） | 见下 |

failureCode：
- 0x01 SSL_REQUIRED_BY_SERVER
- 0x02 SSL_NOT_ALLOWED_BY_SERVER
- 0x03 SSL_CERT_NOT_ON_SERVER
- 0x04 INCONSISTENT_FLAGS
- 0x05 HYBRID_REQUIRED_BY_SERVER
- 0x06 SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER
- 0x07 ENTRA_AUTH_REQUIRED_BY_SERVER

## 6. 官方 CC 注解 dump（可作固定测试向量）

```
03 00 00 13   TPKT: version=3 reserved=0 length=0x0013=19
0e            X.224 LI = 14
d0            X.224 code = CC
00 00         dst-ref = 0
12 34         src-ref = 0x1234
00            class/options = 0
02            RDP_NEG type = TYPE_RDP_NEG_RSP
00            flags = 0
08 00         length = 8
00 00 00 00   selectedProtocol = PROTOCOL_RDP
```
总长 19 字节，LI=14 对应其后 14 字节（6 + 8）。

## 7. 客户端行为约束（2.2.1.2 处理规则）

- TPKT 内部长度必须与实际数据一致，不一致 SHOULD 断链。
- CCF 的 dst-ref/src-ref/class 可忽略。
- rdpNegData 缺失 → 隐含 PROTOCOL_RDP。
- rdpNegData 存在但非 RSP/FAILURE → SHOULD 断链。
- 收到 FAILURE → 提取 failureCode 后 SHOULD 断链。
- 选定 PROTOCOL_RDP 后：可直接继续，或断开重连且只请求 PROTOCOL_RDP。
- routingToken 与 cookie 互斥（二者不可同时出现）。
- CORRELATION_INFO_PRESENT(0x08) 置位时，rdpCorrelationInfo(36B) 必须存在；未置位时必须不存在。
