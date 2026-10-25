# S10 实测裁决：`Handshake` 的 `consumed = in_size` 是否丢字节

生成方式：主代理独立探针 `F:\rtsc\.tmp\probe_s10_main\probe_s10.cpp`（不引用产品代码，
按 `src/net/tls_schannel.cpp:114-167` 的调用形状重写），实跑输出见本文末。

## 1. 被测断言

`src/net/tls_schannel.cpp:164-167`：

```
// Handshake input is fully absorbed: SChannel's stream handshake does
// not report EXTRA, and leaving bytes unconsumed would make the caller
// replay them forever.
consumed = in_size;
```

`docs/spec/tls-backend.design-a.md:513` 的契约要求：
「**只**丢弃前 `consumed` 字节，剩余 `in_size-consumed` 必须保留到下一轮」。

两者冲突。审计甲把这条列为 **S10（P1，未实测）**，并标注「必须实测裁决（U1）」。

## 2. 实验构造（保真度）

| 要素 | 做法 | 保真度 |
|---|---|---|
| 真实 SChannel 服务端 | `AcquireCredentialsHandleW(SECPKG_CRED_INBOUND)` + `AcceptSecurityContext` | 真实 SSPI，非模拟 |
| 自签证书 | `CertStrToNameA` + `CertCreateSelfSignCertificate(0, ...)`，与 `tests/test_tls.cpp:136-151` 同一构造 | 真实证书 |
| 协议版本 | `SP_PROT_TLS1_2_SERVER` / `SP_PROT_TLS1_2_CLIENT` | TLS 1.2，与回环测试一致 |
| 应用记录 | `QueryContextAttributesW(SECPKG_ATTR_STREAM_SIZES)` 取 hdr=13/trl=16，再 `EncryptMessage`（st=0x0） | **真实加密记录**，非占位字节 |
| 合段 | `combined = CCS+Finished(51B) ‖ app record(36B)` = 87B，一次 `InitializeSecurityContextW` | 模拟「同一 TCP 段到达」 |

**第一版实验作废**：我最初用全 `SECBUFFER_EMPTY` 描述符调 `EncryptMessage`，返回
`SEC_E_ENCRYPT_FAILURE (0x80090329)`，尾随 7 字节是明文占位，不是有效记录。
该版本虽也得到 `extra=0`，但**不能证明「有效应用数据被丢弃」**，故重做。
（这正是「变异被检出 ≠ 检查机制生效」的同类问题：实验跑出了预期结论，但实验本身无效。）

## 3. 实测结果

```
flight1 client st=0x00090312 (SEC_I_CONTINUE_NEEDED) out=165
flight2 server st=0x00090312 out=782
flight3 client st=0x00090312 out=158
flight4 server st=0x00000000 (SEC_E_OK) out=51        <- CCS + Finished
server QueryContextAttributes(streamSizes) st=0x0 hdr=13 trl=16 max=16384
server EncryptMessage st=0x0 hdr=13 data=7 trl=16
app record assembled: 36 bytes (valid: EncryptMessage OK)

combined buffer = Finished(51) + app(36) = 87 bytes
combined head: 14 03 03 00 01 01 | 16 03 03 00 28 ...
               ^^ CCS(6)        ^^ Finished 记录头(40 payload)

  [ISC] st=0x00000000 in=87 cBuffers=1 types={2,87} out=0
CLIENT FINAL st=0x0 consumed=87 extra=0 left=0 out=0
DecryptMessage(app record alone) st=0x00000000 plain=7
```

## 4. 结论

**S10 成立，且比审计描述的更精确。**

1. **ISC 路径确实不报 `EXTRA`**：`in_desc.cBuffers` 仍是 1，`in_bufs[0].BufferType` 仍是
   `SECBUFFER_TOKEN (2)`，`extra=0`。所以设计文档要求的
   `consumed = in_size - Σ(EXTRA.cbBuffer)` 在这个场景下**算出来仍然等于 `in_size`**
   —— **算术修正救不了这条**。
2. **`consumed = in_size` 会让调用方丢弃 36 字节有效密文**。TLS 1.2 下服务端在 Finished
   之后立即发应用数据是合法的，同一 TCP 段到达完全可能。
3. **关键补充（审计未提）**：`DecryptMessage(app record alone)` 返回 `SEC_E_OK, plain=7`。
   说明 SChannel **没有**把那条应用记录当作握手数据处理掉，接收序号也没前进——
   **密文仍然可解，只是调用方手里已经没有了**（因为它按 `consumed=87` 全丢了）。

   这排除了「SChannel 内部已消化」这一更糟的可能，也说明修复是可行的：
   **只要安全层不把应用数据喂给 ISC，就不会丢。**

## 5. 修复方向（由实测直接推出，不是猜测）

`consumed = in_size` 与 `consumed = in_size - Σ(EXTRA)` 都不可靠，因为 ISC 在
「握手记录 + 应用记录」合段时**不告诉**我们分界在哪。

唯一可靠的判定是**按 TLS 记录自行切分**：
- 握手期只把**完整握手记录**（`ContentType = 20/21/22`）喂给 ISC；
- `ContentType = 23`（application_data）的记录**留在自己的缓冲里**，等握手完成后交给
  `DecryptMessage`。

这条要求安全层或 TLS 后端具备「按记录头切分」的能力。`tls_schannel.cpp` 的
`Receive` 已经有这个能力（`:247-270` 按 `record_size` 精确切分），但 `Handshake`
没有。**最小修复**：`Handshake` 也用同一套记录切分，遇到 `ContentType=23` 就停止
喂入并把剩余字节留在 `rx_buffer_`，`consumed` 只报真正喂进去的长度。

## 6. 局限

- 只测了 TLS 1.2。TLS 1.3 下 `Finished` 之后服务端通常先发 `NewSessionTicket`
  （被 SChannel 报成 `SEC_I_RENEGOTIATE`），分界行为可能不同，**未测**。
- 只测了「一条应用记录」合段，未测多条。
- 未测客户端方向（`Send` 是否也有同类问题）。
