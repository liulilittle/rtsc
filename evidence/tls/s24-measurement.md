# S24 实测：`Shutdown()` 发出的是重协商请求，不是 close_notify

生成方式：主代理独立探针 `F:\rtsc\.tmp\probe_s24p\probe_s24p.cpp`，
**链接真实产品库 `build\verify\rtsc_tls.lib`**（被测代码是产品代码，不是重写）。

## 1. 被测断言

`include/rtsc/net/tls.h:178-180` 承诺：

```
// ---- graceful close -----------------------------------------------------
// Idempotent: repeated calls return kOk with an empty `out`.
virtual Error Shutdown(std::vector<uint8_t>& out) = 0;
```

`src/net/tls_schannel.cpp:401-434` 的实现：

```
409:        SecBuffer token{0, SECBUFFER_TOKEN, nullptr};
410:        SecBufferDesc desc{SECBUFFER_VERSION, 1, &token};
411:        ApplyControlToken(&ctx_, &desc);          <- 返回值被丢弃
...
419:        const SECURITY_STATUS st =
420:            InitializeSecurityContextW(&cred_, &ctx_, nullptr, req, 0, ...
```

## 2. 实测结果（真实产品库）

```
handshake complete

Shutdown -> status=0 native=0x00090312 out=201 bytes
  record type = 22 (Handshake), version = 0303, length = 196
  head: 16 03 03 00 c4 00 00 00 00 00 00 00
  closed() = true
Shutdown again -> status=0 out=0 bytes (test asserts out non-empty)
```

对照探针（同一进程内手写两种调用形状）：

```
PRODUCT SHAPE (SecBuffer{0, TOKEN, nullptr})
  ApplyControlToken -> 0x80090302 (FAILED)
  ISC               -> 0x80090318
  out = 0 bytes

CORRECT SHAPE (SecBuffer{4, TOKEN, &SCHANNEL_SHUTDOWN})
  ApplyControlToken -> 0x00000000 (SEC_E_OK)
  ISC               -> 0x00000000
  out = 31 bytes
  record type = 21 (Alert), version = 0303, length = 26
  head: 15 03 03 00 1a 00 00 00 00 00 00 00
```

## 3. 结论

**S24 成立**：产品 `Shutdown()` 发出 **type=22（Handshake）** 的 201 字节记录，
即**重协商请求**，而不是 close_notify（type=21，31 字节）。

根因链条：
1. `:409` 构造 `SecBuffer{0, SECBUFFER_TOKEN, nullptr}` —— `cbBuffer=0`、`pvBuffer=NULL`。
2. Microsoft 要求该缓冲区携带一个 `DWORD` 等于 `SCHANNEL_SHUTDOWN`（值 1）。
   `cbBuffer=0` 时 `ApplyControlToken` 失败（探针实测 `0x80090302` `SEC_E_UNSUPPORTED_FUNCTION`）。
3. `:411` **丢弃**该返回值，继续调 `InitializeSecurityContext`。
4. 因为关闭没有被登记，ISC 把这次调用当成**重协商发起**，返回
   `SEC_I_CONTINUE_NEEDED (0x00090312)` 并产出一条 Handshake 记录。
5. `:429` 的 `st == SEC_I_CONTINUE_NEEDED` 分支把状态报成 `kOk` 并置 `closed_ = true`。

**影响**：`Shutdown()` 声称 graceful close，实际请求重协商。而 RDP 禁止重协商
（`tls_schannel.cpp:291`/`:317` 都把 `SEC_I_RENEGOTIATE` 判为 `kProtocolError`），
所以对端很可能直接报协议错误断开。

## 4. 为什么一直没发现

`tests/test_tls.cpp:848` 的 `shutdown_is_idempotent` **只断言 `out` 非空**，没有断言
record type。201 字节非空、31 字节也非空 —— 测试无法区分「正确关闭」与「重协商请求」。

这与 memory 中「门禁通过 ≠ 覆盖」是同一类问题：断言太弱，恰好被错误的实现满足。

## 5. 主代理探针的一处自我修正

我第一版探针（`probe_s24.cpp`，手写两种形状）得到 **PRODUCT SHAPE → out=0 字节**，
与甲报告的「out=201, type=22」不一致。原因是我手写的客户端上下文与产品上下文不同：
产品在握手期走了 `ISC_REQ_ALLOCATE_MEMORY` 等路径，上下文内部状态不同，
所以同样的错误调用在两边产生了不同后果（0 字节 vs 201 字节重协商）。

**教训**：被测对象是产品代码时，必须链接产品库，不能用手写副本代替。
手写副本只能用于「验证某个 API 语义」（如 `SCHANNEL_SHUTDOWN` 要 4 字节），
不能用于「验证产品行为」。

## 6. 修复方向

`src/net/tls_schannel.cpp:409-411` 改为：

```cpp
DWORD type = SCHANNEL_SHUTDOWN;
SecBuffer token{sizeof(type), SECBUFFER_TOKEN, &type};
SecBufferDesc desc{SECBUFFER_VERSION, 1, &token};
const SECURITY_STATUS act = ApplyControlToken(&ctx_, &desc);
if (act != SEC_E_OK) {
    // Surface the failure instead of silently emitting a renegotiation.
    ...
}
```

并**检查 `ApplyControlToken` 返回值**。

## 7. 局限

- 只测了 TLS 1.2。
- 未测真实 RDP 服务器收到真 close_notify 后的断开时序（甲的 U-N3）。
- 未验证修复后 `shutdown_is_idempotent` 是否仍绿（甲的 U-N2）。
- `native_code` 被报成 `0x00090312` 而非 0 —— 这是 `Shutdown` 的另一处信息泄漏，
  未在甲的清单里，**建议单列或并入 S24**。
