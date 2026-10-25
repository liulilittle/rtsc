# S19 实测：TLS1.3-only 凭据获取失败

主代理独立探针 `F:\rtsc\.tmp\probe_s19\probe_s19.cpp`（不引用产品代码，直接按
`src/net/tls_schannel.cpp:462-475` `ProtocolMask()` 产出的掩码调
`AcquireCredentialsHandleW`）。

## 1. 被测断言

`src/net/tls_schannel.cpp:462-475`：

```
DWORD ProtocolMask() const {
    DWORD mask = 0;
    if (config_.allow_tls10) mask |= SP_PROT_TLS1_0_CLIENT;
    if (config_.min_version <= kTls12 && config_.max_version >= kTls12) {
        mask |= SP_PROT_TLS1_2_CLIENT;
    }
    if (config_.allow_tls13 && config_.max_version >= kTls13) {
        mask |= SP_PROT_TLS1_3_CLIENT;
    }
    if (mask == 0) mask = SP_PROT_TLS1_2_CLIENT;
    return mask;
}
```

当 `min_version = max_version = 0x0304`（只允许 TLS 1.3）时，掩码只含
`SP_PROT_TLS1_3_CLIENT`。

## 2. 实测结果

```
SP_PROT_TLS1_3_CLIENT = 0x00002000
SP_PROT_TLS1_2_CLIENT = 0x00000800
tls1.2 only       mask=0x00000800 -> 0x00000000 OK
tls1.3 only       mask=0x00002000 -> 0x80090331 FAIL
tls1.2|tls1.3     mask=0x00002800 -> 0x00000000 OK
tls1.0|1.2|1.3    mask=0x00002880 -> 0x00000000 OK
SEC_E_ALGORITHM_MISMATCH = 0x80090331
```

## 3. 结论

**S19 成立**：只请求 `SP_PROT_TLS1_3_CLIENT` 时 `AcquireCredentialsHandleW` 返回
`SEC_E_ALGORITHM_MISMATCH (0x80090331)`，后端在 `CreateTlsTransport` 阶段就失败，
**握手根本不会开始**。

只要掩码里同时含 1.2（`0x2800`）就正常，所以这不是「TLS 1.3 不可用」，而是
**SChannel 不接受「仅 1.3」的客户端凭据请求**。

## 4. 现有测试为何没发现

`tests/test_tls.cpp:877-885`：

```
Loopback lb;
std::string why;
const bool started = lb.Start(cfg, why);
if (!started) {
    // Either the backend refused up front or the handshake failed: both are
    // acceptable, silently succeeding with 1.2 is not.
    CHECK(!why.empty());
    return;
}
NegotiatedInfo info{};
CHECK(lb.client().negotiated(info).ok());
CHECK_EQ(info.tls_version, static_cast<uint16_t>(0x0304));
```

`Start` 失败就 `return`，**TLS1.3 的真实协商路径从未被执行**。该用例的注释甚至
写明「backend refused up front ... acceptable」——它把「后端一开始就拒绝」当成了
合法结果，于是 S19 被永久掩盖。

## 5. 与 memory 中既有教训的关系

这正是 memory 规则「门禁通过 ≠ 覆盖」与「变异被检出 ≠ 检查机制生效」的又一实例：
一个**永远走不到断言**的测试，其绿色不提供任何信息。

修法方向（不是结论，待定案）：
- 让 `ProtocolMask()` 在只请求 1.3 时**同时带上 1.2**（因为 `grbitEnabledProtocols`
  是白名单，加上 1.2 后仍由握手后的版本自检拒绝 1.2），或
- 明确拒绝「仅 1.3」的配置并给出可诊断错误，同时**测试改为断言这条拒绝**（而不是
  把任何失败都当通过）。

两条都要求测试区分「预期拒绝」与「意外失败」。

## 6. 局限

- 只在 Windows SDK 10.0.26100 + 本机 SChannel 上测过。
- 未测 `ASC_REQ`（服务端方向）是否有同样限制。
- 未测 `SCH_CREDENTIALS`（新式 API）下是否仍然如此；本项目用的是 `SCHANNEL_CRED`。
