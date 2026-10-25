# N6 实测：TPKT 长度上限的 3 字节缝隙

主代理独立验算，源文件：

- `include/rtsc/proto/tpkt.h:15` — `kMaxLength = 0xFFFF`
- `include/rtsc/proto/tpkt.h:18` — `kMaxPayload = 65528`
- `src/proto/framing.cpp:100` — `if (size > TpktHeader::kMaxPayload) return {};`
- `src/proto/framing.cpp:78` — `if (length < kMinTpktLength)`，`length` 为 `uint16_t`
- `src/proto/framing.cpp:86` — `payload.assign(... read_ + kTpktHeaderSize, ... read_ + length)`

## 1. 两个上限的定义

`TpktStream::Next` 从 4 字节头的 `length` 字段（`uint16_t`）算出 payload 长度：
`payload = length - 4`，`length` 最大 `0xFFFF` → **payload 最大 65531**。

`WrapTpkt` 显式拒绝 `size > kMaxPayload`，而 `kMaxPayload = 65528` → **payload 最大 65528**。

## 2. 验算

```
TpktStream max payload : 65531
WrapTpkt   max payload : 65528
gap                    : 3 bytes

payload 65528  TpktStream True  WrapTpkt True
payload 65529  TpktStream True  WrapTpkt False  <- MISMATCH
payload 65530  TpktStream True  WrapTpkt False  <- MISMATCH
payload 65531  TpktStream True  WrapTpkt False  <- MISMATCH
payload 65532  TpktStream False WrapTpkt False
```

## 3. 结论

**N6 成立**：payload 长度 65529–65531 的帧能被 `TpktStream` 正常取出，但 `WrapTpkt`
会返回空 vector。

### 为什么 `kMaxPayload = 65528` 而不是 65531

65528 是一个**实现选择**（可能是为了给某个上层协议留 3 字节余量），不是 TPKT 的物理上限。
TPKT 的物理上限由 16 位长度字段决定，即 65531。

### 对修复的影响

安全层若用 `WrapTpkt` 把「剥了头的 payload」还原成「带头的完整帧」交给
`ConnectMachine::OnData`（这是 S3 的修法），则**必须**检查 `WrapTpkt` 返回空并报
`kProtocolViolation`。不能假设「服务器不会发这么大的帧」——MCS Connect Response
理论上可以接近这个尺寸。

**这是一条真实的分支**，不是理论洁癖：`WrapTpkt` 的空返回值如果不检查，会变成一个
零长度帧送进 `OnData`，产生与真实原因无关的解析错误。

## 4. 局限

- 只做了算术验算，未构造 65529 字节的真实帧跑端到端。
- 未确认 65528 这个数字的历史来源（可能是某个旧版本协议的余量）。
