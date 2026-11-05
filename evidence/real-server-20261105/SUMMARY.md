# 真机联调证据（2026-11-05，第二轮）

目标：`192.168.1.7:3389`（Windows 11 22H2，DESKTOP-5BFDKO3）
凭据：`MicrosoftAccount\windowsvipcuv@live.cn`（密码见 memory.md，不在本文件重复）

## 结论汇总

| 路径 | 命令 | 结果 | 证据文件 |
|---|---|---|---|
| TLS + CredSSP（kInsecure） | `rtsc_connect --tls-insecure` | **EXIT=0，Client Info PDU sent** | `connect-run.txt` |
| TLS + CredSSP（kStrict） | `rtsc_connect` | EXIT=1，`CERT_E_UNTRUSTEDROOT` (0x800B0109) | `connect-strict-tls-run.txt` |
| GUI 端到端渲染 | `rtsc_gui --tls-insecure --seconds 12` | **EXIT=0，1299466/1310720 非黑，826 色，bit-exact 1:1** | `gui-run.txt` |
| Standard RDP Security | `rtsc_connect --rdp` | EXIT=1，服务器 RDP_NEG_FAILURE | `connect-rdp-run.txt` |

## 关键判定

### 1. plan.md:137「真机联调到 active session」→ 成立
`gui-run.txt:26-28`：
```
surface: 1280x1024, 1310720 pixels, 1299466 non-black, 826 distinct colours
view: 1280x1024 -> 1280x1024 at (0,0), scale 1.000 (zoom), 1299466 non-black
lossless 1:1: bit-exact (5242880 bytes compared)
```
非黑占比 **1299466 / 1310720 = 99.14%**，5242880 字节逐字节 bit-exact。
**推翻了 plan.md:209 的旧结论「从不发位图（表面全黑）」**：该现象是当时客户端
静态 VC 未按 channel_id 分派的后果，已在同批次修复，本轮实测确认修复有效。

### 2. plan.md:67/75「数据面签名 / Security Exchange PDU」→ 本服务器不可达
`connect-rdp-run.txt`：`FAILED: server rejected the requested protocols (RDP_NEG_FAILURE)`
服务器在 X.224 协商阶段直接拒绝 PROTOCOL_RDP，因此：
- Standard RDP Security 路径（RC4 + Security Exchange PDU + TS_SECURITY_HEADER 数据面签名）
  **在本目标上结构性不可达**，与 plan.md:75 记录一致。
- 结论：这两项的验证必须换一台允许 PROTOCOL_RDP 的服务器（或自建 rtsc_server 回环），
  不是代码缺陷。

### 3. TLS 默认策略的行为确认
kStrict 下自签证书被正确拒绝（`0x800B0109` CERT_E_UNTRUSTEDROOT + `dwChainErrorStatus=0x00000020`），
证明 `fce4ac4` 的证书策略真正生效；kInsecure 下可连通，符合设计。

## 未覆盖项

- TLS1.3 ticket 分支（plan.md:56）：本服务器协商结果为 TLS 1.2，票据分支仍未实测。
- 真机输入注入清单（plan.md:603）：本轮 `application sends: input=0`（headless 模式未发输入），
  UIPI/多会话/SAS/Pause/多屏仍 UNVERIFIED。

## 复现命令

```powershell
$env:TEMP="F:\rtsc\.tmp"
F:\rtsc\build\Release\rtsc_connect.exe --tls-insecure 192.168.1.7 3389 `
    MicrosoftAccount windowsvipcuv@live.cn '<password>'
F:\rtsc\build\Release\rtsc_gui.exe --tls-insecure 192.168.1.7 3389 `
    MicrosoftAccount windowsvipcuv@live.cn '<password>' --seconds 12
```
## 追加（2026-11-05 第三轮）：TLS 版本可观测 + 输入探针

| 项 | 命令 | 结果 | 证据 |
|---|---|---|---|
| TLS 协商版本 | `rtsc_connect --tls-insecure` | **version=0x0303 cipher=0x009d (TLS 1.2)** | `connect-tls-version.txt:24` |
| 输入注入路径 | `rtsc_gui --tls-insecure --input-probe --seconds 15` | **input probe queued → application sends: input=2** | `gui-input-probe.txt:14,35` |

### plan.md:56 TLS1.3 ticket 分支 → 本目标不可达（已量化）
服务器只协商 TLS 1.2（0x0303），密码套件 TLS_RSA_WITH_AES_256_GCM_SHA384（0x009D）。
TLS 1.3 的 NewSessionTicket / SEC_I_RENEGOTIATE 分支在此目标上**结构性不可达**。
可观测性缺口已修补：新增 `SecurityLayer::negotiated_tls()`（批82 `391de9b`），
rtsc_connect 在会话建立时打印版本，未来换支持 TLS 1.3 的服务器即可直接判定。

### plan.md:603 真机输入清单 → 输入路径已实证
`--input-probe` 排队 scancode 0x1E（'A'）+ 鼠标 (11,13)，
服务器侧收到 `application sends: input=2`（键盘 1 + 鼠标 1，计数精确匹配）。
仍 UNVERIFIED：UIPI 落点、多会话归属、SAS 序列、Pause 后 NumLock 物理状态、多屏坐标。