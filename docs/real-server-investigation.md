# 真机联调调查报告（192.168.1.7:3389）

状态：**阻塞于凭据/账户侧**（与本代码库无关）。本文件记录调查证据与结论，供后续续做。

## 1. 环境

- 服务器：`192.168.1.7:3389`（Windows 11 22H2，机器名 `DESKTOP-5BFDKO3`）
- 客户端：`F:\rtsc`（RTSC，C++ 跨平台 RDP 客户端）
- 账号（用户提供）：`MicrosoftAccount\windowsvipcuv@live.cn`，密码 `yy520o!`
- 观察：`net user windowsvipcuv` 无输出 → 该账号是 **Microsoft Account，不在本地 SAM**；服务器需**联网**校验 MSA。
  `net localgroup "Remote Desktop Users"` → 成员为空。

## 2. 客户端到达的阶段（协议层面**全部走通**）

```
sent X.224 Connection Request (42 bytes)
round 0: recv 19,  send 147   phase=await-external-security, protocol=0x00000008  (HYBRID_EX)
round 1: recv 846, send 318   ← TLS 握手
round 2: recv 51,  send 86    ← CredSSP TSRequest #1
round 3: recv 291, send 614   ← 我们发出 NTLM AUTHENTICATE（含 MIC）
FAILED: CredSSP error: server reported an error (ntstatus 0xC000006D)
```

→ **X.224 / MCS / TLS / CredSSP 通道全部建立**；失败点是**服务器拒绝 NTLM 凭据**（`STATUS_LOGON_FAILURE`）。

## 3. 关键判定：不是我们的代码

| 假设 | 结论 | 证据 |
|---|---|---|
| NTLMv2 计算/消息构造错误 | **否** | Python 按 [MS-NLMP] 复算 `nt_response`/`session_base_key`/`lm_response`/`MIC` 与 C++ 输出**逐字节一致**；`auth.flags` 与 Microsoft NTLMSSP 生成**完全相同**；`NTOWFv2` 与 MS 逐字节相同 |
| 我们的 AUTHENTICATE 消息无效 | **否** | 把 rtsc 产出的 AUTHENTICATE 喂给 **Microsoft `msv1_0!AcceptSecurityContext`**：正确密码 `ACCEPTED(0x0)`、错误密码/用户 `SEC_E_LOGON_DENIED(0x8009030C)` |
| MIC 缺失 | **否** | 服务器 CHALLENGE 实测含 `MsvAvTimestamp`；我们**确实发 MIC**（`have_timestamp=1`、auth len=430、MIC 非零） |
| CBT 置零 / 缺 TargetName | **非根因** | 已修复为真实 CBT + SPN，**真机 NTSTATUS 未变**（仍 `0xC000006D`） |
| **凭据/账户本身** | **是** | **Windows 自带 mstsc 以同一凭据登录同样失败**（「你的凭据不工作 / 登录没有成功」）；OS 自带 NTLM `net use \\192.168.1.7\IPC$ /user:MicrosoftAccount\...` → **1326（用户名或密码不正确）** |

## 4. 已排除的凭据假设

- `o` vs `0`（字母/数字歧义）：`yy520o!` 与 `yy5200!` **均** `0xC000006D`。
- 域格式：空域 → `NTLMv2 computation failed`；`MicrosoftAccount` → `0xC000006D`（域格式正确）。
- OS 级 NTLM：`net use` → 1326（**独立于 rtsc**）。

## 5. 待确认（需服务器/账户侧信息）

1. 密码逐字符（是否还有其它歧义：大小写、末位符号、首尾空格）。
2. **Microsoft Account 是否需联网校验**：服务器能否访问 Internet；MSA 登录 RDP 通常需服务器联机。
3. 账户**是否被锁**：多次失败尝试可能触发锁定（调查中曾出现 `0xC0000234 STATUS_ACCOUNT_LOCKED_OUT`，约 10 分钟后自动解锁）。
4. 该 MSA 是否**被允许 RDP 登录**（`Remote Desktop Users` 组为空；可能需在服务器侧加入或使用本地账户）。

## 6. 代码侧就绪度（凭据可用即可跑通）

- orders 批次（判据 1/2a/2b/3a/3b/3b2/3b3a/3b3b/3c/3d-1/2/3d-3/3e/3f）**全部双审盖章**；
- CredSSP 线（CBT 布局 / MsvAvTargetName / Z(16) 回退）**双审盖章**；
- 认证后路径**完整接线**：Client Info PDU → 许可 → 会话建立（Demand/Confirm Active）→ `session_active()` → `rtsc_gui` 渲染 + 输入转发；
- Windows `ctest` **37/37**；Linux 门禁 **PASS 36/36**；`rtsc_orders_tests` **103/5793**；
- 复跑命令：`scripts/real-server-test.ps1`（凭据从环境变量 `RTSC_USER`/`RTSC_PASS` 读入，不落盘）。

## 7. 复现步骤

```powershell
$env:RTSC_HOST="192.168.1.7"; $env:RTSC_PORT="3389"
$env:RTSC_DOMAIN="MicrosoftAccount"; $env:RTSC_USER="windowsvipcuv@live.cn"; $env:RTSC_PASS="<密码>"
.\scripts\real-server-test.ps1
```

凭据可用后，若 `rtsc_connect` 仍失败而 mstsc 成功，则问题回到客户端，届时用 `scripts/ntlm_sspi_verify/` 与真机抓包定位。
