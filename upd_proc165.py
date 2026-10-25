import io

proc = """

## 第165轮：决定性发现——mstsc 用同一凭据也失败 → 根因在凭据/服务器（非我们的代码）

- **调试子代理用 Windows 自带 mstsc 实测**（同服务器 192.168.1.7、同格式 `MicrosoftAccount\\windowsvipcuv@live.cn` + `yy520o!`）：
  **mstsc 也认证失败**，对话框原文「你的凭据不工作…登录没有成功」；cmdkey 存储与直接键入均失败。
  → **否定「用户确认 mstsc 能登」的前提**；`0xC000006D` 根因在凭据/服务器侧。
  （附注：`net use \\\\192.168.1.7\\IPC$ /user:MicrosoftAccount\\... ` 也 1326；全邮箱名触发 1909 账户被锁。）
- **调试子代理已实现 EPA/CBT 修复**（真实 CBT + MsvAvTargetName），真机 NTSTATUS **未变**（仍 0xC000006D）→ 佐证非根因，但作为正确增强保留。
- **离线决定性验证（保留价值）**：rtsc 的 AUTHENTICATE 喂给 **Microsoft msv1_0 `AcceptSecurityContext`** → 正确密码 `ACCEPTED(0x0)`、
  错误密码 `SEC_E_LOGON_DENIED(0x8009030C)` → **我们的 NTLMv2/MIC 消息本身正确**。已固化为 `scripts/ntlm_sspi_verify/`。
- **[BASH] 主代理核验**：`cmake --build build --config Release --target rtsc_connect` **BUILD_EXIT=0**（编译通过）；
  当前树含 `RTSC_NTLM_DUMP` 临时调试（`credssp.cpp:30-32`、`:122-123`）与 `:8-10 #pragma warning(disable:4996)`；
  指纹 `credssp.cpp E462C8F54E9823F2`/565、`credssp.h 1C702FB46091D87B`/138、`security_layer.cpp D59FE9FF252F22E5`/404、`ntlm.cpp` 未改。
- **[relay:调试子代理]** ① 清理临时调试与 pragma（`/WX` 零警告）；② EPA/CBT 保留并**如实标注「未在强制 CBT 的服务器上验证」**，
  并对 `MsvAvTargetName`（CHALLENGE target_name vs SPN `TERMSRV/<host>`）**以规范为准**给出依据；③ 确认离线脚本自包含可复跑；
  ④ 完成后交甲/乙**双审**（CredSSP 线独立改动）；**不再尝试登录**。
- **待用户**：确认密码（`yy520o!` 的 `o` vs `0`）、或 MSA 是否需联网/已改密。
- 在途：调试子代理清理 + 双审；真机认证待凭据。
"""
io.open('.opencode/process.md', 'a', encoding='utf-8').write(proc)
print('ok')
