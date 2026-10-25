import io

proc = """

## 第162轮：取到 NTSTATUS `0xC000006D`（STATUS_LOGON_FAILURE）→ 恢复调试子代理聚焦 MIC/target_info

- **调试子代理 `ses_e9102349` 因卡死被救护中止**（rule 14④：技术故障必须恢复）→ 已按 rule 8① `prompt` 直发恢复续做。
- **[BASH] 主代理复核子代理落盘**：`src/credssp/credssp.cpp:108` 已改为 `"server reported an error (ntstatus 0x%08X)"`（505L `85E5DE6AA84E0540`）；
  `ntlm.cpp` 未改（`D640D75C25AD114C`/441）；`rtsc_credssp_tests` 23/69/0。
- **[BASH] 重编 + 真机复现**：
  ```
  round 0: recv 19, send 147, phase=await-external-security, protocol=0x00000008
  round 1: recv 846, send 318 ...
  round 2: recv 51, send 86 ...
  round 3: recv 291, send 576 ...   ← 已发 NTLM AUTHENTICATE
  FAILED: ... CredSSP error: server reported an error (ntstatus 0xC000006D)
  ```
- **解读**：`0xC000006D` = **STATUS_LOGON_FAILURE** → 服务器侧 **NTLM 校验未通过**（非结构错误）；用户确认凭据可用 → 我们的
  NTLMv2 计算或消息构造有误。
- **[relay:调试子代理]** 恢复任务 + 按嫌疑排序逐条验证（**H1 MIC 缺失（`credssp.cpp:260` 仅 `have_timestamp` 时发 MIC）为首要**）、
  要求先实测服务器 CHALLENGE 是否含 `MsvAvTimestamp`，并交叉参考 FreeRDP `nla.c`；H2 target_info/H3 auth.flags/H4 KeyExch/H5 Version/H6 域格式。
- 在途：NTLMv2 排查。真机联调需认证通过后才能到 active session。
"""
io.open('.opencode/process.md', 'a', encoding='utf-8').write(proc)
print('ok')
