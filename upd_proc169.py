import io

proc = """

## 第169轮：甲发现新规范偏差（MsvAvTargetName NULL 分支应发空值 AV_PAIR）→ 派发修复

- **甲逐字提取 [MS-NLMP] §3.1.1.5 原文**：
  ```
  If ClientSuppliedTargetName is not NULL
      Add an AV_PAIR ... MsvAvTargetName ... Value = ClientSuppliedTargetName ...
  Else
      add an AV_PAIR ... MsvAvTargetName ... Value = empty string without terminating NULL.
  ```
  → **NULL 分支也必须发 AV_PAIR（空值），不是省略**。
- **[READ:src/credssp/credssp.cpp:249]** 现为 `if (!client_target_name_.empty()) { ... }` → 空串时**整个 AV_PAIR 省略**（与规范不符）；
  注释「empty value is equivalent for verification」不成立（规范区分 NULL 与空串，且这是「该发未发」）。
- **甲裁定**：真偏差、**严重度低（非阻断）**——MIC 输入是 CBT 而非 TargetName、服务器通常忽略客户端 TargetName、真机失败根因是凭据。
- **最小修复**：`SetClientTargetName` 增 `has_target_name_ = true`（区分「未设置」与「显式空串」，**二者都发**空值 AV_PAIR）；
  `credssp.cpp:249` 改 `if (has_target_name_)`；**不能**只写 `if (true)`（须语义显式）。
- **[task:general] 新开子代理** 执行该修复 + 新增测试（有值填 UTF-16LE 无 NUL；NULL 分支**仍存在**空值 AV_PAIR）+ 变异 1 个；不跑 Linux 门禁。
- 在途：修复 + 双审。真机复测待有效凭据。
"""
io.open('.opencode/process.md', 'a', encoding='utf-8').write(proc)
print('ok')
