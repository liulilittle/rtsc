# RDGSP 请求头方向归属 — 反汇编裁定（父会话定案）

**裁决对象**：`docs/spec/gateway-evidence.md` §2 的头部方向模型（原按"报错文本措辞"推断）。
**裁决方法**：反汇编 `mstscax.dll!FUN_1801c3818`（sha256 `d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05`，版本 10.0.26100.8875）。
**结论**：原 §2 方向推理**作废**，按本表执行。

## 1. 判定依据（关键控制流）

```
:5    int FUN_1801c3818(longlong param_1, longlong *param_2, int param_3, int param_4)
:59   local_298 = param_3;              // param_3 != 0  =>  IN 通道
:170  if (param_3 != 0) {
:171      if (param_4 == 0) {
:172          AddRequestHeader("transfer-encoding", "chunked")     // IN 流式
:186      goto LAB_1801c3e24;
:188  AddRequestHeader("Connection", "Keep-Alive")                   // 非 IN 流式
        }
:204  LAB_1801c3e24:
:226      AddRequestHeader("RDG-Correlation-Id", ...)               // 两路共同跳达 => 双通道
:248      AddRequestHeader("RDG-Diagnostics-Info", ...)             // 仅判非空 => 双通道
:264  if ((local_298 != 0) && (*(int *)(param_1 + 0xd30) != 0)) {
:265      StringCchPrintf(..., "IN_CHANNEL_RETRY_COUNT_%d", *(int *)(param_1 + 0xd38))
:269      AddRequestHeader("RDG-INCHANNEL-RETRYMODE", ...)          // IN-only + 重试标志
:299  if (local_298 == 0) {                                          // ===== OUT-ONLY 分支 =====
:312      AddRequestHeader("RDG-Client-AppBuild", local_260)
:383      AddRequestHeader("RDG-Client-Generation", ...)            // 默认 "Win32#0.0=7"
        } else {                                                     // ===== IN-ONLY 分支 =====
:544      AddRequestHeader("RDG-User-Id", base64(user))             // :568 "failed to base64-encode the user name"
        }
:74   AddRequestHeader("RDG-Connection-Id", param_1 + 0x60)         // 分支前 => 双通道
:77-95 Load Balancer Cookie（param_1+0x1480/0x1488 非空时）
```

## 2. 定案表（实现必须逐条对齐）

| 头 | 正确归属 | 值/条件 | 反汇编依据 |
|---|---|---|---|
| `RDG-Connection-Id` | **双通道** | 客户端生成 GUID | `:74`（位于 `:299` 分支之前） |
| `RDG-Diagnostics-Info` | **双通道** | 非空才发 | `:248`（仅判 `*(wchar_t*)(param_1+0x1c2) != 0`） |
| `RDG-Correlation-Id` | **双通道** | 非空才发 | `:226`（`LAB_1801c3e24` 由 chunked 与 Keep-Alive 两路共同跳达） |
| `RDG-User-Id` | **仅 IN** | 用户名 **base64** | `:544`（位于 `:444` else 分支，即 `local_298 != 0`）；`:568` 明示 base64 |
| `RDG-Client-AppBuild` | **仅 OUT** | 可配 | `:312`（在 `local_298 == 0` 分支内） |
| `RDG-Client-Generation` | **仅 OUT** | 默认 `Win32#0.0=7`，否则 `%s#%d.%d=%d` | `:383`（同在 `local_298 == 0` 分支内）；`:372`/`:345` |
| `Load Balancer Cookie` | **仅 OUT** | 可选 | `:77-95`（受 `:105` 的 `param_3 != 0 && param_4 == 0` 与 `:97` 状态判定约束） |
| `RDG-INCHANNEL-RETRYMODE` | **仅 IN + 重试标志** | `IN_CHANNEL_RETRY_COUNT_<n>` | `:264-269` |
| `Transfer-Encoding: chunked` | **仅 IN**（`param_4 == 0`） | 否则 `Connection: Keep-Alive` | `:170-188` |
| `Host` | 双通道 | gateway authority `host:port` | 出厂 URL 格式 `%s://%s:%hu%s`（`FUN_1801bd574`），`/remoteDesktopGateway/` 仅为路径 |

## 3. 被推翻的旧推理（lesson）

原 `gateway-evidence.md` §2 结论"`RDG-User-Id`/`RDG-Correlation-Id`/`RDG-Client-Generation`/`Load Balancer Cookie` 仅 OUT——因为这些头的错误文本只提 OUT channel"**错误**。

**错在哪**：错误串的措辞反映的是**失败上报时的上下文**（该次 `AddRequestHeader` 调用发生在哪个通道的请求构造流程里），不是**头的归属条件**。用日志文本反推控制流是无效推理。

**正确做法**：必须在反汇编里看 **`AddRequestHeader` 调用点的支配关系**（在哪个分支内、被哪些 `goto` 汇合点共享），不能看错误消息文案。

**同型教训家族**（本项目已累计 4 例）：
1. 单测用实现者自造的错误布局 → 假绿（`discover.md` 1402）
2. 修复一层掩盖另一层（`discover.md` 1410）
3. 守卫测试固化缺陷方向（`discover.md` f3b798a）
4. **用日志文本/字符串存在性反推控制流**（本条 + 101 状态码误判）

## 4. 双方审计的对错记录

| 审计 | 主张 | 判定 |
|---|---|---|
| 甲（`ses_e720e33f`） | correlation/user/generation 共享构造，应为双通道 | 对 1/3：correlation 对；generation 实为 OUT-only；user 方向被完全漏判（实为 IN-only） |
| 乙（`ses_e720e1cd`） | 同上，主张"仅 retry IN-only、LB cookie OUT-only，其余双通道" | 对 2/4：correlation/diagnostics 对；generation/AppBuild 过宽 |
| 父代理（原 §2） | correlation/user/generation 均 OUT-only | **全错**（user 方向完全相反） |

**正确性归团队共有**：三方都有错，最终由反汇编事实定案，不以角色或权威论。
