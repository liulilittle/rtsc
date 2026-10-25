# 批 2 审计甲 · 可执行性终检

> 对象：`security-integration.audit-a.md` §19.3.3（A20-3 七条订正版）。
> **严格只读**：未改 `src/`/`include/`/`tests/`，未构建，未跑变异，未启动 exe。
> 结论：**还有 3 处要改**（1 处阻断、2 处高危）。`0x15` 断言、S22 隔离、Linux 链接三项已核实通过。

## 1. 已核实通过（不用改）

| 项 | 结论 | 证据 |
|---|---|---|
| **A1** `first[0]==0x15` | ✅ 正确 | `probe_u4d` S3：缺陷态 `out=201, type=22(Handshake)`；`probe_u4e` T1：修复态 `out=31, type=21(Alert), raw=15 03 03...`。`c:428` 的 `out.assign(p, p+cbBuffer)` 拿的是 `SECBUFFER_TOKEN`，**含完整 TLS record** |
| **A3** S22 不破坏 `shutdown_is_idempotent` | ✅ 成立 | `t:849` 用**函数内局部** `Loopback lb`，22 个用例全是局部的 → 零共享。且 `Start()` 跑完整握手 → `have_ctx_==true`，`:407` 分支在它里面**永不触发** |
| **Linux 链接** | ✅ 不存在问题 | `CMakeLists.txt:65-69` 与 `:127-131` **都把 `tls_schannel` / `rtsc_tls_tests` 包在 `if(WIN32)`**。Linux 既不编译也不链接 → `tls.h` 声明只在 Windows 有定义的函数是安全的（同 `CreateSchannelTransport` 模式） |
| **A2** `tls.h` 无 Windows 类型 | ✅ 确认 | `SECURITY_STATUS` 仅出现在 `:59` 注释；`tls.h:5-8` 明写"free of any platform dependency"；`:28` 有 `<cstdint>` |

## 2. 必须改 1：`doc:3823-3832` PowerShell 脚本已被转义破坏（**阻断**）

```
3823 : $ErrorActionPreference='Stop'; $env:TEMP='F:
3824 : tsc\.tmp'; $env:TMP='F:
3825 : tsc\.tmp'
3826 : cmd /c F:
3827 : tsc\.tmpuild_tls.bat
```

**根因诊断（比「被拆成两行」更精确）**：路径里的反斜杠被当作**转义序列**解释了：

| 原文应为 | 实际字节 | 转义含义 |
|---|---|---|
| `F:\rtsc\.tmp\build_tls.bat` | `tsc` + `0x08` + `uild_tls.bat` | `\b` -> 退格 `0x08` |
| `...\build\verify\rtsc_tls_tests.exe` | `tsc` + `0x08` + `uild` + `0x0b` + `erify` + 换行 + `tsc_...` | `\b`->`0x08`, `\v`->垂直制表 `0x0b`, `\r`->回车 |

全文件扫描确认：**2 个 `0x08`（`:3827` / `:3830`）+ 1 个 `0x0b`（`:3830` 附近）**，其余正文无控制字符。`\r` 被解释成回车后 `rtsc` 的 `r` 消失、`\n` 变成换行，所以看到 `tsc_tls_tests.exe`。

**执行 AI 照抄会立刻失败**，且控制字符**不可见**，比普通换行更难察觉。对比 `doc:4009`（批 3 脚本）完好，说明是本节编辑时用错了转义。
**修法**：恢复为纯文本单行路径，写完后再扫一遍 `0x08` / `0x0b` / `0x0c`。

## 3. 必须改 2：`MapShutdownStatusForTest` 的实现位置（**高危**）

主代理方案（声明放 `tls.h`，实现放 `tls_schannel.cpp`）**可行**，但有两个执行细节必须写进 §19.3.3，
否则执行 AI 会撞 C++ 编译错误：

**细节 A：匿名 namespace 的可见性**
`tls_schannel.cpp:45` 是 `namespace {`。若 `MapShutdownStatus`（规则）放匿名 namespace，
而 `MapShutdownStatusForTest`（公开）在**匿名 namespace 之后**定义，则**看不见**前者。
**必须**：规则函数放在匿名 namespace 内，公开包装放在 `}  // namespace` **之后**、`namespace rtsc::tls` 之内。
（主代理已提到"注意顺序"，但需写成明确的行序约束。）

**细节 B：`tls.h` 声明需带 `RTSC_API` 风格吗？**
实测 `tls.h` 的其它自由函数（`CreateTlsTransport`、`EnumerateTlsBackends`）**无导出宏**
（`rtsc_tls` 是 `STATIC` 库，`CMakeLists.txt:71`）。→ 直接声明即可，**不要**加 `__declspec`。

**建议写进 §19.3.3 的完整形态**：
```cpp
// include/rtsc/net/tls.h（tls.h 保持零平台依赖，只用 int32_t）
Status MapShutdownStatusForTest(int32_t native_status);

// src/net/tls_schannel.cpp
namespace rtsc::tls {
namespace {
Status MapShutdownStatus(SECURITY_STATUS st) { ... }   // 规则
}  // namespace
Status MapShutdownStatusForTest(int32_t s) {           // 包装，在匿名 ns 之后
    return MapShutdownStatus(static_cast<SECURITY_STATUS>(s));
}
```

## 4. 必须改 3：门槛是 **8 条 / 34 tests**（订正 2 算错）

逐条核对（实测 `tests/test_tls.cpp` 26 个 `RTSC_TEST`，8 个候选名**全部不存在**）：

| 缺陷 | 新用例 | 能否复用已有？ |
|---|---|---|
| S24-a | `shutdown_emits_close_notify_alert` | ❌ 不能（`shutdown_is_idempotent` 无 `first[0]` 断言） |
| S24-b | `shutdown_reports_continue_needed_as_failure` | ❌ **不能**（实测该用例零 `status`/`native_code` 断言） |
| S24-c | `shutdown_maps_failure_status_to_error` | ❌ 不能（规则级，无对应） |
| S22 | `shutdown_before_handshake_is_rejected` | ❌ 不能（现有用例全在握手后） |
| S9 | `shutdown_then_receive_still_drains` | ❌ 不能 |
| S19 | `tls13_only_config_does_not_fail_acquire` | ❌ **不能**（`t:868` 的 `if (!started) return;` 会假绿） |
| S23 | `peer_alert_is_reported_as_context_expired` | ❌ 不能 |
| S10 | `coalesced_finished_and_app_data_are_both_delivered` | ❌ 不能 |

**8 条全部必须新建 → 门槛 `>= 34 tests`。**
§19.3.3 订正 2 的「共需新增 7 条（6 + 1）」**算错**：6 条全新 + 2 条订正新增 = **8**。

## 5. 必须改 4：总数门槛会被 S10 跳过掩盖（已实测）

我构造了「26 既有 + 7 条新（漏 S10）= 33 tests」的合成源：
- **旧门槛 `>= 33`：通过**（漏了 S10 也不报）
- **新门禁 `batch2_gate.py`：`exit=1`**，且指出 `MISSING: coalesced_finished_and_app_data_are_both_delivered` + `TOO FEW TESTS: 33 < 34`

## 6. 交付物：`evidence/exec/batch2_gate.py`（已写并双向自测）

规格符合主代理要求：
- 逐名 `grep` 8 个 `RTSC_TEST(<name>)`，缺任何一条 **`raise SystemExit(1)`**
- 同时检查总数 `>= 34`（双保险）
- 输出逐条 OK/MISS + 明确列出缺哪些

**双向自测结果（实跑）**：
```
--selftest（合成源，故意漏最后一条）:
  SELFTEST PASSED: checker rejected the incomplete source   -> exit 0
当前树（8 条全缺、26 tests）:
  BATCH2 GATE FAIL: 0/8 required tests present, 26 total    -> exit 1
合成 33 tests（漏 S10）:
  BATCH2 GATE FAIL: 7/8 required tests present, 33 total    -> exit 1
```

**建议写进 §19.3.3 验收脚本**（替换单一总数检查）：
```powershell
python F:\rtsc\evidence\exec\batch2_gate.py
if ($LASTEXITCODE -ne 0) { throw "BATCH2 GATE FAILED" }
```

## 7. 结论

**§19.3.3 还有 4 处要改，暂不可执行**：

| # | 问题 | 严重度 | 归属 |
|---|---|---|---|
| 1 | `doc:3823-3832` PowerShell 脚本转义损坏 | **阻断** | 主代理改文档 |
| 2 | `MapShutdownStatusForTest` 需写明匿名 namespace 行序 + 无导出宏 | **高** | 主代理补 §19.3.3 |
| 3 | 门槛应为 `>= 34`（8 条新用例，不是 7 条） | **高** | 主代理改 |
| 4 | 验收脚本改用 `batch2_gate.py`（逐名检查） | **高** | 已交付，待接入 |

**改完这 4 处即可执行。** 其余（`0x15` 断言、S22 隔离、Linux 链接、`tls.h` 零平台依赖）均已核实通过。
