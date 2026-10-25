# 批 0 主代理独立复核记录

日期：2026-10-23
对象：执行 AI `ses_e99c24117ffeWAQpIkIbFYCNoc` 的批 0（S21 + S0.9）交付

## 1. 我独立重跑的结果（不采信转述）

### 1.1 Windows

```
cmd /c F:\rtsc\.tmp\build_tls.bat   ->  ninja: no work to do
ctest --test-dir F:\rtsc\build\verify -> 100% tests passed, 0 tests failed out of 16
```

### 1.2 Linux 全量（从零 configure，非增量）

脚本 `F:\rtsc\.tmp\verify_linux.sh`（`rm -rf .tmp/bl-verify` 后重来）：

```
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254132
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
```

**与执行 AI 的报告逐项一致。**

### 1.3 S0.9 的四行改动

```
tests/test_credssp.cpp:50        [[maybe_unused]] Bytes Str(const char* s) { ... }
tests/test_licensing.cpp:37      [[maybe_unused]] std::vector<uint8_t> AnsiBytes(const std::string& s) {
tests/test_licensing.cpp:60      [[maybe_unused]] std::string ToHex(const std::vector<uint8_t>& v) {
tools/rtsc_crashtest/main.cpp:9  #include <exception>
```

全部就位。

### 1.4 S24-b 未被顺手修掉

```
430:         }
431:         if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
432:             closed_ = true;
433:             return MakeError(Status::kOk, st, "");
434:         }
435:         return MakeError(Status::kOk, st, "shutdown best effort");
```

`tls_schannel.cpp:431` 原样未动 —— 执行 AI 没有越界做批 2 的修复。

## 2. 我对 `[[maybe_unused]]` 的独立判断

### 2.1 `Str`（`test_credssp.cpp:50`）

```
[[maybe_unused]] Bytes Str(const char* s) { return Bytes(s, s + std::char_traits<char>::length(s)); }
```

`Str` 全仓只出现 1 次（即定义行）。检查 23 个用例的字符串构造方式，**全部走 `FromHex`**
（`FromHex` 出现 26 次），没有一处该用 `Str`。

**判断：`Str` 是遗留物，不是「本该用但漏了」。`[[maybe_unused]]` 可接受，但更干净的做法是删除。**

### 2.2 `ToHex` / `AnsiBytes`（`test_licensing.cpp:37/60`）

同样各只出现 1 次（定义行）。`ToHex` 用于把字节转成十六进制字符串做比对，
而 `test_licensing.cpp` 的断言直接与硬编码 hex 字符串比较（47 个用例 175 个断言）。

**判断：同样是遗留物。** 但注意：`ToHex` 若被使用，会把「期望值」变成「实现算出来的值」，
这恰恰是我在 memory 规则 38（自指测试）里批评的反模式。**删掉比用起来更安全。**

### 2.3 结论

`[[maybe_unused]]` 解决了编译错误，但**没有消除死代码**。
这是一个可接受的临时措施（批 0 的目标是「Linux 能构建」，不是「清理测试代码」），
但应记入技术债：**这 3 个 helper 应删除，而不是标记为可能未使用。**

## 3. 我对 CMake 拆分的独立判断

`src/net/tls_factory.cpp` 全文 47 行，结构清晰：
- `:18-37` `CreateTlsTransport`：`#if defined(_WIN32)` 走 `CreateSchannelTransport`，
  否则返回明确错误 `"no TLS backend for this platform (SChannel is Windows only)"`；
- `:39-45` `EnumerateTlsBackends`：Windows 返回 1 条，其他平台返回空。

**这是正确的结构**：非 Windows 上不是静默 nullptr，而是**带原因的 nullptr**。
执行 AI 的探针实测也确认了这一点（`default_why=no TLS backend for this platform...`）。

## 4. 我发现的缺口（提交给双审计交叉验证）

| # | 缺口 | 级别 | 说明 |
|---|---|---|---|
| G1 | `tools/rtsc_crashtest/main.cpp` 加 `#include <exception>` 后**没有在 Windows 上验证过行为** | P2 | 该文件不在 ctest 里，只有 `verify.ps1 -CrashCheck` 跑。执行 AI 只验证了「编译通过」 |
| G2 | 3 个 `[[maybe_unused]]` helper 是**死代码**，未删除 | P2 | 见 §2 |
| G3 | 「Linux 能构建」**没有持续门禁** | P1 | `verify.ps1` 没有 `-LinuxBuild`。下一轮改 CMake 可能静默退化 |
| G4 | `src/net/tls_schannel_internal.h` 只有 559 B、只声明一个函数，**可能不必要** | P2 | 可在 `tls_factory.cpp` 内前置声明 |

## 5. 局限

- 我没有对 `test_licensing.cpp` 的 47 个用例逐一判断「是否该用 `ToHex`」，只做了计数与抽样。
- 我没有验证 `-CrashCheck` 的实际行为（G1）。
- Linux 验证只覆盖 `cmake --build` + `ctest`，未覆盖实际运行 `rtsc_probe`。
