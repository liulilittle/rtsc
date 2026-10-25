# 批 0 收尾：B0-07 / U20-5 / A20-4 修复记录

日期：2026-10-23
依据：双审计 §20 / §10 / §11 的合并缺陷清单

## 1. B0-07（P2）：`verify.ps1` 只看退出码

审计乙新发现。原代码：

```powershell
& wsl -e bash $gateWsl
if ($LASTEXITCODE -ne 0) { Write-Error "linux build gate failed"; exit 1 }
Write-Host "  linux build gate passed"
```

**问题**：如果门禁脚本被误改成「打印一行然后 `exit 0`」，`$LASTEXITCODE` 是 0，
verify 会报「passed」——**门禁被阉割了也看不出来**。

### 修复

```powershell
$gateOut = (& wsl -e bash $gateWsl 2>&1 | Out-String)
Write-Host $gateOut
if ($LASTEXITCODE -ne 0) { Write-Error "linux build gate failed"; exit 1 }
if ($gateOut -notmatch 'LINUX GATE PASS') { ... exit 1 }
foreach ($needle in @('FAILED_COUNT=0', 'WINDOWS_H_COUNT=0', 'FACTORY_SYMBOL=present')) {
    if ($gateOut -notmatch [regex]::Escape($needle)) { ... exit 1 }
}
```

四项**正向**断言：PASS 行必须出现，三个计数行必须出现且为期望值。

### 红证（实测）

把 `scripts/linux-build-gate.sh` 临时替换成 `echo NEUTERED; exit 0`：

```
$ verify.ps1 -LinuxBuild
Write-Error: linux build gate exited 0 but never printed LINUX GATE PASS (gate is not doing its job)
neutered_exit=1        <- 期望非 0，符合
```

恢复脚本后：

```
LINUX GATE PASS
  linux build gate passed
restored_exit=0
```

**结论：B0-07 修复有效，且红证证明新断言真的会触发。**

## 2. U20-5（P2，乙改判「应做」）：`#if` 3 → 2

审计甲提出、乙最初判「不值得（+66 KB）」，后被甲推翻。
乙的错误模式：**用自己的实现（`PlatformPolicy` + lambda，68 行，320596 B）去否定这个目标**。
甲只把 include 移出 `#if`（50 行，254220 B，**比现状还小 48 B**）。

### 关键：这不是体积问题，是「静默空白」

| 树 | `#if` 数 | internal header 注入 `<windows.h>` | Linux 构建 |
|---|---|---|---|
| 修改前 | 3 | 是 | **`TLS_BUILD_EXIT=0` ← 静默通过** |
| 修改后 | 2 | 是 | **`TLS_BUILD_EXIT=1` + `tls_schannel_internal.h:5: fatal error: windows.h`** |

**修改前，如果有人往 `tls_schannel_internal.h` 加 Windows 头，Linux 构建完全察觉不到。**

### 修复

```cpp
// Included unconditionally, even though CreateSchannelTransport is only CALLED
// on Windows (U20-5). The header declares a platform-neutral function, so it
// compiles everywhere; keeping the include outside #if means that if someone
// ever adds a Windows-only include to it, the Linux build fails immediately
// instead of silently passing.
#include "tls_schannel_internal.h"
```

### 实测

- `#if defined(_WIN32)` 计数：**3 → 2**
- Windows：`rtsc_tls_tests` 仍 **26/139/0/0**
- 文件大小 1365 → 1800 B（增加的是注释，不是代码）

### 红证（实测）

往 `tls_schannel_internal.h` 首行注入 `#include <windows.h>`：

```
LINUX GATE FAIL: FAILED=1 WINDOWS_H=2
injected_gate_exit=1
```

恢复后：

```
LINUX GATE PASS
restored_gate_exit=0
```

**结论：U20-5 修复有效，静默空白已堵。**

## 3. A20-4 / W3（P2）：删除 3 个死代码 helper

`[[maybe_unused]]` 的语义是「可能不被使用，这是合法的」，
而事实是「**确实不被使用，且不需要**」——它把真实的死代码信号永久静音。

两位审计独立确认零引用：
- 甲：整段删除后 `BUILD=0`，用例数仍 23/69、47/175
- 乙：`tests/test_crypto.cpp:36-48` 有**逐字相同/逻辑相同的活版本** → 复制粘贴遗留

### 删除清单

| 文件 | 内容 | 行数 |
|---|---|---|
| `tests/test_credssp.cpp` | `Str` | 1 |
| `tests/test_licensing.cpp` | `AnsiBytes` | 5 |
| `tests/test_licensing.cpp` | `ToHex` | 9 |

### 实测

```
test_credssp.cpp  Str        remaining lines: NONE   maybe_unused: 0
test_licensing.cpp ToHex     remaining lines: NONE
test_licensing.cpp AnsiBytes remaining lines: NONE   maybe_unused: 0

rtsc_credssp_tests   23 tests,  69 checks, 0 failing
rtsc_licensing_tests 47 tests, 175 checks, 0 failing
```

**用例数与断言数与删除前完全相同** → 证明这 3 个 helper 从未参与测试。

## 4. 全量验证（修复后）

```
verify.ps1 -LinuxBuild
  ...
  WINDOWS_H_COUNT=0
  LIB_BYTES=254140
  FACTORY_SYMBOL=present
  CTEST_EXIT=0
  100% tests passed, 0 tests failed out of 15
  LINUX GATE PASS
  linux build gate passed
exit=0
```

## 5. 局限

- B0-07 的「缺 cmake → exit 2」分支未由我实测（乙实测过，`GUARD_EXIT=2`）。
- U20-5 的红证是「注入 `windows.h`」，未测其他形式的漂移（例如注入 `<schannel.h>`）。
- 删 3 个 helper 后未跑 `-PseudoLint` / `-DocLint`（它们不涉及测试文件）。
