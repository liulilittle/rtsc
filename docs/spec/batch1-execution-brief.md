# 批 1 执行任务书（CredSSP 生产注入）

> 本文由主代理编写，供批 1 执行 AI 使用。**定案由批 1 审计甲/乙共同确认**，
> 本文只负责把定案转成可执行步骤 + 硬约束 + 验收判据。

---

## 0. 你的角色与边界

你是**批 1 执行 AI**。职责：按本任务书 TDD 实现，把结果报给审计甲/乙验证。

**禁止**：
- 自行改变定案（若有异议，凭**真实证据**说服审计，不得自行修改）
- 改动 `tests/` 里既有用例让它通过（H7）
- 用 `#pragma warning(disable)` 过编译（H4）
- 用 `rand()`/`srand()`/`std::random_device`/`mt19937` 生成任何密钥材料（N6）
- **启动任何 `.exe`**（见 §7 探针规则）

**必须**：
- 严格 TDD：写测试 → 编译 → **确认失败并记录红证** → 最小实现 → 编译 → 确认通过
- 红证必须是**具体用例名 + 断言文本 + 实际读数**
- 每步改完跑 `cmd /c F:\rtsc\.tmp\build_tls.bat`

---

## 1. 硬约束（违反任一 = 本批不通过）

| # | 约束 |
|---|---|
| **H1** | 所有产物只写 `F:\rtsc` 内；临时文件放 `F:\rtsc\.tmp`；**禁止写 C 盘** |
| **H2** | 编译前设 `$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'` |
| **H3** | 构建入口唯一：`cmd /c F:\rtsc\.tmp\build_tls.bat`；**不要新建 build 目录、不要换生成器**（Ninja） |
| **H4** | `/W4 /WX` 已开，警告即错误；**禁止加 `#pragma warning(disable)`** |
| **H5** | `.ps1`/`.bat` 只能 ASCII |
| **H6** | 写中文用 `write` 工具或 Python `io.open(..., encoding='utf-8', newline='')`；禁止 `Set-Content`/`Out-File` |
| **H7** | **禁止改测试让它通过** |

---

## 2. 六条缺陷与定案（D1–D6 已裁决）

| 缺陷 | 级别 | 定案 |
|---|---|---|
| **S1** | P0 | nonce 用 CSPRNG 填充；**加提前尺寸守卫**（D5） |
| **S5** | P1 | **只拒下界**（D2）：`if (req.version < kMinVersion) return Fail(kUnsupported, ...)` |
| **S6** | P1 | **`std::min(version_, req.version)`，不是 `clamp`**（D1） |
| **S11** | P1 | MAC 必须用 `DeriveSigningKey(exported, /*server_to_client=*/true)`（D4） |
| **S18** | P0 | 空公钥守卫放 **`BuildStep3` 入口**，不是 `Start`（D3） |
| **N-B1** | **P0** | `exported_session_key_` 改独立 16 字节 CSPRNG，**禁止从 nonce 派生** |

### 2.0 N-B1 的失败分支用哪个 Status（主代理裁决，别再问）

`include/rtsc/credssp/ts_request.h:21-26` 的枚举**当前只有四个值**：

```cpp
enum class Status : uint8_t {
    kOk = 0,
    kTruncated,       // input ended inside a TLV
    kMalformed,       // tag/length/structure violation
    kUnsupported,     // valid structure, value this implementation rejects
};
```

**没有 `kInternal`。** `tls::Status::kInternal` 在 `rtsc::net` 命名空间，
传进 `credssp::Fail()` **类型不匹配，编译不过**。

**正确做法不是换个 status，而是给 `credssp::Status` 补上 `kInternal`（见下）。**
审计乙的稿子写 `Fail(kInternal, ...)` 时方向是对的，只是枚举缺这个值。

> **不要**把它改成 `kUnsupported` 或 `kMalformed`：
> - `kMalformed` + `native_code=0` 会被批 3 映射成 `kProtocolViolation`
>   （`security-integration.audit-a.md:603`），用户会被告知「服务器违反协议」。
> - `kUnsupported` 无法与「服务器版本太低」区分。
> - **这两个错误都不会让任何测试变红**（N-B1 用例只断言 key ≠ nonce 窗口，
>   不查失败分支的 status），错误会一路活到批 3 才暴露。

**定案（第三次裁决，前两次被审计甲用证据推翻）：批 1 新增 `credssp::Status::kInternal`。**

```cpp
// ts_request.h
enum class Status : uint8_t {
    kOk = 0,
    kTruncated,       // input ended inside a TLV
    kMalformed,       // tag/length/structure violation
    kUnsupported,     // valid structure, value this implementation rejects
    kInternal,        // local environment failure (CSPRNG unavailable, etc.)
};
```

```cpp
// credssp.cpp, N-B1 的失败分支
if (!RandomBytes(exported_session_key_, kExportedKeySize)) {
    return Fail(Status::kInternal, "CSPRNG unavailable for exported session key");
}
```

#### 为什么不是 `kMalformed`（我最初的裁决，已被推翻）

批 3 的错误映射（`security-integration.audit-a.md:603`）规定：

```
native_code == 0 且 status == kMalformed/kTruncated  ->  kind = kProtocolViolation
```

于是 `CSPRNG unavailable` 会被报成 **「服务器违反协议」**，让用户去查服务器/网络。
**把本地环境故障误分类成对端问题，比「不精确」更糟。**

#### 为什么不是 `kUnsupported`（审计甲的第一建议）

`kUnsupported` 的映射是 `kind=kUnsupported`，至少不误导，但**仍无法与「服务器版本 v1」区分**。
调用方看到 `kUnsupported` 不知道该查服务器还是查本机加密服务。

#### 为什么新增枚举值成本为零（审计甲实测，我已复验）

| 检查项 | 结果 |
|---|---|
| `credssp::Status` 上的 `switch` 穷举 | **0 处**（`credssp.cpp`/`ntlm.cpp` 各 0；`ts_request.cpp` 唯一的 switch 是 DER tag） |
| `static_cast<int>(status)` | 0 处 |
| `status == <数字>` | 0 处 |
| `arr[status]` | 0 处 |
| `static_cast<Status>` | 0 处 |

→ **加枚举值不触发 `/W4 /WX` 的未处理枚举警告。**

#### 为什么「靠 message 区分」不成立

仓库有三处明文契约禁止这么做：

- `include/rtsc/net/tls.h:60`：`std::string message; // human readable only; never drives control flow`
- `include/rtsc/credssp/ts_request.h:31-33`：`native_code` 注释「**instead of guessing from the text**」
- `security-integration.audit-a.md:614`：**任何控制流分支都不许 `strstr(detail, "...")`**

实测：全仓 `Error.message` 参与分支判断 **0 处**（`src/` `include/` `tests/` `tools/` 四目录，
六种模式全零命中）。**「靠 message 区分」在当前仓库没有任何实现基础。**

#### 你还要改的一处

`security-integration.audit-a.md:605` 已加映射行：
```
| credssp::Error | status == kInternal | kInternal | kNone | 批 1 新增枚举值 |
```
**批 3 实现映射时必须照这一行走**，否则 `kInternal` 会落到 `:603` 的兜底变成 `kProtocolViolation`。

### 2.1 D6：版本检查的位置

版本下界检查必须放在 **errorCode 分支之后**，否则 `native_code` 丢成 0。

### 2.2 R2：落点收窄（重要）

**`S5` 的下界检查和 `S6` 的 `min` 回写，都必须收窄在 `kAwaitChallenge` 分支内。**

理由：`OnServerResponse` 是第 2 步和第 4 步**共用入口**（`c:107-112` 按 `step_` 分派）。
若放在分支外，第 4 步会再回写一次，导致：
- 第 2 步服务器回 6、第 4 步回 4 → `version_` 6→4 → 第 5 步发 4，而第 3 步已按 6 发哈希+nonce → **协议状态不一致**
- `version()` 被第 4 步篡改（它是上层错误分类依据）

目标形态：
```cpp
if (step_ == Step::kAwaitChallenge) {
    if (req.version < kMinVersion) return Fail(Status::kUnsupported, "...");
    version_ = std::min(version_, req.version);
    return BuildStep3(req, out);
}
if (step_ == Step::kAwaitServerEcho) {
    return BuildStep5(req, out);
}
```

---

## 3. 八条要新增的用例（名字不可改）

| 用例名 | 缺陷 | 断言要点 |
|---|---|---|
| `two_constructions_have_different_nonces` | S1 | **必须驱动到第 3 步**再比 `ExportedSessionKeyForTest()`；只构造时该值为空 vector，两个空 vector 恒相等 → 修复后仍红（假红证） |
| `version_below_min_is_rejected_with_valid_challenge` | S5 | 必须用**合法 CHALLENGE**（`ServerChallengeMessage()`，`test_credssp_sm.cpp:75`）+ `version=1`；**不能用 `t:134` 的 `"0011"`**，否则失败在 token 解析，是假绿 |
| `server_version_is_echoed_back` | S6 | **必须两组**：A 组（客户端 6 + 服务器 3，抓「不回写」）、B 组（**客户端 4 + 服务器 6**，抓「clamp 升级」）。`t:478` 那条是客户端4+服务器4，`min`/`clamp` 都得 4，**区分不了** |
| `tampered_signature_checksum_is_rejected` | S11 | 必须篡改 **`echo[4]`（checksum）**，不能篡改 `echo[20]`（那是密文，被回显比对拦住，测不出 MAC） |
| `start_without_public_key_fails` | S18 | 不设公钥 → `Start` 成功但 `BuildStep3` 必须 `!ok()` |
| `client_nonce_does_not_disclose_session_key` | N-B1 | 驱动到第 3 步后，`exported` 不等于 `client_nonce` 的**任一 16 字节窗口**（`o=0..16`，共 17 个）。只比 `[8..24)` 不够——会放过「换偏移继续派生」的糊弄实现 |
| `server_echo_version_does_not_downgrade` | R2 | 第 2 步服务器回 6、第 4 步回 4 → **`step5 的 req.version` 仍是 6**（断言发出去的字段，不是 `c.version()`） |
| `error_code_wins_over_bad_version` | **D6** | **out-of-range version（1）+ errorCode（0xC000006D）同时出现** → 必须返回 `native_code == 0xC000006D`，**不是** `kUnsupported`+`native_code=0`。**对照组**：同样的 `version=1` 但无 errorCode → 必须被版本检查拒绝 |

### 3.1 为什么第 8 条必须有（D6 的零回归保护）

审计乙逐条核过现有 15 条 + 前 7 条新用例，**没有一条**能抓「版本检查挪到 errorCode 之前」：

| 用例 | 为什么抓不到 |
|---|---|
| `error_code_aborts_with_server_status`（`t:354`） | `err.version = 6`（合法）→ 版本检查不触发 |
| `error_code_is_checked_before_any_token_processing`（`t:375`） | 同样 `version=6` |
| `version_below_min_is_rejected_with_valid_challenge` | 没有 errorCode |
| 其余 9 条 | 全发合法 version（`t:155/190/225/291/328/405/421/449/487`） |

**没有第 8 条，D6 完全没有回归保护**——将来任何人把版本检查挪到 errorCode 之前，
**测试全绿**，但用户的 `native_code` 会丢成 0，诊断信息消失。

参考实现：`evidence/exec/batch1-a-new-tests-reference.cpp:709-731`（含对照组）。

---

## 4. 参考实现（**不是可提交代码**）

`F:\rtsc\evidence\exec\batch1-a-fixed-credssp-reference.cpp`

**状态：静态检查 26 项 PASS / 未编译 / 未测试。** 已同步 `kInternal` 与 R2 收窄。
仅供对照结构，**禁止直接复制**——它的组合未编译验证。

测试参考：`evidence/exec/batch1-a-new-tests-reference.cpp`（751 行，含全部 8 条新用例 + 对照）。

---

## 5. 验收判据（**不是 preflight**）

### 5.1 修复后的判据 = 测试套件

```
cmd /c F:\rtsc\.tmp\build_tls.bat
F:\rtsc\build\verify\rtsc_credssp_sm_tests.exe   >= 23 tests（原 15 + 新增 8）
F:\rtsc\build\verify\rtsc_ntlm_tests.exe         >= 27 tests
F:\rtsc\build\verify\rtsc_credssp_tests.exe      >= 23 tests
全部必须 "0 failing tests, 0 failed checks"
```

### 5.2 **警告：`batch1_preflight.py` 修复后必然报 BAD，这是预期**

preflight 只验证「**修复前**缺陷存在」。批 1 落地后：

```
S5b  -> PRESENT（新增了下界检查）
S6   -> PRESENT（新增了回写）
S18  -> PRESENT（新增了守卫）
N-B1 -> ABSENT（缺陷消失，但 want=True 仍期望 PRESENT）-> 报 BAD
```

**禁止为了让 preflight 变绿而回退修复。**
落地后应改跑 `verify.ps1 -DocCite` + 上面三套件。

### 5.3 红证配方（变异回修复前，每条都要先红后绿）

| 缺陷 | 变异 | 预期失败用例 |
|---|---|---|
| S1 | `nonce_.assign(kNonceSize, 0)` | `two_constructions_have_different_nonces` |
| S5 | 删掉 `:93` 之后的版本下界检查 | `version_below_min_is_rejected_with_valid_challenge` |
| S6 | 删掉 `version_ = std::min(...)` | `server_version_is_echoed_back` |
| S11 | `:357-360` 恢复不验 MAC | `tampered_signature_checksum_is_rejected` |
| S18 | 删掉 `BuildStep3` 入口的空公钥检查 | `start_without_public_key_fails` |
| N-B1 | 恢复 `exported_session_key_.assign(nonce_...)` | `client_nonce_does_not_disclose_session_key` |

---

## 6. 18 条易错点（审计甲 §12.7，直接照做）

1. 只写实现不写测试 → 无法证明测试能抓问题
2. 测试用 `"0011"` 假 token → 失败在解析，假绿
3. **公钥守卫放 `Start()` → 3 条原测试红 + `0xC0000409` 崩溃**
4. **S11 用 `signing_key_` → 所有 step5 用例红**（那是 client→server 方向）
5. 篡改 `echo[20]` 而非 `echo[4]` → 测不出 MAC
6. `min` 写成 `clamp` → B 组红 4 条
7. S5 双边拒绝 → 拒绝 v7/v8 服务器
8. 版本检查放在 errorCode 之前 → `native_code` 丢成 0
9. 只比 `nonce[8..24)` 不查全部窗口 → 放过换偏移的糊弄实现
10. **控制组复用同一 client → `Fail()` 锁死 `step_`（`c:54`），假红**
11. 只构造不驱动就比 exported key → 两个空 vector 恒相等，假绿
12. 忘了 N-B1 的下游（`c:196-197/208/215/312/353/384-385`）会跟着变
13. 把 `c:176 client_challenge` 也改了 → 无谓改动（它明文传输，不是秘密）

    > 规范依据（批 1 审计乙 §9.5 核实）：
    > `security-layer.md:1127` ClientChallenge 直接拼进 NT response（明文）；
    > `security-layer.md:1143`「ClientChallenge：8 字节随机」——只要求随机，不要求保密；
    > `security-layer.md:1394` 随机数清单含 nonce / ClientChallenge / ExportedSessionKey，**三者都要随机，
    > 但只有 ExportedSessionKey 不能等于别的随机值**。
    > S1 修好后 `nonce[0..8)` 已是 CSPRNG 输出，作为 ClientChallenge 合格。
    > **明确不改的两处**：`c:176`（client_challenge）与 `c:193`（无 KEY_EXCH 分支 = `session_base_key_`，
    > `security-layer.md:831` 本来就是派生）。

14. 忘了收窄 R2 → 第 4 步回写，`server_echo_version_does_not_downgrade` 红
15. 用 `std::random_device` → N6 门禁红
16. 只写 S6 的 A 组 → `clamp` 也能过
17. **忘加 `#include <utility>`（`std::move`）→ `/W4 /WX` 编译失败**
18. **忘在 CMake 加 `src/crypto/random.cpp` → 链接失败**

### 6.1 N-B1 改动不会破既有 15 条的实测依据

`tests/test_credssp_sm.cpp:205-208` 用 `ExportedSessionKeyForTest()` **重算** MIC 再比对：

```cpp
const Bytes exported = client.ExportedSessionKeyForTest();
const auto mic_arr = ComputeMic(exported, client.NegotiateMessageForTest(),
                                client.ChallengeMessageForTest(), req.nego_token);
CHECK(Hex(Bytes(mic_arr.begin(), mic_arr.end())) == Hex(mic));
```

它读的是**实际值**而不是硬编码 `nonce[8..24)`，所以 exported key 换成独立随机后
两边一起变，断言仍成立。
`t:301/337/458` 用的是 `MakeServerEchoForTest()`，同样从实际密钥派生。

**结论**：N-B1 改动对既有 15 条是透明的。但这**不构成「不需要跑测试」的理由**——
仍必须跑满三套件确认。

> 核实：`src/crypto/random.cpp` **当前不存在**，`include/rtsc/crypto/random.h` 也不存在。
> `rtsc_crypto` 现在只有 `src/crypto/hash.cpp`（`CMakeLists.txt:39`）。
> 执行 AI 必须**新建** `include/rtsc/crypto/random.h` + `src/crypto/random.cpp`
> （BCryptGenRandom / 平台等价物），并把 `src/crypto/random.cpp` 加进
> `add_library(rtsc_crypto STATIC ...)`（`CMakeLists.txt:39`）。
> `kNonceSize = 32` 定义在 `credssp.cpp:16`（**不是** header），
> 若需要新常量（如 16 字节 exported key）也放在同一处。

---

## 6.2 CSPRNG 的跨平台形态（**必须先看这一节再动手**）

`bcrypt` 是 Windows 专有库，但目标是「先 Windows，后 Linux」，
且 `verify.ps1 -LinuxBuild` 跑 `scripts/linux-build-gate.sh` 是**硬门**。

### 硬约束

`scripts/linux-build-gate.sh` 断言 `WINDOWS_H_COUNT == 0`。
**任何进入 `rtsc_crypto` 的源文件都不能无条件 `#include <windows.h>`。**

### 正确形态（照抄 `tls_schannel` 的既有模式）

`CMakeLists.txt:56-60` 已有先例：

```cmake
if(WIN32)
    add_library(rtsc_tls_schannel STATIC src/net/tls_schannel.cpp)
    target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api)
    target_link_libraries(rtsc_tls_schannel PUBLIC secur32 crypt32)
endif()
```

**`random.cpp` 照同一结构写**：

```cmake
# Platform CSPRNG. Windows uses BCryptGenRandom; the POSIX branch uses
# getrandom(2) (Linux) with a /dev/urandom fallback.
add_library(rtsc_crypto STATIC src/crypto/hash.cpp)
target_include_directories(rtsc_crypto PUBLIC include)
if(WIN32)
    target_sources(rtsc_crypto PRIVATE src/crypto/random_win.cpp)
    target_link_libraries(rtsc_crypto PUBLIC bcrypt)
else()
    target_sources(rtsc_crypto PRIVATE src/crypto/random_posix.cpp)
endif()
```

### 具体做法

| 文件 | 内容 | 平台 |
|---|---|---|
| `include/rtsc/crypto/random.h` | `bool RandomBytes(uint8_t* out, size_t n);` + `bool RandomBytes(std::vector<uint8_t>& out, size_t n);` | 通用，无平台头 |
| `src/crypto/random_win.cpp` | `#include <windows.h>` + `<bcrypt.h>`，`BCryptGenRandom(nullptr, ...)` | 仅 Windows |
| `src/crypto/random_posix.cpp` | `#include <sys/random.h>`，`getrandom()`；`ENOSYS` 时退回 `/dev/urandom` | 仅 POSIX |

**返回值必须是 `bool`，不得抛异常**（本仓库不抛异常），失败时返回 `false`，
调用方按定案返回 `Status::kInternal`。

### 6.2.1 `random_posix.cpp` 的两个必做点（**已用 WSL 实测校准**）

> **重要更正（2026-10-23，审计甲实测）**：本节初版称「`-std=c++20` 会让 glibc 隐藏
> `getrandom`，缺 `_DEFAULT_SOURCE` 则 Linux 门禁必红」。**该断言已被实测证伪**，现更正如下。
> 证据：`evidence/exec/batch1-a-csprng-glibc-probe.txt`、
> `evidence/exec/batch1-a-csprng-portability-probe.txt`。

#### 实测环境

```
WSL Ubuntu-24.04 / g++ 13.3.0 / glibc 2.39 / Linux 6.18.33.2-microsoft-standard-WSL2
```

#### ① `_DEFAULT_SOURCE`：**不是必需的**（原「必红」结论错误）

**实测结果**：

```
=== TEST A: -std=c++20 -Wall -Wextra -Werror -Wpedantic ===   exitA=0
=== TEST B: -std=gnu++20 ===                                  exitB=0
=== TEST C: -std=c++20 + -D_DEFAULT_SOURCE ===                exitC=0
```

**三个都通过。`getrandom` 在 `-std=c++20` 下完全可见。**

**根因**：`__STRICT_ANSI__` 确实被定义，但不起作用：

```
$ g++ -std=c++20 -dM -E -x c++ /dev/null | grep GNU_SOURCE
  #define _GNU_SOURCE 1
```

g++ 在 Linux 上**无条件预定义 `_GNU_SOURCE`**（来自 libstdc++ 的 `os_defines.h`）。
glibc `features.h:221-222` 见到 `_GNU_SOURCE` 就置 `_DEFAULT_SOURCE=1`，于是 `:231` 的
`__STRICT_ANSI__` 分支根本不被求值。实测两者共存：

```
STRICT_ANSI=yes
DEFAULT_SOURCE=yes
```

且 glibc 2.39 的 `<sys/random.h>:34` 里 `getrandom` **没有 `__USE_MISC` 守卫**，是无条件声明。

**结论**：**不写 `_DEFAULT_SOURCE` 也能编译通过。** 但**保留它无害**（实测 exitC=0，
glibc 会 `#undef` 后重定义，不产生重定义警告），可作为「不依赖 libstdc++ 隐式提供
`_GNU_SOURCE`」的防御性措施。

**任务书措辞**：不要写「不加会编译失败」。若要保留，写明它是**防御性**的：

```cpp
// Defensive only: g++ predefines _GNU_SOURCE on Linux, which already enables
// _DEFAULT_SOURCE. Kept so a non-libstdc++ toolchain still sees getrandom().
#if defined(__linux__)
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif
```

#### ② `EINTR` 必须重试（**这条是真的，且是本节唯一的高危项**）

`getrandom()` 被信号打断时返回 `-1` 且 `errno == EINTR`。若写成
`if (r < 0) return false;` → **收到任意信号就误报 CSPRNG 失败**，进而返回
`Status::kInternal`，表现为**难以复现的间歇性握手失败**（比编译错误危险得多）。

**实测**：`doc:3995-3999` 的草稿原样编译通过（`exit=0`），但 `grep EINTR` 零命中。

```cpp
ssize_t r;
do {
    r = getrandom(out + done, size - done, 0);
} while (r < 0 && errno == EINTR);
if (r < 0) return false;
```

**注意**：`getrandom` 可能返回**少于请求的字节数**（部分读取），必须循环直到填满。

#### ③ `__has_include(<sys/random.h>)`（可选，仅当要支持 macOS）

当前仓库只跑 Windows + Linux。**若不打算支持 macOS，可直接 `#include <sys/random.h>`**
（Linux 实测可用），省略 `__has_include`。若要支持 macOS，才需要它
（macOS 用 `arc4random_buf`，无 `<sys/random.h>`）。

#### ④ `<fcntl.h>` / `<unistd.h>` 必须**无条件**包含（实测踩坑）

`/dev/urandom` 兜底路径用 `open`/`read`/`close`。若把这两个头放进
`#if !RTSC_HAVE_GETRANDOM` 条件块内，**ENOSYS 兜底时符号未声明**，实测报错：

```
error: 'O_RDONLY' was not declared in this scope
error: 'open' was not declared in this scope
error: 'read' was not declared in this scope
error: 'close' was not declared in this scope
```

**这是审计甲自己第一版实现的 bug，已修。** 正确写法：两个头无条件包含。

#### 实测矩阵（全部 `-Wall -Wextra -Werror -Wpedantic`）

| 变体 | 结果 |
|---|---|
| A 完整 getrandom 路径，`-std=c++20` | exit 0，输出随机（`nonzero=YES differ=YES`） |
| B2 `/dev/urandom` 独占路径（守卫强制 0） | exit 0，输出随机 |
| C `-std=c++17` | exit 0 |
| D `-O2` | exit 0 |
| E `-fsanitize=address,undefined` | exit 0，输出随机 |


### 6.2.2 **降级方案**（若 Linux 环境编译受阻）

**纯 `/dev/urandom`**：只用 `<fcntl.h>` + `<unistd.h>`，**零 feature-test 宏风险**。

```cpp
int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
// read in a loop until n bytes, retrying EINTR
```

**安全性等价**（都是 CSPRNG），代价是多一次 `open()`、fd 耗尽时失败。
**这是可接受的降级，不是次等方案。** 若 `getrandom` 路线在 Linux 上编译不过，
直接改用此方案，**不要加 `#pragma`（违反 H4），不要改 `CMakeLists.txt` 的编译选项**。

### 6.2.3 **Linux 门禁真的会跑到这个文件**（不是「第二阶段的事」）

审计甲核过（我复验）：

```
CMakeLists.txt:142  add_executable(rtsc_credssp_sm_tests ...)   <- 无 WIN32 守卫
CMakeLists.txt:172  add_test(NAME credssp_sm ...)               <- 无 WIN32 守卫
linux-build-gate.sh:53  cmake --build "$BUILD_DIR"              <- 无 --target，构建全部
linux-build-gate.sh:90  ctest --output-on-failure               <- 跑全部已注册测试
```

只有 `CMakeLists.txt:167-169` 的 `tls` 测试被 `if(WIN32)` 守卫。
**`rtsc_credssp_sm_tests` 在 Linux 下会构建 + 运行**，批 1 的 8 个新测试都会跑。

**所以 `random_posix.cpp` 不是可选项——批 1 就必须在 Linux 上编译通过并让新测试绿。**

### 6.2.4 **实测：完整参考实现已在 Linux 上构建通过**（红证）

审计甲把整套批 1 改动（`random.h` + `random_posix.cpp` + CMake 拆分 +
参考 `credssp.cpp` + `ts_request.h kInternal` + `credssp.h SetServerPublicKey`）
装进影子树，在 WSL 上完整构建并跑 ctest。**这是可执行证据，不是推理。**

影子树：`F:\rtsc\.tmp\shadow_linux`（`F:\rtsc` 的副本，排除构建产物）
证据文件：`evidence/exec/batch1-a-linux-shadow-build.txt`

```
=== CONFIGURE ===
CONFIG_EXIT=0
=== BUILD ===
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0

=== CTEST ===
CTEST_EXIT=0
 1/15 Test  #1: proto ............................   Passed
 ...
13/15 Test #13: credssp ..........................   Passed
14/15 Test #14: ntlm .............................   Passed
15/15 Test #15: credssp_sm .......................   Passed
100% tests passed, 0 tests failed out of 15

=== credssp_sm detail ===
15 tests, 92 checks, 0 failing tests, 0 failed checks
```

**关键读数**：

| 项 | 值 | 含义 |
|---|---|---|
| `FAILED_COUNT` | **0** | 零编译错误 |
| `WINDOWS_H_COUNT` | **0** | 无 `windows.h` 泄漏到 Linux 构建日志 |
| ctest | **15/15 passed** | 全部既有测试在 Linux 绿 |
| `credssp_sm` | **15/92** | 与 Windows 基线一致，证明该套件在 Linux 真实运行 |

**这意味着**：按 §6.2 的三文件形态实现，**Linux 门禁从第一天起就能绿**。
执行 AI 若遇到 Linux 编译失败，**大概率是自己的实现偏离了本节**，而不是环境问题。

**同时证明**：`_DEFAULT_SOURCE` 不写也能过（该影子树里 `random_posix.cpp`
保留了这个 `#define`，但 §6.2.1 的 A/B/C 三组实验已单独证明不写也 exit 0）。

**注意**：15/92 是**既有测试**的读数，不含批 1 的 8 条新用例。
新用例的预期读数是 `rtsc_credssp_sm_tests` ≥ 23。


### 禁止的做法

- **禁止**把 `bcrypt` 无条件链进 `rtsc_crypto`——Linux 链接器找不到该库。
- **禁止**在 `random.h` 里出现任何平台头文件。
- **禁止**让 `random_posix.cpp` 依赖任何 Windows 头。

> **关于 `#ifdef _WIN32` 单文件写法的澄清**（我先前的说法有误，已更正）：
> `linux-build-gate.sh` 的 `WINDOWS_H_COUNT` 统计的是**构建日志**里 `windows.h` 的出现次数
> （`grep -c 'windows\.h' "$BUILD_LOG"`），不是源码文本。
> 因此 `#ifdef _WIN32` 包住 `#include <windows.h>` 时，Linux 上该分支不参与编译、
> 不进日志，**不会触发门禁**。
> **所以单文件 `#ifdef` 是可行的**——但**仍推荐分文件**：
> 分文件让「哪个平台用了什么系统头」一目了然，且不必在同一个 TU 里维护两套 include 顺序。

### 验证

写完后**必须**跑：
```
powershell -NoProfile -ExecutionPolicy Bypass -File F:\rtsc\verify.ps1 -LinuxBuild
```
必须看到 `LINUX GATE PASS` 且 `WINDOWS_H_COUNT=0`。
**Windows 编译通过不算完成——Linux 门禁也必须绿。**

---

## 7. 探针规则（**血泪教训**）

探针是 `/MDd` 构建，`_ITERATOR_DEBUG_LEVEL=2`。迭代器误用触发 CRT 断言，
默认弹**模态框**。在循环里跑它 → 每轮弹一个框 → 进程挂死 → 桌面被刷满。**已发生两次。**

**规则**：
1. **优先不写探针**。能用单元测试验证的，一律用单元测试。
2. 必须写探针时，**只能用**：
   ```
   cmd /c F:\rtsc\.tmp\build_probe_safe.bat <src.cpp> <out.exe> [libs...]
   ```
   它用 `/FI F:\rtsc\.tmp\silent_crash_auto.h` 注入崩溃静默，**源码不用改**。
3. 运行必须经：
   ```
   F:\rtsc\.tmp\audit-b1\run_probe.ps1 -Exe <out.exe> -TimeoutSec 30
   ```
   看门狗超时会杀进程并返回 `TimedOut=true`。
4. 退出码含义：`0`=正常，`4`=断言（已静默），`5`=SEH（已静默，有 minidump），`-2`=超时被杀。
5. **禁止**直接 `& <exe>` 或 `Start-Process`。

---

## 8. 完成时报告什么

```
1. 六条缺陷各自的：改哪几行 / 改成什么
2. 七条新用例的红证（修复前）：用例名 + 断言文本 + 实际读数
3. 七条新用例的绿证（修复后）
4. 三套件最终读数（tests / checks / failing）
5. verify.ps1 -DocCite 的 exit code
6. 你踩过的坑（对照 §6 的 18 条）
```

**禁止**把「21/164 全绿」当「定案实现已通过」的证据——那是甲的参考实现读数，
不含 N-B1、不含 R2 收窄、且未编译。
