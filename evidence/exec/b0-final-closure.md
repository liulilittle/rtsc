# 批 0 最终闭环记录

日期：2026-10-23
状态：**批 0 PASS，A20-1 已闭环**

## 1. 批 0 交付内容

| 项 | 内容 | 验证 |
|---|---|---|
| **S21**（跨平台） | `rtsc_tls_api`(INTERFACE) / `rtsc_tls_schannel`(if WIN32) / `rtsc_tls`(门面) 三库拆分 | Linux `BUILD_EXIT=0`、`WINDOWS_H_COUNT=0`、ctest 15/15 |
| **S0.9**（4 行） | 3 个 `[[maybe_unused]]` + 1 个 `#include <exception>` | Linux 全量绿 |
| **A20-4** | 删除 3 个死代码 helper（`Str`/`AnsiBytes`/`ToHex`） | `RTSC_TEST` 23/47 不变、23/69 与 47/175 不变 |
| **U20-5** | `#if` 3→2（internal header 无条件 include） | 注入 `windows.h` → `WINDOWS_H_COUNT=2` 红证 |
| **B0-01/02** | `scripts/linux-build-gate.sh` + `verify.ps1 -LinuxBuild` | 绿证 + 红证（还原旧 CMake → FAIL） |
| **B0-07** | 门禁四项正向断言 | 桩门禁 `exit 0` → verify 报错 exit=1 |
| **A20-6/B0-08** | 整行锚定 `(?m)^...\r?$` | 3 种输入：正常 accept / `=01` reject / 带后缀 reject |
| **A20-1** | 全文 59 处引用改锚点定位 | `verify_a201_v2.py` exit=0 |

## 2. A20-1 的三次尝试（前两次都错）

| 尝试 | 判据 | 结果 | 错在哪 |
|---|---|---|---|
| 1 | 正则 +2 | 报 `RESIDUAL 0` | 漏 `t:NNN-MMM` / `tls_schannel.cpp:NNN-MMM` 两种形式；且**原引用本身就差 1**，+2 引入新错误 |
| 2 | `backup[n]==current[n+2]`（甲提出） | 报 86 处 STALE | **重言式**：实测 `[42,700)` 区间 658/658 = 100% 成立，零区分力 |
| 3 | 语义匹配（散文→构造→定位） | **57/57 通过** | — |

### 尝试 2 为什么必须记录

甲的判据可机器判定，但**没有区分力**。它测的是「这行有没有位移」，
对插入点之后的每一行都成立。我沿用后报出的 86 处里，**18 处是我已修好的新值**。

甲自己在 §25 承认：

> 我的谓词变量是 `n`，它只查了两个文件——从来没看文档。
> 这是**插入操作的恒等式**，不是对引用的检验。
> 两种情况都 True，零区分力。
> **真正的教训：判据必须先问「什么输入会让它返回 False」，答不上来就是重言式。**

### 尝试 1 引入的错误

`doc:494` 原文 `tls_schannel.cpp:429`，语义「Shutdown 置 `closed_=true`」。
`old:429` 是 `if` 条件行，`old:430` 才是 `closed_ = true;` —— **原引用差 1**。
机械 +2 得 `:431`（仍是 `if` 行）。正确值 `:432`。

## 3. 最终验证（v2 验证器）

`evidence/exec/verify_a201_v2.py`：

```
anchored citations, verified OK : 59
anchored citations, MISMATCH    : 0
navigation citations w/o anchor : 0
record citations (must keep old): 1
moved-to-factory citations      : 7
exit=0
```

**新增「记录性引用」类别**：`doc:5777` 的 `tls_schannel.cpp:242 应为 :244`
是**描述曾经错在哪**，必须保留旧值，否则失去「修过什么」的证据。
v1 验证器把它误报为缺锚点，v2 已区分。

## 4. 全量验证（四项，逐项单独跑）

```
verify.ps1              exit=0
verify.ps1 -LinuxBuild  exit=0   (LINUX GATE PASS, ctest 15/15)
verify.ps1 -PseudoLint  exit=0
verify.ps1 -DocLint     exit=0   (TOTAL fail=0 warn=0)
```

测试基线：tls 26/139、credssp 23/69、licensing 47/175 —— 全部 0 failing。

## 5. 一处测量错误（两次犯同一个）

第一次：`verify.ps1 -PseudoLint | Select-String ...` 后读 `$LASTEXITCODE` 得 `-1`。
第二次：`foreach` 循环里读 `$LASTEXITCODE` 得 `-LinuxBuild exit=1`。

**两次都是管道/循环覆盖了 `$LASTEXITCODE`**，实际逐个单独跑都是 exit=0。

**判据：读到意外的失败码时，第一反应是「我的测量方式是否改变了被测对象」。**

## 6. 批 0 遗留

| 编号 | 级别 | 内容 | 处置 |
|---|---|---|---|
| — | — | **无 P0/P1** | — |
| A20-4 备注 | P3 | 3 个 helper 已删除，但 `test_crypto.cpp:36-48` 有等价活版本 | 无需处置 |

## 7. 下一步

批 1（CredSSP：S1 S5 S6 S11 S18）与批 2（TLS：S7 S8 S9 S10 S19 S22 S23 S24）**可并行**
（不同库、无共享文件）。
