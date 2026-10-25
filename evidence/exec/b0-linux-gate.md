# B0-01 / B0-02 修复记录：Linux 构建门禁

审计乙在 §10 提出两条 P1，**都成立**：

| 编号 | 问题 |
|---|---|
| **B0-01** | `verify.ps1` 无 `-LinuxBuild`，批 1/2/3 每加一个 CMake target 都在裸奔 |
| **B0-02** | 批 0 的 Linux 绿证**不可重放**——`b0-main-review.md:17` 引用的 `.tmp/verify_linux.sh` 已被删除 |

**B0-02 是我自己造成的问题**：我跑完脚本就 `Remove-Item` 了，只留下输出文本。
乙的原话「只有输出文本、没有可重跑脚本」完全准确。

## 1. 新增 `scripts/linux-build-gate.sh`

永久、可重放的 Linux 构建门禁。契约：

| 退出码 | 含义 |
|---|---|
| 0 | Linux 构建成功、零警告、ctest 全绿 |
| 1 | 真实缺陷：编译错误 / `-Werror` / 测试失败 |
| 2 | **环境缺失**（无 cmake / ninja / 编译器） |

退出码 2 与 1 分开，对齐 `verify.ps1:160-164` 的 G9 教训：
**环境缺失必须显式区分，不能静默跳过。**

除退出码外还断言两件退出码本身证明不了的事：
- `FAILED_COUNT == 0`（ninja 可能在有警告时仍报成功）
- `WINDOWS_H_COUNT == 0`（S21 回归的精确签名）

另加两条结构断言：
- `librtsc_tls.a` 必须产出
- `CreateTlsTransport` 符号必须存在于该库（证明平台中立门面没被拆坏）

## 2. 门禁的绿证（实测）

```
$ wsl -e bash /mnt/f/rtsc/scripts/linux-build-gate.sh
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254140
FACTORY_SYMBOL=present
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15
LINUX GATE PASS
exit=0
```

## 3. 门禁的红证（实测，证明它真能检出 S21 回归）

在 `.tmp/gate-red-full/` 复制整棵树（`src`/`include`/`tests`/`tools`），
把 `CMakeLists.txt` 换成批 0 之前的备份 `CMakeLists.txt.20261023-085223`：

```
CFG=0
BUILD=1
WINDOWS_H=2
/mnt/f/rtsc/.tmp/gate-red-full/src/net/tls_schannel.cpp:29:10: fatal error:
    windows.h: No such file or directory
```

**`WINDOWS_H=2` 与 `BUILD=1` 正是门禁要捕获的签名**，证明门禁不是摆设。

> 第一次尝试失败：我只复制了 `CMakeLists.txt`，没有源码目录，configure 直接失败（`CFG=1`），
> 这不是有效红证。补全源码树后才有意义。

## 4. `verify.ps1 -LinuxBuild`

新增开关，纯 ASCII（已校验 0 行非 ASCII）。

关键设计：**`wsl` 不存在时 `Write-Error` + `exit 1`，不是 skip**。
理由写在代码注释里：门禁存在的目的就是证明 Linux 能构建，WSL 缺失意味着**证明未取得**。

路径转换：`F:\rtsc` → `/mnt/f/rtsc/scripts/linux-build-gate.sh`（盘符小写 + 反斜杠转正斜杠）。

### 实测

```
$ powershell -File F:\rtsc\verify.ps1 -LinuxBuild
...
100% tests passed, 0 tests failed out of 16     <- Windows ctest
== linux build gate ==
CONFIGURE_EXIT=0
BUILD_EXIT=0
FAILED_COUNT=0
WINDOWS_H_COUNT=0
LIB_BYTES=254140
FACTORY_SYMBOL=present
CTEST_EXIT=0
100% tests passed, 0 tests failed out of 15      <- Linux ctest
LINUX GATE PASS
  linux build gate passed
exit=0
```

## 5. 局限

- 只验证了「WSL 存在」这条路径。「WSL 不存在」分支的 `exit 1` 未实测
  （本机有 WSL，无法轻易移除）。
- 门禁脚本自身「环境缺失 → exit 2」的分支未实测（同上）。
- 门禁目前是**手动触发**（`-LinuxBuild`），不是默认运行。
  是否改为默认跑，取决于是否接受每次 verify 多花约 10 秒。**未决**。
