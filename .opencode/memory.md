# RTSC 记忆（memory.md）

## 项目本质
RTSC = mstsc 逆向重写（Reverse To Source Client）。以 Windows 官方 RDP 客户端
mstsc.exe + mstscax.dll 为逆向对象，用 C++ 跨平台重写，最终支持 Windows 与 Linux。

## 多平台路线（2026-10-23 用户明确指示）

**用户原话**：「先逆向成 C++ 没有问题后我们要考虑 Android/其它平台」
「就是跨平台实现，但先把 Windows 版本搞正确没问题」。

### 顺序（不可颠倒）
1. **先把 Windows 版做正确**（当前阶段）：协议正确性、SChannel 后端、CredSSP、实机连通。
2. **之后**扩 Android / Linux / macOS。**不是现在并行做**。

### 但架构必须从一开始就为跨平台留位（零成本前置）
这些约束**现在就要遵守**，因为事后改造代价远大于当下遵守：

| 约束 | 现状 | 要求 |
|---|---|---|
| 协议层零平台依赖 | ✅ 已满足：`src/proto/*`、`src/crypto/*` 无任何 Windows 头 | 禁止在 proto/crypto 引入平台 API |
| 字节序显式移位 | ✅ 已满足：`byte_order.cpp` 全用 `<<`/`|` 手工拼，无 `htonl`/`__builtin_bswap`/`memcpy` 到整数 | 禁止用平台字节序函数；ARM 大端/小端都必须对 |
| 平台耦合集中隔离 | ✅ 仅 `src/util/crash_guard.cpp` 一处 `#ifdef _WIN32`，且已提供非 Windows no-op | 新平台代码必须新建文件，不得在既有文件里加 `#ifdef` 分支 |
| TLS 后端接口化 | 🔄 `TlsTransport` 纯虚接口已设计（`design-a.md`） | Windows=SChannel，Linux/Android=OpenSSL/BoringSSL，**禁止**把 SChannel 类型泄漏进接口 |
| 测试可跨平台 | ✅ 12 套件全用自研 CHECK 宏，无 gtest/Catch 依赖 | 禁止引入需平台适配的测试框架 |
| CMake 平台分支 | ⚠️ 现为 `if(MSVC)` 加 `/W4 /WX`；`target_link_libraries(rtsc_util PUBLIC dbghelp)` 在 MSVC 内 | 新平台用 `if(CMAKE_CXX_COMPILER_ID MATCHES ...)`，不得假设 MSVC |

### 已知的 Android 特有约束（现在记下，实施时验证）
- **TLS**：Android 系统无 OpenSSL 公开 API，需 BoringSSL（NDK 自带）或自编译 OpenSSL；**不可**假设有 SChannel。
- **证书库**：SChannel 的 `CertCreateSelfSignCertificate`（自签测试用）无对应物，需 BoringSSL 的 `X509` API 或测试期静态证书。
- **字符编码**：Android 全 UTF-8，`wchar_t` 是 4 字节（Windows 是 2 字节）→ **禁止**在协议层用 `wchar_t` 表达 UTF-16；现有 `client_info.cpp` 已有显式 UTF-16LE 编码函数，正确。
- **线程/网络**：Android 用 POSIX socket + pthread；`std::thread` 可用（libc++ 支持）。
- **崩溃取证**：`crash_guard` 的 dbghelp 路径在 Android 需换为 `debuggerd`/`tombstone`，但这是**开发期工具**，不影响产品代码。

### 架构分层目标（最终形态）
```
include/rtsc/proto/   协议编解码（纯数据，零平台依赖）
include/rtsc/crypto/  密码学原语（MD4/MD5/SHA1/HMAC/RC4/NTLM）
include/rtsc/net/     传输抽象：ITransport（socket）、TlsTransport（TLS）
src/net/win/          SChannel 后端 + Winsock ITransport
src/net/posix/        OpenSSL/BoringSSL 后端 + POSIX ITransport
src/net/android/      平台特定（JNI 桥、证书库适配）
```

## 硬约束（用户口径）
- 所有产出物必须位于 F:\rtsc 内；禁止在 C 盘创建/写入任何工作文件（含临时文件）。
  命令行中显式设置 TEMP/TMP 为 F:\rtsc\.tmp。
- 逆向工具链位于 G:\sre（只读使用）：Ghidra 12.1.4、Temurin JDK 21.0.12.1。
- REA 版本以 6.7.0 为准（技能文档中的 6.3.0 已过期）。

## 方法论
1. 双证据源：官方规范（[MS-RDPBCGR] 等）+ 二进制取证（Ghidra/REA）；二者冲突时以
   真实抓包（pktmon）裁决。
2. 分层实现：TPKT → X.224 → MCS(T.125) → 安全层 → 能力交换 → 图形/输入/通道。
3. 每层 TDD：先写规格测试（红）→ 最小实现（绿）→ 重构。
4. 每条协议常量/字段必须能追溯到规范章节或 Evidence 地址。
5. **文本检查与结构检查是两类不同手段，不可互相替代**（2026-10-23 沉淀）：
   - 文本层（doc-lint、残留扫描、正则判据、变异测试）只能发现"字写错了/漏了/不一致"。
   - **控制流结构缺陷（缺回边、变量未定义、状态入口检查与返回点不自洽）会被文本检查全部放过**。
     实例：design-a 的 B1（成功路径无 `continue` → 一次 Receive 只解一条）、
     B2（`extra_len` 从未定义）、B3（`kClosed` 不置 `terminal_` 却承诺幂等），
     三条阻断**全部通过**了 doc-lint(fail=0) + 残留扫描。
   - 伪代码/代码必须**逐路径走查**：列出全部出口与回边，对每个出口断言
     「资源是否已消费」「输出是否已正确累加」「返回值是否符合契约」。
6. **位置类缺陷只能靠执行路径模拟发现**：连续两轮静态审阅都可能放过同一处
   （乙两次读 design-a `plaintext_out.clear()` 都当成"失败路径保护"，
   因为它位置在循环体内才出错）。**"模拟 N 条数据逐迭代走一遍"是唯一可靠手段。**
7. 审计方与被审方**都要能自我更正**：本项目已出现多次"审计 AI 判错后主动撤回"
   （乙撤回 D14、更正绿证 8 机制分析、承认 N5 是自身遗漏），
   以及"主代理判断错误被子代理纠正"（我的"原伪代码也能返回 kOk"分析被乙推翻）。
   **正确性属于团队，不属于角色权威。**

## 改文件与汇报的硬规则（2026-10-23 三次失实后沉淀）

本项目已发生 **3 次「汇报已改但实际未落地」**（`:88` 一次、`kOk_WITH_CLOSED_FLAG` 两次）。
根因两类：①写了替换代码但没跑就汇报；②`assert` 失败被后续串联命令掩盖。
以下 4 条为硬规则，**违反即视为未完成**：

1. **汇报「已改」必须附「改后文件的实际状态」，不是「我写了什么代码」**。
   - ❌「已改为 `re.match(r'^st\b', cond)`」← 这是意图
   - ✅「读回文件：`re.match(r'^st\b'` 命中 :91；`'st' in cond` 仅注释 1 处」← 这是事实
   - 成本 +1 次读回，第 1 类失实归零。

2. **每处替换必须双向断言 + 读回**：
   ```python
   if old not in L[idx]: raise SystemExit(1)      # 锚点失效立即停
   L[idx] = L[idx].replace(old, new)
   # 写完读回
   chk = io.open(p, encoding='utf-8').read()
   assert old_pattern_gone(chk) and new_pattern_present(chk)
   ```
   只检查「旧串在不在」不够，必须检查「替换后旧串是否消失」。

3. **禁止用 `python -c` 串联多个操作**。改文件/验证一律独立脚本文件，
   一次一件事，退出码即结论；PowerShell 侧逐条 `if ($LASTEXITCODE -ne 0) { exit 1 }`。
   **「命令链最后一行成功」≠「每一行都成功」。**

4. **每条正则/锚点检查必须配「等价写法」红证**。
   同一语义至少测三种写法：①行首 `^\s*X` ②`;` 分隔 `; X` ③跨行。
   实例（G8）：`closed_=true; pass`（同行）曾漏检，而伪代码自己就在用 `closed_ = true; return kClosed` 同行写法。
   **锚点是正则最易出错处，且只在特定写法下暴露。**

5. **「变异被检出」≠「检查机制生效」**。
   若变异同时改变了被 EXPECT 比对的动作，报错可能来自上层比对而非下层检查（「顺带检出」）。
   验收新增检查时，必须有**直接调用检查函数**的测试，绕开 evaluate/EXPECT/main。
   实例：`verify_sideeffect_leaf.py` 直接调 `_classify_leaf()`。

6. **门禁文件的缺失必须 FAIL，不能静默 skip**。
   实例（G9）：`verify.ps1` 预检漏了 `$side`/`$csr`，删掉检查器文件后门禁仍通过。
   所有门禁脚本必须先进 `foreach ($f in @(...)) { if (-not (Test-Path $f)) { exit 1 } }`。

## 正则锚点与证据的补充规则（2026-10-23 第 15-16 轮沉淀）

7. **扫描/统计类验证的 12 条铁律**（原 7-29 条压缩；细节见 git 历史）
   a. **先定 oracle 再谈偏差**：任何"多少次/偏多少/是否一致"的统计，必须先写明预言机是什么
      （规范原文/独立参考实现/数学定义/真机抓包）；两个实现互比只能答"是否一致"。
   b. **口径必须全量**：说"全部扫描"就必须覆盖全部候选（含注释、docstring、字符串、跨行），
      并把"扫了多少行/多少个文件"写进输出；只扫子集却宣称全量 = 假证据。
   c. **匹配必须加词/边界**：`x in text` 一律禁止；用 `\b<标识>\b` 或 `<stem>.cpp/.exe`
      等具体展开，否则 `iso` 命中 `poisoned`、`probe` 命中英文单词。
   d. **统计源只取已定性文档**：把"元文档/探针本身的输出"当结论来源 = 自证循环。
   e. **差值要显式写出 A - B = C**，不能只报 A；"22 次匹配"里 20 次是假命中时，
      报"减 20 = 2"才是结论。
   f. **三态判定**：未记录 / 记录且未变 / 记录且改变。把"无记录"折成"未变"= bug 同源。
   g. **状态快照不能覆盖轨迹**：追加式 JSONL 而非覆写 JSON；"记录历史"的工具要检查写入方式。
   h. **before 状态必须在改动前落盘**（`*.before.log` / `*.after.log`），事后补写 = 伪造。
   i. **缺数据要分两类**：环境/工具缺失 → skip 并打印原因；被验证物缺失/无框架/无脚本
       → exit 1（并给显式 override）。把后者当 skip = 静默漏测。
   j. **脚本与日志成对留档**：过程脚本可删，但"结论 + 修复前后输出"必须落到 evidence/。
   k. **禁止硬编码期望值**（如 `code == 8`）：改用"与真实实现比"的对照验证。
   l. **正则扩展后必须反向自测**：既验证"该匹配的都匹配"，也验证"不该匹配的没匹配"。
8. **技术实证记录（TLS/NTLM/CredSSP 等）**：保留在原第 30-146 条（下文），
   核心结论：`dwProtocol` 是 `SP_PROT_*` 位掩码不是 0x0303；`InitializeSecurityContext`
   首次调用必须 `cbBuffer=0, pvBuffer=nullptr` 否则 `SEC_E_INVALID_TOKEN`；
   NTLMv2 的 LMv2 字段与 AV 列表必须按官方文档逐项核对；
   `subprocess` 无法直接 `call vcvars64.bat`（需写 .bat 再 `cmd /c`）。
9. **验证方法论总纲（原 30-146 条压缩；逐条细节见 git 历史）**
   证据优先 / oracle 先行 / 口径全量 / 匹配加边界 / 三态判定 / 快照不覆盖轨迹 /
   缺数据分两类 / 禁止硬编码期望值 / 变异验证 / 同型排查
   —— **与规则 7 的 a-l 同义，以规则 7 为准，不重复展开**。
   规则 7 未覆盖的补充：
   - **双审分工**：一个自顶向下、一个自底向上，避免同向盲区；审计与执行必须不同 AI。
   - **失败即档案**：每次失败记 [尝试][错误][下一步]；同一错误三种方法无解必须升级。
   - **文档与代码同源**：文档里的行号/常量/接口必须可 grep 验证；文档漂移视为缺陷。
   - **注释即契约**：注释写"因为…所以安全"之前必须找到那个"因为"；找不到就不写。
   - **平台差异**：Windows 路径转义、`$LASTEXITCODE` 被循环覆盖、`subprocess` 无法直接 call vcvars
     等平台坑必须实测，不凭记忆。
   - **技术实证（保留结论）**：`dwProtocol` 是 `SP_PROT_*` 位掩码（TLS1.2=0x40）不是 0x0303；
     `InitializeSecurityContext` 首次调用必须 `cbBuffer=0,pvBuffer=nullptr`；
     NTLMv2 的 LMv2 与 AV 列表必须按官方文档逐项核对；
     `SEC_I_CONTINUE_NEEDED` 在不同阶段语义相反；
     `SECBUFFER_EXTRA` 为 0 不代表无数据，需按记录头判断。
## 环境事实
- OS Windows 11 10.0.26200 x64，管理员权限可用
- MSVC 14.44.35207（VS2022 Enterprise），cl/dumpbin/link 在 PATH
- CMake 3.31.6-msvc6 / Ninja 1.12.1 位于 VS CommonExtensions，未在 PATH
- Git 2.55.0、Python 3.14、Node 24.21.0
- 无 IDA / 无 Hopper / 无 jadx / 无 tshark
- 无 OpenSSL、无 vcpkg（加密层必须自带实现，或另行解决依赖）
- 本地 RDP 服务默认关闭（fDenyTSConnections=1）

## REA 接入（2026-10-22 完成）
- `C:\Users\liulilte\.config\opencode\opencode.json` 的 `mcp.rea` 已由
  `rea-agents@6.7.0 setup --client opencode --yes` 写入，手工补 `environment`：
  GHIDRA_INSTALL_DIR=G:\sre\ghidra、JAVA_HOME=G:\sre\java\jdk-21.0.12.1+1、
  TEMP/TMP=F:\rtsc\.tmp、npm_config_cache=F:\rtsc\.tmp\npm-cache、
  REA_GHIDRA_STARTUP_TIMEOUT_MS=1800000，`timeout`=180000。
- 技能 `C:\Users\liulilte\.agents\skills\reverse-engineer-anything` 已升级 v34→v42（207 工具）。
- 独立探针验证：MCP initialize 返回 `{"name":"rea","version":"6.7.0"}`，tools/list 207 项。
- 配置改动需重启 opencode 才在会话内出现 REA 工具；未重启时走 CLI
  `npx -y rea-agents@6.7.0 <cmd>`（同样需上述环境变量）。
- 备份：`.opencode/backups/opencode.json.20261022-141140`、`rea-SKILL.md.20261022-141140`。

## 目标二进制
- C:\Windows\System32\mstsc.exe  10.0.26100.8875  1,114,112 B（仅 shell/连接对话框）
- C:\Windows\System32\mstscax.dll 10.0.26100.8875  9,166,848 B（协议栈核心，ActiveX 客户端）
  sha256 d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05，
  image base 0x180000000，22814 procedures / 20659 strings
- 协议相关模块：rdpbase.dll、rdpcorets.dll、rdpnanoTransport.dll、RdpAvenc.dll、
  rdpcredentialprovider.dll、rdpendp.dll、rdpclip.exe

## 设计原则（E6-E10 沉淀）
- 协议解析一律使用显式偏移 + 边界检查的 Reader，禁止 memcpy 结构体直接映射（对齐/端序风险）。
- 解码函数返回三态：Ok / NeedMoreData / Invalid*，便于流式解析与断链判定。
- 长度字段与实际数据必须一致性校验（TPKT 规范明确要求）。
- 不使用第三方依赖起步（避免 vcpkg/网络依赖），加密层自带实现（已落地）。

## 崩溃取证（2026-10-22 沉淀，用户明确要求）
- **根因**：Windows 未处理异常默认交给 WER，弹出模态对话框 → 进程挂住 → 自动化流水线
  看到的是"超时"而不是"失败"，等于把崩溃信息全部丢掉。只装
  `SetUnhandledExceptionFilter` + `CaptureStackBackTrace` 而没有关 WER、没有 minidump，
  仍然会阻塞。
- **正确做法**（`src/util/crash_guard.cpp`，`rtsc::util::InstallCrashGuard`）：
  1. `SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX)`
     —— 关掉 GPF 弹窗，这是"不阻塞"的关键。
  2. `_set_error_mode(_OUT_TO_STDERR)` + `_set_abort_behavior(0, _WRITE_ABORT_MSG|_CALL_REPORTFAULT)`
     —— CRT abort 不再进 WER。
  3. `_CrtSetReportMode/_CrtSetReportFile(_CRT_ASSERT|_CRT_ERROR → STDERR)`
     —— assert 对话框改到 stderr。
  4. `SetUnhandledExceptionFilter` + `MiniDumpWriteDump`（ThreadInfo|UnloadedModules|
     ProcessThreadData）+ 文本报告（异常码/地址/模块+偏移/参数/符号化栈）。
  5. `set_terminate` / `_set_purecall_handler` / `_set_invalid_parameter_handler` /
     `signal(SIGABRT)` 全部接管。
  6. 收尾 `TerminateProcess(..., 3)` —— 用非零退出码，让 ctest 立刻判失败。
- **回溯必须最先抓**：`CaptureStackBackTrace` 要在 `CaptureAndDie` 入口调用（`skip+1`），
  否则栈顶全是 crash-guard 自己的帧。
- 输出目录：`RTSC_CRASH_DIR` 环境变量优先，否则 `<exe目录>\crashes`。
- 验证入口：`verify.ps1 -CrashCheck`（三种模式 null/abort/terminate，每个独立目录，
  60s 未退出即判 FAIL，并断言 reason 行与模式匹配）。
- 测试统一入口 `tests/test_main.h` 的 `rtsc::test::run_all(app)`：装 guard + 跑用例 +
  失败时打印 dump 目录，避免每个测试文件重复 main。

## MCS 层事实（2026-10-22 规范核实，推翻早期假设）
- **1002 是 Server Channel（固定 `0x03EA`），不是 I/O 通道、也不是用户通道**。
  客户端**不 join** 1002；它只作为 server→client Send Data Indication 的 `initiator`。
- 客户端 join 顺序（[MS-RDPBCGR] 3.2.5.3.8）：User Channel（Attach User Confirm 分配）→
  I/O Channel（SC_NET 的 `MCSChannelId`）→ Message Channel（仅当非 0）→ Static VC
  （SC_NET 的 `channelIdArray`，顺序与 CS_NET 请求一致）。
- 除 1002 外**所有 channel id 都由服务器指定**，不是规范固定值。
- UserId 编码 = `(id - 1001)` 的 u16 大端；ChannelId 编码 = 原值 u16 大端。
- `DynamicChannelId ::= ChannelId (1001..65535)`；[MS-RDPBCGR] 3.3.1.2 写的
  "1001 to 65536" 与 T.125 冲突，取 T.125。
- Send Data 的 `dataPriority|segmentation|padding` 字节恒为 `0x70`。
  choice 25=`0x64`（请求）、26=`0x68`（指示）。
- Send Data 的 `userData` 上限 **16383**（[MS-RDPBCGR] 2.2 禁止 PER 分片形式）。
- DPU：`21 80` 共 2 字节；[MS-RDPBCGR] 2.2.2.3 写 "mcsDPum (8 bytes)" 是笔误。
- `Result` 枚举 16 值、`Reason` 枚举 5 值；RDP 侧 Result 只用 0 与 14，
  Reason 只用 1（provider-initiated）与 3（user-requested）。
- Fast-Path **不经** TPKT/X.224/MCS，连接建立全程走慢路径。
- GCC 内层长度是 **PER 14-bit determinant**（非 BER），正确上限 `0x3FFF`。
- `h221NonStandard` 是 4 字节 ASCII（"Duca" 客户端 / "McDn" 服务器），前置 1 字节
  PER 长度决定因子（len−4=0）。

## 密码学与许可层事实（2026-10-22 落地）
- 自带实现（`src/crypto/hash.cpp`）：MD4 / MD5 / SHA-1 / HMAC-MD5 / RC4。
  MD4 只为 NTLM 的 NT hash 保留——换成 SHA-* 会直接导致认证失败。
- RC4 是**有状态**流密码：许可的 MAC/加密对、NTLM 的 SEAL 都要求同一实例连续推进。
  用独立实例算 checksum 会得到错误值（已被 [MS-NLMP] 4.2.4.4 向量的红证确认）。
- 许可 L3 密钥派生（[MS-RDPELE] 5.1.2）：
  `SaltedHash(S,I) = MD5(S || SHA1(I || S || ClientRandom || ServerRandom))`，
  `SaltedHash2` 的随机数顺序**相反**（ServerRandom 在前）。这是最易写错的地方。
  `'A'/'BB'/'CCC'` 是字面字符串，不是重复字符。
  `MAC-salt-key` = SessionKeyBlob 前 16 字节；
  `LicensingEncryptionKey` = MD5(后 16 字节 + ClientRandom + ServerRandom)。
- 许可 MAC（5.1.5）= `MD5(mac_salt_key || pad2 || SHA1(mac_salt_key || pad1 ||
  LE32(len) || data))`，pad1 = 40×0x36，pad2 = 48×0x5C，输出**完整 16 字节**
  （不是 Standard RDP Security 的 8 字节截断）。
- `ERROR_ALERT(0x07, 0x02)` = `STATUS_VALID_CLIENT` + `ST_NO_TRANSITION` 是**成功**信号，
  不是失败。当成失败会自己掐断连接。
- `wBlobLen == 0` 时 `blobData` **不出现在线上**（不是"存在但为空"）。
- `EncryptedPlatformChallenge.wBlobType` / `EncryptedHWID.wBlobType` 服务器发垃圾值或
  `0x0001`（官方 dump 即如此），**禁止校验**。
- `NEW_LICENSE_INFO.pbScope` 是 **ANSI**，同结构内 `pbCompanyName`/`pbProductId` 是
  **UTF-16LE**（官方 dump 并存，硬证据）。
- HYBRID_EX 下 L3（许可内部 RC4）**仍然加密**；TLS 只替代 L2（Standard RDP Security），
  只免除 `SEC_LICENSE_ENCRYPT_CS/SC` 标志。
- RSA 是 **raw**（`c = r^e mod n`，无 PKCS#1/OAEP），线上格式 6 字段
  `magic/keylen/bitlen/datalen/pubExp/modulus`，modulus 尾部有 **8 字节零填充**并计入 keylen。
  Windows 实际用 2048-bit（`keylen=264`），规范正文写 512-bit 是过时描述。
- 许可阶段有两条路径：personal terminal server 走**零许可消息**（只解析 16 字节
  ERROR_ALERT）；application server mode 必须走完整 13 步。运行时按 bMsgType 分支，
  禁止编译期写死。

## 安全层事实（2026-10-22 规范核实 + 实机红证）
- **CredSSP 在 TLS 之上**：X.224 CCF（明文）→ TLS 握手 → TSRequest×5（全在 TLS 内）→
  EUAR 4 字节裸 PDU（仅 HYBRID_EX）→ MCS Connect Initial（在 TLS 内）。
- 目标 192.168.1.7:3389 强制 `PROTOCOL_HYBRID_EX`（0x08）：
  `RDP_NEG_RSP flags=0x0F selectedProtocol=0x08`。
- pubKeyAuth v5/6：`SHA256("CredSSP Client-To-Server Binding Hash\0" || nonce ||
  SubjectPublicKey)` 再经 NTLM SEAL 封装成 `LE32(1)||checksum||LE32(0)||ciphertext`，48 字节。
  `SubjectPublicKey` 是证书 SPKI 里的 BIT STRING 去掉 unused-bits 字节，
  **不是**整证书、**不是**整 SPKI、**不是**指纹。
- 本服务器要**裸 NTLM blob**；用 SPNEGO negTokenResp 包会返回 `SEC_E_INVALID_TOKEN`。
- 客户端发 version 1..8，服务器恒回 6。

## TLS 后端事实（2026-10-22 实机实测，推翻 security-layer.md §8 结论）
- **Windows 侧零依赖可行**：SChannel 对真实 RDP 服务器完成 TLS 1.2 握手，
  `protocol=0x0800`、`cipher=0x6610`（TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384）、
  `stream sizes: header=13 trailer=16 maxmsg=16384 block=16`，**2 轮往返**完成。
- **SPKI 导出**：`CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO)` 作用于
  `cert->pCertInfo->SubjectPublicKeyInfo` → **294 字节** DER，与证书 DER 偏移 134 处逐字节相同。
  CredSSP pubKeyAuth 用的是其中 **270 字节**（去掉 24 字节 SPKI 头）。
  把整张证书传给 `CryptDecodeObjectEx(X509_PUBLIC_KEY_INFO)` 会 **0xC0000005 访问违例**。
- **进程内回环可行**（`evidence\tls\loopback_schannel.cpp`，`RESULT=PASS`）：
  同进程 INBOUND + OUTBOUND 双上下文，2 轮握手，双向应用数据、双记录 `SECBUFFER_EXTRA`、
  截断记录 `0x80090318` 全部符合预期。这是 TLS 层红证的主路径。
- **SChannel 流上下文三个必踩的坑**：
  ① `DecryptMessage` 的 `sb[0]` 必须是 `SECBUFFER_DATA` + **完整记录**（含 5 字节头）；
     `SECBUFFER_STREAM` 是 datagram 上下文用法，用了会 `0x80090308 SEC_E_INVALID_TOKEN`。
  ② `ISC_REQ_ALLOCATE_MEMORY` 与预分配 `SecBuffer` **不能同时用** —— SChannel 会替换
     `pvBuffer`，导致发出垃圾字节 → 对端 `0x80090331 SEC_E_ALGORITHM_MISMATCH`。
  ③ 每轮复用同一个输出 vector 必须 `clear()`，否则 token 被回喂给自己。
- `SP_PROT_TLS1_2_CLIENT`(0x800) / `SP_PROT_TLS1_2_SERVER`(0x400) 是**方向标志**不是版本号；
  判版本要看 `SECPKG_ATTR_CONNECTION_INFO.dwProtocol` 的完整掩码。
- **选型结论**：双后端 + 后端无关接口。Windows=SChannel（零依赖，已验证），
  Linux=OpenSSL（后续）。**禁止**用系统 `CredSSP` SSP —— 会把 pubKeyAuth/NTLM 整个黑盒化，
  与"逆向重写协议栈"的项目目标冲突。NTLM/CredSSP 一律自研。
- 环境无 vcpkg / perl / nasm / OpenSSL，`security-layer.md` §8.2 的三条 Windows 集成路径
  在当前环境**全部不可用**；且 §8 建议的 `find_package(OpenSSL REQUIRED)` 会让整个工程
  configure 失败、所有测试套件全灭，直接违反零依赖硬约束。
- 红证 harness 保真度 5 条（由双向批评沉淀）：①不得添加被建模代码没有的检查；
  ②不得遗漏被建模代码已有的检查；③建模判定必须在报告中显式声明"这是建模结论"；
  ④必须另附逐字实现交叉验证；⑤下溢/回绕按真实语义建模并注明。

147. **安全层接入的核心约束：阶段与缓冲区必须同属一个所有者**（2026-10-24 第27轮）。
    同一条 TCP 字节流在连接建立期要依次被切成四种单位：TLS record / CredSSP DER 自定界 /
    EUAR 固定 4 字节 / MCS TPKT。谁决定"从缓冲区头部消费几个字节"，谁就必须同时知道"现在是什么阶段"。
    拆到两个对象必然产生 split-brain。实现：SecurityLayer 持有单一 pending_cipher_，
    Step() 追加后跨阶段循环推进。
148. **EUAR 不会被误当 MCS，但会被"静默吞掉"**（2026-10-24）。
    TpktStream 在头部不是 03 00 时逐字节前扫并丢弃；AUTHZ_SUCCESS 与 AUTHZ_ACCESS_DENIED
    都会被当垃圾丢掉。结果：授权被拒也"看起来连上了"。必须有一个显式的"恰读 4 字节"阶段。
149. **驱动器不能在 kWrite 后重复 pump**（2026-10-24 第27轮，实测缺陷）。
    ConnectionDriver::DriveSecurity 初版在 want==kWrite 后 continue 再调 Step(nullptr,0)，
    而脚本化 TLS 每次调用都推进一轮，导致 TLS 握手被无输入推到第 2 轮完成。
    正确语义：kWrite 即返回（调用方写完再读再调 OnData）。
    "循环直到需要输入"不等于"循环直到无输出"。

150. **HYBRID_EX 下除 Client Info/licensing 外无 RDP security header**（2026-10-24 第29轮）。
    docs/spec/security-layer.md §1.3：[MS-RDPBCGR] 5.4.4 原文
    "Because RDP encryption is not used in the presence of an External Security Protocol layer,
    the security header data is not present in any RDP traffic (except for the Client Info and
    licensing PDUs)"。
    所以 Demand Active / Synchronize / Control / FontMap 等慢路径 PDU 的 share control header
    直接跟在 MCS payload 之后。licensing PDU 用 4 字节 Basic 头（flags = SEC_LICENSE_PKT 0x0080）
    区分。把 security header 当成"总是存在"会让整个数据面偏移 4 字节且无错误码。
151. **会话建立状态机（S0-S6）的分支完备要点**（2026-10-24 第29轮，capabilities.md §12）。
    - S1 收 pduType 不符 -> **忽略**；长度不符 -> **断链**（两者处置相反，不能合并）
    - Confirm Active 发出后**立即**获得 input 发送许可（不等 Server Synchronize）；
      但服务端在收到 Font List 之后才发图形（两者不对称）
    - S5（Deactivate All）**不重跑** MCS/安全层/licensing，只重跑能力交换与最终化
    - 未列出的 (state, event) 一律忽略并告警，不改状态、不断链
    - Font Map 是连接序列最后一个 PDU，收到它才是 S4

152. **RDP 的 RSA 不是 PKCS#1，是原始 RSA**（2026-10-24 第30轮，已联网核实）。
    [MS-RDPBCGR] 5.3.4.1 原文：`c = r^e mod n`，且 "The client random value is interpreted
    as an unsigned **little-endian** integer value"，结果拷进 `(bitlen/8)+8` 字节的零缓冲。
    三个易错点：①无填充（不是 PKCS#1 v1.5）②输入小端 ③输出多 8 字节零尾。
    任一处错，服务器解不出 premaster，症状只是"连接被断"，无错误码。
    实现：Windows BCrypt（`BCRYPT_PAD_NONE`），输入反序并左填充到模长。
    与 TLS 的 RSA（PKCS#1 v1.5）**完全不同**，禁止复用同一段代码。

153. **许可 L3 加密与 TLS 无关，永远存在**（2026-10-24 第31轮，licensing.md §6.1）。
    只要走 NEW_LICENSE_REQUEST 路径，就必须实现许可自身的 RC4 + MD5 MAC 层：
    48 字节 premaster + 32 字节 client random 用服务器 RSA 公钥加密，
    Encrypted* 字段用许可加密密钥 RC4 加密。HYBRID_EX 下 TLS 只保护外层，
    L3 是内层独立保护——**不能因为"有 TLS 了"就跳过 L3**。
    L3 密钥派生两轮的 random 顺序相反（SaltedHash 是 CR||SR，SaltedHash2 是 SR||CR），
    这是最常写错处；MasterSecret 是 48 字节（3×16），不是 32。
154. **许可 PDU 是 HYBRID_EX 下仅有的两种带 security header 的 PDU 之一**
    （2026-10-24，security-layer.md §1.3）。许可 PDU 带 4 字节 Basic 头（flags = SEC_LICENSE_PKT 0x0080）；
    其余慢路径 PDU 无头。所以"收到第一个 PDU 先看前 2 字节是否是 0x0080"是区分许可与能力交换的判据。

155. **Standard RDP Security 与许可 L3 的密钥派生相似但不同**（2026-10-24 第33轮，已用 FreeRDP 交叉核对）。
    两者都是 `SaltedHash(S,I)=MD5(S+SHA1(I+S+CR+SR))` 的链，但：
    | | PreMasterSecret | SessionKeyBlob 标识符 | SessionKeyBlob 的 random 顺序 |
    |---|---|---|---|
    | Standard RDP Security | First192Bits(CR)+First192Bits(SR) | X / YY / ZZZ | CR \|\| SR（同 SaltedHash） |
    | 许可 L3 | RSA 解密的 48 字节 | A / BB / CCC | SR \|\| CR（SaltedHash2） |
    **禁止把两者合并成一个函数**。标识符长度也不同（'X'=1, 'YY'=2, 'ZZZ'=3）。
    算法已用 FreeRDP `libfreerdp/core/security.c`（security_establish_keys/security_A/security_X）逐行核对。
156. **差分测试的「独立实现」也可能自己错**（2026-10-24 第33轮）。
    我写的 Python hashlib 参考实现把 `b'ZZ'` 写成了 `b'ZZZ'`（少一个 Z），
    结果 EncryptKey 期望值错，被 C++ 实测抓出（Python 错，C++ 对）。
    **教训：差分测试发现不一致时，先假设「任一方都可能错」，用第三信息源（规范原文/FreeRDP）裁决，
    不能默认「被测代码错」。** 这与 memory 规则 26（驳回前先验证前提）同族。

157. **RDP 加密顺序：MAC 先于 RC4，且 MAC 覆盖明文**（2026-10-24 第34轮，已核实官方原文）。
    [MS-RDPBCGR] 5.3.6 逐字："First, a MAC value is generated over the unencrypted data.
    Next, the data block is encrypted with RC4 using the current client or server encryption
    substitution table." 解密是反序：先 RC4 解密，再对明文算 MAC 比对。
    **易错点**：若先加密再对密文算 MAC，或解密后对密文算 MAC，两边都自洽但都与服务器不兼容。
158. **Standard RDP Security 每 4096 包必须更新密钥**（2026-10-24，[MS-RDPBCGR] 5.3.6.1）。
    key = RC4(key, MD5(update_key + pad2 + SHA1(update_key + pad1 + key)))，
    update_key 是**初始**密钥（不随更新变），40/56-bit 更新后再套盐。
    RC4 是流密码，不更新会让密钥流超过安全长度。收发两个方向**各自**独立计数与更新。
    测试方法：跑 >4096 包并跨边界，两端必须仍能互解（否则说明只更新了一端或计数不同步）。

159. **Fast-Path 的两个头位序必须分开记**（2026-10-24 第35轮，已核实官方原文 + 4.7 dump）。
    - **事件头**（TS_FP_INPUT_EVENT::eventHeader，1 字节）= `eventFlags`(低 5 位) | `eventCode`(高 3 位)。
      证据：官方 4.7 dump `0x20` → eventCode=1(MOUSE)、eventFlags=0。
    - **PDU 头**（TS_FP_INPUT_PDU::fpInputHeader，1 字节）= `action`(低 2 位) | `numEvents`(4 位) | `flags`(高 2 位)。
      证据：官方 4.7 dump `0xc4` → action=0、numEvents=1、flags=0x3(ENCRYPTED|SECURE_CHECKSUM)。
      **numEvents 是 4 位（不是 5 位）**；>15 事件时该 4 位写 0，并在 dataSignature 之后插 1 字节扩展计数。
    两个头都容易把「低 5 位 vs 高 3 位」记反，一旦记反所有事件类型都会错位。

160. **Fast-Path 更新头与「字段存在」vs「数据压缩」是两回事**（2026-10-24 第36轮）。
    - `TS_FP_UPDATE::updateHeader` = `updateCode`(低 4 位) | `fragmentation`(2 位) | `compression`(2 位)。
      `compression == 0x2` 只表示**后面有一个 compressionFlags 字节**（字段存在），
      **不表示数据已压缩**；数据是否真压缩看 `compressionFlags & PACKET_COMPRESSED (0x20)`。
      两者混为一谈会导致：把未压缩数据当压缩去解，或漏读/多读 1 字节导致后续全部错位。
    - 更新数据长度 `size` 是 u16 LE，位于 updateHeader [+compressionFlags] 之后。
      解析必须按 `size` 前进而不是按「结构预期长度」，否则遇可变长 payload（位图/指针）必错。

161. **RDP 未压缩位图：自底向上 + 每行补齐到 4 字节**（2026-10-24 第37轮，已核实官方原文）。
    [MS-RDPBCGR] 2.2.9.1.1.3.1.2.3 逐字："Uncompressed bitmap data is formatted as a
    bottom-up, left-to-right series of pixels. Each pixel is a whole number of bytes.
    Each row contains a multiple of four bytes (including up to three bytes of padding,
    as necessary)."
    - **自底向上**：wire 第 0 行是图像最后一行；转成顶向下要整行倒序。
    - **4 字节行补齐**：1x1 的 16bpp 也要 4 字节；按 `width*bpp/8` 算长度会短读。
    注意与 RLE 的 `scanWidth`（2 字节对齐）区分——两者对齐单位不同。
162. **像素字节序**：24bpp 是 BGR、32bpp 是 BGRA（不是 RGB/RGBA）。
    16bpp 是 RGB565（R 5 位在最高、G 6 位居中、B 5 位最低），15bpp 是 RGB555。
    位扩展用 `(v << n) | (v >> (width - n))`（如 5 位 -> `(v<<3)|(v>>2)`）以保证 0/满量程映射正确。

163. **RLE 位图压缩序的分派规则**（2026-10-24 第38轮，[MS-RDPBCGR] 2.2.9.1.1.3.1.2.4）。
    三种形式共存于一个字节流，分派顺序必须是：
    1. `h >= 0xF0`：扩展序（0xF0-0xF8 MEGA_MEGA_*，0xF9/0xFA SPECIAL_FGBG，0xFD/0xFE WHITE/BLACK）
    2. `(h & 0xF0) == 0xC0/0xD0/0xE0`：LITE 形式（4 位 code = h>>4，4 位 run = h&0x0F）
    3. 否则：REGULAR 形式（3 位 code = h>>5，5 位 run = h&0x1F）
    run 为 0 表示 MEGA：跟一个字节，REGULAR 加 32 / LITE 加 16；FGBG_IMAGE 例外（加 1，
    且非 MEGA 时 run = (h&0x1F)*8）。
    **不能只按 `h>>5` 分派**：LITE 的 0xC/0xD/0xE 会被误判成 REGULAR 的 6/6/7。
164. **RLE 的三个语义细节**（2026-10-24 第38轮）：
    - FG 色初值 = 白；FGBG 的 1 位 = `上一行像素 XOR 当前 FG`（首行则是 FG 本身），
      0 位 = 上一行像素（首行则是黑）。
    - 连续两个 BG 序之间必须补 1 个 FG 像素（且计入长度）；**唯一例外**是
      第一个 BG 在首行、第二个在次行——此时不补。
    - 抖动序（DITHERED_RUN）的 run 是**像素对数**，不是像素数。

165. **虚拟通道分块的三个不变量**（2026-10-24 第39轮，[MS-RDPBCGR] 2.2.6.1.1 / 2.2.6.1）。
    - `CHANNEL_PDU_HEADER.length` 是**整条消息**的未压缩总长，**每个分块都写同一个值**，
      不是本块长度。按「本块长度」理解会让重组永远对不上。
    - 单块消息必须**同时**置 `FIRST|LAST`；中间块**都不置**；顺序不可乱（无位置字段）。
    - 所有分块消息必须置 `CHANNEL_FLAG_SHOW_PROTOCOL (0x10)`，否则接收方无法重组。
    - 未协商 VCChunkSize 时，线上每块 <= 1600 字节。

166. **Surface Commands 的 cmdLength 是自包含的**（2026-10-24 第41轮，[MS-RDPBCGR] 2.2.9.2）。
    TS_SURFCMD = `cmdType(2) + cmdLength(2) + cmdData`，其中 **cmdLength 含 4 字节头**。
    遍历必须按 cmdLength 前进；`cmdLength < 4` 必须判畸形（否则原地死循环）。
    一个 FastPath SURFCMDS 更新（code 4）可携带多个 TS_SURFCMD，按序处理。
    Set Surface Bits 的 cmdData 内含一个 Extended Bitmap Data（含实际 width/height/bpp/编码数据），
    destRight/destBottom 是 exclusive 且规范说 SHOULD 被忽略——尺寸以 Extended Bitmap Data 为准。

167. **虚拟通道协议层是「通道数据」而非「整帧」**（2026-10-24 第42轮，cliprdr）。
    cliprdr 的 CLIPRDR_HEADER（msgType u16 + msgFlags u16 + dataLen u32）是**通道数据**的头部，
    外面还要套 `CHANNEL_PDU_HEADER`（8 字节，见规则 165）。两层头各有各的 length：
    - CHANNEL_PDU_HEADER.length = 整条通道消息的未压缩总长（分块重组用）
    - CLIPRDR_HEADER.dataLen = 本 PDU 的 payload 长度（单条消息内）
    混淆两者会把通道重组和协议解析搅在一起。所有虚拟通道协议（cliprdr/rdpdr/rdpsnd/drdynvc）
    都遵循这个「两层头」结构。
168. **cliprdr Format List 是 u32 数组，长度必须是 4 的倍数**（2026-10-24，[MS-RDPECLIP] 2.2.3）。
    非 4 倍数说明解析错位（或用了 Short Format Name 变体 + CB_ASCII_NAMES），必须判畸形而非静默截断。

169. **drdynvc 头的位序与变长 ChannelId**（2026-10-24 第43轮，[MS-RDPEDYC] 2.2）。
    DYNVC_HEADER 1 字节 = `cbId(2, 低) | Sp(2) | Cmd(4, 高)`：
    `cbId = h & 0x03`、`Sp = (h >> 2) & 0x03`、`Cmd = h >> 4`。
    **cbId 在低位（不是高位）**，写反会让所有命令类型错位。
    ChannelId 宽度由 cbId 决定：0->1 字节、1->2 字节、2->4 字节、**3 非法必须拒绝**。
    这是 RDP 里少见的「头部自带字段宽度」设计，解析前必须先读 cbId 才能知道读几个字节。

170. **RDPDR_HEADER 是 4 字节，没有 PacketLength**（2026-10-24 第44轮，官方 dump 佐证）。
    [MS-RDPEFS] 2.2.1.1 的 RDPDR_HEADER = `Component(2) + PacketId(2)`，共 4 字节。
    官方 2.2.2.2 的 Server Announce dump 是 12 字节：
    `72 44 6e 49 | 01 00 | 0c 00 | 01 00 00 00`（Component | PacketId | VersionMajor | VersionMinor | ClientId），
    **紧跟 header 的是 VersionMajor 而不是长度**。长度由外层虚拟通道 PDU 隐式给出。
    （FreeRDP 的 RDPDR_HEADER 结构体里带 PacketLength，与规范不符——**以规范和官方 dump 为准**。）

171. **rdpsnd 的 SNDPROLOG.BodySize 在 SNDC_WAVE 下语义不同**（2026-10-24 第45轮，[MS-RDPEA] 2.2.1）。
    SNDPROLOG = `msgType(1) + bPad(1) + BodySize(2)`，共 4 字节。
    对**除 SNDC_WAVE(0x02) 之外**的所有类型，BodySize = 其后数据的字节数；
    但 SNDC_WAVE 时 BodySize 的含义由 2.2.3.3 的 Header 字段另行定义（不是简单长度）。
    解析器必须按 msgType 分支，不能对 SNDC_WAVE 直接用 BodySize 当长度。

172. **RDP 6.0 位图（RDP6_BITMAP_STREAM）与 NSCodec 是两个不同编解码器**（2026-10-24 第46轮）。
    - `RDP6_BITMAP_STREAM`（[MS-RDPEGDI] 2.2.2.5）是**整幅位图**的 AYCoCg/ARGB 平面编码，
      用于 Bitmap Update / Fast-Path Bitmap Update / Cache Bitmap Rev1/Rev2 的 bitmapData。
    - `NSCodec`（[MS-RDPNSC]）是**分块（tile）**编解码器，用于 Set Surface Bits / Cache Bitmap Rev3。
    两者外观相似（都叫「RDP 6.0 压缩」）但结构完全不同，禁止混用。
173. **RDP6 FormatHeader 的 CS 位与 CLL 有依赖**（2026-10-24，[MS-RDPEGDI] 2.2.2.5.1）。
    FormatHeader = `CLL(3, 低) | CS(1) | RLE(1) | NA(1) | Reserved(2, 高)`。
    CLL=0 表示 ARGB 色彩空间；CS（chroma subsampling）**只对 AYCoCg 适用**，
    故 CS=1 且 CLL=0 是非法组合，必须拒绝。
    RDP6 RLE 的 controlByte = `nRunLength(4, 高) | cRawBytes(4, 低)`，**不得为 0**；
    nRunLength=1/2 是扩展长 run 编码（run=16+cRaw / 32+cRaw），此时无 RAW 字节。

174. **RDP 6.0 RLE 平面的行差分是「累加」而非「绝对」**（2026-10-24 第47轮，[MS-RDPEGDI] 3.1.9.2）。
    RLE 解码出的平面字节不是最终值：**第 0 行是绝对值，第 y 行（y>=1）的每个字节是「delta」**，
    还原时 `plane[y][x] = plane[y][x] + plane[y-1][x]`（8-bit mod 256）。
    这是**空间差分**（与上一行比较），不是时间差分。忘记这步会得到「整体对但逐行偏移」的图，
    看起来像「颜色渐变」而不像错误。
    raw 平面（RLE=0）不做差分；此时平面后还有 1 字节 Pad（可忽略）。

175. **无官方向量的编解码器必须找第三方权威实现交叉核对**（2026-10-24 第48轮，RDP6）。
    RDP6 RLE 我按规范文字实现了两处，都错：
    - controlByte 半字节顺序（规范位图「低位在左」→ nRunLength 在低 4 位）
    - 行差分是「符号-幅值」编码（bit0=符号，`d>>1` 是幅值），不是无符号累加
    **两处都自洽通过了我自造的测试**——因为测试数据是按同样的错误假设构造的。
    只有对照 FreeRDP `planar.c` 才暴露。
    **判据：自造测试只能验证「实现与我的理解一致」，不能验证「理解正确」。
    没有官方向量时，必须找第三方权威实现（FreeRDP/微软测试套件）逐位域核对。**
    与规则 38（自指测试无检出能力）、规则 23（差分测试需信息源不同）同族。
176. **规范位图的方向：字段顺序 = 位序从低到高**（本项目已多次踩）。
    RDP 规范里的 bitmask 图（如 FastPath `action | numEvents | flags`、
    RDP6 `nRunLength | cRawBytes`）**最左字段是最低位**。
    实例：`action = h & 0x03`（低 2 位）、`nRunLength = cb & 0x0F`（低 4 位）。
    按「最左=最高位」理解会全部写反，且错误在自洽测试下不可见。

177. **RDP YCoCg 逆变换的具体形式**（2026-10-24 第49轮，FreeRDP prim_YCoCg.c 交叉核对）。
    ```
    T = Y - Cg;  R = T - Co;  G = Y + Cg;  B = T + Co;   // 各分量 clamp 0..255
    ```
    **注意 R 用减 Co、B 用加 Co**（与直觉相反；规范矩阵写 1/2 系数，FreeRDP 把 /2 折进色度移位）。
    色度字节转有符号：`(int8_t)(raw << (CLL - 1))`。
    我初版把 R/B 写反（R=T+Co），被测试抓出 R/B 值互换。
    平面顺序：Alpha(可选) / Y / Co / Cg；CS 时 Co/Cg 为 (w+1)/2 × (h+1)/2 并上采样 2x2。

178. **NSCodec 的结构要点**（2026-10-24 第50轮，FreeRDP nsc.c 交叉核对）。
    - 头 20 字节：`PlaneByteCount[4]`（各 u32 LE）+ `ColorLossLevel`(1..7) + `ChromaSubsamplingLevel` + 2 保留。
    - **平面顺序 = Y, Co, Cg, A**（不是直觉的 A 在前）。
    - 平面按 PlaneByteCount 判定：`==0` → 填 0xFF（全不透明）；`< originalSize` → RLE；`== originalSize` → 原样。
    - NSCodec RLE 与 RDP6 RLE **完全不同**：
      `value value <len>` 表示 run，len<0xFF 时实际长度 = len+2，len==0xFF 时后跟 u32 LE；
      **最后 4 字节永远是原样拷贝**（不参与 RLE）；`left==5` 时单字节特殊处理。

179. **NSCodec 与 RDP6 的 Co 符号约定不同**（2026-10-24 第51轮，各自 FreeRDP 文件交叉核对）。
    - RDP6（planar.c/prim_YCoCg.c）：`T=Y-Cg; R=T-Co; G=Y+Cg; B=T+Co`
      → 展开：R = Y - Co - Cg，B = Y + Co - Cg
    - NSCodec（nsc.c）：`R=Y+Co-Cg; G=Y+Cg; B=Y-Co-Cg`
    **两者 R/B 的 Co 符号相反**。禁止复用同一个 AYCoCg 逆变换函数。
    另：NSCodec 的 Y 平面行 stride 补齐到 8（`ROUND_UP(width,8)`），不是 width。
    色度字节始终是**有符号**：`(int8_t)(raw << (CLL-1))`（0x80 = -128，不是 128）。

180. **RDP 绘制序的两种变长整数编码**（2026-10-24 第52轮，[MS-RDPEGDI] 2.2.2.2.1.2.1）。
    - 两字节编码：首字节**最高位为 0** → 值 = 该字节（1 字节）；为 1 → 值 = `((b0 & 0x7F) << 8) | b1`（2 字节）。
    - 四字节编码：首字节最高位为 0 → 值 = 该字节（1 字节）；为 1 → 值 = `((b0 & 0x3F) << 24) | (b1<<16) | (b2<<8) | b3`（4 字节）。
    注意四字节编码的**首字节只贡献低 6 位**（0x3F），不是 7 位（两字节编码才是 7 位）。
    解析必须返回消耗字节数（1 或 2/4），不能假设固定宽度。
181. **CACHE_BITMAP_REV2_ORDER 的 extraFlags 位域**（2026-10-24，[MS-RDPEGDI] 2.2.2.2.1.2.3）。
    `extraFlags`(u16) = `cacheId`(3, 低) | `bitsPerPixelId`(4) | `flags`(9, 高)。
    flags：`HEIGHT_SAME_AS_WIDTH`(0x01，置位则**高度字段省略**，高度=宽度) /
    `PERSISTENT_KEY_PRESENT`(0x02，置位则 key1+key2 存在) /
    `NO_BITMAP_COMPRESSION_HDR`(0x08) / `DO_NOT_CACHE`(0x10，cacheIndex 必须=32767)。
    bitsPerPixelId：0x3=8 / 0x4=16 / 0x5=24 / 0x6=32 bpp。

182. **新增 target 时必须把 `/W4 /WX` 放进 `if(MSVC)`**（2026-10-24 第53轮，真实阻断）。
    我在 `add_executable(...)` 后直接写 `target_compile_options(x PRIVATE /W4 /WX)`，
    结果 Linux 构建把 `/W4 /WX` 当输入文件传给 g++（`/W4: linker input file not found`），
    Linux 门禁 FAIL。**MSVC 专属编译选项一律放 `if(MSVC)`**；
    平台存在性用 `if(WIN32)`，编译器特性用 `if(MSVC)`，二者不要混用。
183. **Windows-only 的测试 helper 在 Linux 上会触发 `-Werror=unused-function`**（2026-10-24）。
    某 helper 只在 `#if defined(_WIN32)` 的用例里调用时，Linux 上它就是 unused。
    修法：把该 helper（及其传递依赖，如 Utf16Z）也用 `#if defined(_WIN32)` 包住。
    这与「按平台门禁构建时，该平台的既有/新增缺陷都属本批范围」同族。
184. **Linux 构建门禁已可复跑**（2026-10-24 第53轮）。
    `bash scripts/linux-build-gate.sh`（WSL Ubuntu 24.04）：退出码 0=通过 / 1=真缺陷 / 2=环境缺失；
    并断言 `FAILED_COUNT==0`、`WINDOWS_H_COUNT==0`、`CreateTlsTransport` 符号存在。
    当前基线：Linux 32/32、Windows 33/33 测试全绿。

185. **OpenSSL 内存 BIO 模式实现 TlsTransport 的要点**（2026-10-24 第54轮）。
    - `SSL_set_bio(ssl, rbio, wbio)`（两个 `BIO_s_mem`）；喂密文用 `BIO_write(rbio,...)`，
      取密文用 `BIO_read(wbio,...)`。`SSL_do_handshake`/`SSL_read`/`SSL_write` 返回 <0 时用
      `SSL_get_error` 区分 `SSL_ERROR_WANT_READ`（需更多输入）与真错误。
    - `consumed = in_size - (pending_after - pending_before)`（rbio 未消费字节 = pending 增量）。
    - `PeerSubjectPublicKey`（CredSSP 要的 BIT STRING 内容）：OpenSSL 3.0 的 `EVP_PKEY_get0_RSA`/
      `i2d_RSAPublicKey` 已废弃（-Werror=deprecated-declarations），改为**手工解析 SPKI DER**
      取 BIT STRING 内容，避免依赖废弃 API。
    - const 成员函数（PeerXxx/negotiated）内要设置 last_error_ 时，last_error_/terminal_ 必须 `mutable`，
      且 MakeError/Fail 必须是 const。
    - CMake 用 `option(RTSC_TLS_OPENSSL OFF)` 默认关：`find_package(OpenSSL REQUIRED)` 会让
      无 OpenSSL 的主机 configure 直接失败（design-a D5）。

186. **窗口抽象必须「未知后端如实报错」而不是静默回退 headless**（2026-10-24 第55轮）。
    `CreateWindow(w,h,"x11",why)` 在 X11 后端未接入时必须返回 nullptr + why，
    **禁止**悄悄返回 headless —— 静默回退会让「本应显示却没显示」变成无错误的黑盒。
    这与 G9「缺失即 FAIL 不静默 skip」同族。
187. **Surface 的 Blit 语义**（2026-10-24）：源矩形与目标表面求交后**逐行 memcpy**；
    越界像素忽略（不环绕）。`Blit(nullptr,...)` 与完全越界都是 no-op，不得崩溃。
    负坐标（如 (-1,-1)）是合法裁剪输入，不是错误。

188. **Win32 窗口后端的三个要点**（2026-10-24 第56轮）。
    - WndProc 里取回 C++ 实例：`WM_NCCREATE` 时从 `CREATESTRUCTW::lpCreateParams` 拿 this 指针，
      `SetWindowLongPtrW(hwnd, GWLP_USERDATA, ...)`；其余消息用 `GetWindowLongPtrW` 取回。
    - DIB 必须 `biHeight` 为**负**才是 top-down（与 Surface 的 top-down 一致），否则图像上下颠倒。
    - Surface 是 RGBA，Win32 DIB 是 BGRA：Present 时必须逐像素交换 R/B。
    - `RegisterClassExW` 第二个窗口会返回 `ERROR_CLASS_ALREADY_EXISTS`，必须容忍。
189. **窗口工厂的「默认 vs 具名」语义**（2026-10-24）：`backend==""` = 平台默认
    （Windows=win32，其它=headless）；**具名但未接入**的后端必须返回 nullptr + why，
    禁止静默回退 headless（否则「本该开窗却没开」变成无错误黑盒）。

190. **位图更新的解码器选择由 flags + bpp 决定**（2026-10-24 第57轮，图形合成管线）。
    `TS_BITMAP_DATA`：
    - `flags & BITMAP_COMPRESSION == 0` -> 未压缩（`DecodeRawBitmap`，行补齐 4 字节）
    - 压缩且 `bpp != 32` -> Interleaved RLE（`DecodeRleBitmap`）
    - 压缩且 `bpp == 32` -> RDP 6.0（`DecodeRdp6Bitmap`）
    - 若压缩且未置 `NO_BITMAP_COMPRESSION_HDR`，则 **bitmapDataStream 前有 8 字节 TS_CD_HEADER**，
      解码前必须跳过；漏跳会让所有压缩位图解错。
191. **FastPath 长度字段包含头与 length 自身**（2026-10-24 第57轮，测试两次踩）。
    `fpOutputHeader(1) + length(1或2) + Σupdate`；每个 update = `updateHeader(1) + size(2) + data`。
    长度字段=**整条 PDU 总字节数**。构造测试 PDU 时最容易漏 updateHeader 那 1 字节。
    且总长 > 127 时必须用 2 字节长度（`0x80|高7位`, 低 8 位），否则 length 被截断。

192. **X11 后端的三要点**（2026-10-24 第58轮）。
    - **命名冲突**：X11 的 `Window` 是 XID typedef，与本项目 `rtsc::ui::Window` 同名。
      在 `rtsc::ui` 命名空间内必须写 `::Window win_`，否则编译器把它解析成抽象基类。
    - X11 的 `keycode` 通常是 evdev scancode + 8；转 RDP set-1 scancode 用 `keycode - 8`。
    - 滚轮在 X11 里是 Button4/Button5，不是独立事件类型，必须在 ButtonPress 里分支。
    - `XCreateImage` 的 data 缓冲由 `XDestroyImage` 释放；若用自分配缓冲，只能随 image 一起销毁一次。
193. **WSL 可装 X11 dev 且**有** X server**（2026-10-24）：`sudo apt-get install -y libx11-dev`
    可用（免密 sudo），且 `/tmp/.X11-unix/X0` 存在 -> `XOpenDisplay(":0")` 成功，
    所以 X11 后端在 WSL 上能**真实创建窗口**，不只是编译通过。

194. **CMake 工程若 `LANGUAGES CXX`，加入 `.c` 源文件会被静默跳过**（2026-10-24 第59轮，真实阻断）。
    `target_sources(x PRIVATE gen.c)` 在只 enable CXX 的工程里**不报错也不编译**，
    只在链接期表现为 `undefined reference`（如 `xdg_surface_interface`）。
    修法：在用到 C 源的块里 `enable_language(C)`。判据：链接期报「某个 C 目标文件里的符号」undefined。
195. **Wayland 后端的三个要点**（2026-10-24 第59轮）。
    - wl_surface 的 shm 缓冲格式 `WL_SHM_FORMAT_XRGB8888` 在小端下字节序是 B,G,R,X；
      Surface 是 RGBA，Present 时必须交换 R/B。
    - listener 结构体随协议版本增加字段（xdg_toplevel 的 `wm_capabilities`、
      wl_pointer 的 `axis_value120`/`axis_relative_direction`）。用**指定初始化器**
      并抑制 `-Wmissing-field-initializers`，否则旧写法在新协议头下 `-Werror` 失败。
    - 输入：`wl_keyboard` 的 key 是 evdev scancode（减 8 得 set-1）；
      `wl_pointer` 的滚轮是 `axis` 事件（axis=vertical），不是按钮。

- [P7 集成] 端到端 `Client` = 连接驱动 + 图形管线 + 输入编码；`Connect` 用
  「先发 CRQ，再 读→OnData→写 循环」直到 `session_active()`；`Pump` 为单步循环。
  入站 PDU 分派：FastPath 判 `byte0 & 0x03 == 0`，慢速路径先 `McsSendData::parse`
  取 `user_data` 再 `SlowPathGraphicsUpdate::parse`。
- [接口约定] 会话激活后由 `ConnectionDriver::SetSessionPduHandler` 独占转交所有
  入站 PDU；驱动自身不再解释（路由函数开头 `session_->active()` 即 return），
  避免图形层与许可/会话机重复解析同一 PDU。
- [工具] 自动化验证脚本参数必须避免依赖「空字符串位置参数」——PowerShell 调原生
  程序会**吞掉空串实参**，导致 argc 错位（width/height/backend 全部左移）。
  需要可选空值时改用命名开关或占位符（如 `-`）。

196. **mstsc 的认证不在 mstscax.dll 里**（2026-10-25，REA 取证）：对 `C:\Windows\System32\mstscax.dll` 做 Ghidra 分析，
    `CredSSP`/`NTLMSSP`/`InitializeSecurityContext`/`SSPI`/`MIC`/`MsvAv`/`NTLM`/`SecBuffer` 字符串**全部 0 命中**。
    mstsc 只做三件事：① 协商 `requestedProtocols=HYBRID_EX`；② 调 **SSPI**（`secur32.dll!InitializeSecurityContext`，package `NTLM`，
    `SECBUFFER_CHANNEL_BINDINGS` 携带 TLS channel binding hash）；③ 把 SSPI token 当 `TSRequest.negoToken` 在 TLS 上收发。
    协议逻辑在 `msv1_0.dll`/`credssp.dll`/`ntlmshared.dll`。
    → 判据：**要证明「某实现不含某功能」，对目标做字符串/符号检索得到 0 命中即可（配合规范确认）**。

197. **NTLM CBT 的权威口径**（2026-10-25）：[MS-NLMP] 2.2.2.1 的 `MsvAvChannelBindings` = `MD5(gss_channel_bindings_struct)`；
    `application_data = "tls-server-end-point:" || SHA256(cert)`（**前缀必须有**，含冒号）。
    **权威依据 = Microsoft Open Specifications 官方博客《NTLM and Channel Binding Hash》的逐字节示例**（app_len=53/struct_len=73），
    与 **FreeRDP `libfreerdp/crypto/tls.c`**（`#define TLS_SERVER_END_POINT "tls-server-end-point:"` + `memcpy`）、**ldap3**/**ntlm-auth** 一致。
    **不要只凭 RFC 5929 §3 的 GSSAPI 段落推断**（那里 `tls-server-end-point` 是「channel binding unique prefix」，
    与 NTLM 的 `application_data` 构造口径不同）。
    结构布局：`initiator_addrtype(4)=0 + initiator_len(4)=0 + acceptor_addrtype(4)=0 + acceptor_len(4)=0 + app_len(4 LE) + app_data`。

198. **`MsvAvTargetName`(0x0009) = 目标服务器的 SPN**（2026-10-25，[MS-NLMP] 2.2.2.1 定义「The SPN of the target server」；
    3.1.1.2 `ClientSuppliedTargetName`）。RDP 场景即 `TERMSRV/<host>`（**不是** CHALLENGE 的 target_name）。
    规范 3.1.1.5 两分支：`not NULL → Value=SPN`；`NULL → Value=空串`（**都要发 AV_PAIR**，空串 Len=0，不得省略）。
    Unicode 且**不带结尾 NUL**。

199. **离线交叉验证 NTLM 消息正确性**（2026-10-25）：把客户端产出的 AUTHENTICATE 消息喂给 **Microsoft `msv1_0!AcceptSecurityContext`**
    （本机建临时账户 + 管理员，脚本 `scripts/ntlm_sspi_verify/`）→ 正确密码 `ACCEPTED(0x0)`、错误密码 `SEC_E_LOGON_DENIED(0x8009030C)`。
    这是**不依赖真机服务器**即可判定「消息本身是否正确」的强证据。
    局限：本地 `msv1_0` 未开 `ApplicationRequiresCBT` 时**不校验 CBT**，故 CBT 正确性需另证（官方示例 + FreeRDP）。

200. **外部前提必须先验证，再断言可推进**（2026-10-25，用户指正）：拿到凭据后我直接断言可继续真机联调，并把失败先归因到代码。
    正确顺序：**先用最小独立手段验证外部前提**（mstsc / `net use` / SSPI）→ 再断言；失败时**先证伪外部前提**，再怀疑自身实现。
    本例：Windows 自带 mstsc 同凭据也失败、OS `net use` 1326、`yy520o!` 与 `yy5200!` 均 `0xC000006D` → 凭据/账户侧问题。

201. **审计三问必须分开**（2026-10-25，甲乙共同教训）：
    ①「字段/代码**是否存在**」；②「其**值是否有效**」；③「它**是否为被测现象的原因**」——三者独立，不可互相推出。
    同族：「**结果对 ≠ 机制对**」（断言处理机制前必须定位拒斥点）、「**偏移 N 字节**必须逐字段确认」（不得凭结构直觉）。

202. **REA 工具：全量列表会超响应预算**（2026-10-25）：对 9MB 的 mstscax.dll 调 `list_names`/`list_strings` 返回
    `resource_constraint`（>10MB）。改用 `get_evidence_bundle` + `inspect_analysis_view`（按 evidence 引用）或
    `search_strings`（带 pattern）/`procedure_callees`/`resolve_containing_procedure` 定点查。

## 教训（2026-10-27）：RAIL/RemoteApp 声明必须按需

- **症状**：客户端连真机 Win11 桌面全黑（服务器发全屏均色黑 tile），mstsc 正常。
- **根因**：客户端无条件广播 `rail` 静态通道 + INFO_RAIL + TS_RAIL_CAPS。Windows 服务器据此准备 RemoteApp 会话，桌面不做合成 → 客户端收到纯黑。
- **规则**：RAIL 三要素（通道广播 / INFO_RAIL / TS_RAIL_CAPS）必须同一开关门控，仅在 RemoteApp 模式开启（mstsc = remoteapplicationmode:i:1）。默认桌面会话禁止声明。
- **方法**：A/B（独立 worktree 构建 HEAD）+ git bisect + 探针（tile 级 non-black 计数）可在 ~1h 内定位此类"服务器按客户端声明改变行为"的回归。
- **附带**：[MS-RDPBCGR] 2.2.11.3 RefreshRect 体 = pad1(1)+count(1)+rects（前导 pad1，写错会触发服务器断开）；GeneralCaps 尾部 refreshRectSupport/suppressOutputSupport 应声明 1。~~highColorDepth=32（24bpp 会话在部分 Win11 构建渲染异常）~~ **已双审裁定为红鲱鱼并废除（2026-10-27）**：24bpp 会话渲染正常（真机 1306328 non-black 实证），当年"24bpp 黑屏"真凶是 RAIL caps 误声明 + fast-path bitmap offset，与色深无关；勿再以"24bpp 部分构建黑屏"为由规避 24bpp。

## 教训（2026-10-27）：线格式必须规范原文+多源交叉验证，禁凭记忆

- 事故：RefreshRect 体按记忆写成 pad1+count（FreeRDP 混淆），SuppressOutput 体虚构 count32+数组；双审以 learn 原文+微软 TestSuites+IronRDP+FreeRDP 四源对照抓出（D-A/D-B），真机观测（刷新 no-op 无重绘）佐证。
- 规则：新 PDU 编解码落地前必须引用规范原文页（learn ID）+至少一个成熟实现（FreeRDP/IronRDP/微软 TestSuites）交叉核对字段序；测试用规范字节写（断言需求不锁定实现）；真机回归观测（colours/rendered 跳变）作为最终验收。
- 流程有效：双审（甲客户端/乙服务器+交叉磋商+三方证据）在 51/51 全绿的情况下仍抓出 2 个高危线格式缺陷——测试绿≠线格式对。
- 32bpp 注意（2026-10-27 已修复）：RDP6 planar 解码 N1-N7 缺陷（逐扫描线模型/段首 run/CD 头路由）已按 FreeRDP planar.c oracle 修复并经真机 32bpp 会话回归；24bpp 全链已实证。


## 教训（2026-10-28）：位图解码必须断言行序方向

- 32bpp planar 修复后桌面整体垂直镜像：像素算术被双审+预言机验证，但行序（bottom-up vs top-down）三方都漏了——真机向量解码值全对、方向反。
- 规则：位图类编解码测试必须包含垂直不对称内容断言（首流行 vs 末流行颜色不同），并引用调用方 vFlip 语义（FreeRDP bitmap.c 对位图更新传 vFlip=TRUE；planar.c vFlip 分支 beg=height-1 递减）。

## 环境（2026-10-28）：cmake/ctest 绝对路径
- cmake 不在 PATH。统一用：C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe（ctest.exe 同目录）。
- 子代理若报 cmake 找不到，直接用该绝对路径，不要花轮次排查 PATH。

## 【最高纪律·2026-10-28 用户裁定】本项目是逆向工程：禁止 AI 自行编造，必须对齐反汇编证据

**用户原话**：「本工程最顶级纪律这是逆向工程，禁止AI自己乱编，必须对齐反汇编证据。」

### 规则（高于一般工程习惯；违反则该批次作废并回溯已合并内容）
1. **任何关于微软行为的论断必须附二进制证据**：`模块!函数名` + 地址 + 伪代码/汇编片段（或 `亿evidence_id`），或 pktmon/Wireshark 抓包字节。三者皆无 → 不得写进代码、注释、测试期望、提交信息、报告。
2. **规范只是下限**：`[MS-RDPBCGR]`/`[MS-RDPECLIP]` 等规定「必须如何」；「微软实际选了什么」（滤波器、常量、默认值、顺序、降级路径、边界）只能来自二进制。二者冲突以二进制为准，并在注释中同时标注两者。
3. **测试期望禁止由生产实现反推**：期望只可来自 ①二进制取证 ②规范原文 ③真机抓包/真机截图 ④独立参考实现（不得调用被测代码）。「先改实现再重钉期望」＝造假。
4. **注释中的「mstsc 是 X」必须附地址**；无证据者删除或标 `UNVERIFIED:`。
5. **每批对齐必须产出证据文档** `docs/spec/<area>-evidence.md`：问题 / 证据（地址+片段）/ 结论（与推断分开）/ 对应实现位置 / 验证方式 / 变异反证方案。
6. **不得用「成熟实现（FreeRDP/IronRDP）」替代 mstsc 证据**：它们可作为交叉参考，但不得作为「微软行为」的唯一依据。

### 已发生的 4 次乱编事故（永久反例）
- planar 行序：凭 FreeRDP 记忆推断，未对齐 mstsc → 活机整屏垂直镜像。
- cliprdr 方向：凭错误记忆让客户端发 Monitor Ready，违反 [MS-RDPECLIP] 2.2.2.2（Server Monitor Ready）。
- drdynvc 裸 DATA：审计与实现都判「无 DATA_FIRST 的 DATA 丢弃」为合规，违反 [MS-RDPEDYC] 3.1.5.2.2。
- 缩放插值：`src/client/view.cpp:144-148` 注释断言「Bilinear ... is what mstsc does」；二进制证明是 `SetStretchBltMode(hdc,4)`=HALFTONE（`FUN_18003444c`）。

### 已取证事实（可直接引用，勿再猜）
- mstscax.dll sha256 前缀 `d73c76d65721043c`，PDB `mstscax.pdb`。
- 缩放：`FUN_18003444c` `SetStretchBltMode(hdc,4)`(HALFTONE) + `SetBrushOrgEx(0,0)`；仅 x/y 比例均 1.0f 走 `BitBlt(0xcc0020)`，否则 `StretchBlt(0xcc0020)`；属性 `EnableSmartSizing`/`ZoomLevel`(100)。佐证 `FUN_180191d30`、`FUN_1804cfb98`。
- 输入：`FUN_1801185e0` 用 `MapVirtualKeyW(vk, MAPVK_VK_TO_VSC)` 取扫描码并由 `FUN_1800e8dfc(inst,0x100/0x101,vk,sc)` 合成键消息；右 Win 置 `|0x8100`；焦点变化时重放 Shift/Win 归位并清零 `+0x414/+0x418`；本地 `keybd_event` 一律带 `dwExtraInfo=0x4321DCBA`；`FUN_180118940` 用 `0x414/0x418` 跟踪 LWIN/RWIN 按下态。
- 调用点分布：keybd_event 10 / SendInput 4 / SetCursorPos 7 / MapVirtualKeyW 126。

## 教训（2026-10-28）：计数必须后置、收尾必须必达、稳定性必须多次采样
- **计数后置**：`++live`／`++count` 之类别在资源创建（`std::thread`、socket、句柄）**之前**递增；创建失败时无人递减 → 等待方永久阻塞。要么后置，要么作用域守卫回滚 + notify。
- **收尾必达**：detached 线程的「减计数 + notify_all」若放在 try 之外，异常即 `std::terminate` 杀全进程或永久挂起。收尾必须 noexcept（内部 try/catch 兜底）。
- **稳定性采样**：单次全绿 ≠ 稳定。零余量断言（期望 == 理论上限）在 Windows 定时器粒度（~15.6ms）下约 15% 概率失败。门禁判定要求：断言留 ≥2× 余量 + 多次运行给分布。
- **交叉验证价值**：两位审计用各自探针独立命中同一缺陷（R-A）与同一抖动（D-1），比单方报告可信度高一档；但也说明「单方全绿」可能是运气。

## 教训（2026-10-28）：审计分歧必须由**自建独立探针**定案，不得择一采信
- 甲与乙在「整数比降采样是否平均」上结论相反，各自都带探针数据。父代理未择一采信，而是**自写最小 GDI 探针**（`arb.cpp`，30 行）复现：结果与乙一致。
- 规则：①两审计结论冲突时，**不得按权威/字数/置信度选择**，必须由第三方（父代理）用最小可复现实验定案；②定案后必须同时纠正**错方的书面材料**（甲工单里的 D4 措辞），否则错误会随文档继续传播；③探针与本仓库代码隔离（`%TEMP%`），避免"用被测实现验证自己"。
- 附带确认：GDI HALFTONE 的降采样是**近似 box**（`probe_q3`：GDI vs 精确 box `mean|d|=1.00`，而抽点实现 `mean|d|=8.00`），放大是精确块复制。契约据此区分「与 mstsc 一致」与「有意改进」。

## 教训（2026-10-28）：索引公式必须用能区分候选的输入实测，不能用"看起来对"的样例
- 我（父代理）此前凭「2x/1.5x 与 floor 逐字节吻合」就指示用 `floor(d*S/D)`，但该公式在 `3→5`（失配 9/25）与 `8→13`（失配 3/13）上错整列。
- 正确做法：**构造能区分候选公式的输入**（非整除比例、源尺寸与目标尺寸互质），并用"源像素值=源索引"的图直接读出映射，再逐组统计失配数。
- 公式：`src = ((2*dst+1)*SrcSize - 1) / (2*DstSize)`（半像素中心 + 整数除法，平局向下），对整数倍自然退化为块复制。
- 同类教训：`2x/1.5x 恰好吻合`不足以证明公式正确——整除比例会掩盖取整差异。

## 教训（2026-10-28）：并发跑测试会伪造出"随机失败"，先排环境再谈缺陷
- 同一份代码：并发时 20 次挂 7 次；独占时 6 次 0 失败、另 12 次 0 失败。差异**完全来自端口争用**（测试用硬编码端口 3390-3398/3480-3488）。
- 规则：①稳定性结论必须注明"独占运行"；②发现"随机失败"先查：残留进程、端口占用、并发测试、共享构建目录；③测试宁可用运行时分配端口，也不要硬编码。
- 推论：此前多位审计报告的"15% 抖动"（`inputs >= 10`）也需重新审视——零余量断言是真实缺陷，但**实测失败率**可能被并发污染放大或缩小。

## 教训（2026-10-28）：计数递减必须"恰好一次"且与可抛操作解耦
- 事故形态：`--live` 在两条路径上都可能执行（body 收尾 + launcher 失败回滚）→ `size_t` 下溢成 SIZE_MAX → `cv.wait(live==0)` 永久阻塞。审计红证：`live=18446744073709551615 HUNG=1`。
- 根因：回滚条件（`started==false`）**不能证明 body 没跑**——launcher 完全可能先启动 body 再失败/抛异常。
- 正确做法：**计数交接原子化** `if (counted->exchange(false)) { --live; notify_all(); }`，让"哪一方负责扣减"由原子交换决定，而不是由启动方的返回值推断。
- 同型：`--live` 与 `erase`（可抛）放同一个 try，一旦 erase 抛出，`--live` 被整段跳过 → 同样卡死。**递减必须独立于可抛操作**（scope guard 或独立临界区）。
- 推论：凡"资源计数 + 等待方"结构，都要问两个问题：①每条退出路径是否恰好递减一次？②递减是否可能被异常跳过？

70. **量纲/单位必须锚定外部权威；内部往返自洽不构成验证**（第 792 轮，同型家族第 12 例）。
    本仓滚轮：encoder 与 decoder 用同一个错误单位假设（格当单位、magnitude+负号标志），
    往返测试永远绿，而真实对端（mstsc）读到的是 1/120 格——**单位错误不会在自证中暴露**。
    正确单位来自三份外部权威（FreeRDP PR #6806 / Remmina 4a546fac / gnome-remote-desktop f134b16）+ [MS-RDPBCGR]。
    **判据：任何"数量/单位/量纲"契约，必须先给外部权威来源（规范/成熟实现），再写断言；
    断言的期望值禁止取自本仓实现的输出。**
    同族：encode→decode 自证、测试固化缺陷（"那个字节今天解得对"不等于规范解得对：
    `0x0301` 在旧实现= -257，在正确实现= -255，断言必须锚规范位布局）。
71. **位/字段定义只能查规范原文表格，不能靠"命名空间"推断**（第 797 轮，本仓第 16 例）。
    我曾裁决"`TS_FP_RELPOINTER_EVENT.flags` 属 PTRFLAGS 命名空间，故不存在 PTRXFLAGS_BUTTON1/2"，
    据此删掉相对事件的 X1/X2 解码。官方原文实际是：
    「The possible flags are **identical** to those found in the pointerFlags field of the
    TS_RELPOINTER_EVENT structure」，而该表**同时**列出 PTRFLAGS_* 与 PTRXFLAGS_BUTTON1(0x0001)/BUTTON2(0x0002)。
    **同一 16 位字段的不同位段并不互斥**——"命名空间"是我发明的概念，规范里没有。
    **判据：①任何位定义裁决必须 webfetch 规范表格并逐位抄行；②审计的"语义矛盾"若不能在原文逐行指出，
    只能记 UNVERIFIED 并保留原行为，禁止据此改代码；③裁决比报告更危险——报告错了会被复核，
    裁决错了会被执行并提交。**

72. **豁免/旁路必须由有界状态集合定界，禁止按事件类别豁免**（第 807-811 轮，本仓输入注入）。
    事故形态：为了让"键抬起不丢"，我下令 `if (is_release) accept;`——**按事件类别**绕过硬上限 1024。
    结果单条 32KB PDU 可带 ~16k keyup 全入队（外加每事件 O(N) 扫描 → O(N²)）。
    正确形态：豁免条件必须是**有限集合的成员判定**（`pressed` 中仍持有该键/按钮），而非类型谓词。
    **判据：任何 `if (X) 绕过容量/限流/配额` 的 X 若不引用有界状态，即为无界入口；
    必须写出上界公式并构造"远超上界"的输入测试。**
    附带：写进文档的不变式必须区分**峰值**与**瞬时**（本仓瞬时公式被探针违反 774 次，
    峰值 `hard + 515·K` 才成立）——否则下一个人会按错误公式做断言并"发现"假缺陷。

73. **幂等哨兵 + 可抛调用 = 永久损坏**（第 819 轮，本仓 `ReleaseInput`）。
    模式：`if (done) return; done = true; <可抛调用>; <真正的清理>`。一旦可抛调用抛出，
    `done` 已为真，清理**永不再执行**——本仓表现为租约槽永久泄漏，此后所有会话被拒。
    **判据：①列出函数内每个可抛调用；②检查"哨兵置位"是否早于"清理完成"；
    ③若有，清理必须 `try/catch` 包住且无条件执行（或把清理提到哨兵之前）。**
    方法论：**读码对异常路径系统性失明**——我连续 5 轮逐行核对了这段代码、两次审计也放行，
    抓到缺陷的审计只是多做了一个"让 sink 抛异常"的测试替身。凡涉及资源释放/幂等守卫，
    必须构造注入异常（throwing stub）的测试，而不是靠肉眼"看顺序对不对"。
74. **验收只钉"0 failing + 用例名"，禁止钉 checks 总数**（第 832 轮，本仓 `rtsc_server_tests`）。
    同一份代码连跑，checks 数在 561/562/563/565/566/574 之间浮动——因为部分用例在 `WaitUntil`
    循环内做 `CHECK`，轮次由调度决定。把 checks 数写进验收判据，会让"绿"变成碰运气，
    并诱使下一个人去"修"一个不存在的回归。
    **判据：验收门禁 = `0 failing tests` + 指定用例名逐条 OK；checks/tests 总数只作参考，不作契约。**
    更一般的规则：**凡是"由调度决定次数"的断言，都不该进总数契约**（重试轮询、并发收敛、时限探测）。

75. **"序列类"缺陷的正确修法要覆盖同序列中未打标记的部分**（第 829 轮，本仓 PAUSE）。
    PAUSE 的线上序列 `04 1D / 00 45 / 05 1D / 01 45` 里只有两个 CTRL 带 `0xE1` 标记；
    只丢"带标记的事件"会留下 `0x45` down/up，NumLock 照样被切换。
    **判据：修完必须用序列编码器的完整输出（本仓 `EncodePauseKey()`）端到端断言，
    并要求"误杀"方向也有用例**（本仓：独立 NumLock tap 必须产出 2 个动作，
    否则"全局丢弃 0x45"这种假修复能全绿通过）。
    状态机设计要点：窗口必须有**上界**（本仓"孤立 E1 最多吞一次 NumLock tap"），
    否则一个孤立的起始标记会永久吞掉后续所有同类事件。
## 教训（2026-11-02）：变异的"落点"和"断言层"必须同时核对

- **`String.Replace` 是全局替换**：在出现 N 次的字符串上做变异，会同时改掉 N 处。
  两次同形的 `return Assemble...(dpi_ok, ...)`（生产入口 + seam）就因此被我一起改掉，
  于是"seam 的断言变红"被误读成"生产入口已覆盖"。**改完必须 `Select-String 'MUT-'` 确认只有一处**。
- **断言能观察到的层 ≠ 变异想改的层**：`:461` 的断言只看 seam 形参；用它证明生产入口的错误是无效论证。
  先问"这条断言经过哪条路径"，再选变异点。
- **别人实测与我的声明冲突时默认我错**：审计 U 给出 13/73 全绿，我按同样落点重跑复现了它。
  先复现对方，再解释差异；不要用"我这里是红的"结束讨论。
- **修复方向**：与其给常量加断言注释，不如让 seam 拥有该维度——
  `MakeGdiDesktopSourceWithDpiProbe(probe, ...)` 让"探针结果 → 装配"这条生产接线可被 falsify。
- **"不可达"要先证伪再接受**：我曾判 F5 的 main 调用点"不可达，接受"；
  审计 U 用 env 门控 sink 证明它可达。不可达的结论必须附"所有可行通道都试过"。

## 教训（2026-11-04）：测试旋钮的可用范围必须被测试自身的等待预算覆盖

- **形态**：`RTSC_TEST_LAUNCH_DELAY_MS` 是"加宽窗口"的旋钮。launcher 在 accept 循环里同步执行，
  所以 `delay_ms × (kConnect-1)` 会串行化注册；用例的注册等待却是**固定 1 s**。
  实测 `delay_ms=200` → `launches=6 registered=-1`、2 failed checks —— 红在**测试自身**，
  看起来却像服务器缺陷；`{0,1,5,40}` 全绿，失效阈值约 140 ms。
- **规则**：任何"可调大"的测试旋钮，其**最大有用值必须被测试自身的超时/等待预算覆盖**
  （预算 = 基准 + 系数 × 旋钮值，并设上限）。否则旋钮一调大就制造假红，且红因不可归因。
- **同族**：例 71（witness 依赖时序）。判据：**问"把这个旋钮调到 10 倍会怎样"**；
  不能回答"仍然绿"的，就不是旋钮而是地雷。
- **附带**：注释里必须写出实测的失效阈值与实测数据（本例 140 ms / 200 ms 红 / 40 ms 绿），
  让下一个人不必重测。

## 教训（2026-11-04）：给自己的测试加输出时，先 grep 这个标记的全部消费者

- **形态**：给 bench 加"重试"打印时复用了 `[bench]` 标记，而 gate 的断言正是
  `grep -c "\[bench\]" >= 7`。重试行被当成一条结果行 ⇒ "一个用例被编译掉 + 另一个重试"
  计数仍是 7 ⇒ gate 假绿。**我在批 42 立下"计数可被同类行补足"的原则，批 56 自己违反了。**
- **规则**：
  1. 新增任何带标记的输出，必须 `git grep` 该标记在 gate / 脚本 / 解析器里的**全部消费者**。
  2. **计数断言应升级为身份断言**：要求每个具名条目各出现一次，而不是"总数达到 N"。
     正则要防前缀误匹配（`1:1` vs `1:1 letterbox` ⇒ 要求标签后紧跟数字串）。
  3. 修完必须给**两层红证**：标记修复的（改回旧标记 → 假绿复现）与身份断言的
     （删掉身份循环 → 换用例仍绿）。只给一层，另一层就是未验证。
  4. **"我自己刚改的代码"最该怀疑**：Rule 16 变异只测"抓不抓得住回归"，
     不测"门禁是否变弱"——两者要分别验。

## 教训（2026-11-04）：注释里的每个数字都要从表里算一遍

- **形态**：bench 注释自带空闲表（0.11 / 0.12 / 4.8 / 22.9 / 16.9 / 1.8 / 43 ms），
  却写"Every budget is about 4x the idle measurement"。**表在、结论错**：
  实际是 3.3x–10.9x。同理"1.5-2x headroom"实测只有 1.43x。
- **为什么危险**：下一个人按"4x"改预算，会把 1:1 从 1.2 降到 0.44，直接掉进抖动地板；
  按"还有 1.5-2x 空间"判断，会在负载下假红。**错误注释会主动引导出错误修改**，
  比没有注释更糟。
- **规则**：
  1. 注释里的每个数字都必须**从相邻的表/数据算一遍**再写，不能凭印象写"约 N 倍"。
  2. "余量/余裕"这类形容词必须给**实测值**（1.43x），不能给区间估计（1.5-2x）。
  3. 若顺带发现某条描述不成立（如"样本 ≥10ms"对 2x 只有 9.6ms），
     **改实现去满足，而不是改注释去迁就**——注释描述实现，不能让实现迁就注释。

## 教训（2026-11-04）：迭代次数不是时间上界；跨机器测量值不能写进注释

- **`sleep_for(1ms)` 在 Windows 上实测 15.50ms**（100 次 = 1550ms）。所以
  `for (i < 5000) sleep_for(1ms)` 的真实上界是 **~78 秒**，不是注释写的 5 秒。
  **规则**：要时间上界就用 `steady_clock` deadline；"迭代 N 次 × 1ms"不是上界。
  平台定时器粒度必须实测（Windows ~15.6ms，Linux ~1ms 量级）。
- **跨机器测量值不能写进注释**：bench 的 budget/idle 比值，我在本机测
  `10.9 / 10.0 / 4.4 / 5.4 / 5.0 / 6.3 / 4.6 x`，审计 X 在另一台同 HEAD 测
  `13.3 / 11.0 / 5.2 / 6.0 / 5.4 / 7.5 / 5.2 x` —— **同一份代码，比值漂移近 2x**。
  逐值列举必然在下一台机器上变成假陈述；应写不变量（"比值随机器漂移约 2x，
  恒定的是绝对余量 ~1.4x"）。
- **两次实测冲突时，两个都对**——说明该量本身不是常量，这本身就是"不要记录
  非常量具体值"的实证。
- 本轮"注释数字错误"**连犯三次**（`about 4x` → 逐值表 → `>=11ms`），
  根因是"写完注释就当成事实"。**判据：注释里出现数字 ⇒ 必须能在同一次运行里复现，
  否则改成定性描述。**

## 教训（2026-11-04）：三层门禁可能只是同一信息源的三次读数

- **形态**：bench gate 有计数（`grep -c -ne 7`）、身份（7 条逐用例正则）、
  产出量（`VIEW_MIN_CHECKS>=7348`）三层。**三层被同一个攻击全部绕过**：
  把 `measure()` 改成 `return 0.01;`（完全不调用 `ScaleSurface`）—— 行不缺、标签不缺、
  checks 不变，gate 打印 `VIEW_BUDGETS=executed` 并 PASS。
  同轮另有 3 个同型洞：`nm -C` 接受 `U`（未定义）符号、`SEC_TESTS>=8`（删一个用例仍过）、
  `-lt 7`（加第 8 个用例仍过）。
- **规则**：
  1. 加断言前先问 **"这三层读的是同一个量吗？"** 是则等于只有一层。
  2. 路径类证据（日志行）的严格升级是**副作用计数器**（`calls=1000 want=1000`），
     它无法被"打印一行"伪造。
  3. **下限 `>=N` 在可增可减的集合上必然 fail-open**（能加就补足，能减就漏）。
     判据：基数是否由本文件决定？是则用等值 `-ne N`。
  4. 修完必须**对每一层各给一个只打它的变异**，否则"修好了"只等于"最强的那个变异不红了"。
- **同族**：单一"我执行到这里了"的布尔标志会被**位置改变**架空 —— 把 store 移到判断之前
  即可伪造。必须**入门 + 出口 + 认领（CAS 结果）三点同时断言**。

## 教训（2026-11-04）：`bash -n` 通过 ≠ 脚本能工作；性能预算的"假红率"与"检出率"是两件事

- **`bash -n` 只解析语法**。批63 我写的两处 awk 有语义错误，`bash -n` 全过：
  ①正则 `/^\[ ( RUN  |  OK  | FAIL )\]/` 多一个空格 ⇒ `[ RUN  ]`（1 空格）与
  `[  OK  ]`（2 空格）**全不匹配** ⇒ honest 日志被拒、gate 不可能 PASS；
  ②`awk -v case=...` 撞 **gawk 内置名** ⇒ `fatal: cannot use gawk builtin 'case'`。
  **规则**：校验脚本的"能跑"必须用**真实输入跑成功路径**；块正则必须对 harness 的
  真实输出形状（`[ RUN  ]`/`[  OK  ]`/`[ FAIL ]` 的空格数）验证，不能按记忆写；
  红证要覆盖"成功路径不该被拒"这一半。
- **预算宽可能不是"定得松"，而是"该用例测的不是算法"**。`0.4x 4K`（3840→1536，倍率 2.5）
  走 generic tap walk；三种变异（重复写回 / 累加两次 / 逐像素浮点除法）都只让它变
  **1.02–1.05x** —— 固定开销占绝大部分，ms 预算无法表达 2x 算法回归。
  **规则**：判据不是"预算/空闲 比值"，而是"**对该用例做真实算法退化，耗时变多少**"。
  变异测不出变化 = 该用例无判别力。两个问题必须分开测：
  **假红率（负载下 N 轮）** 与 **检出率（真退化跑一次）**。
  处置要诚实：不要为指标好看调预算，应在注释写明判别力上限。

## 教训（2026-11-04）：验证脚本必须先跑一个"已知答案"的场景自检

- **形态**：批64 写"提取 gate 真实代码块跑五场景"的红证脚本，**连续三轮结果全错**，
  每次都差点当结论上报：
  1. `sed -n '358,364p'` 只取到 `echo` 行，缺 `exit 1`/`fi` ⇒ 提取块是**语法不完整的 if**
     ⇒ bash 报错退出（rc=2）⇒ 五场景全"no-failure"。我读成"硬化没生效"。
  2. `bash -c "$(cat blk.sh)"` 里多行 `'...'` 被二次解析破坏 ⇒ 应 `bash blk.sh`。
  3. **`if cmd; then` 的退出码语义写反**（rc=0 = 无失败，rc!=0 = 报失败）⇒ 前三轮
     "全部 BAD" 全是映射错。
- **规则**：
  1. **先跑一个已知答案的场景**（healthy → 必须通过）。它都错 ⇒ 错的是脚本，不是被测对象。
  2. 提取代码片段时必须验证**块的完整性**（有 `if` 没 `fi`、有 `then` 没 `exit`），
     `bash -n` 对片段不适用。
  3. rc → 语义标签的映射写在一处并单独核对，不要边映射边判断。
  4. 同族于例 80：**验证工具的正确性不在验证工具的检查范围内**，
     必须用"已知答案"反向自检。

## 教训（2026-11-04）：多路径函数必须按路径分别变异；"X 守护 Y"要证明"Y 坏时 X 红"

- **形态**：批63 我写"精细守护交给 `0.5x 4K`（变异到 3.1x）"。审计 X 用**分支级**变异
  推翻：`0.5x 4K` 对 generic 退化**完全免疫**（0.94x/0.97x），只响应 uniform 快路径
  （13.92→24.89）；真正放大 generic 的是 `0.8x`（20.50→39.18）。
  ```text
                                0.5x 4K        0.8x          0.4x 4K
  uniform 分支 ×2              1.79x          无             无
  generic 分支 ×2              无             1.91x          1.86x
  ```
- **我为什么错**：只变异一条分支，却以为在测整个函数。"某 case 不响应"有两种解释——
  ①该 case 走另一条路径；②变异无效。我把两者混用了。
- **规则**：
  1. 函数有多条路径时，**变异必须按路径分别打**，再对每个 case 建"响应矩阵"。
  2. 写"X 用例守护 Y 实现"之前，必须证明 **Y 被改坏时 X 会红**；
     不是"Y 被改坏时某个用例红了"。
  3. **不能因为一个用例对某变异免疫就删它**：`0.4x 4K` 对 generic 小变化不敏感，
     但它是唯一的"2.5 倍非整数倍率"覆盖，价值在**输入形状**不在判别力。
  4. 我的表与审计的表冲突时，**先假设我的表错了**（本例确实是我跑了旧版本代码）。

## 教训（2026-11-04）：自检必须双向；区间提取必须定义关闭；注释数字必须可推导

- **自检只钉"接受"方向 = fail-OPEN**：批65 我加的自检只断言"健康日志被接受"。
  函数改成 `return 0` 后，**自检通过、真实检查也通过** ⇒ 门已死而 gate 仍 PASS。
  原缺陷（正则写坏）是 fail-closed（假红，一定被看见），`return 0` 是 fail-open
  （假绿，永远没人报）。**自检必须同时钉"该接受的接受"与"该拒绝的拒绝"。**
- **区间提取必须定义开启 AND 关闭**：`inb = (name == want)` 在 OK/FAIL 行仍为 1，
  块要等下一个 RUN 才关 ⇒ 目标用例 OK 之后的文本全被吞进它的块（marker-after-OK
  实测 accept，应为 reject）。只写开启条件时，区间延伸到下一个开启点。
  "当前不可利用"≠"不用修"。
- **注释里的性能数字必须可推导**：`>=8x`、`0.12 -> 9.05`、`per-pixel division is 10x`
  这类一次性测量，换机器就失效且互相矛盾（X/Y2 各测出不同数）。改为
  `敏感度 = budget/base` 直接算，并写出反直觉结论（2x 结构性回归**不可见**）。

## 教训（2026-11-04）：单引号程序内禁撇号；budget/base 是阈值不是灵敏度

- **awk/sed 单引号程序内禁止出现任何撇号**（含 `it's`、`'ok'` 这类引号包裹的词）。
  撇号会闭合 shell 的单引号，程序被切成多个 shell 词，其中的 `#` 变成 shell 注释，
  整个程序错位。**致命之处：全文件 `bash -n` 仍返回 0**，因为撇号成对出现、引号总量
  恰好平衡。实测后果是提取器变成"永远 accept"（6 场景 4 个翻转）。
  检测：①把函数体切出来单独 `bash -n`（片段级才会报错）；②跑**已知答案的场景矩阵**。
  要引用文本就在程序外拼好再 `-v` 传入。
- **`budget/base` 是阈值倍数，不是最小可检测回归**。budget 按负载峰值标定，把它当分子
  算"能抓多大回归"是循环论证：调大 budget，N 变大而探测力变差。两者只在回归是纯倍乘
  时相等。措辞必须是 "trips at Nx wall-clock"，不是 "catches Nx algorithmic regressions"，
  且必须标口径（同一用例 idle 8.3x vs 负载 4.9x）。
- **同族三例**：例 80（`bash -n` 过但函数静默犯错）、例 84（自检只钉单方向）、
  例 87（撇号撕引号）。共同结构：**语法检查器不检查语义**，唯一可靠验证是
  "已知答案的场景矩阵"。

## 教训（2026-11-04）：边界测试要覆盖"匹配多严"；守卫本身必须做 Rule 16

- **边界测试只覆盖"在哪"，不覆盖"匹配多严"**：六个边界都在验证"marker 是否落在
  正确的块内"，却从不验证 marker 文本必须完整匹配、用例名必须完全相等。
  四个宽松化变异（`/drain:/`、`/drain: challenge/`、`index(name,want)==1`、
  `substr` 前缀比较）全部 rc=0 通过自检。**松紧是独立维度，必须单独设探针**：
  截断输入尾部（`${marker%??????}`，**不是**追加后缀 —— 追加后仍含完整 marker，
  探针变成空断言）+ 前缀用例名。
- **死守卫比没有守卫更糟**：批67 我加的"awk 内撇号静态守卫"从未生效 ——
  守卫自身头部 `awk -v q="'"` 就带两个撇号，状态机立刻误判。
  重新注入原错误，守卫保持沉默。**任何守卫必须先证明它在攻击下会红**
  （Rule 16 对守卫本身同样适用）。偶奇校验也抓不到（批67 错误 6 个撇号，偶数，
  `bash -n` rc=0）—— 想当然的检测方案要先反证。
- **同一语义在多处实现时逐一检查**：Y2 指出 RUN 的 open 写死 `tag=="RUN"`，
  我改 `tolower(tag)=="run"` 后 8 个拼写仍全 reject —— 真正根因在名字剥离正则
  `[A-Z]+` 只吃大写。**靠逐字段打印中间值定位，不要猜。**

## 教训（2026-11-04）：放宽≠fail-open；匹配松紧有四个独立方向

- **要证明 fail-open，必须给出一个输入使它 accept 而正确实现 reject。**
  审计报 `/[Dd]rain:/` 是 fail-open，我用"无 marker"三场景（空块 / 无关文本 /
  别的用例有 marker）实测三个变体全 reject ⇒ 它只是**接受更多拼写变体**，
  无法让没打印 marker 的用例通过。是宽容，不是漏洞。
  但这类放宽仍值得加探针，理由是另一个：它会**掩盖 marker 常量被改坏**。
  措辞必须按"约束强度"而非"假绿"来说。
- **"匹配是否过松"必须覆盖头 / 尾 / 中 / 大小写四个方向。**
  批68 只做 tail 截断，只能证明"不是只匹配前半段"；实测 `/record/`（TAIL）与
  `/coalesced record/`（MID）在七边界下都 ACCEPT。
  修法：tail 比例截断 + head 截断（同时覆盖 MID）+ 全大写 + 交替大小写。
- **`${s%??????}` 的语义陷阱**：不足 6 字符时原样返回，**恰好 6 字符时塌成空串**，
  探针变空断言。固定长度截断不安全，用比例 `${s:0:${#s}*2/3}`。

## 教训（2026-11-04）：注释里的"为什么"必须验证；变异脚本会随源码静默失效

- **注释里的机制解释必须与行为同等验证**：我写"`declare -A` 时 `printf -v` 写 `[0]`
  而 `$V` 为空，所以探针跑在空路径上"。实测 `printf -v V` 与 `$V` **读写同址到 `[0]`**，
  路径完好（`wc -l < "${V}"` = 3）。我只测了 rc=0 就编了一个机制解释，
  并在两个竞争假设（探针失效 / 目标本身合法）里选了更戏剧化的那个。
  区分方法：**直接打印中间值**（`$V` 与 `${V[0]}`），不要从最终 rc 反推机制。
- **变异测试第一步是断言变异已应用**：源码把 `tag == "RUN"` 改成 `tolower(tag) == "run"`
  后，旧变异脚本的替换串不再匹配，变异**根本没应用**，但输出显示 "MISSED"，
  看起来像"变异逃逸"。**所有变异脚本必须校验替换次数 == 1，不匹配要显式报错。**
  这是例 82 的同族第二次复发：验证工具自身的正确性不在它的检查范围内。
- **"接受更多拼写"≠ fail-open**：`/[Dd]rain:/` 接受 `Drain`/`drain`，
  但无 marker 三场景全 reject ⇒ 只是宽容。要证明 fail-open 必须给出
  "正确实现 reject 而它 accept"的输入。

## 教训（2026-11-04）：审计要复用真实构造函数；flag 守卫对 nameref 失明

- **审计构造的输入必须复用真实构造函数**：审计用 Python `i=0` 重写"交替大小写"
  得到 `dRaIn`，据此断言注释错；但 gate 里是 awk **1 基**（`i=1 -> toupper`），
  真实产出 `DrAiN`。**用自己的语言重写"等价物"会得到相反结论。**
  这是"变异必须来自真实函数体"的另一面 —— 对变异有这条规则，对探针输入却没有。
  执行方法：`sed`/`awk` 从真实文件提取函数或表达式，直接运行，并**断言提取唯一**。
- **按 flag 串判断变量形态的守卫，对 nameref 一律失明**：`declare -n` 的
  `declare -p` flag 串只有 `-n`，不含目标的 `-a/-A/-i/-r`。后果：
  nameref→数组时 `printf -v` 写穿到 `REAL[0]`，**数组守卫完全看不到**；
  nameref→未设置目标会创建一个新全局变量。处理：nameref 与数组同级拒绝。
- **注释与实测脱节是双向的**：我更新了实测结论（"P10 也抓不到 [Dd]"）却忘记同步注释，
  留下自相矛盾的句子。**改结论时必须搜一遍旧结论出现过的所有位置**（注释、提交消息、记忆）。

## 教训（2026-11-04）：严格化会移动假红边界；修复必须配套回归探针

- **"更严格的匹配"不等于"闭合某个漏洞"**：我断言"整行锚定 `^[[:space:]]*marker$`
  能闭合 `/[Dd]rain:/` 缺口"。真实函数体四象限实测：锚点+`[Dd]` **仍接受** `Drain`，
  且**新引入两个假红**（`note: <marker> (see above)`、`<marker>  extra`）。
  严格化会**移动**假红边界而不是消除假红。改匹配方式前必须同时测两侧：
  "该拒的仍拒" + "该受的仍受"。描述一个方案时要**读它自己的正则**
  （`^[[:space:]]*` 明明允许任意缩进，我却写"pin the indentation forever"）。
- **修复一类输入时必须补该输入的探针**：批68 修了 `[A-Z]+` → `[A-Za-z]+`（小写 RUN
  打开块），但所有探针的 RUN 行都是大写，回退修复后 11 探针全绿。
  **"当前不可达"不构成不补的理由** —— 恰恰因为不可达，回归时没有其他路径能发现。
- **枚举"变量形态守卫"必须包含"未设置"**：`declare -p` 对未设置变量返回空 ⇒
  `flags=""` ⇒ 所有 flag 分支不匹配 ⇒ 无守卫。虽非 fail-open（`printf -v` 会创建
  普通标量），但**调用方拼错变量名会静默测试一个新变量**。
  与"枚举必须包含空/零"同族。

## 教训（2026-11-04）：构造形式的枚举；一条新形态探针闭合多个变异

- **"X 不可构造"必须按构造语法的形态分类枚举**：我用 `declare -in V=R`（带赋值）
  失败（rc=4，变量未创建）就断言 `-in` 整个形状不可构造。审计实测：
  `declare -in V`（**不带赋值**）→ `flags=-in`，合法且能到达守卫。
  **一个反例只能否定一种构造形式，不能否定整个形状。** 要枚举：
  带赋值 / 不带赋值 / 多变量 / 数组 / 引用，各测一次。
  更糟的是我**代码对、理由错** —— 错误理由会误导后来者回退改动（同族于例 94）。
- **一条覆盖"新输入形态"的探针会顺带闭合该形态下的多个变异**：
  批72 加的 `[ Run  ]`（混合大小写 RUN）探针，除了钉住 `[A-Z]+` 回归，
  还让 `CASE_BUILTIN`（`tag=="RUN"` 与 `tolower`）从 escape 变 caught。
  探针覆盖不是"一探针一变异"的线性关系。**加探针优先加新输入形态**，
  而不是给每个变异各加一条同形态的探针。

## 教训（2026-11-04）：空串穿过黑名单过滤器；回归判据要对准不变量

- **"拒绝含 X 的输入"与"只接受由 Y 组成的输入"不等价 —— 前者漏掉空串**：
  `case "$suf" in *[!0-9]*) continue ;; esac` 语义是"含非数字字符就跳过"，
  空串没有任何字符，自然没有非数字字符 ⇒ 放行。实测后果：legacy 目录
  `linux-gate-logs.` 被当成 PID 目录删除，还吃掉一个保留配额。
  **安全过滤器要用白名单**（只接受合法形状，如 `"$prefix".<digits>`），
  不要用黑名单（拒绝已知坏形状）。空串/空集合是字符类过滤器的通用盲点。
- **"不影响 X" 的评估必须列举所有受影响的不变量**：这条 plan 遗留项被标为
  "低（不影响有界性）"所以长期没修。实际上它有界性没坏，但**删除了本应永久保留的
  证据** —— 被问到的那一个不变量不是唯一的不变量。
- **回归判据必须精确对准被修的那个不变量**：我给 rotate_logs 写判据时用
  "带点目录死亡 AND PID 目录数变 4"。实测回归版带点目录确实死亡，但 PID 目录**仍是 5 个**
  （带点目录不占配额），于是误报 "SURVIVED"。改成"只看带点目录是否存活"后正确 caught。
  把"修复的观察"和"修复的副作用"混在一条 AND 里，会在副作用不变时误判测试无效。

## 教训（2026-11-04）：源码回基线 ≠ 被测二进制回基线；plan 标记只是线索

- **恢复源码后必须 touch**：`Copy-Item` 恢复备份会把 mtime 退回原值，
  增量构建（MSBuild/ninja）据 mtime 判断"源文件没变"而**跳过重编**，
  于是跑的还是变异版二进制。实测：md5 与 `git diff` 都确认源码已回基线，
  测试却仍红，差点误判成"源码恢复不完整"。
  **"源码对了"与"被测二进制对了"是两件事**：恢复后必须
  `(Get-Item $src).LastWriteTime = Get-Date`，并通过**重编日志**确认目标确实重编。
- **记忆/plan 的状态标记不是事实，是线索**（与 memory 顶部规则同源）：
  `[~]` 不等于"未修"，`[x]` 也不等于"已验证"。关闭一个 item 前必须逐条复核
  **文件:行**证据；既不能因为标记是 `[~]` 就重做，也不能因为"看起来做过"就勾选。
  实测：plan 标 `[~] 修复中（D1）`，实际 D1–D4 全部已修且集成测试早已存在。
- **编码不干净的记忆文件用字节级最小差分**：`.opencode/plan.md` 含历史坏字节，
  整体 `encoding='utf-8'` 解码直接抛错。做法：按字节定位目标前缀 → 校验上下文 →
  单字节替换 → 长度校验。不要"解码-改-重编码"整体处理，会把原来的坏字节二次损坏。

## 教训（2026-11-04）：混合编码文件全程字节级；锚点必须限定范围

- **不要"解码-改-重编码"处理含坏字节的文件**：我用
  `raw.decode('utf-8', errors='surrogateescape')` + `'\n'.join(...)` + 重新编码，
  结果 **1571 行的文件中文行全部黏连、行数骤降**。原文件里有裸 `\r` 与非法字节，
  解码往返改变了结构。
  正确做法：**全程 `bytes`** —— `raw.find(b'<ASCII 指纹>')` 定位 →
  `block.split(b'\n')` 逐行 → 只改目标字节 → `b'\n'.join`。
  证据文本只用 ASCII。写回后校验**行数变化等于新增行数**（本例 1571→1589，+18 行证据）。
- **按内容定位的锚点必须唯一且限定在目标块内**：我用「文件里第一个 `fail-closed`」
  做插入点，结果插到了另一个章节（`:165`）。改用唯一 ASCII 指纹 + 块起止范围约束，
  再 `grep -n` 回读确认行号落在预期区间。
  这是「变异必须来自真实函数体并断言唯一」的推广：**任何按内容定位的编辑都要断言范围唯一性**。
- **plan 里的判据本身可能是错的**：`pixels_are_physical = (SM_*VIRTUALSCREEN == ...)`
  这条判据若被实现，会在所有多屏机器上恒判 not-physical，让 `--monitor N` 失效。
  实现改用 `SM_CXSCREEN/SM_CYSCREEN` 是对的。
  **勾选"已完成"时不能只核对"代码是否符合判据"，还要核对"判据是否符合事实"。**

## 教训（2026-11-05）：变异验证与并发观测

- **变异体必须保证编译通过**。M2 删节流后 `MoveInterval()` 变死代码，`/WX` 的 C4505
  把变异变成**构建失败**——跑出来的"失败"是编译错误，什么也没证明。
  改 `MoveInterval() * 0` 后才有真红证。
  **判定顺序**：先 `BUILD_EXIT==0`，再看测试红。构建失败的变异作废重设计。
- **变异矩阵禁止累积应用**。第一轮在同一工作树依次套 M1→M5，五个变异报同样的
  4 failing（M2 还用着 M1 的旧二进制）。正确做法：**每个变异前从干净基线恢复 +
  断言替换次数==1 + 反向 grep 确认变异串 0 命中**，再编译再跑。
  独立后 M4 只红 1 个用例——这才证明用例针对性。
- **release/acquire 只给"最终一致"，不能当屏障**。worker 序列是
  `Emit → Publish`，同一 Dispatch 内 Publish 之后还可能再 Emit；
  所以"观察到 pending==0"不证明"此后不再 emit"。唯一完整 happens-before
  是 `join()` 之后那次发布。测试必须 `WaitUntil` 轮询，文档必须写明降级。
- **注释约定的不变量要变成断言**。进程级测试钩子（`g_emit_hook`、
  `g_move_interval_ns`）无法按 sink 隔离时，用 `g_live_emit_hook_guards` 计数 +
  `CHECK_EQ(...,1)` 把"每个用例只能一个 recorder"变成硬失败（变异改 99 → 5 用例红）。
- **`Stats().injected` 这类纯计数器证明不了"发的是正确的那 N 次"**。只要被测输出是
  动作序列，就必须有观测**内容与顺序**的 seam；否则合并/排序/时序全部改坏也全绿
  （批77 四条盲区，见 discover 例 111）。
- **纯查询函数禁止自己取时钟**。`MoveDue` 内部 `Clock::now()` 与调用方已采的 `now`
  比较，语义退化为"两次采样恰好相等"，在细粒度时钟上无限自旋（discover 例 112）。
  时间点必须由调用方传入。

## 教训（2026-11-05）：可回归性与提交卫生

- **修对了 ≠ 有回归网**。`MoveDue` 二次采样改回 `Clock::now()` 后 77 tests 全绿——
  它只影响 worker 自旋次数（延迟/资源），不影响输出的动作序列；而测试体系全部基于
  "发出了什么"。此时必须**登记 known gap**，说明为何不能加断言（跨负载不稳定），
  禁止为了让变异变红而写依赖时序的假测试。**不要声称"已完全覆盖"。**
- **提交前检查暂存区**。`git add -A` 会把 `.opencode/` 下含未盖章表述的流程记录一并暂存。
  代码提交与流程记录必须分离：`restore --staged` 掉记忆文件，process 记录留到结论定案后写。
- **"文件是否被 git 跟踪"只能自己查**。审计报告说"未跟踪 0 字节文件"，实际是
  `407d03e` 误提交的**已跟踪**垃圾（`git diff --numstat` 为 `0 0`）。
  `git ls-files --others` 对含 `%`/`(`/`,` 的路径会转义而漏报。
  唯一可信的是 `git cat-file -s HEAD:<path>` / `git log --diff-filter=A` / `git status` 状态码。
- **窗口类缺陷要把"缩小"和"关闭"分开说**。ReleaseSession 后仍可发一帧移动：
  守卫把"无限"缩到"每次迭代至多一个已弹出 item"，但 `EmitDueMoves()` 无锁运行且不复核
  forget 的窗口 (a) **仍未关闭**。文档与提交消息必须写"窗口缩小 + 诚实登记为未修"，
  不得写"已修"。审计 B 三次拒绝给"已修"盖章，这个坚持是对的。
- **批93**：调试通道实测（`--ui-debug-port` / surface 命令 / pixel 统计），变异：空：empty 恒假 -> 1 用例红；恢复全绿。