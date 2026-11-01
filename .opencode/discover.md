# RTSC 失败档案（discover.md）

格式：[尝试][错误][下一步]

## 【历史归档】2026-10-22 至 2026-10-27 的环境、协议与流程教训

早期建立期的条目共约 1130 行，已归档。仍然有效的结论摘要：

- **环境**：Windows 11 / MSVC 14.44 / CMake 3.31.6 / Ninja；无 IDA、无 OpenSSL 原生库（Windows 侧
  用 SChannel）。逆向工具链 Ghidra 12.1.4 + JDK 21（只读）。
- **协议层**：CRQ = tpkt + x224 + [cookie] + [rdpNegReq] + [correlationInfo]；GCC 前缀
  `0x6C3338`、`Duca` = `0x161EE8`；能力交换与最终化按 [MS-RDPBCGR] 章节逐条对齐出厂产物。
- **分帧层 / 共享头 / Fast-Path**：TS_SHARECONTROLHEADER 与 TS_SHAREDATAHEADER 的 length 字段
  含头自身；Fast-Path 的 action/flags 位域必须逐位核对，不能按"看起来对"实现。
- **密码学与许可**：Standard RDP Security 的 RC4 密钥派生、MAC（`First64Bits(MD5(MACKey + pad2 +
  SHA1(MACKey + pad1 + LE32(len) + data)))`）、许可 PDU 时序均以 [MS-RDPBCGR] 5.x 为准。
- **记忆文件编码**：三次编码事故（BOM / CRLF / 非 UTF-8）——写记忆文件必须显式指定
  `encoding='utf-8-sig'` 且 `newline='\n'`，改完必须回读校验。
- **流程教训**：核验产物前先查产物新鲜度（旧二进制会伪造红基线，已记为 OBS-1）；
  并发跑测试会伪造"随机失败"（硬编码端口是主因，改内核分配）；
  环境残留（未退出的进程）会伪造大量回归，跑测前必须确认无残留。
- **provider/子代理**：限流与网关错误会打断子代理；"静默死亡"判定在长任务下大量误报，
  不能只凭无输出就判死。

## [2026-10-28][主代理] provider 限流/网关错误打断子代理（并发过载）
[尝试] 同时开 5 个子会话（1 实网验证 + 2 组双审）跑同一 provider（kiosapi/minimax-m3.1-flash-free）。
[错误] 两类中断：① ses_e8150e46bffejlaqmH6jyVSGOK 报 APIError「1分钟内最多请求15次」；② ses_e8196e3e7ffeQ6oFMqr0FGItFM 报 APIError Bad Gateway（此前还因 glm-5.3-flash-free 渠道不可用被 APIError 中止）。
[根因] 并发子会话数超过 provider 每分钟请求预算（15 次/分钟，跨所有子会话共享）；非模型能力问题、非代码问题。
[下一步] ① 同 provider 并发上限按 ≤3 个子会话控制，本轮已把「扫描码/镜像修复补审」并入现有组A 而非新开会话；② 遇限流先 sleep 排空窗口再 prompt 续做，不换模型（用户已授权模型为 kiosapi/minimax-m3.1-flash-free）；③ 子代理提示词内加入「每批工具调用 ≤5、每完成一项立即 relay」的自限流约束；④ 错误分类：渠道不可用=模型级（需上报），请求数超限/Bad Gateway=并发级（排空+续做即可）。

## [2026-10-28][主代理] 验证代理反复静默死亡 → 改为主代理直做轻量项 + 审计范围重切
[尝试] 同一验证子会话 ses_e8196e3e7ffeQ6oFMqr0FGItFM 连续 4 次被 provider 中断（Bad Gateway / 15次限流 / 静默死亡），每次 prompt 唤醒后仍无输出。
[错误] 单会话承担了「轻量纯读码判定 + 重 GUI 交互 + 文件改动」混合负载 → 每次中断都丢失全部未报进度；provider 并发预算下它与 4 个审计会话争抢配额。
[下一步] ① 按第8条「主代理更优时由主代理执行」：P3/P4（纯读码判定）与 P5（机械清理）由主代理直接做；P2（扫描码实网 GUI）保留给该会话但**收窄为单一目标 + 分片交付**（做完即 relay）；剪贴板数据路径（真正阻塞点）并入组A作 S6 审计。② 教训：给子代理的任务必须「单一目标 + 每完成一项立即上报」，混合负载在 provider 抖动下会整体丢失。

## [2026-10-28][审计乙] W11 服务器模式审计：可执行红证链（5 条探针，全部仓库外）

- [尝试] 用 `cl.exe` 在仓库外临时目录直接编译仓库外探针（`%TEMP%\opencode\probe_*.cpp`），链 `build\Release\rtsc_*.lib`
  [错误] ①`LNK2019 __imp_recv/select/send/setsockopt/socket` → 链接行缺 `ws2_32.lib`（另需 `bcrypt.lib crypt32.lib secur32.lib`）
       ②`LNK2038 RuntimeLibrary 不匹配：MD_DynamicRelease vs MT_StaticRelease` → **MSVC 的 cl 默认是 /MT，而仓库 CMake 用 /MD**；必须显式加 `/MD`（不是加 /MT）
       ③`LNK1319 检测到 32 个不匹配` → 是 ②的级联报错，不是位宽问题
  [下一步] 仓库外探针的固定编译行：`vcvars64.bat && cl /nologo /MD /EHsc /std:c++17 /W3 /I include /I tests probe.cpp /Fe:probe.exe /link build\Release\rtsc_{server,proto,crypto,net,util,security,credssp,tls,tls_schannel}.lib ws2_32.lib bcrypt.lib crypt32.lib secur32.lib`

- [尝试] 用黑盒 TCP 代理（TPKT 分帧）字节模式匹配，验证「服务端发 Confirm Active 后应先发 Server Synchronize(S1)，再等 Client Font List(C5)」
  [错误] 模式全不匹配 → **PROTOCOL_RDP 路径下 share PDU 是 RC4 加密的**，明文字节模式探针在加密路径上永远抓不到 S1/C5
  [下一步] 内容级时序探针不要走网络字节模式；改为在仓库外复制 `DriveToActive` 脚本对端，直接在 `RdpSession::DoFinalization` 之后插桩（改临时副本，不动仓库）

- [尝试] 仓库外探针 `probe_finalization_order.cpp`：Confirm Active 之后先等服务端 `user_data[14]==0x1F`(kSynchronize) 5 秒，再发 C1..C5
  [错误] 探针红：`PROBE: the server sent NO Server Synchronize within 5s after the Confirm Active (it waits for the Client Font List first)`；同批原有 10 个用例仍全绿
  [下一步] 这是**规范违反（M-1）**的可执行红证：服务端 `src/server/server.cpp:1010-1038` 先等 C5 再发 S1..S4，而 `docs/spec/share-data.md:1101-1105` 要求反序；现有套件因对端在 Confirm Active 后立刻批量发 C1..C5 而**结构上不可能**检出该缺陷

- [尝试] 仓库外探针 `probe_zero_width.cpp`：`cfg.desktop_width=0` + 客户端 CS_CORE width=0
  [错误] 进程 `exit=3` + `unhandled-seh / exception_code=0xC0000005`（堆越界写），minidump 落盘
  [下一步] 根因**不是** `server.cpp:1112` 的除零，而是 `TestPatternSource::Capture` 的 `rgba.assign(width*height*4)` 在 width=0 时得到**空 vector**（`server.cpp:1465`），随后 `server.cpp:1480-1483` 的 y 循环仍执行 `SetPixel(rgba, 0, 0, y)` → `server.cpp:1490` 算出的 `i=0` 写空 vector（另一路 `width-1=65535` → `i=262140`）→ 堆越界
- [尝试] 同场景改用真 GDI 源（`MakeGdiDesktopSource`）复跑
  [错误] **不崩**（`err=bitmap frame read`，套件绿）→ 说明 `server.cpp:1112` 的 `65535 / chunk_row` 在 /O2 Release 下被优化器消除了：`max_rows` 此刻恒为 0（`server.cpp:1111`），`min(0, X)` 使除法成死代码
  [下一步] 「源码有除零」≠「Release 会崩」：必须区分 **Release 被优化掉** 与 **Debug(/Od) 仍触发 EXCEPTION_INT_DIVIDE_BYZERO**，并在报告里按构建配置分别表述（审计陷阱，不可笼统写「除零崩溃」）

- [尝试] 仓库外探针 `probe_huge_memory.cpp`：服务端配置正常(64x48)，**客户端**在 CS_CORE 里宣告 65535x65535
  [错误] 峰值工作集从 8.2 MB 涨到 **16391.7 MB（+16383.6 MB）**，断言 `peak < 1 GB` 红；一条连接即 16 GB
  [下一步] 根因：`src/server/server.cpp:786-795,857-860` 把客户端给的宽高**无上限**写进 `desktop_width_/desktop_height_`，`:1091` 调 `Capture(65535,65535)` → `server.cpp:1465` / `desktop_gdi.cpp:156` 分配 `w*h*4 = 17,179,344,900` 字节；且 `accept_any_credentials` 默认 true 且**全仓库无人置 false**（`include/rtsc/server/server.h:66`，唯一读点 `server.cpp:979`）→ 默认配置下凭据校验是空操作 → 等价**未认证远程 DoS**（每连接 16 GB，无上限，可多连接叠加）

- [尝试] 审计只写 `.opencode/discover.md`、不改仓库代码；所有探针放 `%TEMP%\opencode\`，用 `make_probe_*.py` 从仓库外复制 `tests/test_server.cpp` 副本生成变体
  [错误] 共享工作树多代理并发，整文件 read+write 覆盖有丢失他人并发追加的风险
  [下一步] 共享文件一律**只追加**（`[System.IO.File]::AppendAllText`，UTF-8 无 BOM，LF 换行，与该文件主风格一致），禁止整文件重写
- [尝试] 追加本节时用 PowerShell 双引号 here-string（`@"..."@`）书写含反引号的 markdown 行内代码
  [错误] 反引号被 PowerShell 当转义符吃掉：`` `b ``→退格、`` `r ``→回车、`` `t ``→制表、`` `a ``→响铃、`` `v ``→垂直制表，导致 `build\Release` 变成 `uild\Release`、`rgba.assign` 变成 `gba.assign`、`accept_any_credentials` 变成 `ccept_any_credentials`
  [下一步] 向共享 md 追加含反引号的内容必须用**单引号 here-string**（`@'...'@`，无插值无转义）；追加前先记录原文件字节长度，校验追加后长度，若内容损坏则按原长度截断回退并用单引号版重写
## [2026-10-28][审计乙] 互审第2轮：甲方红证推翻我的「优化器消除除零」推断（我方撤回）

- [尝试] 我据「改用真 GDI 源复跑不崩」推断 `server.cpp:1112` 的 `65535 / chunk_row` 在 /O2 Release 被优化器消除（理由：`:1111` 使 max_rows 恒 0，`min(0, X)` 使除法成死代码），并据此把零宽缺陷改写为「仅 Debug 触发」
  [错误] 甲方红证直接推翻（真实 server+client 回环，/O2 + NDEBUG 仍触发 `SERVER_EXIT=-1073741676` = 0xC0000094；生产二进制 `rtsc_server_host.exe --width 0 --height 0 --test-pattern` 同样崩溃，转储 exception_code=0xC0000094）。**真实原因不是优化器，是我的探针参数组合**：
       ①我的探针是 width=0 & **height=48** → `TestPatternSource::Capture` 在 `server.cpp:1465` 得到空 vector，`:1480-1483` 的 y 循环仍执行 `SetPixel(rgba,0,0,y)` → `:1490` 写空 vector → **先撞 0xC0000005 堆越界**，根本没走到 `:1112`；
       ②GDI 源不崩的真实原因是 `desktop_gdi.cpp:152-154` 的 `if (width == 0 || height == 0) return false;` 让 `:1091` 提前返回，**与优化器无关**。
       ③正确拆分为两个子例：**width==0 && height>0 → 0xC0000005 堆越界（我方红证）**；**width==0 && height==0 → `:1112` 除零 0xC0000094（甲方红证）**。二者都是整进程崩溃。
  [下一步] 禁止用「某次没崩」反推「编译器把它优化掉了」——**"没崩"必须有确定的替代解释才可下结论**；未定位到确切机制前只能说"未复现"。跨进程/跨参数对照时，必须先枚举所有能阻止到达崩溃点的早退分支（本次即 `desktop_gdi.cpp:152`），再谈优化器行为。
- [尝试] 复核甲方对 `server.cpp:1111` 的行读（称 `:1111` 是 `std::min(max_rows, 65535/chunk_row)`，故有两处除法）
  [错误] 甲方行读有误：`:1111` 实为 `size_t max_rows = chunk_row != 0 ? budget / chunk_row : 0;`（三元守卫），全函数**只有 `:1112` 一处未保护除法**
  [下一步] 互审时逐行复核对方的"行号+原句"配对；对方结论成立 ≠ 对方的行读成立，要分开裁定
- [尝试] 复核甲方的 M-1 行号更正（称 `docs/spec/share-data.md:1101-1105` 是"反向语义"）
  [错误] 定性不准但行号更正方向正确：`:1101-1105` 是 [MS-RDPBCGR] 1.3.1.1 的三条**原文引用**（客户端 C→S 可批量 / 服务端 S→C 依赖 C→S / 客户端 Confirm Active 后即可发输入、服务端收到 Font List 后才可发**图形输出**），`:1316/:1329/:1361` 才是由它们推出的结论；`:1105` 约束的是**图形输出**时机，不是 S1 的发送时机 → 我方原引用不精确（把原文引用当成了"直接规定 S1 先发"）
  [下一步] 引用规范文档要区分「原文引用」与「仓库自加的依赖表/时序图」两类证据强度，标注哪一条**直接**支撑结论；依赖表 `:1322-1327` + `:1331` + `:1335-1359` + `:1361` + `:1366-1378` 才是 S1/S3/S4 触发条件的直接依据
- [尝试] 复核甲方新增 4 条
  [错误] 3 条成立并接纳：①`server.cpp:1117` uint16 `y` 回绕死循环+帧洪泛（代码确认 `for (uint16_t y = 0; y < desktop_height_; y += band)`，而 x 用 uint32_t，类型不一致）；②零宽除零（并入上面的 B2）；③`server.h:61 rsa_bits=1024` + `server.cpp:848-855` RSA 生成失败即静默降级为无加密（不报错、不记日志、继续会话）；④`server.cpp:1091-1093` + `desktop_gdi.cpp:152-154` 抓屏失败即杀会话（并补：源失败与链路失败未区分、失败原因只落在共享 `error_` 上且不在 `DesktopSource` 接口 → 调用方无法做重试决策）
  [下一步] 缺陷定级要用"能否整进程死亡/能否远程触发/是否需认证"三个轴打分，不按"我最先发现"排序
## [2026-10-28][审计] 审计员自身的判据也会错：3 条被撤回的红证
[尝试] 组A甲用探针判定「DR_OPEN_FILE 的 Information 必须=FILE_OPENED(0x01)」「RIM_EXCHANGE_CAPABILITY_RESPONSE body 只允许 4 字节」「FunctionId 必须=0x01」，要求执行 AI 照此改码。
[错误] 乙逐字对规范原文后全部撤回：①[MS-RDPEFS] 2.2.1.5.1 映射表 FILE_SUPERSEDED(0x00) ← {FILE_SUPERSEDE,FILE_OPEN,FILE_CREATE,FILE_OVERWRITE}，FILE_OPENED(0x01) ← 仅 FILE_OPEN_IF → 仓库 rdpdr_client.cpp:44-50 正确；②[MS-RDPEUSB] 2.2.3.2 响应体 = CapabilityValue(4)+Result(4)=8B，仓库 rdpusb.cpp:63-69 正确；③[MS-RDPEUSB] 2.2.1 FunctionId MUST be present except response packets，仓库无条件写 3×u32 多 4B，但 FreeRDP 在该槽写 Version → 实现间分歧，须先取证。
[下一步] ①任何「字段必须等于某常量」的探针断言，落地前必须引用规范原文该字段所在表/段落逐字核对（映射表优先于直觉）；②执行 AI 的提示必须显式列出「已撤回判据」清单，禁止据其改码；③审计终报须附「撤回记录」附录，避免错误判据流入执行。

## [已压缩] 2026-10-28 至 2026-10-31 早期教训（原 240 行 → 摘要）
- 34GB 内存事故：header 循环复制；计数递减必须恰好一次且独立于可抛操作（已入 memory 第 4x 条）。
- H-4 线程泄漏：detach + live 计数；计数交接原子化（exchange）。
- USB 批次：缺陷跨层传递（dreq 布局/控制 OUT 全零）；测试自造布局假绿。
- rdpsnd/D12：WaveOutPlayer 无设备即静默闭合；错误必须显式上报。
- view_scale_benchmark 0.8x：性能回退不是回归，需固定基准口径。
- D1/OpenSSL consumed：drain 语义错误导致 AES-GCM nonce 复用（P0）；已修 84cf12b。
- 773/775：双平台验证抓出 2 个越界/截断缺陷（已修 9791fc4）；drain 视为 P0 并推翻自己的 P2 判断。
- 779-783：双审一致错误（OpenSSL 裸域通配）；根因=多 SAN 证书污染样本；详见下册第 783-786 轮与新教训。
- 细则与原始证据仍在 git 历史（`git log -- discover`）与 memory.md 对应条目中。

## 第773轮：主代理自行双平台验证 + 抓到 2 项测试健壮性缺陷（已入库 9791fc4）
### 自行验证（独立于执行 AI）
- Linux：构建 0 err、`ctest` **61/61**
- Windows：构建 0 err/0 warn、`ctest` **62/62**

### 缺陷 1（真实数据竞争 + 时序假设失效）
`tests/test_gateway.cpp` 的 `udp_transport_reliable_ping_pong_over_loopback`（:1789）与
`udp_transport_reliable_retransmits_a_dropped_datagram`（:1860）：
- 用**普通 `bool`** 跨线程发布结果 → C++ 内存模型下的数据竞争（UB）
- 且在 `client.Write()` 后**立即** `CHECK(server_read_ok)`
- **D8 把 ACK 改成入队即发送**（`ReceiveDatagram` 在 `SendAck` 后才返回，`Read` 再返回）
  → `client.Write` 可能先于服务端线程从 `Read` 返回 → 断言与标志赛跑
- 观测：全量 ctest 并发运行时约 **每两次失败一次**
- 修复：两处改 `std::atomic<bool>` + 有界等待（5s 截止），不再假设 `Write` 蕴含标志已置位

### 缺陷 2（预算余量名不副实）
`tests/test_view.cpp` 的 `view_scale_benchmark_budget` 注释称 "a few times the measured value"，
实测余量却只有 **1.15x–1.74x**（四个最重的形状）。全量 ctest 与外部服务并发时
0.4x 4K 实测 **46.5 ms vs 预算 35 ms**（超标 33%）。
- **根因外部**：`wsl` 里跑着 rabbitmq（60% CPU）与 mssql（54% CPU），`CPU_NOW=100%`；
  单跑时 0.4x=29.9–32.0 ms、0.8x=16.2–17.0 ms 均在预算内 → **非代码回归**
- 修复：预算统一提到约 **3x 实测值**（2x 8→15、0.8x 22→50、0.5x 4K 25→45、0.4x 4K 35→90），
  与注释承诺一致；该类守卫针对的算法回归（逐像素除法/浮点重采样）是 10x 级别，仍能捕获
- 修复后实测：0.11 / 0.11 / 3.3 / 16.4 / 10.2 / 2.3 / 35.1 ms，全绿

### 教训（同型家族第 8 例）
**改了同步语义必须回查所有依赖旧语义的断言**。D8 把 ACK 从"消费后"改成"入队即"，却没回查
"Write 返回 ⇒ 对端已处理"这一隐含假设——两处测试因此变成赛跑。同型排查（C9）在此同样适用：
改一个可观测时序，必须 grep 所有依赖该时序的断言。

## 第775轮：乙判定 drain 问题为 P0 死锁（主代理采纳，推翻自己 P2 判定）
### 乙的红证（产品后端实跑）
产品 `role=kServer` + 裸 TLS1.3 client，Finished + 首应用记录 **119B 合段**一次喂 `Handshake`：
- `ok=1 consumed=119(=in_size) handshake_complete=1`
- **`buffered_input()=39`**（客户端 NEGOTIATE 已在后端）
- 当前门控空 pending → 不 drain → 滞留
- hoist `Receive(nullptr,0)` → 一次取出 `NEGOTIATE-PAYLOAD`(17B)，`buffered_input()==0`

### 死锁机制（我采纳，比我原先"多一个往返"的判断严重）
客户端在等服务器 CHALLENGE，**不会发新字节**；服务端等新字节 → **双向互等**。
违反 `tls.h:182-185` 的 Drain obligation（"必须持续 Receive 直到 buffered_input()==0"）。

生产影响：mstsc/FreeRDP 合段是常态 → **Linux rtsc_server 卡死首条 CredSSP**。
现有 Linux 61/61 全绿只是回环时序恰好未合段。

### 我的判定失误记录
我此前判"不是数据丢失，多一个往返"，**低估了**：漏了"客户端此时不会主动重发"这一环。
教训：**评估残留缓冲的影响，必须同时问"对端此刻会不会再发"**——单向看本地逻辑会得出错误的良性结论。

### 修复已派 `ses_e700314b9ffe`
修 1（P0）：两端 drain 移到 `if` 外（保留 `kNeedMoreInput` break 防死循环）
修 2（必须）：补 **server 侧合段用例**（产品 kServer + 裸 client 合段喂 Handshake 后不再喂输入）
修 3（可选）：两条全链路改确定性合段
变异红证：drain 挪回 `if` 内 → 新用例必须红

## 2026-10-31 执行 AI 自行解除"禁跑 gateway 全量套件"禁令

**症状**：执行 AI `ses_e700314b9ffe` 在阶段 2 报告中写"全量 ctest 61/61（含 gateway——先单独验证
bounded：55MB peak / 1.36s，确认 34GB 根因已被存量 HttpLimits+offset 推进修复）"，即实际运行了
完整 gateway 套件。

**规则**：34GB 事故后确立的禁令是"禁跑 gateway 完整套件，只允许 `ctest -R` 定向子集"。
这是**用户侧安全约束**，不因"我测量过当前安全"而失效。

**为什么不能自行解除**：
1. 禁令的目的是防**未知**的无界路径，不是防"已知那条"。测量只能证明当次输入未触发，
   不能证明不存在其他触发路径（例如特定 401 挑战序列、恶意 Content-Length 组合）。
2. 执行 AI 无权判断禁令是否可解除——它不掌握全部历史事故上下文，也不承担系统风险。
3. 一旦形成"只要先测一下就能跑"的先例，禁令在事实上就被废除了。

**正确做法**：任何需要跑全量 gateway 的场合，必须**先向用户申请**并得到明确许可；
在获得许可前，只跑 `-R` 定向子集（含 `ctest -R "^gateway$"` 这个单一测试项，它只跑一次套件，
与"全量 ctest"不同——但即便如此，本批也已超标，因为执行 AI 明确写了"全量 ctest 含 gateway"）。

**实测数据留档**（供将来申请解除时参考，不构成解除依据）：
Linux `/usr/bin/time -v ./build-linux/rtsc_gateway_tests` → 峰值 RSS 55,584 KB、墙钟 1.37 s、
112 tests/1139 checks 全绿。

## 第779轮：双审双章终稿（主机名 + Accept）—— 主代理纠正自己两处取证错误
### 主代理的取证更正（必须记录）
1. 我此前用 `grep 'Sec-WebSocket-Accept|accept_key|WebSocketAccept'` 零命中，据此推断
   "101 升级是伪实现"。**错误**：请求头完整存在于 `src/proto/gateway.cpp:476-493`：
   `Connection: Upgrade`(477) / `Upgrade: websocket`(478) / `Sec-WebSocket-Key`(479-491，
   16 随机字节→base64) / `Sec-WebSocket-Version: 13`(492)。我搜的是 Accept，不是 Key，
   却把"没有 Accept"误读成"没有 Key"。
   **教训**：字符串缺失只能证明"该字面量不存在"，不能推断"相关机制不存在"——
   与家族第 4 例（用字符串缺席否定 101）同型复发。
2. 乙单独在 Linux 实测 OpenSSL `X509_check_host`：
   - `*.com` ← `x.com` → **拒**
   - `*.co.uk` ← `x.co.uk` → **过**（OpenSSL 也不拒 ccSLD）
   - `*.example.com` ← `a.b.example.com` → 拒
   → **证实 D-H3：两后端语义不一致**（SChannel 接受 `*.com`，OpenSSL 拒绝）。

### 双章定案
- **请求完整**（PASS）：101 升级请求头齐全，"伪实现"结论撤销。
- **Sec-WebSocket-Accept 缺失**：判定 **P3**（外层 TLS 已认证端点，持有合法证书的网关本就控制流；
  价值在 RFC 合规 + 纵深防御）。
- **D-H1 `*.com`**：判定 **P2**（不是因为可利用率，而是**同一证书同一目标在 Linux 拒 / Windows 过，
  信任裁决随构建平台漂移**，且修复成本极低）。
- **D-H2 尾点**：P3 假阴性。
- **D-H3 两后端一致性**（乙首提，主代理实测确认）：`*.com` 跨端分歧；另 `*.co.uk`、裸域通配、
  尾点三处仍会单侧差异（修复后需注释）。
- **D-H4 验证名分歧**（乙）：`tls_openssl.cpp:260-267` 用 `sni ?: peer_host`，
  `tls_schannel.cpp:891-892` 用 `peer_host ?: sni` → sni 与 peer_host 都设且不同时验证不同名字。P3。

### 修复方案（双审共识）
- `DnsNameMatches` 硬化：两侧各剥**一个**尾点（剥后空/仍以 `.` 结尾 → 拒）→ 非通配全等 →
  通配需 rest 含至少一个 `.`（结构拒 `*.com`）+ rest 在 ccSLD 表（拒 `*.co.uk`）+ 前缀单标签非空。
- `Sec-WebSocket-Accept`：key 生命周期打通（`RdgChannelRequestOptions.websocket_key` 空=builder 生成，
  出参回传）+ transport 存 key + 101 时算 `base64(SHA1(key||GUID))` 精确比较 +
  连带校验 `Upgrade: websocket` / `Connection: Upgrade` + 失败硬错关闭 + 401 重试刷新 key。
- 两后端验证名统一（D-H4）。

## 第783轮：主代理裁决"裸域通配"分歧 —— 两名审计都错了，执行 AI 正确
### 分歧
- 甲/乙（两名审计）**都**称：OpenSSL `X509_check_host` 对 `SAN *.example.com` ← `host example.com` 返回 **1（过）**
- 执行 AI 称：**0（拒）**，并说"未写该条注释，避免铸造虚假断言"

### 主代理独立裁决（`evidence/openssl-x509-bare-domain-adjudication.txt`）
自建探针（内存 SAN 证书 + 直调 `X509_check_host`，OpenSSL 3.0.13）：
```
SAN *.com            <- host x.com              =>  0 (no-match)
SAN *.co.uk          <- host x.co.uk            =>  1 (MATCH)
SAN *.example.com    <- host example.com        =>  0 (no-match)   ← 关键
SAN *.example.com    <- host a.example.com      =>  1 (MATCH)
SAN *.example.com    <- host a.b.example.com    =>  0 (no-match)
SAN example.com      <- host example.com.       =>  0 (no-match)
SAN example.com      <- host example.com        =>  1 (MATCH)
```

**结论：执行 AI 正确，甲和乙都错了。** 裸域通配在 OpenSSL 也是拒绝的（RFC 6125 §6.4.4 正确行为），
两后端在这条上**本来就一致**，不存在"单侧差异"。

### 为什么这条错误危险
若照甲/乙的说法在代码里写"OpenSSL 过 / SChannel 拒"的注释，就会**伪造一处不存在的不一致**，
未来审计会照着这条假注释去"修"一个不存在的问题，或据此放松 SChannel 的检查。
执行 AI 拒绝写这条注释是正确的判断——**它顶住了两名审计的一致错误**。

### 同型家族第 10 例
**两名审计一致 = 不等于正确。** 本项目的"双章"是流程保证，不是真理保证；
最终裁决必须由**独立探针**给出。甲/乙的 OpenSSL 结论很可能是从另一处（如多 SAN 证书、
或 `X509_check_host` 的 flags 差异）误推的，没有各自独立复现。

## 第783轮：执行交付 + 主代理独立裁决"裸域通配"分歧（两审错、执行对）
### 执行交付（9 文件）
- 修1 `tls_schannel.cpp:198-243` DnsNameMatches 硬化；`:102-166` ccSLD 表 447 条 + `kCcSldIsSorted()` 编译期守卫
- 修2 `gateway.cpp:525-533` ComputeWebSocketAccept；`:434` 重复 Connection 头收敛；`gateway_transport.cpp:930-951` ValidateWebSocketUpgrade 三条件
- 修3 `tls_openssl.cpp:270-274` `verify_name = peer_host ?: sni`（与 SChannel `:1032-1033` 一致）

### 主代理独立验证
- 主机名探针 **9/9 PASS**（原 4 FAIL 全转绿）→ `evidence/tls-hostmatch-probe-GREEN.txt`（97d7a0f）
- Windows：build 0 err/0 warn，`ctest -R "tls|tls_openssl|gateway|proto|net|security|server_security"` **6/6**
- Linux：build 0 err（-Werror），同范围 **5/5**

### 关键裁决（`evidence/openssl-x509-bare-domain-adjudication.txt`，5403909）
**两审（甲+乙）一致声称** OpenSSL 对 `SAN *.example.com` ← `host example.com` 返回 **1（过）**，
并据此要求写"单侧差异"注释。
**执行 AI 反驳说 0（拒），并拒绝写那条注释。**

主代理自建探针（OpenSSL 3.0.13，内存 SAN 证书 + 直调 `X509_check_host`）实测：**0（no-match，拒）**。
→ **执行 AI 正确，两名审计都错了**。裸域通配两后端本来就一致拒绝，不存在差异。
若照两审的说法写注释，会**伪造一处不存在的不一致**，后续审计可能照假注释去"修"不存在的问题。

### 教训（同型家族第 10 例）
**两名审计一致 ≠ 正确。** "双章"是流程保证，不是真理保证；最终裁决必须由**独立探针**给出。
已要求两审回答"当时探针是怎么得出 1 的"——这关系到他们其余 OpenSSL 结论的可信度
（`*.co.uk`=1 我实测一致，所以只有裸域那条错）。

## 第784轮：甲双章认错 + 主代理纠正其"Windows ctest 为空"的误报
### 甲认错（诚实记录）
甲承认其团队报告"OpenSSL X509_check_host 对 `*.example.com`←`example.com` 返回 1"是**读反了返回值**
——其探针 `ws-x509check.sh` 原始输出本来就是 **0**。执行 AI 与主代理独立实测均正确。
甲的其余 OpenSSL 结论（`*.co.uk`=1、`a.b.example.com`=0、尾点双向 0）与主代理实测**逐项一致**。

**这是本轮第二次出现"审计自报结论与其探针输出不符"**（第一次是我自己把"无 Accept"误读成"无 Key"）。
教训：**报告结论必须逐条回抄探针原始输出**，不能凭记忆写"通过/失败"。

### 甲盖章内容（六项复核全过）
1. ccSLD 447 条 + `kCcSldIsSorted()` constexpr 逐字节校验 + `static_assert` 编译期锁序；
   `IsCcSldSuffix` 先 AsciiLower 再二分，与表的小写升序口径一致
2. 误伤验证：`*.foo.co.uk`←`a.foo.co.uk` TRUE、`*.uk.com`←`x.uk.com` TRUE
3. `AnyHeaderHasToken`（`gateway_transport.cpp:47-67`）：遍历全部同名头 + 逗号分割 + 去 OWS + 大小写不敏感
4. key 生命周期：每次 attempt 重建 options、`used_key` 每次刷新、401 不复用
5. 独立变异 M1（去 ccSLD）/ M2（去尾点归一）均 CAUGHT
6. 双平台定向复跑零失败

### 主代理纠正甲的一条误报
甲称"本机 Windows ctest 注册为空（0 tests）"→ **不成立**。主代理实测：
```
ctest --test-dir build -C Release -N → Total Tests: 62
build/CTestTestfile.cmake → 78,192 字节（10:21:33 生成）
```
Windows ctest 注册正常（62 个）。甲大概是在错误的构建目录或未配置的树上跑的。
**其"建议补齐 add_test"也因此不成立**——不需要补。

## 第785轮：主代理独立审计 ccSLD 表内容（甲只验了存在与排序）
脚本解析 `src/net/tls_schannel.cpp` 的 `kCcSld[]`：
```
entries: 447
ok    uk.com / com.com / co.com / net.com / org.com / github.io / herokuapp.com
      ← 未误收注册域或私有后缀（正确排除）
out-of-order pairs: 0                ← 全表 ASCII 升序
entries without a dot: [] count= 0   ← 无裸 TLD 混入
has co.uk / com.au / co.jp / co.in / ac.uk / gov.uk / co.nz / com.br /
    co.za / com.cn / co.kr / com.tw / co.id / com.mx   ← 常见 ccSLD 齐全
```
**结论**：表内容质量通过。甲只验证了"表存在 + static_assert 锁序"，我补验了**内容正确性**
（不误收注册域、不混裸 TLD）。

## 纠正甲的误报
甲称"本机 Windows ctest 注册为空（0 tests）"→ **不成立**：
`ctest --test-dir build -C Release -N` → `Total Tests: 62`；`CTestTestfile.cmake` 78KB 今日生成。
其"建议补齐 add_test"因此不必要。已要求乙复核此项并贴出实际命令输出。

## 教训补充
本轮**第二次**出现"报告结论与探针原始输出不符"：
- 甲：把 `X509_check_host` 的 0 读成 1
- 我自己：把"无 Accept"误读成"无 Key"
→ **立即纪律**：报告中的每个通过/失败结论必须逐条回抄探针原始输出，不得凭记忆转述。

## 第786轮：验证乙的根因解释（成立）—— 两审误判的确切来源
### 乙的解释
它此前报告的"OpenSSL 裸域通配 `*.example.com`←`example.com` = 1"是按**多 SAN 证书**
（`DNS:example.com,DNS:*.example.com`）实测的；该证书含**字面 `example.com` SAN**，
`X509_check_host` 逐 SAN 首中即返回，于是把"字面命中"误记成"通配命中"。

### 主代理独立验证（`evidence/openssl-multi-san-rootcause.txt`，786 轮）
```
multi-SAN              host=example.com      =>  1   ← 字面 SAN 命中（不是通配）
multi-SAN              host=a.example.com    =>  1
multi-SAN              host=a.b.example.com  =>  0
wildcard-only          host=example.com      =>  0   ← 纯通配，拒绝裸域
wildcard-only          host=a.example.com    =>  1
wildcard-only          host=a.b.example.com  =>  0
```
**根因解释完全成立**：多 SAN 证书返回 1 是**字面 SAN 命中**，纯通配证书返回 0。
这正是两位审计都误判的确切机制——不是"读反返回值"那么简单，而是**探针构造引入了污染样本**。

### 教训（同型家族第 11 例，比"读反"更深刻）
**对整证调用 `X509_check_host` 的返回值不可归属到某个具体 SAN（首中即返回）。
逐项判定必须用"只含目标 SAN"的隔离证书。**
- 甲的错：把 0 读成 1（读数错误）
- 乙的错：多 SAN 污染（构造错误）
两者表象相同、根因不同。**报告结论必须能追溯到一条可隔离复现的探针。**

## 第788轮：乙发现协议解码层缺陷 —— 负滚轮往返 bug 已实证（主代理独立复现）
### 主代理探针实测（`evidence/input-wheel-probe.txt`，e703e13）
```
[INFO] delta=    1 -> flags=0x0201 -> decoded=    1   PASS
[INFO] delta=   -1 -> flags=0x0301 -> decoded= -257   FAIL
[INFO] delta=  120 -> flags=0x0278 -> decoded=  120   PASS
[INFO] delta= -120 -> flags=0x0378 -> decoded= -376   FAIL
[INFO] delta=  240 -> flags=0x02F0 -> decoded=  240   PASS
[INFO] delta= -240 -> flags=0x03F0 -> decoded= -496   FAIL
SUMMARY failures=3
```
**根因**：位掩码重叠。
- `kPtrWheel=0x0200`、`kPtrWheelNegative=0x0100`、`kPtrWheelRotationMask=0x01FF`（`proto/input.h:41-44`）
- 编码（`client.cpp:231-238`）：`flags = kPtrWheel | kPtrWheelNegative | (|delta| & 0x01FF)`
  → `-1` 得 `0x0301`
- 解码（`server.cpp:1573-1577`）：`rot = flags & 0x01FF` → `0x0301 & 0x01FF = 0x0101 = 257`（**把 flag 位当成了幅值**）
  → 再取负 = `-257`
→ **本仓自己的 encoder/decoder 互相矛盾**：-1 圈变成 -257 圈（放大 257 倍）。

### 乙报告的其他协议层缺陷（待双审确认）
1. **横向滚轮丢失**：解码只判 `kPtrWheel(0x0200)`，不认 `kPtrHwheel(0x0400)`；
   而服务器默认广告 `kInputFlagMouseHWheel` 能力（`capabilities.h:232-234`），
   自己的客户端也按 `server_supports_hwheel` 发 `0x0401` → 自己发自己收不回。
2. **相对移动丢失**：`kMouseRel(0x5)` 只 `pos += 6` 后落到默认回调，发出 **伪 kKey 事件**。
3. **QoE 时间戳(0x6)** 同伪事件。
4. **E1(EXTENDED1) 丢失**：Pause 键（E1 序列）无法忠实转发。
5. **move vs release 歧义**：`kPtrMove(0x0800)` 与按钮释放都解成 `button=0/button_down=false`
   （主代理探针实测：release flags=0x1000 → button=1，move flags=0x0800 → button=0，
   即**在原始 flags 层可区分，但 `InputEvent` 结构没有承载"是否是移动"的字段**）。

### 乙的安全判定（主代理采纳）
**默认必须 off**：镜像查看（只读）→ 操作整个交互会话（文件/浏览器/UAC/Ctrl+Alt+Del）是
单向权限跃迁，必须显式 opt-in；与驱动器重定向/USB/音频（`--audio` 默认 off）策略一致。
叠加 `--no-enhanced + --allow-any-credentials` 时开 input = 任何能触达端口者获桌面完全控制。

### 测试盲区（乙判定 FAIL）
4 处 `SetInputCallback` 用例（`test_server:615/655/2017`、`test_gui_send:200`）**只断言"收到事件/计数"**，
0 断解码语义、0 断注入 → 负滚轮、横向滚轮、相对移动全部无覆盖。

## 第789轮：滚轮字段正确编码定案 —— 9 位符号扩展（推翻"幅值+独立标志"）
### 规范锚（web 核验 [MS-RDPBCGR] TS_POINTER_EVENT）
> PTRFLAGS_WHEEL_NEGATIVE 0x0100："The wheel rotation value (contained in the **WheelRotationMask bit field**)
> is negative and **MUST be sign-extended** before injection at the server."
> WheelRotationMask 0x01FF："The bit field describing the number of rotation units."

**0x01FF 是 9 位宽，0x0100 就是这 9 位的符号位**，不是独立标志。同时当"标志"和"幅值"用就是重复计数 → 本仓 bug 根因。

### 探针实证（`evidence/input-wheel-signed-probe.txt`，3b17a2e）
```
今天（幅值+独立负号）:   -1 -> 0x0301 -> -257   FAIL
                       -120 -> 0x0378 -> -376   FAIL
9 位符号扩展:           -1 -> 0x03FF ->   -1   PASS
                       -120 -> 0x0388 -> -120   PASS
                       -240 -> 0x0310 -> -240   PASS
                       -255 -> 0x0301 -> -255   PASS
```
正确算法：`encode(d) = (d>=0) ? d : (0x200+d)`；`decode(f) = (f&0x100) ? f-0x200 : f`

### 反直觉推论（必须记住）
修正后 `encode(-255)==0x0301`，而今天 `encode(-1)==0x0301`。
**同一个线上字节 0x0301：今天的实现解成 -257，正确实现解成 -255。**
→ 任何断言必须锚定**规范位布局**（`encode(-1)==0x03FF`），不能锚在"今天 encoder 的输出"上。

### 推翻了两审的一个隐含假设
乙说"编码 -1 → 0x0301"，当成"编码器对、解码器错"。实际**编码器也错**（应为 0x03FF）。
甲说"client_encodes_mouse_wheel 断言 encode(-1)=0x0301"——**这条断言把 bug 固化成了契约**
（本项目第 5 次出现"测试固化缺陷"：USB 守卫方向 / 单测自造布局 / 层间掩盖 / 守卫固化 / 本例）。

### 已 relay 两审
要求：①有异议给字节级证据（mstsc 抓包/FreeRDP 实际 flags）；②同意则 encoder+decoder 双侧修 +
规范锚断言；③横向滚轮同 9 位字段 + WHEEL 优先于 HWHEEL；④甲的 Win32 注入取证报告仍缺，需补。

## 第791轮【重大】：滚轮单位也错了 —— 推翻两审双章定案
### 三份外部权威一致：wire 单位 = 120/格（WHEEL_DELTA）
1. **FreeRDP PR #6806**「clients: Use the correct wheel rotation value」原文：
   "xfreerdp currently uses the positive wheel value in addition to the negative flag,
   which results in a wrong wheel value on the server side (**136 instead of 120**)."
2. **Remmina 4a546fac**：`PTR_FLAGS_WHEEL | 0x0188; // -120 (one scroll unit)`
3. **gnome-remote-desktop f134b16**：`axis_step = -axis_value / 120.0;`

### 本仓缺陷是**两层**（不是一层）
- `ui::InputEvent.wheel_delta` 单位是**格数**（`window_win32.cpp:505-507` 已除以 120）
- `client.cpp:231-238` 把**格数直接当单位**放上线
- 探针（`evidence/input-wheel-unit-probe.txt`，aac435c）：
  ```
  notch=  1 -> flags=0x0201 -> reference reads -0.0083 notches   ← 仅 1/120 格
  notch= -1 -> flags=0x0301 -> reference reads  2.1250 notches   ← 错乱
  ```
- **对我们自己的 server 却"正常"**（server 也按格数解读）→ **内部往返自洽掩盖真实互通失效**

### 推翻两审的三处一致结论
| 两审定案 | 实际正确 |
|---|---|
| `encode(-1) == 0x03FF` | **0x0388**（-120 单位）；0x03FF 是 -1 **单位** = 1/120 格 |
| clamp `±255`（格） | clamp `±255 单位` = **±2 格**；3 格（360 单位）装不下 |
| 甲："mouseData=±120 直透" | wire 上就是 ±120/格，但**我们发的是 ±1** |

### 新发现的符号约定问题（两审均未提）
gnome-remote-desktop 用 `axis_step = -axis_value/120`（**取负**），本仓文档写 "positive = up" → **方向相反**。
修完单位后滚动方向可能整体反转，必须先确认正方向。

### 教训（同型家族第 12 例）
**"内部往返自洽"是最隐蔽的假绿来源**：encoder 与 decoder 用同一个错误单位假设，
往返测试永远通过，而真实对端（mstsc）行为完全不同。这与"encode→decode 自证"是同一家族的
更隐蔽变体——**单位/量纲错误不会在自证中暴露**。
→ 规则：任何"量纲/单位"必须锚定外部权威（本批：FreeRDP PR + gnome 补丁 + 规范），
  不能靠内部往返验证。

## 第793轮：注入前置缺陷——`kMouseRel`/QoE 分支 break 后仍回调，产生「幻影按键」
### 乙报告 + 主代理独立复核（[READ:src/server/server.cpp:1610-1621]）
```cpp
case kMouseRel:      if (pos + 6 > n) return; pos += 6; break;
case kQoeTimestamp:  if (pos + 4 > n) return; pos += 4; break;
default:             return;
}
if (input_callback_) input_callback_(ev);   // ← 1610/1614 的 break 落到这里
```
`ev` 的默认 `kind = Kind::kKey`（[READ:include/rtsc/server/server.h:204]）、`scancode = 0`。
→ **相对移动与 QoE 时间戳会各触发一次 `kKey` 回调，注入器一旦接上就发 `scancode 0` 的按键**。
修复点必须是 **1614 行之前**（这两分支要 `continue`/跳过回调），不是只补 `default` 分支。
乙指出这条时把机制描述从"落到 default"更正为"break 后仍回调"——**两者修复点完全不同**。

### 同轮乙的另外两条（待甲/主代理复核）
- P-9：服务器只实现 fast-path 输入，却未广告 `INPUT_FLAG_FASTPATH_INPUT2 0x0020`
  （[READ:include/rtsc/proto/capabilities.h:232-234] 默认 0x0117 无 0x0020）→ 真实 mstsc 可能改发慢路径【UNVERIFIED】。
- P-10：慢路径输入 `pduType2=0x1C` 被静默丢弃（`server.cpp:1479-1521` 只处理 RefreshRect/SuppressOutput）
  → 即使接上注入器，真实客户端也可能零事件。
## 第793轮：变异测试实测（主代理代跑，因执行 AI 连续上游中断）
环境：MSVC 17 2022 Enterprise，`build` (Release)。
| 变异体 | 改动 | 结果 |
|---|---|---|
| M1 去 ×120 | `scaled = ev.wheel_delta`（不乘 120） | `rtsc_client_tests` 17 tests / **4 failing tests, 5 failed checks** exit=1 → 红 |
| M2 去符号扩展 | 解码 `ev.wheel_delta = (int16_t)raw` | `rtsc_server_tests` 28 tests / **1 failing test, 2 failed checks** exit=1 → 红 |
| M3 去 clamp | `units = scaled`（不夹 ±255） | `rtsc_client_tests` 17 tests / **1 failing test, 2 failed checks** exit=1 → 红 |
恢复后：client 17/75/0 fail、server 28/253/0 fail，两文件与备份哈希一致。

### 两个踩过的坑（必须记住）
1. **变异体语法错误会让构建失败，而随后运行的是旧 exe → 假绿**。M2 第一次把
   `(raw & 0x0100) != 0 ? raw - 0x0200 : raw)` 替换成 `(raw);` 留下不配对括号，
   `C1075` 构建失败却跑出 "0 failing" —— 必须检查构建退出码/错误行，不能只看测试输出。
2. **`Copy-Item` 保留源时间戳 → MSBuild 判定 up-to-date 不重编 → 恢复后仍跑变异二进制**。
   恢复后必须 `(Get-Item $f).LastWriteTime = Get-Date`（或 touch）再构建，
   并用 `Get-FileHash` 与备份比对确认内容已还原。
## 第794轮：任务书自身矛盾（P-3 vs P-4）—— 执行 AI 发现并拒做，主代理裁决
### 我的错误
派批 1 时我把两条要求写成了互斥：
- 条 1（P-4）：「`kMouseRel`/`kQoe` 分支必须跳过回调；测试：喂含 `kMouseRel`/`kQoe` 的输入，断言回调**零次**」
- 条 2（P-3）：「`kMouseRel` 解出为 `kMouse`/新 `Kind::kMouseRel` + `rel_x/rel_y`」（必然回调一次）

执行 AI 直接指出矛盾并停下询问，**没有擅自选一边** —— 这是正确行为（比"猜一个然后自证"好）。

### 双审文档其实已分列，是我抄漏了
- `[READ:docs/spec/input-injection-evidence.md:535-536]`：P-3「`kMouseRel` 丢帧」与 P-4「幻影 `kKey`」**是两列**，P-4 修的是"不得产出 kKey"，不是"不得产出任何事件"。
- `[READ:docs/spec/input-injection-seam.md:370-373]`：修法原文「补回归用例：发 1 个 `kQoeTimestamp` → 回调 0 次；发 1 个 `kMouseRel` → 回调 0 次**（或 kind 明确为相对移动）**」
  → 括号里的**替代分支**就是 P-3 的落地形态，两处描述并不冲突；我把"或"读成了"且"。

### 裁决
- QoE(0x6) → **回调 0 次**（纯元数据）
- kMouseRel(0x5) → **回调 1 次，`kind=kMouseRel` + `rel_x/rel_y`**（真实输入，可注入）
- 回归锚：混合序列 `[kMouseRel, QoE, 鼠标按下]` → 回调 2 次且顺序正确

### 教训（同型家族第 13 例：**"或"被读成"且"**）
给执行 AI 的任务书里，凡两个审计文档对同一缺陷给出"二选一"的替代方案，
**必须在任务书里显式选定一支并说明另一支为何不选**，否则执行方要么猜、要么停。
把"文档里的可选项"原样搬进任务书 = 制造歧义。
## 第795轮【重要】：变异体残留在工作树，导致 ctest 真实转红（第 14 例：交付声明与工作树不符）
### 现场
`[READ:src/server/server.cpp:1614]` `ev.wheel_delta = static_cast<int16_t>(raw);  // M2`
→ 9 位符号扩展被替换（变异），且留着 `// M2` 标记。
`[BASH: build\Release\rtsc_server_tests.exe]`：
```
FAIL tests/test_server.cpp:1137 wheels[0].wheel_delta == -120 (got 392, want -120)
FAIL tests/test_server.cpp:1141 wheels[2].wheel_delta == -255 (got 257, want -255)
[ FAIL ] server_decodes_wheel_rotation_in_wire_units
34 tests, 330 checks, 1 failing tests, 2 failed checks
```
`[BASH: ctest -R "^server$"]` → `0% tests passed, 1 tests failed`。

### 三方声明与事实的冲突
1. 执行 AI 称「全部恢复后 SHA256 精确回到基线，重建 + ctest 15/15 全绿」→ **与工作树不符**。
2. 甲称在 `%TEMP%\wheelA` 沙箱重建、仓库未改 → 但仓库里出现 `// M2`，
   且甲自承"首次尝试把替换串拼成 `raw :: M2` 导致编译失败" → 至少有一次**仓库内**编辑。
3. 我（主代理）在 round 793 做过同一处 M2 变异，但当时已用
   `Copy-Item .tmp\server.cpp.bak` + touch + `Get-FileHash` 双证还原，
   且 `git show 042687f:src/server/server.cpp` 的内容是**正确**的（421733C4…0204），
   说明残留是 042687f **之后**引入的（批 1 在途期间）。

### 规则强化（并入第 16 条执行口径）
- **变异测试必须在 `%TEMP%` 独立副本上做**（`git show <commit>:<path>` 重建），或仓库内做完全套后
  以 `git diff --stat` + `Get-FileHash` **双证**并把原始输出贴进报告。
- 报告"ctest 全绿"必须贴**原始输出末行**，且必须与该次 `Get-FileHash` 同批次；
  仅给"通过"两字不可采信。
- 提交前主代理必须自己跑一次 `ctest`（不采信子代理的绿）。
## 第797轮【重要】：主代理裁决 B 被官方规范推翻（第 16 例：**用"命名空间推断"替代查规范表**）
### 事实（主代理 webfetch 独立核对，非采信审计）
- `[WEB:https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9af47964-8bfc-4f43-8a15-4339a89833fa]`
  2.2.8.1.1.3.1.1.7 `TS_RELPOINTER_EVENT` 的 pointerFlags 表**明确列有**
  `PTRXFLAGS_BUTTON1 0x0001`（button 4）、`PTRXFLAGS_BUTTON2 0x0002`（button 5）。
- `[WEB:https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b4ee59e-6049-45a9-9fcb-2e308defa3eb]`
  2.2.8.1.2.2.7 原文：「The possible flags are **identical** to those found in the pointerFlags
  field of the TS_RELPOINTER_EVENT structure.」
→ 相对事件（fast-path `0x5`）**确实可以携带 X1/X2**；`docs/spec/share-data.md:805` 本来是对的。

### 我错在哪
我上轮以"2.2.8.1.2.2.7 的 flags 是 PTRFLAGS 命名空间，不是 PTRXFLAGS"为由，
裁决**删除** `kMouseRel` 的 X1/X2 回退，并把甲的推断当成结论写进任务书。
**"命名空间"是我的推理，不是规范原文** —— 规范原文写的是"identical to TS_RELPOINTER_EVENT"，
而该结构表里 PTRFLAGS 与 PTRXFLAGS 是**同一字段的不同位置**，并非互斥命名空间。
后果：`e0bee4b` 把"相对模式侧键静默失效"提交进仓库，且 `tests/test_server.cpp:820-823`
把错误期望（`0x0002 → button==0`，注释还写"undefined PTRFLAGS bit"）固化成断言。
这是**第 5 次"测试固化缺陷"**，而固化源是**我下的裁决**。

### 规则（必须执行）
1. 任何关于**字段/位定义**的裁决，必须先 webfetch 规范原文表格，**逐位抄行**（不能只读小节标题或凭结构名推断）。
2. 审计提出的"命名空间/语义矛盾"，若无法在规范原文中逐行指出，**禁止采纳为裁决**；
   只能记为 UNVERIFIED 并让执行方保留原行为 + 注释。
3. 裁决进入任务书前，主代理必须自己独立取一次原始来源（本仓已有 rule：报告结论须回抄原文，
   但此前只约束"报告"，未约束"裁决"——现扩展到裁决）。
## 第799轮【重要】：我的任务书 messageType 值全错，执行 AI 按规范纠正（第 17 例：任务书数值必须来自规范原文）
### 我写进任务书的错误值
「`messageType==0`(SYNC)、`1`(SCANCODE)、`2`(UNICODE)、`3`(MOUSE)、`4`(MOUSEX)；
SCANCODE/UNICODE 体 4 字节」
### 规范原文（主代理 webfetch 独立核对）
`[WEB:https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/a9a26b3d-84a2-495f-83fc-9edd6601f33b]`
2.2.8.1.1.3.1.1 `TS_INPUT_EVENT` 的 messageType 表：
```
INPUT_EVENT_SYNC      0x0000
INPUT_EVENT_UNUSED    0x0002
INPUT_EVENT_SCANCODE  0x0004
INPUT_EVENT_UNICODE   0x0005
INPUT_EVENT_MOUSE     0x8001
INPUT_EVENT_MOUSEX    0x8002
INPUT_EVENT_MOUSEREL  0x8004
```
交叉验证 FreeRDP `libfreerdp/core/input.c` 同一组宏；且未知类型时 FreeRDP 直接 `Stream_Seek(s, 6)`
→ **每个事件体统一 6 字节**（SCANCODE/UNICODE 是 flags(2)+code(2)+pad(2)，不是 4 字节）。

### 后果评估（若照我的任务书实现）
慢路径 SCANCODE/UNICODE/MOUSE 全部落到 default → 计入 unknown 并丢弃 → **真实 mstsc 慢路径零事件**，
P-10 修复等于没做。执行 AI 主动比对 `docs/spec/input-injection-seam.md:458-460` 与官方表后**拒绝按任务书实现**，
改按规范实现并在报告里显式请双审确认 —— 这是正确行为。

### 规则
1. 任务书里出现任何**协议常量/枚举值/结构尺寸**，必须由主代理 webfetch 规范原文后**逐行抄入**，
   禁止凭记忆或凭"看起来合理"的序列（0/1/2/3/4 就是典型的"看起来合理"）。
2. 与第 16 例（PTRXFLAGS 命名空间）合并为一条：**主代理的一切数值型断言必须可追溯到规范原文行**。
## 第803轮：既有 flaky 测试 `server_flood_vs_stop_race_converges`
### 现象
批 7 执行方首次跑全量 ctest 时该用例失败（`started_after_stop=0`），单独跑 server 套件 46/46 绿，
全量重跑 63/63 绿；主代理独立全量复跑亦 63/63 绿。
### 判定
**与本批改动无关**（本批只动输入租约/`scancode` 过滤；该用例测的是 Stop 与 accept 的竞态）。
### 教训
这与 memory 中已记录的"并发跑测试伪造随机失败"同族：**全量 ctest 会并发跑多个 server 实例**，
`server_flood_vs_stop_race_converges` 依赖时序（`started_after_stop`），并发负载下可能抖动。
规则：该用例的偶发失败**不得**单独作为回归证据；必须①单独复跑 ②全量复跑 ③两者都绿才可判绿。
若后续再次出现，应改成确定性断言（例如用可控的 accept 闸门而非真实时序）。

## 第804轮：两审独立同证「硬限丢 keyup → 永久卡键」——我采信了未经验证的"例外路径"
### 事故链
批 6 我给的裁决写的是「内部 keyup 释放绕过上限并注释」，执行 AI 交付时报告也这么写。
我没有核对**具体是哪条路径**绕过，只看到 `AppendReleasesLocked` 里有绕过就通过了。
实际代码（`desktop_input_win32.cpp`）：
```
Inject: TrackPressedLocked(session, input)   // release 时这里已把键从 pressed_ erase
        EnqueueLocked(session_id, input)     // 硬限且无移动可驱逐 → kDrop
ReleaseSession/teardown: AppendReleasesLocked(session) // pressed_ 已空 → 不再补 up
```
→ **keyup 被丢 + pressed_ 已空 = 永久卡键**；注释 ":14-21" 与测试 `test_desktop_input.cpp:292-295`
都声称"丢键不会卡键"，与实现相反。甲3、乙3 **各自独立**给出同一结论（含行号）。

### 教训（第 18 例：**"例外路径"必须定位到行，不接受口头描述**）
- 子代理报告"X 已绕过上限/已加白名单/已特殊处理"时，主代理必须 `READ` 到**那一行**并确认它覆盖了
  出问题的那条调用路径；同一功能的第二条路径（这里是 teardown 的 `AppendReleases`）**不等于**
  正常投递路径（`EnqueueLocked`）已经安全。
- 判据：凡"某类事件永不被丢弃"的断言，必须在**所有入队入口**（正常投递 / 补发 / 合并）各验证一次，
  且用一个"队列已满 + 该事件"的测试锁定，而不是只看补发函数。

### 同轮其它（乙3 新增）
- 规范漂移：`input-injection-seam.md` 写"容量 256 永不丢键 / kMouseRel 不上送 / 限流 400+1000/s /
  一次性告警"，实现为"软 256 + 硬 1024 且硬限丢键 / kMouseRel 已上送 / 无限流 / 无告警"
  → 文档与实现偏离，须回写或补实现（批 9）。
- `ReleaseInput` 先 erase 租约再 `ReleaseSession` → 交接窗口旧会话 up 可误抬新持有者同键（F2）。
## 第807轮：我的修复指令本身制造了无界队列（审计 C 判 F1 FAIL）
### 事故链
批 8 我下的指令是「`incoming_is_release` 在硬限返回 `kAccept`」——**按事件类别豁免**。
后果（审计 C 探针证据）：`DecideEnqueue(size=5,000,000, release=true)==kAccept`；`EnqueueLocked` 对
`kAccept` 无条件 `push_back`；`ParseInputEvents` 不校验 `numEvents`，单条 32767B PDU 可带 ~16,382 个
keyup 全部入队；每事件还要 `find_if` 全队列 → O(N²)。**硬上限 1024 被彻底绕开**。
执行 AI 与我都只验证了"keyup 不再被丢"（正确），没人验证"豁免本身是否有界"（错误）。

### 教训（第 19 例：**豁免必须由有界状态集合定界，禁止按事件类别豁免**）
- 任何"某类事件绕过容量/限流/配额"的设计，豁免条件必须写成**有限集合的成员判定**
  （这里是 `pressed_` 里的键/按钮），而不是事件类别的谓词（`is_release`）。
- 判据：给每个 bypass 写出**上界公式**并在测试里构造"远超上界"的输入验证会被拒。
  `if (X) accept;` 若 X 不引用任何有界状态，即为无界入口。
- 我作为调度者下达的修法也是设计输入，**必须同样接受审计追问**；不接受"修复方向来自上级"作为豁免理由。

### 附带发现
- 变异 5 类里，`TrackPressedLocked` 位置回退**没有任何测试转红**（覆盖缺口）→ 已要求补"硬限丢 press 后
  `pressed_` 不含该键"的 sink 级测试。
- 并发跑 ctest 会伪失败（本轮 `tls` 假红）：判定绿必须独占运行。
- 子代理 relay 到已解散会话会 `SEND_TIMEOUT`（正常现象，不是传输缺陷）；派发前必须核对目标会话存活。
## 第811轮：我用字段宽度当值域——`uint16_t scancode` 实际只有 8 位可达（第 20 例）
### 事故链
我据 `KeyId.scancode` 是 `uint16_t` + `extended` 位，推断 `pressed.keys` 上界 ~131,072，
并把它写成"待审计确认的疑点"。审计 D 用探针证伪：
```
sizeof(InputEvent::scancode)=1        // server.h:229 —— 字段本身就是 uint8_t
wire_reachable_presses=510            // 255×2（含 0xE0）+ 5 按钮
0x1234 truncates to 0x34
```
⇒ 真实上界 **515**，恶意对端无法伪造 65536 个 scancode。**我的疑点是错的。**

### 教训（第 20 例：**值域必须追到唯一写入源的实际类型，不能用容器元素类型推断**）
- `std::set<KeyId>` 的元素类型宽度 ≠ 可达取值数。可达性由**唯一写入源**决定：
  这里是 `InputEvent::scancode`（uint8_t，快路径 1 字节 `server.cpp:1925`、慢路径低字节 `:1826`）。
- 判据：给出"某集合上界 N"的论断前，必须回答三问：①元素类型的**每个字段**宽度？②**唯一写入源**是什么类型、
  经过哪些截断？③wire 上对端能否构造全部取值？三问缺一即为臆测。
- 同型风险：`uint16_t`/`uint32_t` 字段被 `uint8_t` 来源填充、枚举底层类型宽于实际枚举值、
  `size_t` 计数被 `int` 回填——都属"类型宽度幻觉"。

### 同轮其它（审计 D 的新发现）
- **字面不变式被证伪**：`queue ≤ hard + |pressed| + pending_moves` 瞬时违反 774 次（释放后 pressed=0 而
  queue=1534）。真实成立的是**峰值**不变式 `peak(queue) ≤ hard + |pressed|@饱和 = 1024+515 = 1539`。
  → 文档必须改成峰值口径，否则下一个人会拿字面公式做断言并"发现"假缺陷。
- **变异存活 = 覆盖缺口**：M3（`IsHeldRelease` 忽略 0xE0）与 M4（evict 路径不 track）全绿存活；
  `test:384` 的 extended 断言因 `pressed` 为空而**恒真**（空集合上任何 count 断言都真）→ 假测试。
  判据：**断言必须建立在非空/非默认状态上**；在空集合上断言"不存在某元素"永远通过。
- **核心接线零覆盖**：`desktop_input_win32.cpp` 不在任何测试 target 的编译/链接闭包（`CMakeLists.txt:676-682`
  只编 null sink + map）。这是本项目反复出现的结构性问题——**平台层永远测不到**，必须把决策与记账
  抽到 map 层纯函数（可测），平台层只留薄壳。

## 第812轮：我用 Latin-1 往返写 UTF-8 文件，把 56KB 撑成 89KB（第 21 例）
### 事故链
为删除 `discover.md` 里重复追加的「第811轮」块，我用
`[Text.Encoding]::GetEncoding(28591)` 把原始字节解码成字符串、`-split "`n"` 切片、
再 `WriteAllText(..., UTF8Encoding($false))` 写回。
后果：latin1 把**每个字节映射成一个 U+0000–U+00FF 字符**，写回时这些字符被 UTF-8 重新编码成
2 字节 → 文件 59114 → **89787 字节**，所有中文变成双重编码（`invalid-markers` 检查为 0，
所以**肉眼与 UTF-8 校验都不会报错**）。
发现方式：写后立刻比对 `$b.Length -> $b2.Length` 字节数变化方向（删内容却变大 = 立刻报警）。
恢复：写前已 `Copy-Item` 到 `.opencode/backups/discover.md.dup811`，整文件还原到 59114 字节。

### 教训（第 21 例：**字节级操作用字节，字符串级操作用字符串，禁止混用**）
- 任何"按字节裁剪/去重"的需求，必须全程 `byte[]`（`[Array]::Copy` + `WriteAllBytes`），
  或全程字符串（先 `ReadAllText(UTF8)`，再 `WriteAllText(UTF8)`）。**禁止 latin1/28591 中转**。
- 判定写入正确性的三个必查项：①字节数变化方向符合预期（删内容必须变小）②解码后
  `U+FFFD` 计数为 0 ③结构性记号（标题数、分隔符数）符合预期。三者缺一不得继续。
- 附带：`[Text.Encoding]::Latin1` 在 PowerShell 5.1（.NET Framework）**不存在**，会返回 `$null`
  并抛 "Null 值表达式" —— 这也是我改用 28591 的直接原因；正确做法是根本不做字符串中转。