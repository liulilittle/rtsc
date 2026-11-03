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


## 【归档压缩：773-807 轮教训（原 528 行）】

- **773** 独立双平台验证抓 2 个跨层短板缺陷（提交 `9791fc4`）。
- **775** 判定 drain 泄漏为 P0 并修复（推翻契约 P2 判断）。
- **779** 双审计收口（审计者 + Accept），形成可执行规范与取证清单。
- **783** 规范化的"数据通道"判定被推翻：以文档原文 + 执行 AI 确认才生效。
- **784** 双审计上传；确立"Windows ctest 为准"的验证口径。
- **785** 反编译 ccSLD 常量，仅采纳可验证的代码路径。
- **786** 验证码归属链路缺失 → 定位到确认来源。
- **788** 协议层缺陷：bug 以实证复现驱动，不靠阅读推断。
- **789** 字段宽度误判 → 9 位扩展标志推翻"阈值+范围日志"假设。
- **791** 关键：字段位宽也不能凭推断 → 推翻审计双方判断。
- **793** 注入前缺陷：`kMouseRel`/QoE 支路 break 导致回退污染（实测复现）。
- **794** 审查意见互相矛盾（P-3 vs P-4）→ 执行 AI 以可执行仲裁。
- **795** 重要：C++ 层看似无问题的 ctest 场景实测转红（第 14 例）→ 测试须跑真实路径。
- **797** 重要：B 方案被官方规范推翻（第 16 例）→ 禁止"经验空间推测"替代规范。
- **799** 重要：messageType 值全部按执行 AI 规范重写（第 17 例）→ 禁止凭数值惯例。
- **803** 修复 flaky 测试 `server_flood_vs_stop_race_converges`。
- **804** 双审计共同证明硬限 keyup 缺陷 → 判"可复现"须有未经过滤的实际路径。
- **807** 我的修复指令本身有误 → 审计 C 判 F1 FAIL（后续第 20-22 例）。
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

## 【归档压缩：811-837 轮教训（原 149 行）】

- **811** `uint16_t scancode` 实际只有 8 位可达 → 值域必须由类型决定，不能凭直觉设上限（第 20 例延伸）。
- **812** 用 Latin-1 中转写 UTF-8 文件把 56KB 撑成 89KB → 字节级写入必须 `byte[]`+`WriteAllBytes`（第 21 例）。
- **819** 只看单个字段的"异常路径泄漏契约"结论不成立 → 必须扫描全部同型点（第 22 例）。
- **823** 修好一处后必须排查同型 3 处 → 一次只扫一处即漏（第 23 例）。
- **829** 修好一个点的 P-6 只覆盖 0xE1 一类事件，NumLock 旁路仍在 → 必须枚举全部类别（第 24 例）。
- **837** 判"正确性"必须判"真实注入 teardown 路径"，不是"看起来对称"（第 25 例）。
### 事实（审计 L 实证，我用行号复核）
我在批 19 给 `RdpServer::Stop()` 加了三处 `try/catch`。后果：
- **① 静默跳过 → 永久挂起**：`sessions = registry->sessions` 抛异常被吞 ⇒ `sessions` 为空 ⇒ 一次 `s->Stop()` 都不发。
  而 `RdpSession::Stop()` 才是置 `stop_requested_` 的唯一入口（`server.cpp:756-759`），`listener->Close()` 不影响已 accept 的 transport
  ⇒ 会话线程永不退出 ⇒ `live` 永不为 0 ⇒ `cv.wait` **永久挂死**（实测 20s 不返回）。
  我写的注释"each one notices the closed transport and tears itself down"**是错的**——`transport_->Close()` 从未被调用。
- **② 静默返回 → UAF 前提**：`cv.wait` 抛异常被吞 ⇒ `Stop()` 立即返回（实测 `live=1`），
  而 `server.h` 明确契约"借用指针 must outlive the server (including Stop())" ⇒ 宿主销毁对象 ⇒ 会话线程访问已释放对象。
  我写的注释"Teardown is already done at this point"**也是错的**。

### 教训（第 26 例：**`catch(...)` 不是"安全"，它把失败转移给调用者的假设**）
- 两条铁律：
  - **I1 不得静默成功**：catch 之后如果"没做到本该做到的事"，必须留下可诊断输出（计数/告警），禁止空 catch 收尾。
  - **I2 不得把"未完成"当"完成"**：对"必须等某状态达成"的等待，**超时/异常不得转化为返回**；
    要么继续等（并周期告警），要么返回明确的失败让调用者处理。**吞掉后 return 是最坏选项**。
- 判断方法：对每个 `catch(...){}` 问"吞掉之后，**外面的人**会基于什么假设继续？"——如果那个假设可能不成立，
  这个 catch 就是一个待爆的雷。
- 反模式清单（本仓已出现）：空 catch 包分配、空 catch 包等待、空 catch 包外部回调、"标志已置位 + 清理跳过"。
- 附带：**注释里的"安全论证"必须能被代码证伪**。我这两处注释都写了"这样做是安全的，因为…"，
  而"因为"部分（传输关闭会让会话自行退出、teardown 已完成）在代码里都不成立。
  **写"因为"之前必须去代码里找到那一行**；找不到就不许写。
## 第846轮：我用"两个实现互比"当误差度量，得到 99.77% 的假数字（第 27 例）
### 事故链
复算几何公式时我先跑了：
```
landA = dec(enc_old(x));  landB = dec(enc_new(x));  count(landA != landB) / total
→ 99.77%
```
我差点把它当成"现实现偏差 99.77%"。这是**错的度量**：它衡量的是**两个实现彼此的差异**，
不是任一实现相对**真值**的误差。正确的 oracle 是端点锚定意图
`truth = round(x*(cw-1)/(fbw-1))`，用 `|land - truth|` 统计：
```
现实现 mean=0.332px max=1px；新公式 mean=0 max=0
```
⇒ 现实现只偏 ≤1px，与审计 M 的"max 1 px、49.18% 偏 1px"量级一致；99.77% 是伪数字。

### 教训（第 27 例：**误差必须对真值/预言机测量，禁止两个实现互比**）
- 判据：任何"偏差/失配/错了多少"的统计，必须先写清 **oracle 是什么**（规范原文 / 独立参考实现 /
  数学定义 / 真机抓包），再比较。`A vs B` 只能回答"两者是否一致"，不能回答"谁对、错多少"。
- 同型风险：新旧实现 A/B 对比、往返自洽（encode→decode 用同一错误单位）、
  "改前改后输出不同"当作"改后正确"的证据。
- 附带：`dec(ceil(x*65536/w))` 与 `dec(round(x*65535/(w-1)))` 在全像素上大量不同的**原因**是
  分母语义不同，这与"哪个更接近真值"是两个独立问题——先定 oracle 再谈差异。
## 第848轮：我上一轮的几何 oracle 是错的（下采样路径），第 28 例
### 事实
我第 846 轮用 `truth = round(x*(cw-1)/(fbw-1))`（端点锚定）当 oracle，判定"新公式 mean=0/max=0，现实现 max=1px"。
**该 oracle 只对阵上采样（1600→1920）恰好成立，对下采样彻底错误。**
### 我的独立 GDI 实测（[BASH: gdi_probe.ps1，DIB→DIB，SetStretchBltMode(COLORONCOLOR)=3]）
```
src=2560 dst=1280  center=0/1280   endpoint=640/1280  leftedge=1280/1280
src=3200 dst=1280  center=0/1280   endpoint=428/1280  leftedge=1280/1280
src=1920 dst=1280  center=0/1280   endpoint=0/1280    leftedge=640/1280
src=1280 dst=2560  center=0/2560   endpoint=0/2560    leftedge=0/2560
src=1920 dst=1920  center=0         endpoint=0         leftedge=0
```
⇒ **`StretchBlt(COLORONCOLOR)` 的取值是中心采样 `floor(((2x+1)*cap)/(2*fb))`，7/7 全零失配**；
端点锚定在 2560→1280 上错 640/1280（50%），在 3200→1280 上错 428/1280。
### 教训（第 28 例：**oracle 必须与被测路径的算法同族，禁止跨采样方向类推**）
- 上采样/下采样/1:1 是三个不同算法域；在其中一个域拟合出的公式不能作为另一个域的预言机。
- 判定"实现偏差多少"之前，必须先问：**这条路径实际执行的是什么算法**（本例：GDI 缩放模式）。
  查代码 → `desktop_gdi.cpp:205-206` 确认走 `SetStretchBltMode(COLORONCOLOR)` + `StretchBlt`。
- 同型风险：把"规格/直觉上的理想映射"当 oracle，而不去实测真实执行体。
- **连带修正**：第 846 轮"M 的公式 mean=0/max=0"这一结论作废——那是用错 oracle 得到的"0 偏差对错误预言机"。

## 第849轮：本环境 SendInput 无法注入（新环境限制）
### 事实
`SendInput(MOVE|ABSOLUTE|VIRTUALDESK)` 返回 **1**（成功），但 `GetCursorPos` 读数**完全不变**（2366,783 恒定）：
```
n=0 sent=1 pos=2366 | n=16384 sent=1 pos=2366 | n=32768 sent=1 pos=2366 | n=65535 sent=1 pos=2366
```
- 首次尝试 `err=87`（ERROR_INVALID_PARAMETER）是我自己的 bug：`INPUT` 结构多了 `long pad`，sizeof=48（应为 40）。修正后 err=0 但位置不动。
- `OpenInputDesktop` 返回非 0（桌面句柄可取）。
- 结论：**该会话无法用 SendInput 驱动光标**（非交互桌面 / 会话隔离子系统 / UIPI 静默丢弃）。
### 影响
- 审计 N 的"真机确证 `phys = origin + floor(n*extent/65536)`（x 4179 点/y 685 点全 0 失配）"我**无法复现**，标注 **UNVERIFIED（我侧）**，只能采信 N 的原始输出。
- 因此 U1/U2 的关闭**仅有 N 单方证据**，不构成我方已确认。
- 真机验收文档必须写明：**自动化环境很可能无法验证注入类断言**，必须由用户在有真实交互桌面时执行。
## 第850轮：转述他人的"会打断既有测试"也必须自己跑一遍（第 29 例）
### 事故
审计 N 主张"纯 ceil 会打断 `tests/test_desktop_input.cpp:272-279` 的既有绿钉子"，
并据此要求采用混合式。我若直接采信，就会把"避免改断言"写进定案理由——**而这是错的**。
### 实测
该用例是 `ev.x=1920`、几何 `1920x1080`，即 `value == extent`（超出末像素）。
现行 `NormalizeAxis` 第一行就是夹取 `if (value >= extent-1) return 65535`
（`src/server/desktop_input_map.cpp:25`），所以：
```
pureceil : v=1920 w=1920 -> n=65535   (test expects 65535) ✅
hybrid   : v=1920 w=1920 -> n=65535   ✅
old      : v=1920 w=1920 -> n=65535   ✅
```
三种编码方案对该用例**都通过**。混合式真正的价值是"末像素 wire 值回到 65535（对齐文档端点语义）"，
不是"避免改动断言"。
### 教训（第 29 例：**别人的"会破坏 X"结论，必须自己复现破坏路径**）
- 转述类论断（"这样改会打断某个测试/某个调用方"）属于**可执行预言**，必须亲自跑；
  不能因为对方给了其他正确结论就整包采信。
- 复现时必须读到**前置分支**：本例的夹取在函数第一行，只看用例数据会误判。
- 若复现不成立，要在文档里**明确纠正**（本仓库 `docs/spec/input-geometry-probe-evidence.md` §5），
  否则错误理由会被后续实现继承，变成"因为怕改断言所以选了个复杂方案"的技术债。
- 同型风险：审计之间的互相转述、对上游库行为的断言、"这行删了会崩"。
## 第851轮：子代理"报告说改了"≠"文件真的改了"（第 30 例）
### 事故
审计 M 报告"§8 U1/U2/U3 由 UNVERIFIED 改'已确证'"，但实测：
```
[BASH: Select-String docs/spec/input-geometry-design-M.md -Pattern '已确证'] → 0 处
:547/:548/:549 仍是原始 UNVERIFIED 三行
```
同时 §3.3「不加 DPI 字段」与 §4.1 新增的 `pixels_are_physical` 自相矛盾，
§6.1 同时存在 49.18% 与 50.23% 两个数字。
### 教训（第 30 例：**验收子代理必须 grep 产物，不能读报告**）
- 子代理的"已完成/已修改"是**声明**，不是证据；必须对产物做可复现检查
  （grep 关键串、行号、数字一致性、编译/测试）。
- 尤其"我把 X 改成了 Y"这类**状态变更声明**，必须验证 Y 真的存在且 X 真的消失。
- 同型风险：子代理说"测试通过"但没跑；说"已提交"但没 commit；说"已删除"但文件还在。
- 附带：文档内部一致性也要查（同一数字两处不同、章节标题与正文相反），
  这类矛盾会直接误导执行 AI。
## 第854轮：`pixels_are_physical` 用虚拟桌面宽比对 DESKTOPHORZRES —— 多显示器下必然 false（第 31 例）
### 缺陷
`src/server/desktop_gdi.cpp:321-324`：
```cpp
const bool pixels_are_physical =
    dpi_ok && physical_w > 0 && physical_h > 0 &&
    desktop.right - desktop.left == physical_w &&      // desktop = SM_*VIRTUALSCREEN 包围盒
    desktop.bottom - desktop.top == physical_h;
```
`physical_w/h` 来自 `GetDeviceCaps(probe, DESKTOPHORZRES/DESKTOPVERTRES)`，`probe` 是
`CreateDC("DISPLAY")` 的**桌面 DC**。
### 权威依据（[WEB: learn.microsoft.com GetDeviceCaps]）
> "On a multiple monitor system, if hdc is the desktop, GetDeviceCaps returns the capabilities
> of the **primary monitor**."
> "The following display capabilities are the same for all monitors: LOGPIXELSX, LOGPIXELSY,
> **DESTOPHORZRES, DESKTOPVERTRES**."

⇒ `DESKTOPHORZRES` = **主显示器**物理宽，不是虚拟桌面宽。
### 后果（High）
多显示器时 `SM_CXVIRTUALSCREEN`（如 3200）≠ `DESKTOPHORZRES`（如 1920）
⇒ `pixels_are_physical=false` ⇒ `AbsoluteMoveMappable` 恒 false ⇒ **所有绝对移动被丢弃**。
而 `--monitor N` 恰恰只在多显示器下有意义 ⇒ **本批要修的功能在多显示器上完全不可用**。
单显示器（本机 2560x1440）两者相等，所以测试全绿、缺陷不可见。
### 正确判据
比较**主显示器**的两种口径，而不是虚拟桌面：
```cpp
pixels_are_physical = dpi_ok &&
    GetSystemMetrics(SM_CXSCREEN) == physical_w &&
    GetSystemMetrics(SM_CYSCREEN) == physical_h;
```
`SM_CXSCREEN` 是主显示器在当前进程 DPI 语境下的宽；`DESKTOPHORZRES` 是主显示器物理宽。
两者相等 ⇔ 进程报告的是物理像素。单屏/多屏都成立。
### 教训（第 31 例：**跨屏功能必须在多屏语义下验证判据，单屏全绿是假绿**）
- 任何"环境能力探测"（DPI/物理像素/虚拟桌面）都要问：**这个 API 在多显示器下返回什么**？
  查官方文档的 "multiple monitor" 段落，不要用单屏实测外推。
- 测试若把错误判据写成断言（`pixels_are_physical == (SM_*VS == DESKTOPHORZRES)`），
  测试会**保护缺陷**而不是发现它。断言必须来自权威语义，不是来自实现。
- 同型风险：`SM_CXSCREEN` vs `SM_CXVIRTUALSCREEN`、`HORZRES` vs `DESKTOPHORZRES`、
  `GetMonitorInfo` vs `GetSystemMetrics` 混用。
## 第855轮：结构守卫测试会"读源码文件"，变异时若不同步改副本源码会假红/假绿（第 32 例）
### 现象
执行 AI 的变异 exe `gdi_mut.exe` 现在跑出 `0 failing`，与报告的"1 failing"矛盾。
原因：新增测试 `desktop_gdi_geometry_uses_primary_screen_metrics` 在**运行时读**
`RTSC_SOURCE_DIR/src/server/desktop_gdi.cpp` 的文本并 grep `SM_CXSCREEN`。
- 变异编译时把调用点改成 `SM_CXVIRTUALSCREEN` → 该 exe 当时读到变异源码 → 红（报告正确）
- 之后副本源码被恢复 → **同一个 exe 再跑就读到恢复后的源码 → 绿**
⇒ exe 的结论依赖**外部文件当前内容**，不是编译期快照。
### 主代理独立复现（重做变异，不信任旧 exe）
```
mutated src/server/desktop_gdi.cpp (SM_CXSCREEN -> SM_CXVIRTUALSCREEN)
build exit=0
FAIL :310 :311 :312 :313  -> 1 failing tests, 4 failed checks, EXIT=1   ✅ 红
restore + touch, hash_same=True
build -> 10 tests, 57 checks, 0 failing, EXIT=0                          ✅ 绿
```
### 教训（第 32 例：**运行时读外部文件的测试，其红/绿取决于该文件当前内容**）
- 这类"源头守卫"测试有效，但**不能靠复跑旧 exe 来验证变异**：必须"改源码 → 重编 → 跑 → 恢复 → 重编 → 跑"。
- 变异证据必须记录**当时**的源码状态（hash 或 diff），否则事后无法分辨是"变异未生效"还是"源码已被恢复"。
- 更稳的替代：把判据抽成纯函数（本批已做 `PixelsArePhysical`）用纯函数单测覆盖语义，
  结构守卫只作为"调用点传参正确"的补充，不承担语义断言。
- 同型风险：任何 `RTSC_SOURCE_DIR` 源扫描测试（本仓库已有多处），
  以及读配置/环境/文件系统状态的测试。
## 第858轮：把"全部历史目录"当审计产物目录 —— 输出 3000+ 行噪声（第 33 例）
### 事故
为查审计 Q 的产物，我跑了：
```powershell
Get-ChildItem "$env:TEMP\opencode\auditQ" -Recurse -File | Select-Object Name,Length,LastWriteTime
```
`$env:TEMP\opencode` 下有**几十个历史批次目录**（Laudit 262MB、mutJ* 多个 85MB、geom_green...），
`-Recurse` 加上 `Select-Object` 未限列宽，输出被截断到 3000+ 行，实际有效信息 0。
### 教训（第 33 例：**目录探针必须先限定范围与列，再输出**）
- `Get-ChildItem -Recurse` 在共享临时根上必然爆量；正确做法：
  `Get-ChildItem <具体子目录> -File | Where-Object LastWriteTime -gt (Get-Date).AddHours(-1) | Select-Object Name,Length`
- 任何"看看有什么"的探查，必须带：**具体子目录 + 时间窗 + 列白名单 + 条数上限**。
- 与既有第 24 例（工具证据口径窄）/第 25 例（集合运算）同源：先定口径，再输出。
- 附带：这类噪声会挤占上下文，比"没查到"代价更高。
## 第859轮：我的"结构守卫"测试是假测试——文本匹配测试的三重失效（第 34 例）
### 事故（我自己写的测试，批22 引入）
`tests/test_desktop_gdi.cpp:295-317` 为验证"调用点传的是 SM_CXSCREEN 而非 SM_CXVIRTUALSCREEN"，
用 `src.find("PixelsArePhysical(dpi_ok")` 取**首个**匹配、再取**首个** `);`，然后 grep 实参文本。
### 主代理实测的三种失效
| 场景 | 期望 | 实测 |
|---|---|---|
| 正确调用**上方**加注释 `// PixelsArePhysical(dpi_ok, Metric(SM_CXSCREEN), Metric(SM_CYSCREEN), ...)`，真实调用改回 `SM_CX*VIRTUALSCREEN` | 红 | **绿**（`10 tests, 57 checks, 0 failing`，EXIT=0）|
| 正确代码 + 注释 `// old: PixelsArePhysical(dpi_ok, Metric(SM_CXVIRTUALSCREEN), ...)` | 绿 | **红**（4 failed checks，EXIT=1）|
| 实参 x/y 互换 | 红 | **绿**（只查存在性，不查顺序）|
### 教训（第 34 例：**禁止用"读源码文本"验证行为；必须走行为 seam**）
- 文本匹配测试的三种必然失效：**假绿**（注释/字符串伪装）、**假红**（注释含被禁词）、
  **不查顺序/结构**（存在性 ≠ 语义）。
- 根因：它验证的是"源码里出现过某串"，而需求是"调用时传对了参数"——**被测物选错了**。
- 正确做法：把决策抽成**可注入的 seam**（如 metric provider、纯函数 + 依赖注入），
  测试驱动 seam 的输入/输出；或把校验放在类型系统里（强类型 struct 而非裸 int 参数）。
- 同型风险：`RTSC_SOURCE_DIR` 源扫描测试（本仓库已有多处）、grep 注释判断"是否实现"、
  用日志文本断言行为。
- 附带：这正是我在批22 自己违反第 16 条（"改坏仍全绿即假测试"）的产物——**测试必须能被变异打死**，
  而该守卫在关键变异下依然绿，说明它从未真正守护任何东西。
## 第862轮：我修了"假绿"却没修"假绿的成因模式"（第 35 例）
### 事故
我（批23）按第 34 例把 `test_desktop_gdi.cpp` 的读源码守卫换成了行为 seam，
并在验收时做了变异"seam 内 SM_CXSCREEN→VIRTUALSCREEN"→ 转红，就判定 H1 通过。
但审计 R 指出且我实测确认：**工厂 `desktop_gdi.cpp:382-383` 换成 VIRTUALSCREEN 仍然 0 failing**。
```
把 PixelsArePhysicalFromMetrics(dpi_ok, metrics)
改成 PixelsArePhysical(dpi_ok, metrics.SystemMetric(SM_CXVIRTUALSCREEN), ...)
→ 10 tests, 57 checks, 0 failing tests, 0 failed checks, EXIT=0
```
即：seam 的**单元**被测死，但 seam 与**装配点**之间的连线没有。
### 教训（第 35 例：**修一个假测试时，必须同时验证"装配点"也被覆盖**）
- 抽 seam（依赖注入）容易让人以为"行为可测了"，但 seam 只在**被装配进生产路径**时才有意义。
- 判据：新 seam 的测试必须至少有一条**经过生产入口**（工厂/构造函数）而非直接调 seam 函数。
- 验证方法：变异必须打在**装配点**（工厂里选哪个 metric），而不只是打在 seam 内部。
- 同型风险：抽了纯函数但调用点仍可写成别的；抽了接口但实现没被注入；
  日志构造抽成函数但宿主没调用它（本次 R3 就是这个）。
- **元教训**：我上一轮修假测试时，只检查了"原来那条假测试没了"+"新测试能红"，
  没有检查"新测试是否覆盖了导致原缺陷的那条真实路径"。**修复必须对着缺陷的成因验证，不是对着修复的形式验证。**
## 第864轮：恢复变异体时"拷贝旧备份"把二进制留在变异态 → 下一次变异证据被污染（例 36）

### 症状
变异 C（改 `FormatInputStats` 的 `input_dropped_unmapped` 键名）只应让
`desktop_input` 与 `host_cli_stats_line` 转红，实测却连
`host_cli_refuse_no_enhanced` / `host_cli_refuse_any_credentials` 也红了。

### 根因
我用 `Copy-Item` 从 `.opencode\backups\...main.cpp` 恢复，但**没有更新 mtime**。
`Copy-Item` 会把目标文件的 LastWriteTime 设成源文件（备份）的时间，该时间**早于**
上一步变异 B 编出的 `rtsc_server_host.exe`/`.obj`，于是 MSBuild 认为 main.cpp
"未修改"，**不重编**，host 仍是变异 B（`return 0`）的二进制 → 拒绝用例继续红。

### 证据
`[BASH: Copy-Item 备份 -> main.cpp 后直接 cmake --build]` 输出里**没有** `main.cpp`
编译行；`[BASH: touch main.cpp + desktop_input_stats.cpp 后重编]` 才出现
`desktop_input_stats.cpp` / `main.cpp` 两行，再跑同一变异 → 只剩预期的 2 个红。

### 教训（例 36）
- **恢复必须 `touch`**：`Copy-Item`/`Get-Content|Set-Content` 都可能带来旧 mtime，
  恢复后必须显式 `(Get-Item $f).LastWriteTime=Get-Date`，再确认构建日志里**出现了该文件**，
  否则"恢复"只恢复了源码、没恢复二进制。
- **变异证据必须看构建日志里有没有重编该 TU**，不能只看退出码：
  `BUILD_EXIT=0` 在"什么都没编"时同样成立，这正是假绿/假红的来源。
- 判据升级：每个变异必须同时记录"被改文件出现在编译输出中"+"目标用例红的名单"；
  恢复后必须记录"hash 相同 + 该文件重编 + 全量绿"。
## 第866轮：装配函数"半注入"——度量来源分叉，变异全绿（例 37）

### 症状
`AssembleGdiDesktopSource(bool dpi_ok, const MetricSource& metrics, ...)` 收下了 `metrics`，
但只有 `PixelsArePhysicalFromMetrics` 用它；desktop 快照与 `ResolveCaptureRect`（捕获矩形
解析 + 裁剪）仍走全局 `Metric()` = `::GetSystemMetrics`。
把 `desktop.right` 从 `SM_CXVIRTUALSCREEN` 改成 `SM_CXSCREEN` → **gdi 全绿**；
把生产工厂的 `dpi_ok` 改成字面量 `true` → **gdi 全绿**。

### 根因
seam（注入点）只覆盖了它自己那一条支路，装配函数里**另一条支路**仍读全局状态。
测试用的 fake 无法影响全局 `::GetSystemMetrics`，于是那条支路在单屏机器上永远等于真值，
任何错误都被真值掩盖。这不是"测试写得不够狠"，而是**注入粒度与装配范围不匹配**。

### 证据
`[BASH: 独立 cl 编译 test_desktop_gdi.cpp+desktop_gdi.cpp+crash_guard.cpp]`
- 基线 `11 tests, 60 checks, 0 failing`
- `desktop.right = ... Metric(SM_CXSCREEN)` → `0 failing`（全绿）
- 生产工厂 `AssembleGdiDesktopSource(true, ...)` → `0 failing`（全绿）
修复后（全部度量走 `metrics.SystemMetric`，`dpi_ok` 变成 seam 形参）：
- `desktop.right` 改 `SM_CXSCREEN` → **FAIL :435/:440，1 failing/2 checks**
- 生产工厂 `dpi_ok` 改 `true` → **FAIL :461，1 failing/1 check**

### 教训（例 37）
- **注入的边界必须等于装配的边界**：只要装配函数里还有一处读全局，那条支路的变异就无人守。
  判断标准不是"这个函数有没有收 metrics"，而是"这个函数**每一处**度量是否都经由它"。
- **字面量参数是缺口信号**：seam 工厂传 `AssembleGdiDesktopSource(true, ...)` 而生产传真实值，
  意味着"这一维"在 seam 下不可调、在测试下不可错。凡 seam 把参数写成常量，
  就问："把它换成常量后谁红？"——答不出即缺口。
- 修复方向永远是**让 seam 拥有该维度**（加形参），不是给常量加断言注释。
## 第866轮：用 String.Replace 做变异会同时改掉同形的多处 → 自己的变异证据说谎（例 38）

### 症状
我报告"F2：生产工厂把 `dpi_ok` 改成 `true` → FAIL :461"，并把这条当作 F2 已闭合的证据。
审计 U 实测同一变异 **13/73 全绿**，要求我复核落点。

### 根因
我用的 PowerShell 语句是
`$s.Replace('    return AssembleGdiDesktopSource(dpi_ok, ...);', '... true ...')`。
该字符串在文件里**出现两次**（`:404` 生产入口、`:411` seam 工厂），`String.Replace` 替换全部。
于是 seam 也变成硬编码 `true`，`:461`（只受 seam 形参影响）转红。
我把"这一行被替换"当成"生产入口被替换"，**没有确认替换次数**。

### 证据
`[BASH: ([regex]::Matches($s, [regex]::Escape($needle))).Count]` → `occurrences=2`。
单点变异（用 `IndexOf` 定位到 `MakeGdiDesktopSource(` 之后再插入）：
- 只改生产入口 `dpi_ok` → **13/73 全绿**（U 正确，我错）
- 只改 seam（`AssembleGdiDesktopSource(true, ...)`）→ 红 `:461`

### 修复（真正的闭合）
给生产入口也装上 seam：新增 `MakeGdiDesktopSourceWithDpiProbe(probe, ...)`，
生产入口变成一行胶水 `return MakeGdiDesktopSourceWithDpiProbe(&EnablePerMonitorDpiAwareness, ...)`。
变异"装配忽略 probe 结果"→ **红 :561 + :571**；变异"生产入口传 nullptr"→ **红 :561**。

### 教训（例 38）
- **变异必须定位到唯一位置**：用 `IndexOf`/`LastIndexOf` 取偏移再 `Remove+Insert`，
  并在替换后 `Select-String 'MUT-'` 确认只有**一处**带标记；`String.Replace` 默认全局，
  是"变异打偏"的头号来源。
- **变异目标必须与断言目标一致**：`@:461` 断言的是 seam 形参，用它来证明"生产入口"是错的；
  正确做法是先问"这条断言能观察到我要改的那一层吗"。
- 别人的实测与我的声明冲突时，**默认我错**并按对方的落点重跑；审计 U 这次是对的。
## 第868轮：备份文件名手抄时间戳 → 恢复失败，变异体残留一轮（例 39）

### 症状
做完 `MUT-M27C` 变异后想恢复，我写了
`Copy-Item '.opencode\backups\src_server_desktop_input_stats.cpp.20261102210506'`。
该文件不存在（真实备份是 `...210559`）。`Copy-Item` 报 `PathNotFound`，
但我没检查 `$LASTEXITCODE`/错误就继续跑 `cmake --build` + `ctest`，
拿到 `97% tests passed, 2 failed out of 69`——把**变异体残留**误读成"还有真缺陷"。

### 根因
1. 备份时间戳靠**手抄**（我写了 `$ts` 变量，却在恢复时重新手写一个不同的字面量）。
2. 恢复失败后没有断言"目标文件已恢复"（hash 对比、`MUT-` 残留计数）。

### 证据
`[BASH: Get-ChildItem .opencode\backups -Filter 'src_server_desktop_input_stats.cpp.*']`
→ 实际有 `...180005 / ...195558 / ...204034 / ...205555 / ...210559`，**没有 210506**。
`[BASH: Select-String -Path src\server\desktop_input_stats.cpp -Pattern 'MUT-']`
→ `43: if (printed == nullptr) return std::string();  // MUT-M27C`（确实还在）。
改用 `...210559` 恢复后：`MUTANT残留=0`，`ctest` **69/69**。

### 教训（例 39）
- **备份与恢复必须共用同一个变量**：保存时 `$bk = "...\$name.$ts"; Copy-Item ... $bk`，
  恢复时 `Copy-Item $bk`。禁止在恢复时重写时间戳字面量。
  更稳的做法：`Get-ChildItem <pattern> | Sort LastWriteTime | Select -Last 1`。
- **每次恢复后必须验证三件事**：`MUT-` 残留为 0、hash 与备份一致、该文件在构建日志里**重新编译**。
  （第三件来自 discover 例 36。）
- **构建/测试失败先查"是不是我自己的变异还在"**，再查产品缺陷；
  恢复命令的失败不能只靠肉眼看输出。
## 第868轮：断言"恰好一次"的观测窗口短于采样周期 → 刷屏变异全绿（例 40）

### 症状
批 27 的 `host_cli_periodic_stats_line` 用 `--seconds 7`（采样间隔 5 s）断言
"periodic 行恰好 1 次"。我把 `printed_input_valid = true` 删掉（宿主每次采样都当无基线 → 每 5 s 打印一行），
**该用例仍然绿**：7 秒窗口内只触发 1 次采样，刷屏与正常不可区分。

### 根因
"恰好一次"的判据必须保证**至少两次采样**才成立：只有一次采样时，
"打印一次"与"每次都打印"产生相同的观测。窗口长度 ≥ 2×采样周期 是判据的必要条件，
我在设计用例时只想着"要有这一次"，没算观测窗口能否证伪。

### 证据
`[BASH: 变异后 --seconds 12 运行]` → `periodic 行数=2`（窗口覆盖 5 s / 10 s 两次采样）；
`--seconds 7` 时 → 1 行，用例绿。
`[BASH: 改为 --seconds 12 后同一变异]` → `CASE periodic_stats_line: expected exactly one ..., found 2`（红）。

### 连带发现（同一轮）
`execute_process(TIMEOUT 10)` 小于新的 12 s 窗口 → 用例报 `Process terminated due to timeout`。
**观测窗口变长时，超时必须同步放大**，否则用例由"断言失败"退化为"超时失败"，更难诊断。

### 教训（例 40）
- **"恰好一次"必须让窗口覆盖 ≥2 次触发**：写这类断言时先算"触发周期 × 次数 = 最短窗口"，
  窗口不足时断言恒真。
- **改长运行窗口必须同步改超时**：把 `--seconds`、`execute_process(TIMEOUT)`、CTest 的
  `TIMEOUT` 视为一组联动常量。
- 变异要针对**判据的盲区**设计：不是"改坏代码看它红"，而是"构造一个判据本该抓住、
  但观测不足以暴露的情形"，再看它是否真的红。例 38/39/40 都是同类：变异本身没问题，
  **是我的观测或落点有问题**。
## 第869轮："非空 + 前缀"不等于"内容正确" —— 基线打印全 0 快照仍全绿（例 41）

### 症状
批 27 的基线行用例只断言 `!first.empty()` 和 24 字节前缀 `input stats (periodic): `。
把实现改成 `return FormatInputStats("periodic", InputStats{});`（**打印全 0 而不是当前值**）后，
`desktop_input` 68 tests / 13912 checks **全绿**。

### 根因
用例的 `base` 本身全 0 ⇒ "打印 current" 与 "打印一个默认 InputStats" 的输出**逐字节相同**，
任何只看前缀/存在性的断言都无法区分。审计 W 的 D1 找到这条，我复现确认。

### 证据
`[BASH: 变异 MUT-D1 = FormatInputStats("periodic", InputStats{})]` → `68 tests, 13912 checks, 0 failing`
修复（`base.injected = 7; base.dropped_unmapped = 5;` + 断言这两个非零值）后同一变异 →
`FAIL :1820 / :1821`，`1 failing tests, 2 failed checks`。

### 教训（例 41）
- **断言必须让"错误实现"产生不同的观测**：先问"如果它打印的是默认值/零值/空值，
  我的断言会红吗？"答"不会"就说明夹具本身没有区分力（全 0 的 base 是最常见的陷阱）。
- **夹具要用非同值**：多字段断言各用**不同**的非零值（7 与 5），这样"字段互换"与"整块丢弃"都能抓到。
  这与 R6/U-4 的做法一致（y 轴用非零异值、virtual origin 用负值）。
- 存在性/前缀断言只能证明"打印了"，不能证明"打印对了"；**要证内容，必须钉住内容**。
## 第870轮：修一个假测试时顺手删掉相邻断言 → 造出新的假测试（例 42）

### 症状
批 28 我修 D1（基线行数值未断言）时，用"行索引数组重建"改写整段用例，
把 change 分支原有的 `CHECK(line.find("input_dropped_unmapped=3") != npos);` **删掉了**，
且没有补等价物。审计 W 发现（B1）：把实现改成 `FormatInputStats("periodic", *printed)`
（change 分支打印**旧快照**）后，`desktop_input` **68 tests / 13912 checks 全绿**。
同一变异在批 28 之前的版本（`db5f764`）下**是红的** ⇒ 这是我在批 28 引入的判据回归。

### 根因
1. 我用"整段行范围替换"改写代码，`$l[0..1809] + 新行 + $l[1821..]` 这种切片会**静默丢弃**
   两个索引之间的一切，而我当时只关心"新加的断言是否正确"，没有逐行 diff 旧内容。
2. 修复假测试时只盯着"被指出的那一处"，没有确认"这段用例的其他断言是否仍在"。

### 证据
`[BASH: git show 1da9e67 -- tests/test_desktop_input.cpp]` → 出现
`-    CHECK(line.find("input_dropped_unmapped=3") != std::string::npos);` 且无替代行。
`[BASH: MUT-B1 = FormatInputStats("periodic", *printed)]` → 修复前 `0 failing`；
补回断言（并加 `line == FormatInputStats("periodic", moved)`）后 → **红 3 处 :1846/:1847/:1848**。

### 教训（例 42）
- **改写既有用例必须逐行 diff**：`git diff` 里出现**只有 `-` 没有对应 `+`** 的断言行，
  就是判据被削弱的信号。禁止用"行号切片重建"编辑测试文件而不复查 diff。
- **修复假测试的最小充分集**：既要让目标变异转红，也要保证**原有变异仍然红**。
  验收时必须把"修复前能抓的变异"全部重跑一遍（审计 W 的 M2/M3 回归扫描正是这个作用）。
- **整行相等 + 字面量断言并用**：`line == FormatInputStats("periodic", moved)` 单独不够
  （`FormatInputStats` 自己丢字段时两边同时变），必须再用字面量钉住每个字段的值。
## 第871轮：给"防假绿的门"写注释豁免启发式 → 门自己假绿（例 43）

### 症状
批 30 我按审计建议给 `verify.ps1` 加了"变异残留门"，并用
`$trimmed.StartsWith('//' | '#' | '*' | '/*')` 把"仅注释"行豁免（理由是测试注释里会引用变异名）。
审计 V 指出：在 C++ 里
- `// log_input_stats_if_changed();  // MUT-XXX`  ← **注释掉的调用**（本仓最常用的残留形态）
- `#define RTSC_MUTANT_ON 1 /* MUT-XXX */`        ← `#` 是预处理指令
- `*ptr = 5; // MUT-XXX`                          ← `*` 是解引用
**三种都是代码**，却全被 `StartsWith` 判成"散文"而放行。

### 证据
`[BASH: 构造 3 行变异，用旧门逻辑从 C:\Windows 跑]` → 只报 1 条（`*ptr = 5`），
另 2 条（注释掉的调用、`#define`）被静默豁免 ⇒ `EXIT=1` 看似"抓到了"，实则放走 2/3。
而这正是 B2 事故的形态：当时 `main.cpp:714` 残留的就是**纯注释行** `// MUT-...: 采样移出循环`。
`[BASH: 改用"任何命中即失败"后同一夹具]` → 3 条全报，`EXIT=1`。
`[BASH: 真实仓库（注释已清理）]` → `mutation residue gate passed`, `EXIT=0`。

### 根因
用"行首字符"猜注释在 C++ 里不可判定（`#`/`*` 也是代码字符）；
而"专业注释里的引用"与"注释掉的语句"在纯文本上**无法区分**。
只要允许豁免，就必须引入白名单（`file:line`），而白名单会随行号漂移失效。

### 修复
1. 把唯一那处引用 `tests/host_cli_check.cmake:73` 的变异名**改写成不含该 token 的描述**；
2. 门简化为"**任何命中即失败**"，删除启发式、删除白名单；
3. 保留 D3/D4/D6 修复（`git -C $root`、`--untracked`、校验退出码 `>1`）。

### 教训（例 43）
- **防假绿的工具本身必须先被"假绿攻击"**：给校验器写豁免规则时，第一件事是构造
  一个"本该被抓但可能被豁免"的样本。豁免规则越聪明，越可能放过它要防的东西。
- **不要用词法/前缀猜测语义**（同 discover 例 34：文本匹配验证行为）。
- **白名单是最后的退路，不是首选**：宁可改掉被豁免的那处内容（这里是注释措辞），
  也不要维护随行号漂移的 `file:line` 白名单。
## 第872轮：把"构建失败"当成"环境噪声"而只记录一次就放过 → 5 个真错误被隐藏（例 44）

### 症状
审计 W/V 多轮都报告"Linux 全量构建被 `src/server/server.cpp` 既有 `-Werror=reorder` 阻断，
非本批引入"，我据此把 Linux 记为 **UNVERIFIED** 并**连续多轮不处理**。
本轮实际跑 gate 后，`FAILED_COUNT=4`，真实错误是 **5 个**（reorder 只是其中一个）：
1. `server.cpp:1400` `InjectGeometry{desktop_width_, desktop_height_}` 只初始化前 2 个成员
   → `-Wmissing-field-initializers`（生产代码）
2. `server.cpp:715` 构造函数初始化列表顺序与成员声明序不符 → `-Wreorder`（生产代码）
3. `tests/test_desktop_input.cpp` 5 处 2 参 `InjectGeometry{...}`
4. `tests/test_desktop_input.cpp:108` `WaitUntil` 在非 Windows 构建下未使用 → `-Wunused-function`
5. `tools/rtsc_server/main.cpp:593` switch 漏 `kMouseRel` → `-Wswitch`
6. `tests/test_server_security.cpp` 用 `#if !defined(_WIN32)` 守卫 OpenSSL，但
   `RTSC_TLS_OPENSSL` 默认 OFF → 链接期 `undefined reference to SSL_*`

### 根因
1. **"既有问题"不是免于验证的理由**：它是不是我引入的，与它是否阻塞我的验证是两件事。
   我用"非本批引入"给"不验证"开了口子。
2. **转述替代了实测**（再犯 discover 例 29）：审计说"被 reorder 阻断"，我就假设只有 reorder。
   实际 gate 的 `FAILED_COUNT=4` 表示 4 个**目标**失败，每个目标可含多个 error。
3. **跨平台差异没进常规验证**：Windows（MSVC）对 `-Wmissing-field-initializers` / `-Wswitch`
   的默认行为与 GCC 不同，所以这些错误在 Release 69/69 全绿时完全不可见。

### 修复与证据
- 5 处逐个修复（逐字段赋值、初始化列表重排、`PartialGeometry` 辅助、`#if` 守卫、
  switch 补 case、`#if defined(RTSC_TLS_OPENSSL)`）。
- 变异验证：`inject_geometry_.width` 改取 `desktop_height_` → 红 `:4099`/`:4491`（值断言有效）。
- `LINUX GATE PASS`，67/67 tests passed。

### 连带发现（同轮）
gate 用 `-DCMAKE_BUILD_TYPE=Debug`（`-g` 无优化），而 `view_scale_benchmark_budget` 的预算按
Release 实测值 ×3 设定 ⇒ Debug 下必然超预算（最慢 256ms / 预算 90ms；Release 同机 43.7ms）。
**性能预算不能在未优化构建上判定**——已用 `#if defined(NDEBUG)` 围住，未优化构建明确打印
"skipped" 而不是失败（诚实跳过 ≠ 伪装通过）。

### 教训（例 44）
- **UNVERIFIED 必须定期重试**：标注 UNVERIFIED 是"本轮没验证"，不是"结论为无需验证"。
  连续多轮停留在 UNVERIFIED 而不尝试，等于把风险静默化。
- **"非本批引入"只影响归因，不影响是否要修**：它阻塞验证 → 就必须处理或明确挂起。
- **平台差异要跑真工具**：MSVC 全绿 ≠ GCC 全绿；`-Werror` 集合不同。
- 看到 `FAILED_COUNT=N` 要逐个看 N 个目标的全部 error，不能只读第一条。
## 第873-874轮（合并）：验证工具自身必须可证伪 —— 两层"绿但没证明"（例 45/46）

### 症状（三层，逐层加深）
**第一层**：`scripts/linux-build-gate.sh` 被 `core.autocrlf=true` 检出为 CRLF →
bash 报 `$'\r': command not found` → **gate 在 Linux 上根本起不来**。
**第二层**：gate 能跑后仍用默认配置（`RTSC_TLS_OPENSSL` **OFF**）→ OpenSSL 后端从未编译，
P0 用例 `tls_server_regression_coalesced_first_record_no_stall` 被 `#if` 守卫掉，
Linux `server_security` **0.01 秒"通过"**，只跑 7 tests/45 checks（开 OpenSSL 后 8/67）。
**第三层**（批 34 修完才发现）：gate 的断言全是**聚合结果**
（`BUILD_EXIT`/`FAILED_COUNT`/`CTEST_EXIT`）。被守卫掉的用例在 ctest 上照样 `100% passed`
⇒ **批 34 修的缺陷，批 34 的 gate 自己抓不住**。

### 根因
"退出码 0"是**必要条件而非充分条件**：它证明"没有失败"，不证明"该跑的跑了"。
对"可选后端 + `#if` 守卫"的组合，**缺席的测试与通过的测试在退出码上完全同形**。

### 证据（三层各自的实跑）
- `[BASH: file scripts/linux-build-gate.sh]` → `with CRLF line terminators`；gate EXIT=2
- `[BASH: gate 默认配置]` → `LINUX GATE PASS` 但 `server_security` `Passed 0.01 sec`
- `[BASH: gate -DRTSC_TLS_OPENSSL=ON]` → **68/68**，`server_security` **8/67**，P0 用例 `[ OK ]`
- `[BASH: OFF 默认配置重跑]` → 构建 0 失败，7/45 全过（守卫是设计性降级，非删测试）
- M1 gate `ON`→`OFF`：`required tests missing: tls_openssl`（EXIT=1）
- M2 `test_server_security.cpp:444 #if defined(...)`→`#if 0`（目标仍在）：
  `REQUIRED_TESTS=present` 但 `P0 ... did not execute`（EXIT=1）⇒ **第2道断言独立有效**
- 恢复：SHA256 `3AE7AFC7...9A8A` 一致；全仓 `MUT-` 残留 0
- 绿证：`EXIT=0`、`LINUX GATE PASS`、68/68、`P0_REGRESSION=executed`、`bash -n` SYNTAX_OK

### 修复
1. `.gitattributes`：`*.sh text eol=lf` + `git add --renormalize`
2. gate 显式 `-DRTSC_TLS_OPENSSL=ON`（缺工具链已由 env 契约 FAIL）
3. gate 增加两道**身份断言**：`ctest -N` 必须列出 4 个关键测试名；直接执行
   `rtsc_server_security_tests` 并要求输出含 P0 用例名

### 教训（例 45/46 合并为一条原则）
**"绿"必须能被证明是"该绿的绿"——凡是可被条件编译移除的测试，聚合断言一律无效，
必须断言身份；每新增一个验证手段，必须先构造一个只触发它的变异体。**
- 默认 OFF 的可选后端，gate 必须显式打开；否则测试被 `#if` 静默编译掉，"通过"只是"没跑"。
- `core.autocrlf=true` 的仓库必须有 `.gitattributes` 钉 `*.sh` 为 `eol=lf`。
- **0.01 秒"通过"是可疑信号**：含 TLS 握手的套件瞬间通过，应怀疑"没跑"。
- **每修一个"验证漏检"缺陷，必须同时问：我的 gate 现在能抓住它吗？**
- **新增断言必须做可证伪性演练**，且构造"只触发该断言"的变异（M2 就是），
  否则无法区分多道断言谁在起作用。


## 第875轮：把断言加进 gate，却没加进调用 gate 的脚本（例 47）

### 症状
批 35 给 `scripts/linux-build-gate.sh` 加了两道身份断言（`REQUIRED_TESTS=present`、
`P0_REGRESSION=executed`），gate 变绿。但 `verify.ps1` 的 `-LinuxBuild` 段
（`:448-464`）捕获 gate 输出后，仍只做**四项** line-anchored 校验：
`FAILED_COUNT=0`、`WINDOWS_H_COUNT=0`、`FACTORY_SYMBOL=present`。
新加的两道断言**没有被上层脚本校验**。

### 根因
把"gate 会输出这两行"当成"这两行被校验了"。断言存在 ≠ 断言被消费。
`verify.ps1` 是 gate 的唯一消费者，消费方不校验，断言就只是日志。

### 证据
- 变异：把 gate 的两条 `echo` 换成 `true`（gate 自己也不再输出）：
  `gate EXIT=0`（其它四项仍满足），但 `verify.ps1` 的断言块报
  `MISSING -> REQUIRED_TESTS=present`、`MISSING -> P0_REGRESSION=executed`
  ⇒ 修正后的 needle 列表**确实生效，不是死代码**
- 恢复后全仓 `MUT-` 残留 0
- 编码：改动前后首字节均 `35`（`#`，无 BOM）、`CR=482` 不变 ⇒ 未破坏原文件格式
- 语法：PowerShell 5.1 Parser `PARSE_OK`

### 修复
`verify.ps1:458` 的 needle 列表补 `REQUIRED_TESTS=present`、`P0_REGRESSION=executed`，
沿用既有 line-anchored 正则（`(?m)^...\r?$`），不放宽为子串匹配。

### 教训（例 47）
- **断言链要端到端**：新增一个输出行，必须同时检查"谁消费它、消费方是否校验它"。
  gate 与 verify.ps1 是生产-消费关系，只改生产方等于没改。
- **这是例 46 第 2 条教训的同型复发**（"修了漏检却留下同样漏检的上层"）。
  说明该教训需要更强的形式：**每加一条断言，立刻在消费方补一条对应的校验**。
- **改非 UTF-8/LF 文件必须用字节级替换**：`ReadAllText`+`WriteAllText` 会加 BOM、
  把 CRLF 换成 LF，产生一个与内容无关的巨大 diff（本轮我犯过一次，已回滚重做）。
## 第876轮：同一族的四处"跑了什么没人断言"（例 48）

### 症状（一次审计收口里，同一根因以四种形态出现）
两审计独立给出 CONDITIONAL，缺陷全部落在"执行身份未被断言"这一族：

1. **门自我认证**（X，D1）：gate 只 `grep "OK .* <case>$"`。而 `tests/test_main.h`
   对"用例体内 printf("skipped: ...") 然后 return"**仍然打印 `[  OK  ]`**。
   红证：把 P0 用例体改成 `if (true) { printf("skipped:"); return; }` →
   `P0_REGRESSION=executed` + `LINUX GATE PASS` + `EXIT=0`。
2. **Debug 掩盖优化分支**（Y，P1 / X，D3）：gate 用 `CMAKE_BUILD_TYPE=Debug`，
   `test_view.cpp` 的预算判定包在 `#if defined(NDEBUG)` 里 ⇒ 七条预算断言在
   唯一自动化 gate 里**从未执行**。批 33 把"Debug 下必超预算"改成 skip，
   等于删掉覆盖而不是修正判据。
3. **零用例却 exit 0**（我自己修第 1 项时被 gate 自己抓出）：
   `tests/test_gui_send.cpp` 整个包在 `#if defined(_WIN32)` 里，Linux 上
   `rtsc_gui_send_tests` 注册 0 个用例却 `exit 0` ⇒ `gui_send` **自 gate 存在以来
   一直是"断言了零件事的绿测试"**。
4. **语义无守护**（Y，P1；X 纠正归因）：`PartialGeometry` 的 `mapped=false` 语义
   没有任何断言。首拒点是信任位（`desktop_input_map.h:80`），所以既有用例里的
   span 破坏永远不会走到 mapped 分支 —— 注释里那句"breaking either one alone
   turns a case red"是假陈述。

### 根因
把"测试进程退出 0"当成"断言执行了"。四种形态的**共同结构**是：
存在一条路径让断言不执行，而所有观测点（退出码 / OK 行 / 汇总行）都表示成功。

### 证据
- D1：用例体改 `if(true){skipped;return;}` → `EXIT=0` / `LINUX GATE PASS`（修前）
- D3：Debug → `skipped: timing budgets...` / 7341 checks；Release → 7348 checks（差 7）
- 零用例：`ctest` 报 `gui_send ... Failed  0.01 sec` + `0 tests, 0 checks`（修 `test_main.h` 后暴露）
- PartialGeometry：删 `!g.mapped` → `:751/:905/:914` 红；删 `!g.pixels_are_physical` → `:755/:908` 红

### 修复
1. gate：OK 行 **+** 无 `skipped:` **+** `tests>=8 && checks>=67`（下限而非等号）
2. gate：追加 `RelWithDebInfo` 构建，只跑 `rtsc_view_tests`，要求 `VIEW_BUDGETS=executed`
3. `test_main.h`：`ran_tests==0` → `exit 2`（拼错过滤器与空注册都堵，且与 exit 1 可区分）
4. `CMakeLists.txt`：`gui_send` 的 `add_test` 加 `if(WIN32)`（目标保留以抓构建破坏）
5. `test_desktop_input.cpp`：两例从 `PhysicalGeometry(2,2)` 出发各坏一个信任位

### 教训（例 48）
- **断言"执行了什么"，不只断言"是否失败"**。任何"可以合法地不执行"的测试都需要
  三道证据：用例名出现 + 无 skip 标记 + 产出量下限。
- **门必须能被打红**：每加一道断言，都要造一个**只触发它**的变异体，否则无法区分
  多道断言谁在起作用（本轮对 skip 与 checks 下限分别造了独立变异）。
- **修 A 类缺陷时留意它是否同时暴露 B 类**：改 `test_main.h` 后 gate 立刻报出
  `gui_send` 的零用例假绿 —— 那是此前所有轮次都没看见的缺陷。
- **别把 checks 等号当通用守则**：`rtsc_server_tests` 在 655/656/657 间漂移
  （两处条件执行的 CHECK）。等号只用于已验证稳定的单个套件，且优先用下限。
- **注释里的"两者都坏会红"必须实测**：`test_desktop_input.cpp:877-879` 的断言
  是假的（Y 用三种变异全绿证明）。注释是不可执行的断言，必须用变异兑现。
## 第877轮：刚修完的 D1，我在 D3 里原地重犯了同一个错（例 49）

### 症状
批 37 修 D1 时确立的原则是"不断言'没有某字符串'，要断言产出量"。
同批的 D3 修法**违反了自己刚立的原则**：
```sh
if grep -q "skipped: timing budgets" "$VIEW_LOG"; then ... exit 1; fi
grep -E "^[0-9]+ tests, [0-9]+ checks, " "$VIEW_LOG" | tail -1   # 只打印
echo "VIEW_BUDGETS=executed"
```
checks 数被**打印**却没被**断言**。

### 红证（审计 X 构造 V8）
```c
#if defined(NDEBUG)   ->   #if 0
"skipped: timing budgets..."  ->  "NOTE: budget evaluation unavailable"
```
结果：`VIEW_RELEASE_EXIT=0`、`60 tests, 7341 checks`（= Debug 的数，七条预算一条没跑）、
`VIEW_BUDGETS=executed`、`LINUX GATE PASS`、`EXIT=0` —— **假绿**。

### 根因
"没有某个字符串"是"用例体执行了"的**代理**，而代理可被任何不叫这个名字的
skip 短路：换文案、提前 return、`#if 0`、未来重构。这与 D1 在结构上完全同形。
更深一层：**我在同一次提交里既写下原则又违反了它** —— 说明"知道原则"不足以避免
重犯，必须让原则变成**检查项**。

### 证据
- 修前 V8：`EXIT=0` / `VIEW_BUDGETS=executed` / `7341 checks`
- 修后 V8：`EXIT=1` / `view budget bodies did not run (checks=7341, want >=7348)`，
  且 `VIEW_RELEASE_EXIT=0` —— 证明这道断言不依赖退出码
- 恢复后：SHA256 `775301AB...8866` 一致、全仓 `MUT-` 0、`7348 checks`、`LINUX GATE PASS`

### 修复
`VIEW_MIN_CHECKS=7348`（= Debug 7341 + 7 条 bench CHECK），断言 `VIEW_CHECKS >= 7348`。
用下限而非等号：给 `test_view.cpp` 新增断言不会误红。

### 教训（例 49）
- **"能观测"不等于"已断言"**：凡是被 `printf`/`echo` 出来供人看的数字，问一句
  "如果它是错的，谁会失败？" —— 若答案是"没人"，那就是一个洞。
- **同一提交内的自我一致性检查**：修 D1 立了"断言产出量"的原则，D3 却在同一批里
  用"断言字符串缺席"。**新原则必须立刻回头扫一遍本次改动本身**。
- **可观测量的差值比绝对值更可靠**：7348−7341=7 正好等于七条预算断言 ——
  一条被跳过则差值归零。差值把"配置形状"翻译成"执行结果"。
## 第878轮：变异全绿不等于"规则无人守"——我误判了自己的修复（例 50）

### 症状
批 37 我新增了一段用例（`requires_usable_geometry` 里的 `:903-914`），注释宣称
"start from a geometry that is otherwise fully usable and break ONE trust bit at a time"，
理由是"`PartialGeometry` 的三种变异全绿 ⇒ 信任位无人守护"。

两审计独立否证：
- 旧用例 `desktop_input_absolute_move_requires_trusted_geometry`（`:750-766`，
  自 `150a6ea^` 就存在）**早已逐位隔离两个信任位**：删 `!g.mapped` → `:751` 红；
  删 `!g.pixels_are_physical` → `:755` 红。
- 我加的那段是**重复覆盖**：删掉它，上述两个变异仍然红（T0/T1）。

### 根因（两层误判）
1. **"变异全绿"不能推出"规则无人守"**。`PartialGeometry` 的变异全绿，是因为它的
   所有调用点都传 `w/h ∈ {0,1}`，被 span 规则在 `:81` 拦下 —— 变异打中的是
   **调用点的下游规则**，而不是 **辅助函数自身的输出契约**。要证明"无人守"，
   必须区分"哪条规则、在哪一层被谁拒绝"。
2. **我连注释里的因果都写错了**（Y 抓到）：我写"span 规则先拒绝 PartialGeometry"，
   实际 `PartialGeometry(1920,1080)` 的 span 合法（1920>1、1080>1），先拒它的是
   trust 位（`:80`），其次空 capture（`:82`）。**被 span 拒的是调用点，不是辅助函数。**
   同一文件里 X 也曾把"span 无人守"当成结论，随后自我作废。

### 证据
- 旧用例独立守护：删 `!g.mapped` → `:751` 红（`requires_trusted_geometry`）
- `PartialGeometry` 三种变异全绿：68 tests / 13922 checks，0 failing
- 新增辅助函数契约用例后，同样三种变异全部红（PG+mapped / +pixels / +capture.width）
- `cl /W4 /WX` 对漏枚举**不报错**，仅 `/w44062` 报 C4062 ⇒ main.cpp 的 switch
  在 Windows 上长期无保护，改 `"relative-move"→"mouse"` 后 `ctest -R host_cli` 6/6 全绿

### 修复
1. **删除**重复覆盖块（无损失，由旧用例承担）。
2. **新增** `desktop_input_partial_geometry_helper_contract`，断言辅助函数**自身输出**
   （width/height/两信任位/两矩形/`AbsoluteMoveMappable`）—— 这才是无人守护的那一层。
3. 按事实重写注释，显式区分"辅助函数被谁拒"与"调用点被谁拒"。
4. 把 `main.cpp` 的 switch 提成 `InputEventKindToken()` 放 `desktop_input_stats.cpp`，
   该文件已有 `FormatInputStats` 先例；switch 结构性消失，`-Wswitch` 隐患在该站点消除；
   新增逐值枚举用例，`"relative-move"→"mouse"` 立即红。

### 教训（例 50）
- **"变异全绿"只说明"这个变异没被抓住"，不说明"没有别的守卫"**。必须先枚举
  全部拒绝路径（本例 `:80`/`:81`/`:82`/`:83`/`:84` 五道），再判断变异实际打到哪一道。
- **"无人守护"的结论必须给出反证**：删掉既有用例后变异是否仍红？红 ⇒ 有人守。
- **注释里的因果链是不可执行断言**，写"X 拒绝了 Y"之前必须逐行核对判定顺序；
  本轮我和 X 各错一次，都是把"调用点行为"当成"辅助函数行为"。
- **宏/枚举 switch 在 MSVC 默认无保护**：想守住"每个枚举值都有处理"，
  必须把 switch 提成可被单测覆盖的纯函数，而不是依赖 `-Wswitch`。
## 第879轮：主验证脚本的主路径从来没绿过（例 51）

### 症状
跑 `verify.ps1 -LinuxBuild`（我之前从未端到端跑过它）时，**Windows 侧 ctest 直接挂**：
```
FAIL tests/test_ui.cpp:252  new_us <= 0.6 * ref_us
rgba->bgra 1280x1024: reference 3155.4 us, vectorised 2440.1 us (ratio 0.77, limit 0.60)
```
三次复跑 ratio 0.77 / 0.79 / 0.77（稳定，非抖动）；同一份代码 Release 是 0.39 / 0.41。

### 根因
`test_ui.cpp` 的断言是**相对倍率**（`new_us <= 0.6 * ref_us`），而 `-Od` 会把
标量参考循环与被向量化的快路径一起放慢，比值反转（0.60 → 0.78）。这是
**构建类型属性**，不是缺陷。而 `verify.ps1` 默认 `-DCMAKE_BUILD_TYPE=Debug`。
⇒ 自 `f77b90f` 引入该断言起，`verify.ps1` 的主验证路径**每次都红**。

与批 33 的 `view_scale_benchmark_budget` 是同一族：优化构建才可观测的
相对性能断言，被放在未优化构建里执行。

### 为什么长期没被发现
- 我所有 "全绿" 结论都来自 **Release** 的 `ctest`（`build` 目录），而 `verify.ps1`
  用的是 **Debug**（`build\verify`）。**两个构建目录，我只盯了其中一个。**
- `verify.ps1 -LinuxBuild` 我此前记作 UNVERIFIED 却一直没跑；审计 X 也把它标 UNVERIFIED。
- 这正是 discover 例 44 的形态："记成 UNVERIFIED 就当它没问题"。

### 证据
- Debug ratio 0.77/0.79/0.77（三次）→ `1 failing tests, 1 failed checks`
- Release ratio 0.39/0.41 → `0 failing`
- Linux Debug 84 checks / RelWithDebInfo 86 checks（差 2 = 两条计时断言）
- 修后：Windows Debug ctest **69/69**（修前 68/69）；Release **69/69**

### 修复
1. `test_ui.cpp`：`#if defined(NDEBUG)` 围住测量与两条断言，未优化构建打印
   `skipped: relative timing requires an optimized build (NDEBUG)`。
2. **同时**在 gate 的 RelWithDebInfo 阶段增跑 `rtsc_ui_tests`，断言
   `UI_RELEASE_EXIT=0` + 无 skip 文案 + `checks >= 86`。
   —— 批 33 的教训是"改成 skip 就完事等于删覆盖"，所以必须补回可观测构建里的断言。
3. `verify.ps1` needle 补 `UI_RATIO=executed`（断言链端到端，例 47）。

### 教训（例 51）
- **"我跑过全绿"必须指明是哪个构建类型、哪个目录**。`Release` 绿 ≠ `Debug` 绿，
  尤其对性能断言。
- **默认配置才是主路径**：`verify.ps1` 是"主验证脚本"，它的默认 `Debug` 挂了，
  等于主路径从来没绿过，而我一直拿旁路（Release ctest）当证据。
- **UNVERIFIED 会累积成盲区**：连续多轮把它记成 UNVERIFIED 而不跑，缺陷就一直藏着。
  每轮应收敛至少一个 UNVERIFIED。
- **同一族缺陷会成对出现**：view 预算是第一个，ui 倍率是第二个。修第一个时没有
  全局扫描"还有哪些相对性能断言"，导致第二个又存活了几十个轮次。
  ⇒ **修一类缺陷后必须全仓扫描同型**（本例 `grep 'CHECK(.*<.*us\|ms'` 找到全部 7 处，
  其中只有 2 处是相对倍率，其余 5 处是宽松超时上限）。
## 第881轮：同一个洞我犯了三次，而且每次换一层（例 52）

### 症状（同族缺陷的三次复发，逐次换壳）
| 次 | 断言 | 被什么绕过 |
|---|---|---|
| 批 35 D1 | `grep "OK .* <case>"` | 用例体自己 `printf("skipped:")` 后 return，框架仍打印 `[  OK  ]` |
| 批 38 V8 | `grep -v "skipped: timing budgets"` | 换掉 skip 文案、`#if 0` |
| 批 41→42 | `checks >= 7348 / >= 86` | **加无关的恒真 CHECK**：checks 计的是"执行了多少次 CHECK" |

第三次最隐蔽：它在**非对抗**路径上也会自己打开。审计 X 的实验：
```
GROW=0 -> 84 (fails)   GROW=1 -> 85 (fails)
GROW=2 -> 86 -> GATE PASSES, ratio body silently untested
GROW=3 -> 87 -> GATE PASSES
```
即"有人正常给这个文件加 2 个 CHECK"之后，body 一旦失效就正好落在下限上。
**测试随时间增长是正常的，所以这个洞会自己打开。**

### 根因
三次都是把**可被旁路影响的数量/字符串**当成"该断言执行了"的证据：
- 字符串"缺席"可被改名绕过
- 计数"达到下限"可被无关增量补足
共同点：**它们都不由被测断言体唯一产生**。

### 修复（第四次终于用对方法）
断言**只有该体才会产生的东西** —— 体内部的 `printf` 输出行：
- view：`grep -c "\[bench\]" >= 7`（每迭代一行，body 不跑则 0 行）
- ui：`grep -q "rgba->bgra 1280x1024:"`（测量行，body 不跑则不产生）
checks 下限**降级**为"套件规模异常"的辅助检查，不再承担举证责任。

### 证据（真 gate 端到端，非模拟）
- view `#if 0` + 补 7 CHECK + 改文案 → `EXIT=1`，`bench lines=0, want 7`（旧代码 PASS）
- ui `#if 0` + 改文案 + 补 2 CHECK → `EXIT=1`，`measurement line missing`
- ui `#if 0` + 改文案 + 补 3 CHECK → 同样 `EXIT=1`
- 未改代码 → `VIEW_BUDGETS=executed` / `UI_RATIO=executed` / `LINUX GATE PASS`

### 教训（例 52）
1. **判断"某段代码执行了吗"，唯一可靠的证据是该段代码自己产生的副作用**。
   任何"总数""存在/不存在某字符串"都能被别处影响。
2. **问一个问题就能提前发现**：这个证据，除了我要证明的那段代码，还有谁能产生？
   若答案是"别人也能"（另一个 CHECK、另一处 printf、改名后消失），它就不是证据。
3. **修完必须验"非对抗增长"**：不仅验"恶意绕过"，还要验"正常改动后是否仍然有效"。
   本轮 GROW=2 才是最有说服力的反例。
4. **同一族缺陷复发三次 = 缺的不是知识而是检查项**：
   以后凡写"断言执行了"的门，必须先写下"该体唯一的副作用是什么"，再断言那一个。
## 第881轮补记：同一条注释我连写三版都写错因果（例 53）

### 症状
`tests/test_desktop_input.cpp` 的 `PartialGeometry` 契约用例注释，三版全部有事实错误：
| 版 | 我的错误 | 实际情况 |
|---|---|---|
| v1 | "span rule rejects those before the trust bits are ever read" | `PartialGeometry(1920,1080)` 的 span 合法；先拒的是 `:80` trust |
| v2 | 第一段说 span 先拒、第二段说 span 不拒 —— **自相矛盾** | 同 v1 |
| v3 | "If either flips … stops being rejected at :80" + "(or … starts mapping)" | `:80` 是 `!mapped \|\| !pixels_are_physical`（OR）：**任一半翻转仍被拒**；两半全 true 后仍被 `:82` 空 capture 拒（`InjectRect` 默认 width/height=0），**永远不会 mapping** |

### 根因
我写注释时凭"印象中的控制流"下笔，没有逐行核对：
- 没区分 `&&` / `||` 的语义方向
- 没检查默认值（`InjectRect` 的 0）
- 没验证"通过 `:80` 之后还会撞到哪道守卫"

### 教训（例 53）
- **注释是给后来人的断言，必须和代码一样被证伪**。写"X 会因为 Y 被拒绝"之前，
  逐行读判定顺序、逐条核对 `&&`/`||` 方向、核对所有默认值。
- **同一段注释改三次仍错 ⇒ 停止重写，改为先做实验**：构造 4 组 (mapped, pixels)
  组合打印 `AbsoluteMoveMappable` 的实际返回值，再照着输出写注释。
  （审计 X 就是这么做的：12/12 单比特翻转实测。）
- 这类错误的代价不是编译失败，而是**误导后来者**：如果有人照 v3 的注释去"优化"，
  以为 `mapped=true` 就会开始 mapping，会得出完全错误的结论。
## 第882轮：用新原则回头扫，立刻又发现一个同族洞（例 54）

### 症状
批 42 修完 view/ui 的"补 CHECK"洞后，我把例 52 的判据（**"这个证据，除了我要证明的那段代码，还有谁能产生？"**）
当成检查项回头扫了一遍 gate 的**其余**断言，当场发现批 35 的 P0 断言有完全相同的洞：

`tests/test_server_security.cpp` 的 P0 用例体末尾
```cpp
if (got_challenge) printf(...);      // <- 没有这行（修复前）
CHECK(got_challenge);
```
gate 断言 `tests>=8 && checks>=67`。把 `CHECK(got_challenge)` 换成两个 `CHECK(true)`：
checks 67 → 68（仍 ≥ 67）→ **`EXIT=0` / `P0_REGRESSION=executed` / `LINUX GATE PASS`**。
drain 回归断言被删掉而 gate 报绿。

### 根因
与例 52 完全相同，只是位置不同：**checks 计数不是该体独有的副作用**。
我批 35 修 D1 时以为"再加两道断言就安全"，但第二道（checks 下限）用的是同一类可被补足的量。

### 证据
- 攻击（真 gate）：`CHECK(got_challenge)` → `CHECK(true); CHECK(true);` ⇒ `EXIT=0`、`LINUX GATE PASS`
- 修复后同一攻击：`EXIT=1`、`body did not reach its success path (drain marker missing)`，
  且变异体 checks=68 **仍高于下限 67** ⇒ 证明抓住它的是标记行而不是计数

### 修复
1. P0 成功路径打印 `  drain: challenge surfaced after coalesced record`（全仓唯一）
2. gate 断言该行存在

### 教训（例 54）
- **新原则确立后必须立刻回扫既有的全部同类断言**。我批 42 只改了"这一批新加的"两处，
  若不是主动回扫，批 35 的洞会继续存在。
- **"我加了两道断言"不等于"两道都可靠"**：可能两道依赖同一个可被旁路的量
  （本例：`tests` 下限 + `checks` 下限，两个都由同一个计数系统给出）。
  判断可靠性要按"证据来源是否唯一"分组，而不是按"断言条数"计数。
- **修改后必须重新测量数字**：我提交信息里写"修后 68 checks"，实测仍是 67
  （新增的 printf 分支不产生 CHECK）。**凭推理写下的数字同样是未验证断言。**
## 第883轮：我宣布"修复生效"的那个变异，其实改的是别的东西（例 55）

### 症状
批 43 我声称："攻击 B（`CHECK(got_challenge)` → 两个 `CHECK(true)`）→ `EXIT=1`，
`drain marker missing`"。审计 X 用真 gate 复现得到 **`EXIT=0` / `LINUX GATE PASS`**。
我独立重做，确认 **X 正确、我的提交信息是错的**。

原因：我那次变异把 **printf 与 CHECK 一起删掉了**，所以 marker 才会消失；
而"只把 CHECK 换成 `CHECK(true)`"时 marker 照常打印，gate 照常通过。

### 二阶洞（比批 42 的更深一层）
批 42 的 view/ui marker 有效，是因为 `#if 0` 会让**整个体**（含 printf）消失。
P0 不同：成功路径照常执行、printf 照常打印，**只有末尾那条 CHECK 被替换**。

两条独立语句：
```cpp
607: if (got_challenge) std::printf("  drain: ...\n");   // marker
608: CHECK(got_challenge);                                // assertion
```
删掉 608 不影响 607。

### 根因（原理性，非实现缺陷）
`CHECK` 宏只调用 `report_failure`，**不中止、不改变控制流**（`tests/test_framework.h:47-53`）。
因此任何"产出物断言"（日志行、文件、计数器）都只能证明**这段路径被走到了**，
不能证明**某条断言语句还在**。审计 X 验证了互斥成功/失败双标记设计，
同样关不掉"删断言"。

### 结论与处置
- **"删断言"原理上无法用产出物断言关闭**。能做的只有：
  1. 让断言失败表现为非零退出码（已有）
  2. 明确声明覆盖边界，不虚报
  3. 把"断言存在性"交给代码评审
- gate 断言分类更正为三档：
  - **身份类**（不可补足）：`REQUIRED_TESTS`（ctest -N 名字）/ `FACTORY_SYMBOL`（nm 符号）
  - **路径类**（证明走到了、不证明断言在）：`P0_REGRESSION` / `VIEW_BUDGETS` / `UI_RATIO`
  - **计数类**（仅辅助）：`SEC/VIEW/UI_MIN_CHECKS`
- 已把边界写进 `scripts/linux-build-gate.sh` 与 `tests/test_server_security.cpp` 的注释。

### 教训（例 55）
1. **变异必须唯一**：我改成"删 printf + 换 CHECK"，却以为在验"换 CHECK"。
   这与 discover 例 38（`String.Replace` 替换全部同形匹配）同类：
   **先写清变异到底改了什么，再声称它证明了什么**。
2. **"修复生效"的证据必须由攻击脚本产生，不能由我口述**。
   我这次是先写结论、后跑变异，结果两者不对应。正确顺序：先跑、贴原始输出、再写结论。
3. **产出物断言的覆盖上限是"路径"**。凡写"某断言会执行"的论断，
   必须区分"执行了"（path）与"还在"（assertion exists）——前者可测，后者不可测。
## 第884轮：我读了自己的测试文件，却没读进去（例 56）

### 症状
批 44 我宣布"P0 没有守住 drain"，依据是 4 个变异全绿。审计 X 指出：**4 个变异全部打错了文件**。

| 我改的 | 实际是什么 | 为什么无效 |
|---|---|---|
| `tls_schannel.cpp` M7 | Windows 后端 | Linux gate 根本不编译 |
| `tls_openssl.cpp` 的 `max_out` 分支 | 后端通用 | 本用例 `max_out=0`，走不到该分支 |
| `security_layer.cpp:244` / `:321` | **客户端 mirror** | 该行注释自己写着 "The server half is the critical path; this client mirror keeps the two symmetric." |
| 同文件 `pending_cipher_` 不 Receive | 同上 | 同上 |

P0 用的是 `ServerSecurityLayer`，其 drain 在 **`src/security/server_security_layer.cpp:194`**。
**更讽刺的是：`tests/test_server_security.cpp:35` 的注释本身就写着** "which lives in
ServerSecurityLayer::DriveCredssp"。我读过那个文件，却没把这句话用在选变异位置上。

### 证据（我独立复现 X 的结论）
- 改 `server_security_layer.cpp:194` → `while (false)` ⇒
  `FAIL test_server_security.cpp:611 got_challenge`，**唯一失败用例就是 P0**
  ⇒ P0 是 `:194` 的唯一守卫，批 34 的结论成立，无需下调。
- 改 `server_security_layer.cpp:292`（`ReceivePdu` 的数据面 drain）⇒
  整棵 ctest **67/67 全绿** ⇒ `:292` 确实无人守护（新登记）。

### 根因
**我用"我觉得应该在哪"代替"代码实际在哪"。** 我把"drain 义务"当成一个统一概念，
在名字最像的文件（`security_layer.cpp`）里找，而没先确认**被测类的实现文件**。
这与例 53（注释因果链凭印象写）是同一类：**用印象替代查证**。

### 教训（例 56）
1. **变异必须先定位"被测对象的实现文件"**：从测试文件里的类名出发，grep 它的
   定义在哪个 .cpp，再在那里下手。测试文件的注释往往直接写着答案。
2. **"变异全绿"的第二种解释**：除了"无人守护"，还有"**打错了位置**"。
   我现在会先问：这个文件真的在测试路径上吗？（例 50 是"变异打中了下游规则"，
   本例是"变异打中了完全不在路径上的文件"。）
3. **镜像/对称实现是最危险的误伤点**：客户端/服务端两份对称代码的存在，
   让"看起来在做同一件事"的位置有两处。选变异点前必须确认**哪一份被测试执行**。
## 第885轮：我把"我没找到配方"当成了"不可能"（例 57）

### 症状
批 45 我判定 `server_security_layer.cpp:292`（`ReceivePdu` 的数据面 drain）无测试覆盖，
处置是**只写边界注释**，理由写的是："Reaching this loop needs a completed handshake
plus a coalesced data segment, which no current test constructs"。

审计 X 直接写出了那个用例（59 + 8 行，零新脚手架），红→绿验证通过。我采纳并落地。

### 我的推理错在哪
我只搜了 `ReceivePdu`（发现测试文件里没有调用），就断定"无法构造"。
但**到达该循环的配方就在同一个测试文件里**：
`server_security_layer_hybrid_without_ex_omits_euar`（`:231-291`）用
`ScriptedTls` + 3 次 `Step()` + 5 步 CredSSP 就到 `Want::kDone`。
唯一缺的是 `ScriptedTls::buffered_input()` 硬编码 `return 0`。

**我搜的是"这个 API 被谁调用"，而不是"这个状态怎么到达"。** 前者只能证明"没有现成用法"，
不能证明"无法构造"。

### 证据
- 新用例正常：9 tests / 79 checks，0 failing
- `:292` 改 `while(false)`：**9 tests / 78 checks，1 failing**，
  `FAIL test_server_security.cpp:361 frames.size() == 1u (got 0, want 1)`，**唯一失败者就是新用例**
- 恢复后全绿、`MUT-` 0

### 教训（例 57）
1. **"没有现成用法" ≠ "无法构造"**。宣布某事不可测之前，必须先问：
   进入该状态的最短路径是什么？已有哪个测试已经到达相邻状态？
2. **边界注释是会过期的断言**。写 "no test constructs this" 时，它当场可能是真的，
   但下一批就可能被推翻 —— 而代码注释不会自动失效。**可验证的就不该只写边界**；
   W5 的"写明不能证明的"仅适用于**原理上**不可验证的情形（如"删断言"）。
3. **采纳外部方案时要照跑红证**：我照抄 X 的骨架后，仍自己重跑了 `:292` 变异，
   确认唯一失败者是新用例，而不是"看起来对了"。
## 第886轮：两个文件写入错误（例 58）

### 错误 A：WriteAllLines 恒把 LF 写成 CRLF（我的归因错了，已由审计 X 更正）
`src/security/security_layer.cpp` 仓库行尾是 LF。我用
`[IO.File]::WriteAllLines(...)` 插注释，写出来 LF=454 / CRLF=454（全变 CRLF）。

**我最初写「例 47 记的是改 .sh 禁止 WriteAllLines」——这是编造的出处。** 审计 X 实测
发现例 47（`:719-725`）从未提过 WriteAllLines；它讲的是 `ReadAllText`+`WriteAllText`
会加 BOM、把 CRLF 换成 LF。**我把没核实过的记忆当成证据写了进去（W5 违规）。**

**实测四种写法（2026-11-04，PowerShell 5.1，源文件 `a\nb\nc\n`，逐字节统计）：**
| 写法 | LF 源 | CRLF 源 |
|---|---|---|
| `ReadAllText` + `WriteAllText(UTF8Encoding($false))` | **LF 保持**（LF=3 CRLF=0） | **CRLF 保持**（LF=3 CRLF=3） |
| `ReadAllLines` + `WriteAllLines` | **LF→CRLF**（LF=3 CRLF=3），且尾部多一个换行（6B→9B） | CRLF 保持，但尾部多一个换行 |
| 连续两次 `WriteAllLines` | LF=4 CRLF=4（**每写一次 +1 换行，非幂等**） | — |

注：例 47 说 `WriteAllText` 会加 BOM——那是**没传 encoding** 时的默认行为；
显式传 `(New-Object Text.UTF8Encoding($false))` 就不加 BOM（上表已验）。

**规则（唯一正确写法）：改文件只用 `ReadAllText` → 按需 `Replace` → `WriteAllText`
（显式 UTF8 无 BOM）；禁用 `WriteAllLines`。写完立刻统计 CR/LF 与该文件原行尾比对。**

### 错误 B：行索引覆盖了 while 行本身
我想在 `:244` 上方插两行注释，用了 `$n[242]` / `$n[243]` 直接赋值。
而 `:244` 的 `while (tls_->buffered_input() > 0) {` 正是索引 243，
**被我的注释覆盖掉了**。`git diff` 立刻显示 `-    while (...)`，少一行 while。
若没看 diff 直接编译，要么编译失败（`const tls::Error d = ...` 无循环体），
要么更糟——语义变了但恰好能编过。

**规则：按行号改文件前必须打印并核对目标行内容；能按文本锚点替换就不要按索引。**
改完后必须 `git diff` 逐行确认"只加了该加的、没删不该删的"。

**补充（审计 X 本轮自己踩到，例 58 原文未覆盖）：多处按索引插入时必须从后往前。**
X 先按正向索引插了 3 个插桩标记，前一次插入使后一次索引失效，得到了错误的
`HIT_1+HIT_2` 结果；改为从后往前插入后重做才得到正确数据。
同理：一次性插入多处时，索引必须从大到小排序处理。

### 证据
- 错误 A：`LF=454 CRLF=454`（WriteAllLines 后）→ `LF=454 CRLF=0`（修正后）
- 错误 B：`git diff` 出现 `-    while (tls_->buffered_input() > 0) {`
- 回滚后 hash 与 `.tmp\sl.bak` 一致（`161EF9B1...`），重做后 diff 只有 +6/-2 注释行

## 第887轮：buffered_input()>0 不等于"有进展"（例 59）+ gate 时间预算偶发（例 60）

### 例 59：`if (buffered_input() > 0) continue;` 在 `for(;;)` 里会死循环
`src/net/gateway_transport.cpp:555`（批48 修复）。

**错误假设**：`buffered_input() > 0` ⇒ 这次 drain 有进展。
**实际**：它只表示后端还有未消费的**密文**。当缓冲里只有一条**不完整**的 TLS
记录时（Schannel `rx_buffer_.size() < 5`、OpenSSL `BIO_ctrl_pending > 0`），
`Receive(nullptr, 0, ...)` 返回 `kNeedMoreInput` 且**不消耗**缓冲，于是
`buffered_input()` 永远 > 0，`continue` 永不退出。

**红证**：`ScriptedPartialRecordTls`（buffered 恒 3、Receive 恒 kNeedMoreInput）
+ `receive_calls > 100` 时返回 kProtocolError（防挂死）：
`FAIL :3660 receive_calls == 1 (got **101**, want 1)`、`n == kReadTimeout (got -1, want -2)`。
101 次调用就是死循环的直接证据。

**修法**：以 `buffered_input()` 前后是否**减少**作为进展判据；不减少就落到读 socket。
这是让记录剩余部分到达的唯一途径。

**C9 复扫结论**：全仓 5 个 `buffered_input()` 循环，只有这一处是 `continue` 无逃逸；
`security_layer.cpp:244/:321/:409` 与 `server_security_layer.cpp:194/:300` 都是
`while` + `if (status == kNeedMoreInput) break;`，安全。

**通用教训**：
1. `X > 0` 类判据若被用作"继续循环"的条件，必须同时证明**每轮都有进展**；
   否则要用"前后对比"或显式逃逸（break/返回）。
2. 检查"缓冲是否非空"和"缓冲能否产出"是**两个不同问题**。前者只说明有数据，
   后者才说明可以前进。
3. 排查循环时先问：**每轮循环是否有状态单调推进？** 没有就是潜在死循环。

### 例 60：gate 的 view bench 时间预算会偶发红（环境噪声，非回归）
首次跑 gate：`FAIL test_view.cpp:1473 best < c.budget_ms`，
`[bench] 1:1 letterbox 1280x1024 -> 1280x1200 0.89 ms (budget 0.60)`。

**同二进制连跑 5 次**：`0.12 / 0.11 / 0.11 / 0.11 / 0.11 ms`，60/7348 全绿；
重跑 gate：`LINUX GATE PASS`。

**结论**：8 倍瞬时噪声（WSL 负载/CPU 频率），不是代码回归。bench 本身已取
3 次 × 5 迭代的最小值（`test_view.cpp:1460-1470`），仍被击穿说明是短时争用。
**不做 budget 调整**（0.6 已是实测 0.11 的 5.4 倍，再抬会削弱 10x 回归检测）。

**教训**：
1. 时间预算类断言天然 flaky。gate 红时先看**是否只有 bench 项红**、
   再连跑同一二进制 3-5 次取分布，再决定是否真是回归。
2. 禁止用"提高 budget"掩盖一次偶发；必须先证明分布。
3. 性能断言只能证明"没有数量级回归"，不能证明"实现最优"——这一条要写进测试注释。
