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