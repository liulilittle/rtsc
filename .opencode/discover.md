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

## 第889轮：过期注释断言（例 61）

### 症状
`include/rtsc/render/orders_apply.h:50` 原写：
"BS_HATCHED and BS_PATTERN are not implemented yet (TODO 3b3) and report
kUnsupported rather than drawing something wrong."

实际 `src/render/orders_apply.cpp:337-342` 早已分发到 `ApplyPatternPatBlt` /
`ApplyHatchedPatBlt`，且 `tests/test_orders.cpp` 有 9 个 pattern/hatch 用例。

### 类别
与例57 同族，但更弱也更常见：**"未实现"类注释一旦实现落地就变成错误陈述**。
它不属于 W5 允许的"边界声明"（边界声明描述的是**能力上限**，不随代码前进失效），
而是**可被直接推翻的事实断言**。

### 检验方法（可复用）
看到任何"X 未实现 / TODO"注释，必须做两件事：
1. `git grep` 该功能的实现符号（如 `BS_HATCHED` → `ApplyHatchedPatBlt`），确认没有实现；
2. 若已有实现，用**变异测试**证明注释里的新陈述为真：
   把该分发置为 `false &&` → 对应用例必须全红；恢复 → 全绿。
本次：`BS_PATTERN` → 5 failing/224 failed checks；`BS_HATCHED` → 5 failing/1870 failed checks。

### 同一轮的 C9 复查结果
| 位置 | 判定 |
|---|---|
| `capabilities.cpp:722` MemBlt/Mem3Blt/SaveBitmap | 准确（渲染侧确无实现） |
| `orders_apply.cpp:347` "Any other style" | 准确（确实返回 kUnsupported） |
| `gateway_transport.h:299` 独立读线程 | 准确（明确写 follow-up） |
| `cliprdr_client.h:94` / `file_list.h:5` 缓存文件存储 | **UNVERIFIED**（无双向确认） |

### 教训
1. 注释里的"未实现/TODO"是**有保质期的断言**，实现落地时必须同步删除或改写。
2. 判断一条注释是否过期，不能只读注释——必须 grep 实现符号。
3. 边界声明（"这里刻意不支持 X，因为 Y"）与状态断言（"X 还没实现"）要分开写；
   前者稳定，后者必然腐化。
## 第890轮：三类缺陷（例 62/63/64）

### 例 62：陈旧目标文件让"测试结果"与"工作树"脱钩
**症状**：`verify.ps1` 报 Windows Debug `tls` 3 处失败，Release 同代码全绿。
**直接原因**：`Copy-Item` 恢复源文件时保留旧 mtime → Ninja 认为 object 最新 →
不重编 → 跑的是**上一个版本的代码**。强制重编后 3 个失败全部消失。
**排除过程**（重要）：我加诊断打印后"3 个失败消失"，一度以为是 UB；
恢复原文件重建后仍然全绿，才定位到是陈旧产物。**不要因为现象消失就下结论。**
**修法（verify.ps1）**：tree 指纹（HEAD + status + numstat + 每个源文件的
size/mtime）写入 build 目录；下次跑时不一致就删目录重建；只有 build+ctest
全成功才写指纹。
**教训**：
1. 变异测试的"恢复"步骤必须 `Set LastWriteTime = Get-Date`，否则红证/绿证都可能是假的（例36 同族，本次在真实构建里再次踩到）。
2. 我第一版守卫（"build 后 dry-run 必须无事可做"）**抓不到**这个失败模式——mtime 回退时 Ninja 也认为无事可做。判据必须对准**根因**（内容/mtime 指纹），不能对准**症状**（有无编译输出）。

### 例 63：`read_offset == 0` 恒真，假修复能蒙混
**症状**：`tls_byte_transport_partial_record_does_not_spin` 断言
`read_offset == 0`，而 `MockTransport::Read` 在无数据时**第一行** return，
不触碰 read_offset ⇒ 无论 Read 被调用 1 次还是 0 次都是 0。
**后果**：把 `raw_->Read(...)` 换成常量 `kReadTimeout`（永不读 socket，所有数据丢失）
的假修复**全部断言通过**（审计 X 实测）。
**修法**：加显式计数器 `read_calls`；再加一个用例断言"缺失的密文被喂回去、
明文真的出来了"（`receive_calls == 2` / `n == 1` / `buf[0] == 0x41`）。
**教训**：
1. **断言必须能区分两个世界**。写断言前先问"什么样的错误实现也能让它通过"。
2. "某量等于 0"往往零信息量（未初始化的默认值也是 0）。要断言**发生了多少次**，不是"是否仍为 0"。
3. 一个测试只证明"没有 A"不等于证明"有 B"。补一个互补用例，让两者正交。

### 例 64：注释里的数量词必须数一遍
`orders_apply.h` 我写 "the **eight** built-in GDI hatch patterns"，
实现是 `kHatch[6][8]` + `hatch > 0x05` ⇒ **6** 个。同一条注释前后 5 次迭代，
两次数量词都写错（eight / six）。**数量词一律用 grep + 数数组维度确认。**
另一处措辞也不准："Only an unhandled style reports kUnsupported" ——
已处理的 BS_HATCHED 在 BrushHatch 越界时也返回 kUnsupported。

### 附：我自己造的假缺陷
我曾认定 `gateway_transport.cpp:655` 写成 `e.status`（应为 `r.status`）是缺陷。
实际那是我**自己的变异残留**被当成原有代码读。HEAD 里本就是 `if (!plaintext.empty())`。
**教训：判断"原有代码有缺陷"前，先 `git show HEAD:<file>` 或 `git diff` 确认工作树状态，
不要在变异过程中读代码。**
## 第891轮：守卫自身的 fail-open（例 65）+ 等价变异不可杀（例 66）

### 例 65：用 git 状态做"是否变了"的判据必然 fail-open
我批52 的 verify.ps1 指纹 = HEAD + `status --porcelain` + `diff --numstat` +
每个文件的 size/mtime。审计 X 用 4 个攻击全部击穿（我复刻判据后逐条重跑确认）：

| 攻击 | 旧指纹 | 根因 |
|---|---|---|
| A `update-index --assume-unchanged` + 等长改写 + mtime 回填 | **fp 相同** | git 被告知"别检查这个文件" |
| B `src/` 下未跟踪头文件改写 + mtime 回填 | **fp 相同** | status 只报 `?? src/gen.h`（路径不变），内容不进 fp |
| C `status.showUntrackedFiles=no` + 新增源文件 | **fp 相同** | 配置让 status 沉默 |
| D git 不可用 | **fp = SHA256("")** | `2>&1 \| Out-String` 把错误吞成空串 |

**D 最严重**：git 一失败，守卫退化成常量，对任何树都"不变"。
**修法**：判据必须是**被测对象本身**（文件字节），不是"关于被测对象的元信息"（git 状态）。
改用 `Get-ChildItem -Recurse -File -Force` + 逐文件 SHA-256，不依赖 git；
枚举为空则 `exit 1` 而不是盖章。

**通用教训**：
1. 守卫/校验器的判据要尽量**直接观测被测事实**。间接判据（git 状态、缓存、索引）
   在被测对象之外，就有被绕过和失效的空间。
2. **"查不到"必须与"没变化"区分**。任何 `2>&1` 吞错误的查询都要显式检查
   `$LASTEXITCODE`，否则失败会静默变成"通过"。
3. 反过来，"任何查询失败就 fail-closed" 也会让守卫在无关噪声（git 的 EOL 警告）下
   误停 —— 正确做法是让判据本身不依赖那个会失败的东西。

### 例 66：等价变异不可杀，不是测试缺陷
X 的 M5 变异把 Write 里的过滤改成 `&& e.status != kClosed`。但 `e` 是 Send 的结果，
且上方 `if (!e.ok()) return false;` 已保证它是 kOk ⇒ 该条件恒真 ⇒ **语义等价于无条件**，
任何测试都杀不掉。

**真正的风险**是用**正确变量**加过滤：`&& r.status != kClosed` —— 那才会丢数据。
我据此补了 `tls_byte_transport_queues_plaintext_when_write_sees_a_close`，
变异后 `:4007 n == 1 (got -2)` 唯一失败。

**教训**：变异测试报告"绿"时，先问**这个变异是否真的改变了行为**。
等价变异（dead condition、恒真条件、被上游已保证的约束）不产生可观测差异，
其"绿"不说明测试弱。要构造**语义上真的不同**的变异。

### 顺带：注释把"某后端"写成"后端普遍"
`ScriptedClosingTls` 注释说 "a real backend answers kNeedMoreInput"，
但只有 SChannel 这样（`:597-600`）；OpenSSL 返回 **kOk + 空明文**（`:404`）。
**教训**：涉及多个实现的共性描述，必须逐个实现核对，不能从一个实现外推。
## 第892轮：遍历 API 的静默跳过（例 67）

### 症状
`verify.ps1` 的内容哈希用 `Get-ChildItem -LiteralPath $fullDir -Recurse -File -Force`。
审计 X 指出：该调用在 PowerShell 5.1 **不进入接合点/目录符号链接，也不报错**。

### 我自己的复现（不采信）
```
tree\src\a.cpp  +  tree\src\inc -> external (mklink /J)
Get-ChildItem tree -Recurse -File -Force   -> 只有 \tree\src\a.cpp
Get-ChildItem tree -Recurse -Force | ? ReparsePoint -> 1 个: \tree\src\inc
```
⇒ 接合点里的 `inc\value.h` **完全不在结果里**，且没有任何错误或警告。

### 后果链
接合点里的头文件是盲区 → 改它指纹不变 → 配 mtime 回填后 Ninja 也不重编
→ **"树变了但 verify 报绿"**，正是本守卫存在的目的。

### 修法
遍历前先扫 reparse，有则 `exit 1`（fail-closed），并说明将来若要支持应哈希链接目标。

### 教训（例 67）
1. **"递归遍历"不保证遍历到全部**。符号链接、接合点、挂载点、权限拒绝的目录
   都可能被**静默跳过**。凡是用遍历结果做完整性判断（哈希/计数/校验），
   必须先确认遍历器是否覆盖了链接与特殊文件。
2. **静默跳过比报错更危险**：报错会被人发现，跳过不会。设计"必须看到全部"的
   逻辑时，要么显式检测并拒绝，要么显式跟随并在指纹里记录"我跟随了哪里"。
3. 这类洞与我前一轮修的 A/B/C/D（git 状态）**同族**：判据看似观测了全部，
   实际有一类输入根本没被观测。判断"我的判据覆盖了 X 吗"时，要问
   **"有没有一类输入能让判据看不见变化"**，而不只是"判据是否合理"。
4. 交叉验证的价值：我自己写的指纹我测了 4 个攻击（A/B/C/D）都堵住了，
   但**没想到 reparse**；审计 X 想到了。**自证 + 他证** 缺一不可。
## 第893轮：修 fail-closed 过头造成的误伤（例 68）

### 症状
批54 我给指纹加了"有 reparse point 就 exit 1"。审计 X 指出：OneDrive 未水合文件
也是 reparse point（tag `0x9000601A`），仓库若在同步目录下会**永久 exit 1**，
且用户看不出原因。

### 我的实测
```
OneDrive 递归 -File  -> 400 个文件里 392 个是 reparse
OneDrive 递归 -Force -> 582 个目录是 reparse
```
**关键**：文件型 reparse **会被 `-Recurse -File` 枚举到**（392 个就是这么数出来的），
所以 `ReadAllBytes` 能读到它。只有**目录型**才是 `-Recurse -File` 的盲区。

⇒ 我批54 的判据把"所有 reparse"当成盲区，**过度拒绝**。

### 修法
只拒绝 `PSIsContainer -and ReparsePoint`（目录型）；文件型照常哈希。

### 教训（例 68）
1. **fail-closed 的粒度必须对准真正的危险**。危险的只有"目录型 reparse"
   （遍历器不进入），文件型 reparse 是**可读的**，拒绝它纯属误伤。
2. 一个判据如果**无法在正常环境里通过**，它就不是守卫而是障碍。
   设计 fail-closed 时必须问：**"什么情况下这个检查会误伤合法输入？"**
3. 区分"看不见"与"看得见但类型特殊"：前者必须拒绝，后者应该正常处理。
   我批54 把两者混为一谈。
4. 这次是审计 X 想到的 OneDrive 场景，我自己只测了 junction/symlink。
   **自证容易漏掉自己环境里不存在的情况**——这正是他证的价值。

### 附带：全局 EAP 不是显式契约（例 69）
X 指出两处 `Get-ChildItem` 没有 `-ErrorAction Stop`，权限拒绝的子树能静默消失。
我实测确认：**无 `-ErrorAction Stop` + 全局 EAP=Continue + deny** 时，
fp 与"文件根本不存在"**逐字节相同**（`A2CAFE20...`）。

**教训**：依赖全局 `$ErrorActionPreference` 的行为是**隐式契约**。
任何一个"必须失败"的操作都要显式 `-ErrorAction Stop`，
否则将来有人挪动/删除那一行全局设置，行为就静默退化，而且没有任何测试会红。
## 第894轮：环境噪声冒充被测对象（例 70）+ witness 与不变量混淆（例 71）

### 例 70：外部负载污染所有时间类断言
`view_scale_benchmark_budget` 偶发红三次，我每次都"重跑一次就绿"，从未查过原因。
审计 X 定量复现后我才去测，发现 **WSL 被另一个项目 `/mnt/f/tctp` 的交叉编译占满**
（`aarch64-linux-gnu-ld`、`cc1plus`，load average 8.7）。同一时刻还有 `sqlservr`
与 `beam.smp` 在吃 CPU。

**关键证据**：同一二进制、同一台机器，空闲时 1:1 是 0.11 ms，负载下 0.89 ms（7.4x）；
而 43 ms 的 4K 用例只涨到 92 ms（2.1x）。**小用例测的是时钟抖动，不是代码。**

**教训**：
1. "重跑就绿"不是证据，是**逃避**。偶发红必须先定位是代码还是环境。
2. 时间类断言必须先量三个数：**空闲值、噪声峰值、真实回归值**。
   预算必须落在"噪声峰值之上、真实回归之下"，否则既会误报又抓不住回归。
3. 样本时长要 ≥ 10 ms 量级，否则调度抖动会主导结果（0.1 ms 的样本抖动可达 7x）。
4. 生产性做法：先用 `ps` / `loadavg` 确认机器状态，再解释测量结果。
   这次我一开始把"0.4x 4K 从 43 ms 涨到 104 ms"当成"变异太弱"，
   实际是别的项目在编译。

### 例 71：witness 断言被误当成不变量
`server_flood_vs_stop_race_converges` 里有两类断言：
- **不变量**：`stop_cleared`、`live == 0` —— 这才是被测行为（Stop 必须回收所有 session）
- **witness**：`started_after_stop >= 1` —— 只证明"测试装置确实制造了那个窗口"

我原来让每个 launcher 固定睡 40 ms，然后赌测试线程能在最后一个 40 ms 内把
`stop_began` 置 true。**这是把"装置有效性"建立在调度运气上**：
负载下测试线程可能被挂起 >40 ms，witness 变 0，红——但与 Stop() 毫无关系。

**修法**：用入口计数识别"最后一个 launcher"（accept 循环串行，进入顺序即注册顺序），
让它**有界等待** `stop_began` 后再启动。窗口变成结构保证。

**教训**：
1. 测试里要区分**被测不变量**与**装置 witness**。witness 依赖时序时，必须
   用信号/同步把时序变成确定性的，而不是"睡足够久"。
2. 改 witness 前必须验证**不变量仍然 load-bearing**：我把
   `if (snapshot_taken)` 改成 `&& false`（跳过所有 `session->Stop()`），
   测试仍然 `RED_TIMEOUT live=8` + `FAIL stop_cleared`。
3. **没复现 ≠ 不存在**。X 报 2/6 失败，我 14 次全绿且 checks 恒定（1 tests/7 checks，
   不是 X 说的 614-641 波动）。但我仍然按代码结构分析修了它，并在提交里
   明确写"未复现，修法基于结构分析"。**不能因为没复现就宣称对方错了**，
   也不能因为没复现就不修。

### 例 72：测试旋钮的可用范围没被测试自己的等待预算覆盖
批 57 把 witness 确定性化后，我按"分支完备"把 `RTSC_TEST_LAUNCH_DELAY_MS` 逐个取值跑，
发现 **`delay_ms=200` 时测试自己红**：
```
flood_vs_stop: launches=6 registered=-1 live=0 total=6 sockets=8 delay_ms=200
1 failing tests, 2 failed checks
```
`{0,1,5,40}` 全绿。

**根因**：launcher 在 accept 循环里同步执行，所以非最后一个 launcher 的 `delay_ms`
睡眠会**串行化后续注册**（8 个连接要 `7 × delay_ms`）。而用例的注册等待是**固定 1 s**
（`for i<100` × 10 ms）。`delay_ms=200` 需要 ~1400 ms → 等待超时 → `all_registered=false`
→ 测试在只注册了 6 个时就发起 Stop()。失效阈值约 140 ms。

**为什么这是测试缺陷而不是服务器缺陷**：同一旋钮在 40 ms 下绿、200 ms 下红，而
服务器代码一字未改。红因不可归因 —— 这比不红更糟，因为下一个人会去"修"服务器。

**修法**：等待预算随旋钮缩放，并设上限：
`register_budget_ms = min(2000 + 4 × delay_ms × kConnect, 60000)`。

**教训**：
1. 任何"可调大"的测试旋钮，**最大有用值必须被测试自身的超时/等待预算覆盖**。
   判据：问"把这个旋钮调到 10 倍会怎样"——不能回答"仍然绿"的，就不是旋钮而是地雷。
2. 分支完备不能只测**生产代码**的分支，**测试装置自己的参数空间**也是分支
   （0 / 1 / 5 / 40 / 200 / 1000 六个值 × 2 次 = 12/12）。
3. Rule 16 要打在新代码上：把缩放预算改成固定 1000 → 只有 `delay_ms=200` 红
   （`launches=6 registered=-1`），其余全绿 —— 说明缩放正好且仅在该生效处 load-bearing。
### 例 73：我修 A 时用 B 的判据把 A 又破坏了（批56 → 批59）
批56 给 view bench 加"有界单次重试"，重试行写成 `  [bench] ... retrying: ...`。
批 59 回头看才发现：gate 的断言是 `grep -c "\[bench\]" >= 7`，**重试行被算成一条结果行**。
于是"一个用例被编译掉 + 另一个用例重试一次"计数仍是 7 → gate 通过。

**红证**（用 sed 从 gate 抽出真实断言块，喂合成日志）：
| 场景 | 修前 | 修后 |
|---|---|---|
| 健康 7 条结果行 | exit=0 | exit=0 |
| 6 条结果行 + 1 条 retry 行 | **exit=0（假绿）** | exit=1 |
| 7 条但缺 `0.5x 4K`、`0.4x 4K` 重复 | — | exit=1 |

**性质**：这正是我在批 42 / 例 52 立下的原则——"判断某段代码执行了吗，唯一可靠证据是该段
代码**自己**产生的副作用，而计数可被任何同类行补足"。**同一条原则，我自己在批 56 违反了。**

**教训**：
1. **给某个测试加输出时，必须问"这行会不会被我自己的门禁当成别的证据"**。
   新增任何带标记的 printf，都要 grep 该标记在 gate / 脚本里的全部消费者。
2. **计数断言应升级为身份断言**：要求每个具名条目各出现一次，而不是"总数达到 N"。
   本例的逐用例正则还要求"标签后紧跟数字串"，否则 `1:1` 会匹配 `1:1 letterbox` 行。
3. **修完要同时给两层红证**：标记修复的（改回 `[bench]` → 假绿复现）与身份断言的
   （删掉逐用例循环 → 换用例仍绿）。只给一层，另一层就是未验证。
4. **"我自己刚改的代码"是最该怀疑的地方**。批 56 我给自己写了 Rule 16 变异（预算值），
   却没检查它是否**削弱了既有的门禁**——变异只测"抓不抓得住回归"，不测"门禁是否变弱"。
### 例 74：注释把"故意的不等比"写成"等比"，且用未验证的余量数字
批56 我在 bench 里写了两句量化断言：
- "Every budget is about 4x the idle measurement" —— 实际是 **3.3x–10.9x**
  （1:1 是 0.11→1.2 = 10.9x；0.4x4K 是 43→140 = 3.3x）
- "roughly 1.5x to 2x headroom" —— 实测负载下是 **1.43x / 1.43x / 1.44x**

两句都**方向性错误**：前者把"小用例故意给大倍数"这个设计决定说成了"统一 4x"，
后者把余量说大了。而且"every sample is at least ~10 ms"也不成立（2x = 9.6ms、
1.33x = 7.2ms）。

**为什么危险**：下一个人若按"4x"去改预算，会把 1:1 的预算从 1.2 降到 0.44，
立刻掉进抖动地板；若按"1.5-2x 余量"判断"还有空间"，会在负载下假红。
**错误注释会主动引导出错误修改**，比没有注释更糟。

**教训**：
1. 注释里的每个数字都必须**从表里算一遍**，不能凭印象写"约 N 倍"。
   本例注释自己就带着空闲表，我却没算——**表在、结论错**，这是最该避免的形态。
2. "余量"这类形容词必须给实测值（1.43x），不能给区间估计（1.5-2x）。
3. 顺带发现的不成立断言（样本 ≥10ms）要一并修实现（iters 2→3、4→6），
   而不是改注释去迁就——**注释应当描述实现，不能让实现迁就注释**。
4. 改完必须重跑结构回归，确认预算没被放松：逐像素变异仍红在 1:1（9.22 vs 1.20）。
### 例 75：`sleep_for(1ms)` 在 Windows 上是 15.5ms，"迭代计数"当上界会差 15 倍
批57 我写 `for (int i = 0; i < 5000 && ...; ++i) sleep_for(1ms)`，注释说 "bounded"。
实测（MSVC /O2，`.tmp/sleepprobe2.cpp`）：
```
 100 x sleep_for(1ms) ->   1550.15 ms  (avg 15.501 ms)
1000 x sleep_for(1ms) ->  15583.47 ms  (avg 15.583 ms)
```
⇒ **5000 次 = ~78 秒**，不是 5 秒。Windows 默认定时器粒度 ~15.6ms，`sleep_for` 向上取整。

**教训**：
1. **"迭代 N 次"不是时间上界**，除非每次迭代的耗时已知且稳定。要上界就用 `steady_clock` deadline。
2. 平台定时器粒度必须实测（Windows ~15.6ms、Linux ~1ms 量级），不能凭"1ms 就是 1ms"。
3. 注释里写 "bounded at N seconds" 必须有实测支撑；这句话这次是**错的**，而且错了 15 倍。

### 例 76：跨机器测量值不能写进注释（本轮第 3 次栽在同类问题）
bench 注释我先写"about 4x"，改完写成一组逐值比值 `10.9x | 9.2x | ...`。
审计 X 在另一台机器同一份 HEAD 实测得到 `13.3x | 11.0x | 5.2x | 6.0x | 5.4x | 7.5x | 5.2x`；
我在本机重测是 `10.9x | 10.0x | 4.4x | 5.4x | 5.0x | 6.3x | 4.6x`。
**比值随机器漂移近 2x** ⇒ 任何逐值列举都会在下一台机器上变成假陈述。

**教训**：
1. 注释应写**不变量**（"比值随机器漂移约 2x；恒定的是绝对余量 ~1.4x"），
   不应写**可观测量的逐值表格**——除非注明"某机某时某构建"并且接受它会过期。
2. 同一类错误（注释数字错误）本轮**连犯三次**（`about 4x` → 逐值表 → `>=11ms`）。
   根因是"写完注释就以为是事实"。规则 78 已立，但我**没有把规则用在自己的新注释上**。
   **判据：注释里出现数字 ⇒ 必须能在同一次运行里被复现，否则改成定性描述。**
3. 被审计方实测与审计方实测冲突时（10.9x vs 13.3x），**两个都对**——
   说明该量本身不是常量。这正是"不要记录非常量的具体值"的实证。
### 例 77：同型排查——全仓 18 处 `sleep_for(1ms)` 的循环上界分类
批61 修了自己的"迭代计数当上界"后，按 C9 回扫全仓：
| 文件 | 上界形态 | 判定 |
|---|---|---|
| `test_gateway.cpp:2198/:2259` | `steady_clock` deadline | 正确 |
| `test_server.cpp:3389` | deadline（批61 改） | 正确 |
| `test_server_multisession.cpp:569/:930` | `while (go.load()==0)` 等原子信号 | 不是上界，而是**同步点**（由其它线程必然置位），无缺陷 |
| 其余 `sleep_for(1ms)` | 短轮询，循环外有 `CHECK(timeout)` | 无缺陷 |
另查 `sleep_for(10ms)` × N（如 `test_server.cpp:3757` 的 1500 次）：Windows 上 10ms 也升到
~15.6ms，实际 23s 而非 15s，但**只影响失败路径的等待长度**，不影响判定。改 80 处风险大于收益
⇒ 登记不改。

**教训**：同型排查要**分类**而不是一律改写。"迭代计数 + 固定 sleep"里，只有
"该计数是本次运行的唯一时间上界"时才构成缺陷；`while (!atomic_flag)` 的自旋是同步，
`for (i<N) ... CHECK` 里的 N 只是轮询次数。**判据：问"如果 sleep 比标称慢 15 倍，
这个函数的等待会不会超出调用方预期"**——只有答案为"会"且调用方有预期时才是缺陷。
### 例 78：门禁"证明路径"与"证明做了工作"是两件事（同一洞第 4 次复发）
bench gate 有三层断言：`grep -c "[bench]" -ne 7`（计数）、7 条逐用例正则（身份）、
`VIEW_MIN_CHECKS>=7348`（产出量）。**三层全部被同一个攻击绕过**：
把 `measure()` 改成 `return 0.01;`（完全不调用 `ScaleSurface`）——
没有任何一行缺失，没有任何标签缺失，checks 数不变，gate 打印 `VIEW_BUDGETS=executed` 并 PASS。

同一轮里另外三个门禁也有同型洞：
| 门禁 | 攻击 | 修法 |
|---|---|---|
| `FACTORY_SYMBOL` | 只有 `U`（未定义）引用的 archive 也满足 `nm -C \| grep` | `nm -C --defined-only` |
| `SEC_TESTS>=8` | 删掉一个 10-checks 用例 → 8 tests/69 checks 仍过 | `-ne 9` + checks>=79 |
| `VIEW_BENCH_LINES -lt 7` | 加第 8 个用例 → 8 行仍过 | `-ne 7` |

**教训**：
1. 三层断言可能是**同一个信息源**的三次读数。本例三层都只读"日志文本的形状"，
   没有一层读"程序实际做了什么"。**加断言前先问：这三层读的是同一个量吗？**
2. "证明执行路径" ≠ "证明产生了有用工作"。路径类证据（日志行）的严格升级是
   **副作用计数器**（本例 `calls=1000 want=1000`），它不可能被"打印一行"伪造。
3. 下限（`>=N`）在**可增可减**的对象上都是 fail-open：能加就能补足，能减就漏。
   判据：**这份集合的基数是否由本文件决定？** 是则用等值 `-ne N`。
4. 修完必须对**每一层**各给一个只打它的变异（本例 5 个变异分别打 5 层），
   否则"修好了"只是"最强的那个变异不红了"。

### 例 79：单一"我执行到这里了"标志会被位置改变架空
flood 测试新增 `gate_waited.store(true)` 作为 "park 真的发生过" 的证据。
审计 X 把这条 store **移到 CAS 之前**，并把 park 条件改成恒假 —— 全绿，
但那次运行**从未 park 过**（`started_after_stop` 由固定 delay 分支撑起）。

**教训**：
1. 单个布尔"我到过这里"只证明**该语句执行过**，不证明**它所在的分支是真实路径**。
   store 的位置一改，语义就没了，而测试不会红。
2. **入门 + 出口各一个原子**（`gate_entered` / `gate_parked`），加上"谁抢到"的 CAS 结果
   （`gate_claimed`），三者同时断言 ⇒ "没进也没出但标志为真" 不可能通过。
3. 更一般的判据：**断言必须覆盖被证明事件的最小可观测前后态**；
   只有"事后"没有"事前"，就能被"把事后标志提前写"伪造。
### 例 80：`bash -n` 通过 ≠ 脚本能工作；awk 的语义错误只有真输入能暴露
批63 我给 gate 写了 case-block 提取 awk，`bash -n` **SYNTAX_OK**，gate 也"跑通了"。
实际有两处语义错误，都是**用真实日志跑七场景**时才暴露：

1. **正则多一个空格**：`/^\[ ( RUN  |  OK  | FAIL )\]/` —— `\[ ` 已吃掉一个空格，
   交替项又各带前导空格，于是 `[ RUN  ]`（1 空格）和 `[  OK  ]`（2 空格）**全都不匹配**。
   后果：`inb` 恒 0 ⇒ honest 日志被拒 ⇒ **`LINUX GATE PASS` 根本不可能打印**。
2. **gawk 内置名当变量**：`awk -v case=...` → `fatal: cannot use gawk builtin 'case' as
   variable name`。脚本直接不工作，而 `bash -n` 依然通过。

**教训**：
1. `bash -n` 只解析语法。校验脚本的"能跑"必须用**真实输入**至少跑一遍成功路径。
2. awk 的变量名要避开 gawk 内置（`case` 就是一个），这不是常识而是实测才会撞到。
3. 提取块的正则必须对**harness 的真实输出形状**验证（`[ RUN  ]` 1 空格、
   `[  OK  ]` 2 空格、`[ FAIL ]` 1 空格），不能按记忆写。
4. 红证要覆盖"成功路径不该被拒"这一半——我原只想着"攻击要被抓"，结果先抓到了自己。

### 例 81：性能预算的判别力有上限，不是"定得松"
`0.4x 4K`（3840→1536，倍率 2.5）走 generic tap walk。我对该分支做的三种变异
（重复写回、累加两次、逐像素浮点除法）都只让它的耗时变化 **1.02–1.05x**。
⇒ 这个用例上 **ms 预算从根本上无法表达"2x 算法回归"** —— 固定开销（Surface 构造、
逐行遍历、写回）占绝大部分。280ms 的预算只能抓 ≥8x 的结构性退化。

**教训**：
1. **一个用例的预算宽，可能因为它测的本来就不是算法**。判断依据不是"预算/空闲 比值"，
   而是"**对这个用例做真实算法退化，耗时变多少**"。变异测不出变化 = 该用例无判别力。
2. 同族：我此前把"预算 = 4x 空闲"当标准，以及后来"按负载峰值 × 2"当标准，
   都只是**避免假红**的口径，没有回答**能不能抓真回归**。
   **两个问题必须分开测：假红率（负载下跑 N 轮）与检出率（真退化跑一次）。**
3. 处置要诚实：**不要为了让指标好看而调预算**，要在注释里写明该 case 的判别力上限，
   并把真正的精细守护交给能测出来的用例（本例 0.5x 4K 是 uniform 路径，变异到 3.1x）。
### 例 82：验证脚本本身必须先自检
批64 我写"提取 gate 真实代码块跑五场景"的红证脚本，**连续三轮结果全错**，而每一次
我都差点当成结论上报：
1. `sed -n '358,364p'` 只取到 `echo` 行，缺 `exit 1`/`fi` ⇒ 提取块是**语法不完整的 if**，
   bash 直接报错退出（rc=2），五场景全显示"no-failure"。我第一版把这个读成
   "硬化没生效"。
2. `bash -c "$(cat blk.sh)"` 里多行 `'...'` 被二次解析破坏 ⇒ 换成 `bash blk.sh`。
3. **我把 `if cmd; then` 的退出码语义写反**：`rc=0` 表示"无失败"，`rc!=0` 表示"报失败"，
   而我在打印标签里写成了反过来。前三轮"全部 BAD"其实全是这个映射错。

**教训**：
1. **先跑一个已知答案的场景**（healthy → 必须 no-failure）。如果它都错，
   错的一定是脚本，不是被测对象。我这次恰恰是 healthy 先报 BAD 才去排查的。
2. 提取代码块时必须验证**块的完整性**（有没有 `if` 没 `fi`、有没有 `then` 没 `exit`），
   类似 `bash -n` 对片段无效。
3. 断言映射（rc → 语义标签）要写在一处并单独核对一遍，不要在同一行里边映射边判断。
4. 这与例 80（`bash -n` 通过 ≠ 能工作）是同一族：**验证工具的正确性不在验证工具的
   检查范围内**，必须用"已知答案"反向自检。
### 例 83：把"谁守护谁"当成常识写注释，结果全反
批63 我在 bench 注释里断言"精细守护交给 `0.5x 4K`（变异能到 3.1x）"。审计 X 用
**分支级变异**推翻：`0.5x 4K` 对 generic 路径退化**完全免疫**（0.94x / 0.97x），
它只响应 uniform 快路径变异（13.92 → 24.89 = 1.79x）。真正能放大 generic 变化的是
`0.8x`（1.91x）。

我此前的变异方法错在**只改一条分支却以为在测整个函数**：我把 ResampleArea 的
generic 行循环改了三版（重复写回、累加两次、逐像素浮点除法），看到 0.4x 4K 只变
1.02x，就得出"这个大用例无判别力"。X 的做法是把 uniform 与 generic **分别**变异，
于是立刻看出每个 case 绑定哪条分支。

**教训**：
1. 一个函数有多条路径时，**变异必须按路径分别打**，否则"某 case 不响应"既可能是
   "该 case 走另一条路径"，也可能是"变异无效"。这两种解释我混用过。
2. 写"X 用例守护 Y 实现"之前，必须证明**Y 的实现被改坏时 X 会红**；
   而不是"Y 被改坏时某个用例红了"。这是批44 那条"证明路径 ≠ 证明断言"的同族，
   只不过对象从断言换成了用例。
3. 反向也成立：**不能因为一个用例对某变异免疫就删它**。`0.4x 4K` 对 generic 小变化
   不敏感，但它是唯一的"2.5 倍非整数倍率"覆盖，价值在输入形状不在判别力。
4. 我的表格与审计的表格冲突时，先假设**我的表错了**（本例确实是我跑了旧版本代码）。
### 例 84：自检只钉"接受"方向 = fail-OPEN，比原缺陷更危险
批65 我给 gate 提取器加了自检，但只断言"健康日志被接受"。审计 X 指出：当函数变成
`return 0` 时，**自检通过、真实检查也通过** —— marker 门彻底失效，gate 仍打印 PASS。
用 HEAD 原文实测证实：
```
BASELINE         selftest=ACCEPT real_attack=REJECT  ok
ALWAYS_ACCEPT    selftest=ACCEPT real_attack=ACCEPT  FAIL-OPEN（marker 门已死，无人发现）
ALWAYS_REJECT    selftest=REJECT real_attack=REJECT  fail-closed（gate 退出）
```
**规律**：自检必须同时钉住"该接受的接受"与"该拒绝的拒绝"。只测一半的方向，
恰好放行"永远通过"这个最致命的方向。原缺陷（正则写坏）是 fail-closed（假红，
一定被看见），`return 0` 是 fail-open（假绿，永远没人报）。

### 例 85：区块"不闭合"—— 目标用例 OK 之后的文本仍算进它的块
批66 审计 Y2 发现：`inb = (name == want)` 在 OK/FAIL 行仍为 1（名字相同），块要等
**下一个用例的 RUN** 才关闭。实测：
```
marker-after-OK    want=reject  got=accept  *** WRONG ***
marker-after-FAIL  want=reject  got=accept  *** WRONG ***
```
修法：先剥出 tag，`tag=="RUN" && name==want` 才置 1。
**教训**：任何"区间提取"必须同时定义**开启**与**关闭**条件。只写开启条件时，
区间会延伸到下一个开启点，把尾部内容全部吞进来。这与例 83 同族：**断言/提取器的
边界条件必须逐一枚举并实测，不能靠"看起来对"**。
当时 harness 恰好不会在 OK 之后打印别的东西，所以不可利用 —— 但"当前不可利用"
不等于"不用修"，它正好削弱了我刚加的自检。

### 例 86：注释里的性能数字必须可推导，不能抄一次测量
我写过 "only catches >=8x"（无推导）、"0.12 -> 9.05-9.22 ms"（他人无法复现）、
"per-pixel division is 10x"（只在整条快路径被替换时成立，只加除法是 2.3x）。
审计 X 与 Y2 各自复现出不同数，两人互相也不一致。
**改为可推导的形式**：敏感度 = budget/base，直接从基准表算出 5.5x-12.1x；
并明确写出"2x 结构性回归**不可见**"这个反直觉结论。
**教训**：注释里的数字若不能由代码内其他数字推导出来，就一定会随环境漂移并成为
误导。要么给公式，要么给区间 + 多机标注，要么不给。
### 例 87：单引号程序内部的撇号会撕开 shell 引号，而 `bash -n` 发现不了
批67 我在 awk 单引号程序**内部**加了注释，里面写了 `'ok'` 和 `'[rtsc-server] ...'`。
撇号闭合了 shell 的单引号，于是 awk 程序被切成多个 shell 词，其中的 `#` 行变成
**shell 注释**（被丢弃），后面的正则/语句也全部错位。

**关键**：`bash -n scripts/linux-build-gate.sh` 返回 **0** —— 因为撇号是成对出现的，
全文件引号总量恰好平衡。实际行为变成提取器**永远返回 accept**（所有场景都对，
包括本该 reject 的四个）。

**检测方法**：
1. 把函数体单独切出来 `bash -n`（片段级检查）——本例中片段 rc=2：
   `syntax error near unexpected token '}'`。
2. 更可靠：**跑场景矩阵**。本例 6 个场景里 4 个从 reject 变 accept，矩阵立刻暴露。
3. 规则：**awk/sed 单引号程序内禁止出现任何撇号**（含英文缩写 it's、引号包裹的词）。
   要引用就在程序外写好再 `-v` 传入。

**同类**：例 80（`bash -n` 过但函数静默返回非零）、例 84（自检只钉单方向）。
共同结构：**语法检查器不检查语义**；唯一可靠的验证是"已知答案的场景矩阵"。

### 例 88：用预算证明灵敏度是循环论证
Y2 指出：budget 是按负载峰值标定的。若用 `budget/base` 反过来宣称"能抓 N 倍回归"，
那么把 budget 调大，算出的 N 就变大，而实际探测能力**变差**。
`budget/base` 是**阈值倍数**（"多大墙钟倍数会越过预算"），**不是**最小可检测回归；
两者只在"回归是纯倍乘"时相等。真实回归带固定开销时严重不等
（1:1 的 2x 工作量只涨 1.31x）。
**规则**：说 "trips at Nx wall-clock"（阈值），不要说 "catches Nx algorithmic
regressions"（检测能力）；并标明是 idle 口径还是负载口径（同一用例两者差约 3 倍：
8.3x vs 4.9x）。
### 例 89：自检只钉"位置"不钉"精确匹配"，四个宽松化变异全部穿透
批66/67 的自检六个边界都在验证"marker 是否落在正确的块内"，**从不验证**：
- marker 文本必须**完整**匹配（不是前缀）
- 用例名必须**完全相等**（不是前缀）

审计 Y2 据此构造四个变异，全部 rc=0 通过自检：
```
MARKER_LOOSE  (/drain:/)               rc=0 漏
MARKER_PREFIX (/drain: challenge/)     rc=0 漏
NAME_PREFIX   (index(name,want)==1)    rc=0 漏
NAME_PREFIX2  (substr 前缀比较)        rc=0 漏
```
**规律**：边界测试只覆盖"在哪"，不覆盖"匹配多严"。任何正则/比较的**松紧**是独立维度，
必须单独设探针：截断输入的尾部（不是追加后缀）+ 前缀用例名。
**坑**：截断探针必须用 `${marker%??????}`（去掉尾部）。我最初想用 `"$marker truncated"`
—— 那仍含完整 marker，探针变成空断言，baseline 自己就红。

### 例 90：我加了一个"永远通过"的守卫，还以为它有效
批67 我加静态守卫检测"awk 程序内不得有撇号"。它**从未生效**：
守卫自己的头部 `awk -v q="'"` 带两个撇号，状态机把它当成"程序内撇号"并立刻关闭状态。
实测把原错误重新注入，守卫**保持沉默**。删掉了。
**教训**：
1. **任何守卫必须先证明它在攻击下会红**（Rule 16 对守卫本身同样适用）。
   我连续两个批次在这里翻车（例 84 是 fail-open 自检，本例是死守卫）。
2. 死守卫比没有守卫更糟：它制造"已覆盖"的错觉。
3. 偶奇校验抓不到本例（6 个撇号，偶数，`bash -n` rc=0）——
   **想当然的检测方案要先反证**。
4. 正确的语义闸是场景矩阵（七边界自检），不是静态扫描。

### 例 91：改一处大小写，根因在另一处
Y2 指出 RUN 的 open 条件写死 `tag == "RUN"` 而 close 白名单已大小写不敏感。
我改成 `tolower(tag) == "run"` —— **8 个 RUN 拼写仍然全部 reject**。
逐字段打印才发现根因在**名字剥离正则**的 `[A-Z]+`（只吃大写）：
`[ Run  ] case` 时 `name` 保留整行，`name == want` 永假。
**教训**：同一语义（"大小写不敏感"）在一条流水线上有多处实现时，
必须逐处检查；改掉日志/错误信息里最显眼的那处，不等于改了根因。
验证方式：**逐字段打印中间值**（`tag`/`name`/`tolower`），而不是猜。### 例 92：审计把"更宽松的拼写匹配"误报成 fail-open —— 要用"无输入"场景判别
Y2 报 `/[Dd]rain:/` 是 fail-open。我用**无 marker 的三场景**判别：
```
variant         empty block   unrelated text   another case has it
exact (base)    reject        reject           reject
[Dd]rain        reject        reject           reject
tolower         reject        reject           reject
```
三者都在"没有 marker"时 reject ⇒ `[Dd]rain` 只是**接受更多拼写变体**，
无法让"某个用例没打印 marker"通过。它**不是**假绿。
**判别法**：要证明一个"放宽"是 fail-open，必须给出一个**输入**使它 accept 而正确实现 reject。
只是"接受更多正常输入"是宽容，不是漏洞。
（同理：`tolower` 那种"忽略大小写"也是拼写宽容 —— 它 accept 的是大写 marker，
真实 harness 打小写，所以不构成假绿；但它确实降低了"marker 必须原样出现"的约束。）

仍值得加探针的理由是另一个：这类放宽会**掩盖 marker 文本被改动**（例如常量被改大小写后
测试仍绿）。所以按"约束强度"而非"假绿"来加，措辞必须准确。

### 例 93：截断探针有三个独立方向，不是两个
批68 加了 tail 截断，批69 Y2 指出还漏：
- **TAIL**（只匹配后半段，如 `/record/`）
- **MID**（只匹配中间片段，如 `/coalesced record/`）
- **大小写**（`tolower` 或 `[Dd]` 类）
实测三个里前两个在七边界下都是 ACCEPT（漏）。
**规律**：任何"模式匹配是否过松"的验证，至少要覆盖 **头、尾、中间、大小写** 四个方向。
只截尾部只能证明"不是只匹配前半段"。
（`[Dd]rain` 型用交替大小写也抓不到 —— 因为它接受 `Drain` 而交替串是 `DrAiN`；
但这类不是假绿，见例 92。）
### 例 94：我写进注释的"机制解释"是错的，而结论恰好对了
批69 我在 gate 注释里写：`declare -A` 时 "printf -v writes element [0] and leaves
$logvar empty, so every probe runs against an empty path"。
审计 X 指出这是错的，我实测确认：
```
declare -A V=([k]=orig); printf -v V '%s' "/tmp/probe"
  scalar=[/tmp/probe]  elem0=[/tmp/probe]  elemk=[orig]
  wc -l < "${V}" -> 3   （路径可打开）
```
`printf -v` 写 `[0]`，`$V` 读 `[0]`，**读写同址**。数据路径完好，自检在数组下完全正常。
我"自检失效"的结论是错的；"仍应拒绝数组"的**动作**碰巧是对的。

**教训**：
1. 注释里的"为什么"必须和"做什么"同等验证。我只测了"rc=0"就编了一个机制解释。
2. 观察到"rc=0"有两个竞争假设（探针失效 / 探针正常但目标本身合法），
   我没有区分就选了更戏剧化的那个。
3. **区分方法**：换一个"该红"的输入（损坏的提取器）看是否仍红 —— 但这只能证明
   "不是假绿"，不能证明"探针路径完好"。要证明后者必须直接观察数据路径
   （打印 `$V` 与 `${V[0]}`）。
4. 三方各错一次：我编错机制，X 第一次说"路径为空"，X 第二次更正为"读写同址"。
   **唯一可靠的是逐项打印中间值。**

### 例 95：变异脚本随源码演进而静默失效
批69 我把 `tag == "RUN"` 改成 `tolower(tag) == "run"`，但 `rule16_b68.py` 里的
变异用旧字符串做替换。批70 运行它时：
```
NO_CLOSURE      ACCEPT ACCEPT  *** MISSED ***
BAD_REGEX       ACCEPT ACCEPT  *** MISSED ***
```
看起来像"两个变异逃逸"，实际是 **`String.Replace` 没匹配上、变异根本没应用**。
换成按新源码字符串的 `rule16_final.py` 后 11/11 全 caught。

**教训**：变异测试的第一步不是"看结果"，而是**断言变异已应用**。
所有变异脚本必须打印/校验"替换次数 == 1"，否则失败要显式报错，不能静默继续。
（这是例 82 的同族第二次复发：验证工具自身的正确性不在它的检查范围内。）

### 例 96：逐字符类正则宽松（`[Dd]rain`）是已知盲区，但**不是** fail-open
现有的"全大写"与"交替大小写"探针都抓不到 `/[Dd]rain:/`：
- 全大写 `DRAIN` 不匹配 `[Dd]rain`
- 交替 `DrAiN` 也不匹配（`[Dd]` 只接受单字符大小写）
唯一能抓的是首字母大写 `Drain`，但那个形状我没加进 gate。

**但它不是 fail-open**：无 marker 三场景（空块 / 无关文本 / 别的用例有 marker）
下 `[Dd]rain` 全部 reject。它只是**接受更多拼写变体**，无法让没打印 marker 的用例通过。
**判别标准**：要证明 fail-open，必须给出一个"正确实现 reject 而它 accept"的输入。
"接受更多正常输入"是宽容，不是漏洞。登记为已知盲区，不修（整行锚定会要求 printf
格式永不改缩进，风险收益不划算）。
### 例 97：审计用"自己重写的等价物"验证，得出与真实代码相反的结论
审计 X 报我注释"the alternating probe's first letter is upper-case"是错的，实测小写 `d`。
**他自己错了**：他用 Python `i=0` 起枚举（`c.upper() if i%2 else c.lower()`）得到 `dRaIn`；
而 gate 里的真实构造是 awk **1 基**：
```awk
for (i=1;i<=length($0);i++) { ... ((i%2)?toupper(c):tolower(c)) }
```
`i=1 -> i%2=1 -> toupper` ⇒ 首字母大写 `D`。X 在续报里主动撤回。
**教训**：审计别人构造的字符串时，必须**复用同一个构造函数**（直接运行源码里的那段），
不能用自己的语言重写"等价物"。这是"变异必须来自真实函数体"规则的另一面 ——
我对变异有这条规则，对"构造探针输入"却没有，结果是同一个坑的两端。
（我这轮也犯了镜像错误：批70 的注释里写"catches the second shape"但没同步自己的实测结论，
是"结论更新了、注释没更新"。两个错误方向相反，根因相同：**注释与代码/实测脱节**。）

### 例 98：nameref 会完全绕过数组守卫
`declare -n` 的 `declare -p` flag 串**只有 `-n`**，不含目标变量的 `-a/-A/-i/-r`：
```
nameref -> 数组  : flags="-n"，printf -v 写穿到 REAL[0]，数组守卫完全看不见
nameref -> readonly : printf -v 报 readonly（目标自身拦住，rc=1）
nameref 链 A→B→C : 写穿到 C
nameref -> 未设置 : printf -v 创建一个新的全局变量（副作用）
```
**规律**：任何"按 flag 串判断变量形态"的守卫，对 **nameref 一律失明** ——
因为 flag 串描述的是引用本身，不是目标。
**处理**：nameref 必须与数组/整数/只读同级拒绝（`*n*` 分支），
理由不是"它坏了"，而是"数据路径不可见"这个原则（与数组同标准）。
### 例 99：锚点不是万能药 —— 它闭合一个口子，同时开两个新口子
我在 KNOWN GAP 注释里写"闭合 `[Dd]` 缺口需要整行锚定 `^[[:space:]]*marker$`"。
审计 X 用真实函数体实测四象限：
| log | real | [Dd] | 锚点+drain | 锚点+[Dd] |
|---|---|---|---|---|
| canonical     | ACCEPT | ACCEPT | ACCEPT | ACCEPT |
| capitalized   | REJECT | ACCEPT | REJECT | **ACCEPT** |
| inline-ref    | ACCEPT | ACCEPT | **REJECT** | **REJECT** |
| trailing-text | ACCEPT | ACCEPT | **REJECT** | **REJECT** |
锚点**闭合不了** `[Dd]`（`anchor_dd` 仍接受 `Drain`），还**引入两个假红**。
**教训**：
1. "更严格的匹配"不等于"闭合某个漏洞" —— 必须先证明它在**该漏洞的输入**上确实收紧。
2. 严格化会**移动**假红的边界，不是消除假红。改匹配方式前必须同时测
   "该拒的仍拒"与"该受的仍受"两侧。
3. 我在注释里写"pin the printf indentation forever"也不准确 ——
   `^[[:space:]]*` 明确允许任意缩进。**描述一个方案时，要读它自己的正则**。

### 例 100：修好一个 bug 后必须补一条"钉住该修法"的探针
批68 修了 `[A-Z]+` → `[A-Za-z]+`（小写 RUN 打开块）。批72 审计 Y2 实测：
把这个修复回退成 `[A-Z]+`，**11 个探针全绿**，无任何探针察觉。
原因：所有探针的 RUN 行都是大写 `[ RUN  ]`，而 `[A-Z]+` 也能匹配大写 ——
**只有小写 RUN 才能区分两版**，但没有探针喂小写 RUN。
**规律**：修复一类输入时必须补该输入的探针，否则修复本身没有回归保护。
"当前不可达"（harness 只打大写）不构成不补的理由 —— 恰恰因为不可达，
回归时没有任何其他路径能发现。
补一条 `[ Run  ]` 的 expect_accept 后，回归从 survived 变 caught。

### 例 101：守卫的"入口校验"漏了最常见的形状 —— 未设置变量
`declare -p` 对**未设置**变量返回空字符串，于是 `flags=""`，
`*r*|*a*|*A*|*i*|*n*` 五个分支全不匹配 ⇒ 无守卫。
实测它不是 fail-open（`printf -v` 会创建普通标量，数据路径完好），
但它意味着**调用方拼错变量名时，自检会静默测试一个新建的空变量，
而真正的日志从未被读取**。
**教训**：枚举"变量形态守卫"时，**"未设置"是一个必须列出的形态**，
不能只列已存在的形态（标量/数组/整数/只读/nameref）。
这与例 105 的"枚举必须包含空/零"同族。
### 例 102："不可构造"的结论必须按构造形式分类，不能一例否定全体
我实测 `declare -in V=R` 报 `V: not found` 且变量没创建，据此断言 **`-in` 不可构造**。
审计 X 指出：这只对**带赋值**的单条语句成立。实测四象限：
```
declare -in V          -> flags=[-in]   <- 可构造
declare -in V=R        -> flags=[]      <- rc=4，失败
declare -in V=42       -> flags=[]      <- rc=4
declare -in V=NOEXIST  -> flags=[]      <- rc=4
```
**一个反例只能否定一种构造形式，不能否定整个形状。**
`declare -in V`（无赋值）是合法的 `-in` 变量，能到达守卫，调序后报 nameref 正确。

**教训**：
1. 断言"X 不可构造"前，必须枚举**构造语法**的形态（带赋值/不带赋值/多变量/数组/引用），
   每个形态各测一次。这和"枚举 IF 与 ELSE 两条分支"是同一条规则。
2. 我用"带赋值"这一种形态的失败，否定了整个 `-in` 形状的可达性 ——
   这是**以偏概全**，而且它恰好是唯一会改变判词的那一种输入。
3. 更糟的是：我的**代码是对的**（调序了），但**理由是错的**。
   错误理由会误导后来者把改动回退。**理由与改动同等重要**（同族于例 94）。

### 例 103：一条好的新探针会顺带闭合多个盲点
批72 加的 1 条 `[ Run  ]`（混合大小写 RUN）探针，除了钉住 Y2 发现的
`[A-Z]+` 回归，还**顺带把 `CASE_BUILTIN` 从逃逸变成被捕获**：
```
上一轮（11 探针）: CASE_BUILTIN  GREEN（tag=="RUN" 与 tolower(...) 语义等价）
本批  （12 探针）: CASE_BUILTIN  RED  （新探针喂混合大小写，tag=="RUN" 会拒）
```
**规律**：探针的覆盖不是"一个探针一个变异"的线性关系。一条覆盖"输入形态"的探针
（这里是"小写/混合大小写 RUN"）会同时覆盖该形态下的所有相关变异。
所以加探针时优先加**新输入形态**，而不是为每个变异各加一条同形态的探针。
### 例 104：空串能穿过"必须含非法字符"的过滤
plan 里记着的遗留项："`linux-gate-logs.`（空后缀）会被当 PID 目录"。
根因：
```bash
suf="${d##*.}"                       # "linux-gate-logs." -> ""
case "$suf" in *[!0-9]*) continue ;; esac   # 空串没有非数字字符 -> 不匹配 -> 放行
```
这个过滤器的语义是"**含非数字字符就跳过**"，它拦不住**空串**（空串没有任何字符，
自然也没有非数字字符）。于是 legacy 目录 `linux-gate-logs.` 被计数、被删除，
还吃掉 5 个配额中的一个。实测确认：8 个目录轮转后 `linux-gate-logs.` 消失。

**修法**：白名单式匹配完整形状（`"$prefix".<digits>`），并显式写 `''|` 排除空串：
```bash
case "$suf" in ''|*[!0-9]*) continue ;; esac
```
**教训**：
1. **"拒绝含 X 的输入"与"接受仅由 Y 组成的输入"不等价** —— 前者漏掉空串。
   安全过滤器要用白名单（只接受合法形状），不要用黑名单（拒绝已知坏形状）。
2. 空串/空集合是"字符类过滤器"的通用盲点，同族于"循环边界必须分析首/尾/空/满"。
3. 这条在 plan 里已经记了很久但没人修，因为它的表述是"低（不影响有界性）"。
   **实际影响不止有界性**：它删除了本应永久保留的 legacy 证据。
   "不影响 X" 的评估必须列举**所有**受影响的不变量，不能只看被问到的那一个。

### 例 105：判据必须对准被修的那个不变量
我给 rotate_logs 写回归判据时，第一版是"带点目录死亡 **AND** PID 目录数变 4"。
实测回归版：带点目录确实死亡，但 PID 目录**仍然是 5 个** —— 因为带点目录不占配额，
删掉它不改变 PID 目录的保留数。第一版判据因此报 "*** SURVIVED ***"，是**判据错**不是测试无效。
改成"只看带点目录是否存活"后正确 caught。
**教训**：回归判据必须**精确对准被修的不变量**。把"修复的观察"和"修复的副作用"
混在一条 AND 里，会让判据在副作用不变时误报"未捕获"。
### 例 106：恢复源码后必须 touch，否则增量构建沿用旧对象文件
Rule 16 验证 D1 时：变异 → 编译 → 测试红（正确）；然后 `Copy-Item` 恢复备份，
md5 与 `git diff` 都确认源码已回到基线，**但测试仍然红**。
原因：`Copy-Item` 把 mtime 退回到备份文件的原值（早于目标 .obj），
MSBuild 据此判断"源文件没变"而**跳过重编**，跑的还是变异版二进制。
必须显式 `(Get-Item $src).LastWriteTime = Get-Date` 后再 build。

**为什么差点误判**：我看到"源码 md5 已恢复 + 测试仍红"，
第一反应是"源码恢复不完整"或"还有别的原因"，而真因是**构建产物没更新**。
"源码对了"与"被测二进制对了"是两件事。

**规则**：
1. 变异测试的恢复步骤必须包含 `touch`（memory 里已有这条，这是我第二次踩）。
2. 恢复后验证要通过**重编日志**确认目标确实重编（`order_engine.cpp` 出现在构建输出里），
   而不只是对比源码 hash。
3. 判断"测试仍红"的性质时，先问"跑的是新二进制吗"。

### 例 107：plan 标记滞后于代码，必须定期复核而不是照着标记做
`plan.md` 把判据3c 标为 `[~] 修复中（D1）`，读起来像还有活要干。
实际复核：D1 已在 `order_engine.cpp:189-195` 修复（noop 单独计数）、
`:253` 中止条件已排除 unsupported、集成测试 `test_order_engine.cpp:199` 已存在并断言
`noop==1 && applied==1 && unsupported==0` 且后续订单仍绘制；D2/D3/D4 也全部到位。

**教训**：
1. **记忆里的状态标记不是事实，是线索**（memory 顶部那条规则同样适用于 plan 的复选框）。
   `[~]` 不等于"未修"，`[x]` 也不等于"已验证"。
2. 关闭一个 item 前必须逐条复核**证据位置**（文件:行），不能因为"看起来做过"就勾选，
   也不能因为标记是 `[~]` 就重做一遍。
3. 这类"标记滞后"会双向浪费时间：既可能重复劳动，也可能让真正未修的项被 `[x]` 掩盖。

### 例 108：混合编码文件的字节级安全编辑
`.opencode/plan.md` 含历史坏字节（不是合法 UTF-8），`python3 io.open(..., encoding='utf-8')`
直接 `UnicodeDecodeError`。用 PowerShell 按字节定位 `- [~] ` 前缀，
确认后继是目标条目的 ASCII 前缀后，只把 `~`(0x7E) 改成 `x`(0x78)，
长度从 121311 不变，`git diff` 只有 1 行变化。
**教训**：对编码不干净的记忆文件，**按字节做最小差分**（定位 → 校验上下文 → 单字节替换 →
长度校验），不要整体解码-重编码（会二次损坏原来的坏字节）。
### 例 109：surrogateescape 解码 + join 会合并行；混合编码文件必须全程字节级操作
批76 我要在 `plan.md`（含历史坏字节）里勾选 8 个复选框。第一版做法：
```python
t = raw.decode('utf-8', errors='surrogateescape')
lines = t.split('\n')
...
io.open(p,'wb').write('\n'.join(lines).encode('utf-8', errors='surrogateescape'))
```
结果：**行数从 1571 骤降，中文行全部黏在一起**。原因：文件里有裸 `\r`（CR 未跟 LF）
作为行内字符，`split('\n')` 不会断开它们，而原文件实际是"某些行以 CR 结尾"，
`split('\n')` 把多行当成一行；重新 join 时又插入 `\n`，于是内容错位。
（无论机制细节如何，可复现的事实是：**解码-改-重编码改变了文件结构**，
而 `git diff` 显示大量中文行被合并。）

**正确做法：全程字节级**
```python
first = raw.find(b'TranslateInput(ev(640,512)')       # 唯一 ASCII 指纹定位
block_start = raw.rfind(b'\n', 0, first) + 1
block_end = raw.find(b'\n### ', block_start)          # 块内无空行，不能用 \n\n
block = raw[block_start:block_end]
lines = block.split(b'\n')                            # 逐行，不碰编码
for i, ln in enumerate(lines):
    if ln.startswith(b'- [ ] '):
        lines[i] = b'- [x] ' + ln[6:]                 # 只改第 4 个字节
wrapper = b'\n'.join(lines)
```
证据文本也只用 ASCII。结果字节数 123500→124617（+1117 全部来自新增 ASCII），
行数 1571→1589（+18 行证据），结构完好。

**规则**：
1. 混合编码/含坏字节的文件，**禁止整体解码-改-重编码**；用 `bytes.find` / `bytes.replace`
   做最小差分，并在写回后校验**行数变化符合预期**（只应等于新增行数）。
2. 写回前先 `cmd /c "git checkout -- <path>"` 回到干净基线再重做，
   不要在已损坏的工作树上继续叠加修改。

### 例 110：锚点必须唯一且限定在目标块内
同一批里，我用「文件里第一个 `fail-closed`」作为插入点，结果证据被插到 `:165`
——那是另一个章节的同名短语。第二次用唯一 ASCII 指纹
（`TranslateInput(ev(640,512)`）并**把搜索范围限制在这个块的起止之间**才正确。

**这与"变异必须来自真实函数体并断言唯一"是同一条规则的推广**：
任何按内容定位的编辑，都必须
1. 断言指纹在**目标范围内**唯一（不是全文件唯一那么简单）；
2. 定位后回读校验（`grep -n` 确认插入位置在预期行号区间）。
### 例 111：现有测试对"跨线程观测面缺失"完全免疫（F-6 移动合并）
`desktop_input_win32.cpp` 的移动合并/节流逻辑有 4 段关键判断，**任何一段改坏，70 个用例全绿**：
| 变异 | 行 | 现有套件 | 独立探针 |
|---|---|---|---|
| 合并改逐条 Emit | `:522` | 70/13934 全绿 | P2/P8 红 |
| 去掉 `+kMoveInterval` | `:463` | 全绿 | P2 红 |
| 删点击前 `FlushSessionMove` | `:529` | 全绿 | P3 红 |
| 删 `last_move_sent_.erase` | `:440` | 全绿 | P6 红 |

根因：**套件唯一的跨线程信号是 `Stats().injected`**，每个成功动作只 +1（`:631-633`），
不含坐标、顺序、时间。`pending_moves_`/`last_move_sent_` 是 worker 私有的（`:729-734`），
钩子头（`tests/desktop_input_win32_test_hooks.h`）也没有 move 观测入口。
于是"发什么/什么顺序/何时发"全都不在断言面内 ⇒ 变异只改变内容不改变计数。

**规则**：只要被测逻辑的输出是"动作序列"而不是"计数"，就必须有能观测**动作内容与顺序**的 seam；
纯计数器只能证明"发生了 N 次"，不能证明"发生的是正确的那 N 次"。

### 例 112：MoveDue 二次采样时钟（真实缺陷，平台相关表现）
```cpp
Clock::time_point MoveDue(uint32_t id) const {
    auto it = last_move_sent_.find(id);
    if (it == last_move_sent_.end()) return Clock::now();   // 第二次采样
    return it->second + kMoveInterval;
}
void EmitDueMoves() {
    const Clock::time_point now = Clock::now();             // 第一次采样
    ... if (MoveDue(id) <= now) { Emit(...); }              // 后采 <= 先采？
}
```
末知 session 时 `MoveDue` 采的时间**晚于** `now`，所以 `<= now` 恒不成立，本轮不发，
靠下一轮重试。主代理在 Windows 实测：`avg_passes=1.2355 max=2 stuck=0`（2000 会话），
`consecutive_samples_equal=1611/2000`（该时钟粒度粗，两次采样常相等，常一次就过）。
同一代码写在 1ns 分辨率时钟上则**无限自旋**（Linux 复现 `stuck=200`）。
审计 A 的探针报 `avg=3.27 max=13`（其会话数与节奏不同）。

**规则**：`MoveDue` 这种"纯查询"函数**禁止自己取时钟**；时间点必须由调用方传入，
一次逻辑操作只采样一次。这样既消除二次采样，又让测试可以注入确定性时间。

### 例 113：ReleaseSession 后仍可能发出一帧移动（跨事件窗口，行为缺陷非 UAF）
`ReleaseSession`（`:196-215`）只把 id 放进 `forget_sessions_` 并 notify；
真正清 `pending_moves_`/`last_move_sent_` 在**下一轮** `WorkerMain` 顶部的
`ForgetReleasedSessionsLocked()`（`:437-440`）。而 `:415 EmitDueMoves()` 在 wait 返回后、
下一轮 Forget 之前执行；`Dispatch` 的非 move 分支 `:529 FlushSessionMove` 也不查 forget。
⇒ 已 pending 且到期的 move 会在 `ReleaseSession` 返回**之后**被发出，
违反 `:429-435` 注释的 "cannot move the pointer after the release"。

这是**行为缺陷**，不是内存安全（`Emit` 只碰 sink 自身成员；宿主析构前必走 `Shutdown`
`:662-700` join worker）。确定性复现需要 worker gate（现有 `SetDesktopInputDispatchFailureHook`
只能在 Dispatch 顶部阻塞，恰好可用作闸门）。

**规则**：向 worker 投递"遗忘请求"后，**同一轮**必须先把该 session 的所有挂起状态清掉再发任何动作；
把清理放在循环顶部等于给出一个"清理前窗口"，任何在该窗口内到达的动作都不受约束。
### 例 114：变异必须保证"编译通过"，否则不是测试红证
批77 的 M2 变异本想删掉移动节流：
```cpp
return it->second + MoveInterval();   // 原
return it->second;                    // M2 第一版
```
结果 **构建失败**：`MoveInterval()` 从此无人调用，`/W4 /WX` 下的 C4505
（"已删除具有内部链接的未引用函数"）被当成错误。跑出来的"失败"是编译错误，
不是测试断言红——**这个变异什么也没证明**。

改成 `return it->second + MoveInterval() * 0;` 后编译通过，3 个用例真正变红。

**规则**：变异验证必须分两步判定——先确认 `BUILD_EXIT==0`，再看测试红。
构建失败的变异体一律作废重设计。反过来，`/WX` 的 C4505 顺带证明了
"删掉节流逻辑"这类改坏确实会让整个函数变成死代码，是有效的静态信号。

### 例 115：变异矩阵不能累积应用
第一轮我写了循环，在同一个工作树上依次套 M1→M2→M3→M4→M5，
每轮只做 `--build` + 跑测试。结果**五个变异全部报同样的 4 failing**。

原因有两层：
1. M2 那轮构建失败，跑的是 M1 留下的旧二进制；
2. 更根本的是每个变异都叠加在上一个变异之上，M5 的失败其实是 M1..M5 的并集。

正确做法（第二轮）：**每个变异前先从干净基线恢复，断言替换次数 == 1，
再编译、再跑**。改完后 5 个变异给出 5 组不同的红名单，
且 M4 只红了 1 个用例——这才说明每条用例的针对性是真的。

**规则**：变异之间必须完全独立。恢复动作要**验证文件确实回到基线**
（hash 或 `grep` 反向确认变异串 0 命中），不能只靠 `Copy-Item` 成功。

### 例 116：release/acquire 只给"最终一致"，不能当屏障用
批77 用 release 原子发布 worker 私有的两个 map 的 size，测试侧 acquire 读。
表面上这是标准的 acquire/release 配对，但审计 B 指出：**它只证明
"那次 store happens-before 这次 load"，不证明"读完之后 worker 不会再 emit"**。

原因是 worker 的序列是：
```
Emit(...) → PublishMoveCountsForTest()      // 同一个 Dispatch 内
... 队列里可能还有下一个 item → 又 Emit ...
```
于是"观察到 pending==0"之后仍可能再来一次 Emit。唯一的完整 happens-before
是 `Shutdown()` 里 `worker_.join()` 之后那次发布。

**规则**：把"最终一致"的观测写成最终一致——测试必须用 `WaitUntil` 轮询，
不能把单次观测当同步屏障。文档里必须写清楚这个降级，否则下一个读者会误以为
acquire 已经提供了顺序保证。（已写进 `tests/desktop_input_win32_test_hooks.h`。）

### 例 117：仅靠注释约定的"进程级测试钩子"要变成硬断言
`g_emit_hook` 和 `g_move_interval_ns` 是进程级全局，而"每个用例只创建一个 sink"
只是注释里的约定。审计 B 指出：两个 sink 同时存活就会把事件混进同一个日志。
修法不是重构（代价大），而是把约定变成断言：
```cpp
int g_live_emit_hook_guards = 0;
EmitHooksForTest() { ++g_live_emit_hook_guards; CHECK_EQ(g_live_emit_hook_guards, 1); ... }
~EmitHooksForTest() { ...; --g_live_emit_hook_guards; }
```
变异验证：把 `1` 改成 `99` → 5 个用例各红 1 次。
**规则**：凡是"约定俗成"的不变量，只要违反会导致难以诊断的错误结果，
就必须写成断言。注释只对遵守注释的人有效。
### 例 118：修对了不等于有回归网（MoveDue 二次采样 = known gap）
批77 把 `MoveDue` 里第二次 `Clock::now()` 改成使用调用方传入的 `now`（`desktop_input_win32.cpp:507`）。
修复本身正确，但批78 审计 A 独立复核发现：**把实现改回 `Clock::now()` 后，77 tests / 14022 checks 全绿**。

原因：二次采样只让 worker 多自旋一次（`EmitDueMoves` 调用次数 avg 3.27 → 2.15），
**输出内容完全不变**。批77 新增的 5 个用例全部基于"发出了什么"（Emit 钩子记录的动作序列），
而自旋次数不是动作序列的一部分，所以任何内容断言都抓不到它。

要钉住它只有一条路：加"调用次数预算"钩子并断言 `EmitDueMoves` 被调用了 N 次以内。
但自旋次数随负载浮动（实测 3.27/13 → 2.15/3 两台机器量级都不同），这种断言**跨负载不稳定**，
审计 A 明确不建议。故接受为 **known gap**，不做假测试。

**规则**：修复的正确性和修复的"可回归性"是两回事。当被修的东西只影响**延迟/资源**而不影响
**输出内容**时，内容断言体系天然覆盖不到它。此时必须：
1. 明确登记 known gap（不要声称"已覆盖"）；
2. 说明为什么不能加断言（跨负载不稳定、需要墙钟、会引入 flaky）；
3. 不要为了让变异变红而写一个依赖时序的假测试——那是把 flaky 当覆盖。

### 例 119：提交前必须检查暂存区是否混入流程文件
批78 我执行 `git add -A` 后，`.opencode/process.md`（第 917 轮记录，其中含**尚未经审计盖章**的
表述）被一并暂存。若直接提交，流程记录会以"已定案"的口吻入库，而实际结论还在复核中。

已 `git restore --staged .opencode/process.md`，只提交代码与文档，process 记录留到 W8 阶段
按最终结论重写。

**规则**：代码提交与流程记录分离。`git add -A` 之前必须先看 `git status`，
把 `.opencode/` 下的记忆文件从暂存区剔除；它们的写入时点是"结论已定案之后"，
不是"提交代码时"。

### 例 120：审计报告的"未跟踪文件"判断可能错，必须自己查 git 对象
批78 审计 B 报告"仓库根有 1 个未跟踪 0 字节文件"。实际核查：
```
$ git status --short
 D "%dn, X509_check_host(...)..."
$ git log --diff-filter=A --format="%h %ad %s" --date=short -- "*X509*"
407d03e 2026-10-31 fix(net,proto): harden hostname matching and verify the WebSocket upgrade
```
它是 **已跟踪** 的（`D` 状态，`git diff --numstat` 为 `0 0`），由 10/31 的提交误加入——
文件名是一段被 shell 误当重定向的 printf 参数。`git ls-files --others --exclude-standard`
之所以报空，是因为对含 `%`/`(`/`,` 的路径做了转义，不是"没有未跟踪文件"。

审计 A 后来用 `git cat-file -s "HEAD:<path>"` 确认 size=0，与我一致。

**规则**：关于"文件是否被 git 跟踪"，唯一可信的是 `git cat-file`/`git log`/`git status` 的
状态码，不是任何人的描述（包括审计报告）。`git ls-files --others` 对怪字符路径不可靠。
### ### 例 121：误判源文件损坏 + wc -l 是第一信号（合并原 121/122）
批 79 我发现 src/server/server.cpp 是 184 行、文件头是 .opencode/backups/...:1707: 前缀，
断定是审计 A 写坏的。**指控是错的**——文件内容干净（git diff --ignore-cr-at-eol 为空，git cat-file -s HEAD:... = 131926 字节，wc -l = 2801）。

**规则**：
1. 判断内容是否被改，可信的是 git diff --ignore-cr-at-eol，或 git cat-file -s HEAD:path 比对字节数 + wc -l 比对行数。wc -l 只能作为“值得怀疑”的信号，不能作为结论。git status 在该仓库会被 CRLF 假差异污染（整树 M 而内容全同）。
2. 读写源文件前先看行数量级。行数差一个数量级以上 + 文件头是 路径:行号: 前缀（两个独立指标同时异常），先怀疑内容被替换，不要继续在当前内容上做任何分析。
3. 指控他人/子代理之前必须自己先复核完整证据链，跳过“是不是我自己弄坏的”这一步是错的。
4. 恢复文件后必须重新核对，不能拿恢复前的观测当现状。
5. 派发只读任务时明确禁止在仓库路径下做输出重定向。
### 例 122：拿自造测试数据自证 = 循环论证（批84 教训，批85 纠正）
批84 我宣布"渲染本身是正确的"，依据是 test-pattern 的
`65537 distinct colours`。问题：那张测试图是我自己写进
`TestPatternSource` 的，我传它、我统计它、我再宣布它正确。整条链
没有接触任何真实桌面。

**规则**：验证链路时必须区分"被测系统"与"验证输入"。
用自产数据验证自产链路，只能证明"这段代码自己前后一致"，
不能证明"它对真实输入正确"。真机缺陷必须用真机证据
（真机 dump 的 non-black/颜色数、抓包、或用户目视）。

### 例 123：诊断采样上限会让诊断对它声称的范围失明（批84）
`count_non_black` 只采样前 1024 个像素（`if (colours.size() < 1024)`）。
1280 宽桌面首行恰好是纯白边框 -> 1024 像素全同色 -> `distinct` 恒为 1。
这个诊断对第 0 行以下的一切是盲的，而它正是回答"远程桌面画出来了吗"
的唯一自动证据。

**规则**：任何"统计/采样"诊断，其采样口径必须与它声称覆盖的范围一致。
有上限就必须在输出里写明上限，或直接全采样。

### 例 124：时机错误的观测等于错误结论（批85）
我枚举进程窗口得到 0，遂断言"GUI 根本没有窗口"。实际那次枚举
发生在 `--seconds 12` 到期、进程已退出之后。常驻运行下
`windows=4, RtscWindowClass vis=True` 稳定存活十余秒。

**规则**：观测结果必须与观测时机绑定记录。断言"X 不存在"之前，
先证明观测窗口内被测进程确实存活且处于目标状态。

### 例 125：调用点存在 ≠ 功能可用（批85 漏网原因）
`test_ui.cpp:1522` 断言 `src.find("ShowConnectionInfoDialog(nullptr")`
存在，于是"连接信息"被视为已覆盖。实际对话框因 `DefWindowProcW(nullptr,
WM_NCCREATE)` 返回 FALSE 而**从未被创建过**。

**规则**：结构化源码断言只能证明"这行代码还在"，不能证明"它有效"。
对"某个 UI 是否真的出现"，唯一有效证据是在运行进程里枚举到那个窗口
（或至少断言构造函数的成功条件）。

### 例 126：闪烁/抖动的根因通常是"重绘范围"，不是"重绘速度"（批86/87）
用户连续三轮指向同一现象，我一开始去查 CPU（实测单核 1.9%，不是瓶颈）、
查帧率闸门（已有 16ms 上限）、查尺寸变化（12 秒内仅 1 次）。
真正的根因是**每次更新都让整幅 1280x1024 重采样 + 全量字节转换 +
整客户区失效 + WM_PAINT 整幅 BitBlt**。

mstsc 平滑不是因为它画得快，而是它只画变化的那块矩形。

**规则**：远程桌面类客户端的绘制性能问题，先量化"每次更新的实际
重绘面积/字节数"，再谈优化。检查顺序：
① 更新是否携带矩形（RDP 位图更新带 destLeft/destTop/width/height）
② 合成是否按矩形裁剪 ③ 上传是否按矩形 ④ InvalidateRect 是否传矩形
⑤ WM_PAINT 是否尊重 ps.rcPaint。

### 例 127：变异测试可能因"定义位置"假存活（批86）
第一次改坏 `Rect::Union` 的空值分支，测试仍全绿。原因是 `Union`
定义在 **header** 里（内联），我改的是 `.cpp`。

**规则**：变异必须改在真正被编译的那份代码里。header 内联函数要改 header。
另外 `--clean-first` 只重建单个目标会删掉其它测试二进制，
导致 ctest 报 "Not Run"——用 clean-first 后必须重建全量。
### 例 128：GUI 长驻测试必须设短超时并强制收尾（2026-11-05 用户严厉纠正）

**用户原话**：「不知道测试要设置超时不超过30~60秒嘛 卡几分钟你要逆天嘛」
「尼玛的你又开始不讲纪律了」

我实际做的三件错事：
1. `Start-Process rtsc_gui` **不带 `--seconds`**，进程无限常驻，只能靠事后手动
   `Stop-Process` 收拾；一旦忘了收就残留到下一轮。
2. `bash timeout` 参数填 180000/300000/600000 毫秒（3~10 分钟），单次工具调用
   就占满整个轮次预算。
3. 反复用 `screenshot` + 外部 Python 探针去"看"画面，而用户早已明确指出应当
   建立进程内 CDP 调试通道（参照 `F:\VGWW` 的 `--ui-debug-port` 方案）。

**规则（硬性）**：
1. 任何拉起 GUI/服务端的测试命令，`bash` 的 `timeout` 一律 **≤60000ms**；
   需要更长等待必须拆分多次调用（T3）。
2. 拉起 GUI 必须**二选一**：带 `--seconds N`（N≤15）让它自己退出，
   或用 `Wait-Process -Timeout <秒>` 显式收尾并在同一命令里强杀。
   **禁止**拉起不带 `--seconds` 的常驻 GUI。
3. 每轮结束前必须 `Get-Process rtsc_gui,rtsc_server_host` 确认无残留。
4. "看画面"必须走进程内调试通道返回结构化状态，不得靠截图+人工判读；
   截图只用于最终目视确认，不作为调试主手段。

已同步把插件 `tool_timeout_ms` 从 600000 降为 60000。
### 例 129：协议常量禁止凭记忆写，必须查规范（2026-11-05，子代理正面示范）

我派发智能卡任务时，凭记忆列出了 7 个 SCARD_IOCTL 数值，**全部错误**：

| 我写的 | 规范值 | 我写的那个其实是 |
|---|---|---|
| LISTREADERSA 0x00090024 | 0x00090028 | LISTREADERGROUPSW |
| DISCONNECT 0x0009002C | 0x000900B8 | LISTREADERSW |
| BEGINTRANSACTION 0x00090030 | 0x000900BC | — |
| ENDTRANSACTION 0x00090034 | 0x000900C0 | — |
| TRANSMIT 0x00090038 | 0x000900D0 | — |
| CONTROL 0x0009003C | 0x000900D4 | — |
| STATUSA 0x000900F0 | 0x000900C8 | READCACHEA |

子代理没有盲从，按 [MS-RDPESC] 3.1.4 实现并列出对照表；我再用规范目录
原文独立核实，确认子代理正确。

**规则**：向子代理派发协议实现任务时，**禁止在任务描述里给出我未查证的
常量值**。要么先查规范并附章节号，要么明确写"数值以规范 3.1.4 为准，
不要采信本消息中的任何数值"。凭记忆的常量比不给常量更危险——它会让
子代理误以为已经有了权威依据。

**附带的正面教训**：子代理"不盲从上级错误输入、按权威源更正并明确标注"
是正确的工程行为，应当鼓励而非视为不服从。正确性 = 团队共同认可，
不以角色/权威论。

### 例 130：弱断言是变异测试唯一抓得到的假测试类型（第三次同类，2026-11-05）

批90 的调试通信用例最初写成"host 收到的 body 包含某子串"。把
`substr(start, i - start + 1)` 改成 `i - start`（丢掉末尾 `}`）后测试
**仍然全绿**——少个花括号，子串依然存在。改成全文精确比较后同一变异立刻红。

本项目至今三次同类：
1. `Rect::Union` 变异改在了 .cpp（定义在 header，改了不生效）
2. 变异后 MSBuild 因时间戳跳过重编译（子代理也踩到）
3. 本条的"子串断言"

**规则**：写断言时先问"如果我删掉/改坏实现里的关键一个字，这个断言会红吗"。
只查子串、只查"非空"、只查"没崩溃"的断言，对结构性缺陷天然免疫。
可以用"哨兵值"技巧：目标区域填一个绝不该出现的神奇值，断言它必须被覆盖。

### 例 131：诊断工具自身的转义会伪装成产品缺陷（2026-11-05）

批90 我为确认 `InnerBody` 是否丢字符，在 PowerShell 里用
`$t.Replace('...fprintf(...\n...')` 插入日志，反引号与 `\n` 被 PowerShell
自己解释，结果输出被截断，我一度判定"实现少了一个 `}`"。插真实日志后
确认 `pushed="op":"tree","filter":{"kind":"button"}` 完全正确。

**规则**：用外部脚本向 C++ 源码注入字符串字面量时，优先用独立 .py 文件
（`io.open(..., newline='')`），不要在 PowerShell 单行里拼转义。
看到"实现似乎少一个字符"时，先怀疑观测管道，再怀疑产品。

### 例 132：ctest -j 并行与串行结果不一致时不得声称通过（2026-11-05）

`ctest -j4` 时 rdpusb 与 ui 各偶发失败一次；单跑 `-R '^ui$'` 通过；
`-j1 -I 1,35` 与 `-j1 -I 36,70` 均通过。

**规则**：报告测试结果必须写明并行度。串行全绿可以写"串行 70/70 通过"，
但必须同时登记"-j4 下曾偶发失败，根因未定位，UNVERIFIED"。
不得只报对自己有利的那个数字。

### 例 133：main() 内局部类不能捕获外围局部变量（MSVC C2326，2026-11-05）

**尝试**：批92 在 `tools/rtsc_gui/main.cpp` 的 `main()` 内定义局部类
`GuiDebugHost`，让它直接引用同一函数里的 `std::mutex dbg_mutex`、
`std::condition_variable dbg_cv`、`std::deque<PendingCommand> dbg_queue`。

**错误**：MSVC 报 `C2326: "std::string main::GuiDebugHost::Execute(const std::string &)"`
函数无法访问 `dbg_mutex`/`dbg_queue`/`dbg_cv`。
原因：C++ 局部类**不捕获**外围函数的局部变量（只捕获类的 `static` 成员/全局），
与 lambda 不同。`Execute` 在局部类定义之后、与 `dbg_*` 同处 `main()` 作用域，
但局部类体内无法看见这些局部变量。

**根因**：局部类与"函数作用域共享状态"在 C++ 里没有捕获机制。
把共享状态放进局部类成员也不行（每次实例化各持一份，不是同一份）。

**下一步 / 正确做法**：把 HTTP 线程与 UI 线程共享的队列封装成一个
**独立类型**（`PendingCommandQueue`），`main()` 里建一个实例，
`GuiDebugHost` 持该实例的指针。两个线程都通过这一个对象访问，
不再有"局部类引用局部变量"的问题。

**规则**：C++ 局部类体（非嵌套在 lambda 内）禁止直接引用 `main()`/函数体里的
局部变量；共享状态必须提升为函数作用域的对象，由局部类持指针/引用传递。
