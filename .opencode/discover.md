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
## 第819轮：我 5 轮都没发现的「异常路径泄漏租约槽」（第 22 例）
### 缺陷
`src/server/server.cpp:762-779` `ReleaseInput()`：
```
input_released_ = true;            // :764 幂等哨兵已置真
input_lease_held_ = false;         // :766 已置假
input_sink_->ReleaseSession(...);  // :773 可抛（Close() 非 noexcept）
holders.erase(...);                // :777 抛异常时被跳过
```
⇒ `holders` 里永久残留该会话 ⇒ **单会话租约（max=1）此后拒绝所有人**。
红证（审计 F 探针）：`throw 时 releases=1 denied=101 second_injects=0`；不抛 `denied=1 second_injects=1`。

### 为什么我 5 轮都没看见
- 第 810 轮我专门核过这段并写下"F3：先 `ReleaseSession` 再 erase ✅"——**只核了顺序，没核异常路径**。
- 第 813 轮执行 AI 主动加了 `ServeOne` 三段 try/catch（E4），我核了"三段都在"就放行——
  **try/catch 的位置覆盖了 `Close/Scrub/ReleaseInput` 的调用点，却没有覆盖 `ReleaseInput` 内部**。
  外层 try/catch 保护的是"异常不逃出函数"，不保护"函数内部状态一致"。
- 两次审计（D/E）也没抓；F 抓到是因为它构造了"抛异常的 sink"。

### 教训（第 22 例：**幂等哨兵与资源释放必须在同一条不抛路径上**）
- 模式：`if (done) return; done = true; <可抛调用>; <真正的清理>` —— 一旦可抛调用抛出，
  `done` 已经为真，清理**永远不会再执行**。这是"幂等哨兵把失败变成永久损坏"。
- 判据：①先列出函数内**每一个可抛调用**；②检查"哨兵置位"是否早于"清理完成"；
  ③若有，清理必须 `try/catch` 且**无条件执行**（catch 后仍需清理，或把清理提到哨兵之前）。
- 审查方法：**读码永远抓不到异常路径**，必须构造"让 X 抛异常"的测试替身（本次是 throwing sink）。
  我此前所有"逐行核对"都是读码，因此对异常路径系统性失明。
- 同型风险清单（本仓）：任何 `~dtor`/`Stop()`/`Close()` 里"先置标志再释放"的写法；
  `ReleaseSession`、`ReleaseInput`、剪贴板/通道关闭、`std::thread::join` 前的标志置位。
## 第823轮：F-1 修好后才知道「同型」有 3 处真实可崩（第 23 例：修一个必须扫全类）
### 审计 H 的同型排查结果（全部带行号）
- **N-1** `desktop_input_win32.cpp:150-170` `ReleaseSession`：`AppendReleasesLocked` 抛 ⇒ `sessions_.erase`
  与 `notify_one` 双双跳过，而 `Inject` 对 forgotten id（`:124-127`）早退**不 notify** ⇒ worker 可能永久睡死。
- **N-2** `:513-530` `Shutdown`：append 抛 ⇒ `worker_.join()` 跳过 ⇒ `std::thread` 析构 `terminate`；
  且 Shutdown 由 `~Win32DesktopInputSink` 调用 ⇒ **直接杀进程**。
- **N-3** `:261-291` `WorkerMain`：无兜底，`Dispatch`/`EmitDueMoves` 分配失败逃出线程 ⇒ terminate。
- 另有 N-4/N-5/N-6：`server.cpp:2461/2474`、`rdpsnd_server.cpp:47-49`、`rdpdr_server.cpp:39-52` 析构/Stop 无 catch。

### 教训（第 23 例：**"修一处 + 扫同型"必须是同一次交付，且扫描维度要按"结构"而非"文件"**）
- 我在第 819 轮修 `ReleaseInput` 时，只把 `ReleaseInput` 当成"这一个 bug"，没把
  「**标志/状态已提交 + 后续可抛调用 + 关键清理在其后**」抽象成结构模式去全仓扫。
  审计 H 正是按这个结构扫，一次找出 3 处**会 terminate 或永久挂起**的同类。
- 判据：任何 teardown/资源释放修复，交付前必须给出"结构扫描清单"：
  ①搜索 `Close(|Stop(|Shutdown(|Release|join(|erase(` 的**调用点**而非定义点；
  ②判定该调用是否在析构/teardown 路径、其后是否还有关键清理；
  ③析构路径上的调用一律要求 `noexcept` 语义（调用点 try/catch 或保证不抛）。
- 另一条：**`catch(...)` 静默 = 不可诊断**。异常被吞但状态已不可回退（`input_released_=true`）时，
  必须有计数或限流日志，否则现场只看到"键卡住"却无任何线索。
## 第829轮：修好一半的 P-6——只丢带 0xE1 的事件，NumLock 仍被注入（第 24 例）
### 事实（本主代理亲自读码）
`src/proto/input.cpp:90-102` `EncodePauseKey()` 的 PAUSE 序列是：
```
04 1D   CTRL down  (extended1=true)
00 45   NUMLOCK down (extended1=FALSE)
05 1D   CTRL up    (extended1=true)
01 45   NUMLOCK up   (extended1=FALSE)
```
批 14 的修法是 `desktop_input_map.cpp:47 if (ev.extended1) return out;`——只丢掉**两个 CTRL**。
剩下的 `NUMLOCK down` + `NUMLOCK up` 照常注入 ⇒ **NumLock 被切换一次** ⇒ P-6 描述的副作用**依然存在**。

### 教训（第 24 例：**修"症状所在的那一半"≠修好；必须按事件的完整序列验证**）
- 审计 I 报的是"extended1 被忽略"，我就只让 extended1 不注入。但 extended1 只是**序列里的标记**，
  副作用来自**同序列中不带标记的其余事件**。单一事件视角永远看不见这一点。
- 判据：修复某"序列/事务/协议交换"类缺陷后，必须用**该序列的完整编码器输出**（这里是
  `EncodePauseKey()` 的 4 个事件）跑一遍端到端映射，逐个断言"应产出/不应产出"，而不是只断言
  "带标记的那个不产出"。
- 同型风险：多包协议（RDP 分片）、代理对（surrogate pair）、多段 PDU 的最后一个带标志位、
  拖拽的 down/move/up 三段——**标志位往往只在首/尾包上**。

### 该缺陷的正确修法方向（待审计 K 独立确认后定案）
PAUSE 的语义是"E1 CTRL 按住期间的那个 0x45 不是 NumLock"。两种可选：
- A（推荐，纯粹）：在 `TranslateInput` 层维护**极小的序列状态**，但映射层目前是无状态的 →
  需要把状态提到 sink 的 per-session 状态里；
- B（更简单）：识别 `extended1` CTRL down 之后的 `0x45` down/up 并丢弃——仍需要状态；
- C（最小且安全）：**只要一条输入 PDU 内出现 extended1 事件，就把该 PDU 内所有 0x45 事件一并丢弃**
  （PAUSE 的 4 个事件总在同一 PDU 里发出）——仍然依赖"同一 PDU"这一假设，**需证据**。
未定案前**不得**声称 P-6 已修。
## 第837轮：审计 J——"隔离了虚调用"不等于"隔离了整条 teardown 路径"（第 25 例）
### 事实
`RdpServer::Stop()` 我给批 13 的修法只包了两个**虚调用**（`listener->Close()`、`s->Stop()`）。
审计 J 指出同一函数里还有三个可抛点没隔离：`sessions = registry->sessions`（vector 拷贝分配）、
`std::unique_lock` 构造、`cv_.wait`。它们逃出 `Stop()` → `~RdpServer() { Stop(); }` → `std::terminate`。
实证（env-gated bad_alloc 探针）：不注入 `EXIT=0`；注入 `EXIT=3 unhandled-seh 0xE06D7363`。

### 教训（第 25 例：**noexcept 语义要按"整条路径"证明，不能按"危险调用点"点数**）
- 我上一轮的判据是"找出会抛的虚调用并包住"，这是**枚举式**思维，必然漏项。
  正确判据是**补集式**：析构可达的整条路径上，"不能抛的地方"必须逐个证明不抛；
  无法证明的（分配、锁、`wait`）一并隔离。
- 具体检查清单（teardown 路径必查的五类可抛点）：①**内存分配**（vector/map/string 拷贝、push_back）
  ②**锁构造**（`unique_lock`/`lock_guard` 可能抛 `system_error`）③**条件变量 wait**（同上）
  ④外部回调/虚函数 ⑤`join`（`EDEADLK`）。
- 验证方法：**必须用注入异常的实证**（bad_alloc 探针/替身），不能靠读码；本仓审计 J 正是靠
  `EXIT=3 unhandled-seh` 才把这条钉死的。

### 同轮其它（审计 J 的测试质量发现，值得单列）
- **断言钉不住竞态**：删掉 `cv_.notify_one()` 后，`drained` 断言 30+20+100 次**全绿**——
  因为 worker 未 park 时首轮 drain 自己就把 forget 队列抽干了。加 `sleep(200ms)` 让 worker 先 park，
  同一变异立刻转红。⇒ **测"唤醒"必须先把被唤醒方置入等待态**；否则测的是"恰好没进入等待"。
- **变异只能证明"能抓住这一类"，不能证明"覆盖全"**：M1/M2/M5 能在 ctest 转红，但
  M3b（打断生产 factory）只有 `rtsc_server_host` 构建能抓 → 文档里"任何变异都不能让 ctest 转红"
  是**错的陈述**，必须写成"部分闭合"。
## 第842轮：我"隔离异常"的修法制造了**更隐蔽的两种失败**（第 26 例）
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