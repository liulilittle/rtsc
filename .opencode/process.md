# RTSC 进度（process.md）

## 2026-10-22 第1轮 环境与基线
- OS Windows 11 10.0.26200；MSVC 14.44.35207；CMake 3.31.6 / Ninja 1.12.1（VS 内置，不在 PATH）
- Git 2.55.0、Python 3.14、Node 24.21.0；无 IDA / Hopper / jadx / tshark；无 OpenSSL / vcpkg
- 逆向工具链（用户提供，只读）：G:\sre\ghidra 12.1.4、G:\sre\java\jdk-21.0.12.1+1
- 目标二进制：mstsc.exe 1,114,112 B；mstscax.dll 9,166,848 B（均 10.0.26100.8875）
- 本地 RDP 服务停止，fDenyTSConnections=1，3389 未监听
- 已建目录：include/ src/ tests/ tools/ docs/spec/ evidence/ captures/ .opencode/backups/

## 2026-10-22 第2轮 规范取证 + 协议第一层
- [MS-RDPBCGR] 2.2.1.1/2.2.1.2 原文入库 `docs/spec/connection-initiation.md`
  - CRQ = tpktHeader(4) + x224Crq(7) + [cookie] + [rdpNegReq(8)] + [correlationInfo(36)]
  - RDP_NEG_REQ: type=0x01, flags, length=0x0008, requestedProtocols(LE32)
  - protocols: RDP 0x0 / SSL 0x1 / HYBRID 0x2 / RDSTLS 0x4 / HYBRID_EX 0x8 / RDSAAD 0x10
- 二进制常量扫描 `evidence/mstscax/constants.txt`：GCC 前缀 0x6C3338、`Duca` 0x161EE8

## 【历史归档】
第1~602阶段台账已裁剪（原 8547 行→现 ~452 行）。
完整历史见 git log（提交信息含每批次结果）与 docs/spec/*.md 证据文档。

---

## 第607轮：A1 两位审计**独立实测**收敛（放大=最近邻族、缩小≈面积平均）+ 我方推断被推翻

- **[收敛证据]** 甲（`probe_gdi12/14`）与乙（`zoomprobe/scan/scan2` 直接解析 PE + 真实 GDI 复刻）**各自独立**得出同一结论：mstsc 的**放大是最近邻族**（1.5x/2x/3x 与最近邻逐字节相同，max|d|=0；1.125/1.25/1.75x 仍属最近邻族，偶发复制列，**从不线性混合**）；**缩小≈面积平均**（0.8/0.5/0.25x vs 面积 max=3/4/9）。
- **[父代理推断被推翻]** 我此前由「`SetStretchBltMode(hdc,4)`=HALFTONE」推出「非 1.0 缩放都做面积平均平滑」——**只对缩小成立**。已修正 `docs/spec/scaling-evidence.md`（b161c79 新增 E7 实测节 + 教训「模式名 ≠ 各方向实际行为」）。
- **[唯一未定论点 R12]** 1px **二维**棋盘在 2x 时 GDI 压平为全 128（唯一平滑现象，高频二维极限），而 1px 条纹/台阶/文本仍是块复制。策略二选一待乙给推荐：kBlock + 显式标注差 128，或加 2x2 前置低通使其为 128。
- **[真实缺陷（必修）]** D1 缩小是**抽点**而非平均：`view.cpp:153-190` 采样点 `uu=i*src_w/vt.width`（像素左上角），0.5x 时恒为偶数源像素 → 奇数源像素永不参与；实测 16x1 交替 → ours 全 0 / GDI 127 / 面积 128；白底 1px 黑线（奇数列）→ ours **255（消失）** / GDI 112 / 面积 128。D2 alpha 不参与（`view.cpp:216` `d[3]=p00[3]`）。
- **[性能预算（乙实测）]** 现状 1536x864 0.8x = 18.7–19.4ms、2160x1215 1.125x = 34.2–36.6ms（预算 16.7ms）、2x = 4.3–4.5ms、1:1 = 0.15–0.23ms；GDI 基准 12.93/52.33/0.26/30.02ms。整数权重可分离面积平均原型 20.4ms（1536x864）、浮点 59.2ms（不可接受）；非整数放大改最近邻后 2160x1215 从 34ms→**3.96ms**。
- **[裁决]** P1 升采样=最近邻族（对齐 GDI）；P2 降采样=一律面积平均（**有意优于** GDI 整数比退化，须单列）；alpha 四通道参与（**有意改进**，须单列）。
- **[流程]** 先改文档判据（D4 三处：`view.cpp:146-147`、`view.h:61`、`scaling-evidence.md` 旧结论）→ 加红用例 → 实现 → 双审复验（含变异反证 R15）。

## 第608轮：缩放分歧由**自建 GDI 探针**定案（整数比降采样确实平均）

- **[分歧]** 甲：整数比降采样（0.5x/0.25x）退化为块复制；乙：做平均。二者各带探针数据，结论相反。
- **[父代理定案·自建探针]** `%TEMP%\opencode\arb\arb.exe`（自写 DIB→DIB + `SetStretchBltMode(HALFTONE)` + `SetBrushOrgEx(0,0)` + `StretchBlt(SRCCOPY)`，源码 `arb.cpp`）：
  `16x1 alt{0,255}->8x1(0.5x) = 127×8`；`4x4 1px checker->2x2 = 128×4`；`32x32 checker->4x4 = 128×16`；`16x1 ramp(3x+1)->8x1 = 1 8 14 20 26 32 38 46`；`8x1 alt->16x1(2x) = 0 0 255 255…`。
  → **整数比降采样做平均（乙对，甲错）**；放大为块复制（两者一致）。
- **[契约重写]** `docs/spec/scaling-evidence.md` 合并为唯一契约（commit 666eb96）：E1-E7 观察、§2 契约表、§3 现状差距、§4 裁决、**偏离清单 D-1/D-2/D-3**（精确 box vs GDI 近似 box ±4/255；alpha 四通道同权；1px 2D 棋盘保留块复制不复刻 GDI 的不稳定压平）、§5 验收要求。旧 §2/§3/§4 的「整数倍也要平滑」「2x 块复制=不一致」等已被推翻并删除。
- **[甲工单裁决]** ① 保留整数倍 k×k 专用内层循环（4ms vs 通用 nearest 13.4ms），对外单一 `kNearest` 语义；② 非整数升采样相位 `floor(x*sw/dw)`，断言「输出 ⊆ 源像素集合」；③ 1px 2D 棋盘不复刻；④ 甲 D4 措辞「GDI 整数比降采样退化」须改为「GDI 用近似 box，我们用精确 box」——已 relay 纠正。
- **[新增缺陷 D7]** `scale==1` 但居中（`vt.x/vt.y != 0`）落到 `k==1` 块路径：1.92ms vs 0.18ms（慢 10x）。修法：1:1 判据放宽为「尺寸相等」并按偏移逐行 memcpy；目标 <0.6ms。
- **[执行]** EXEC-A1 `ses_e7f80e77fffeGVbzWG5w0Jhitf` 已收到完整契约（含定值表与性能预算），按「注释→红用例→实现→性能→变异反证」推进。

## 第609轮：升采样索引公式定案（E8）——执行 AI 实测发现，推翻父代理此前的 floor 指示

- **[执行 AI 发现]** `probe_gdi16.exe`（源像素值=源索引，256 色内唯一）测得 mstscax 升采样 x-map：`4x4→6x6 = 0 0 1 2 2 3`、`3x3→5x5 = 0 0 1 2 2`、`8x1→13x1 = 0 0 1 2 2 3 3 4 5 5 6 7 7`、`4x4→8x8 = 0 0 1 1 2 2 3 3`。
- **[父代理独立复算]** 三种公式失配数：A `floor(d*S/D)` → `3→5` 失配 9/25、`8→13` 失配 3/13；B `floor((2d+1)*S/(2D))` → 多处失配；**C `((2d+1)*S-1)/(2*D)` → 6 组全 0 失配**。平局点验证：`4→6` d=1 → 0、`8→13` d=6 → 3（均平局向下）。
  → **升采样相位必须用 C**；我此前指示的 `floor(d*S/D)` 在 3→5、8→13、1.37x 生产量级会产生整列偏移，已撤回并写入契约 E8。
- **[E9 舍入约定]** 降采样：GDI 对 `127.5` 截断得 127；本项目用四舍五入得 128。属约定差异，记为偏离 D-1 一部分；测试期望取单值 128（不接受 127/128 双值，避免放松测试）。
- **[R9 修正]** `2x2 RGWB → 3x3 @1.5x` 中心按 E8 为 `(255,0,0)`，工单原写 `142,170,170` 是双线性值（笔误）。
- **[契约变更]** `docs/spec/scaling-evidence.md` 新增 E8（三种公式失配对照表）、E9（舍入约定），提交 `1f7a56e`。
- **[当前阶段]** EXEC-A1 `ses_e7f80e77fffeGVbzWG5w0Jhitf` 处于"探测完成、未改码、写第 1 步红用例"阶段（`wrote` 时间戳新鲜，平台的静默死亡为误报）。

## 第610轮：审计甲/乙收敛到同一条「内存安全」缺陷 + 契约新增 E10/E11；测试抖动归因端口争用

- **[双方独立收敛]** 甲（`probe_verify2`）与乙（`relax.exe`）各自复现同一结论：**只放宽 1:1 判据而不修 x/y 偏移 = 越界读 + 整幅错位**。实测 `1920x1080 → 1920x1200 (vt.y=60)` 越界读源 60 行、错像素 2,071,680/2,304,000；`1920x1080 → 1922x1080 (vt.x=1)` 整幅左移 1px。根因 `view.cpp:95-99` 行循环 `s = sdata + y*src_w*4`（未减 vt.y）、`d = ddata + y*dst.width()*4`（未加 x0）。正确版实测 `wrong=0`、`0.159-0.248ms`（shipped 1.52ms）。→ D7 必须「放宽判据 + 修双偏移」一起做。
- **[E10 新增·高频抖动]** GDI HALFTONE 在**二维高频**内容上产生 7.3–11.6% 源中不存在的值（`max|d|=35~42`）；低频内容（渐变/条纹/台阶/1px 线）`max|d|=0`。→ 升采样断言只能用 E8 公式当黄金标准、只在低频内容验证；**禁止**用 GDI 输出当期望、**禁止**对 1px 2D 棋盘设值断言。
- **[E11 新增·舍入]** GDI 的 127/128 取决于**单轴 vs 双轴**（单轴 16xH→8xH 全 127；双轴 16xH→8xH/2 全 128）。本项目统一 round-half-up 得 128，文档不得写「128 与 mstsc 一致」。
- **[E8 交叉验证]** 乙用 16-bit 双通道索引编码在生产尺寸复核：`1920→2560(1.333x) A=640/2560 B=0 C=0`、`1920→2880(1.5x) A=0 B=960 C=0`、`1920→3840(2x) 全 0`、`1000→1333 C=0`；甲用低频 ramp 在 2400/2560/2880/3840 全部 `mismatch=0`。→ C 式确认。甲同时自我纠正：其 `probe_e8` 把「匹配数」标成 mismatch，已用 `probe_verify` 重算并对齐乙。
- **[测试抖动归因]** 并发跑 20 次挂 7 次、独占跑 6 次+12 次全 0 失败；失败集中于依赖既有连接的 `server_suppress_output_gates_refresh:800` 与 `server_refresh_send_failure_closes_session:944`。根因=`tests/test_server.cpp` **硬编码端口**（3390-3398/3480-3488）在并发测试下被抢占，**非代码缺陷**。规则入档：①稳定性结论必须注明「独占运行」；②发现随机失败先排环境（残留进程/端口/并发/共享构建目录）；③中期把测试端口改为 bind(:0) 运行时分配。
- **[在途]** EXEC-A1 已收到 E8/E10/E11 + D7 双偏移要求，继续第 1 步红用例。

## 第611轮：GW-MEM 完成（2745MB → 9.6MB）+ 测试端口改运行时分配派发

- **[GW-MEM 绿证]** 9 条内存用例逐条 [OK]，峰值 **peakWS 9.6MB / peakPriv 5.3MB**（修复前同路径 2745.6MB 被 kill）：`http_message_rejects_a_huge_content_length`、`…oversized_header_block`、`…honours_configured_limits`、`gateway_tunnel_rejects_an_endless_response_body`、`…stops_reading_a_gateway_that_never_frames`、`…does_not_wait_forever_after_the_chunks_stop`（`bytes_read=65553 reads=16` 在上限处退出、不等不会来的数据）、`…fails_at_the_session_byte_ceiling`（`8389061 ≈ 8MiB+4KiB`）、`…one_mebibyte_scripted_ceiling`（`supplied=256` 停供后 257 次读即退）、`…enforces_the_entity_ceiling_and_exposes_it`。
- **[实现落点]** proto：`kMaxHttpHeaderBytes=64KiB`/`kMaxHttpHeaderCount=512`/`kMaxHttpEntityBytes=128KiB` + `HttpLimits` 4 参 `parse()` 重载（原 3 参保留）；`ParseHttpHead` 修 `offset = line_end + 2`(:125)；`HttpStatusLine` 修 `compare(0,5,"HTTP/")`(:223)；`ReadEntity` 解析 CL 即拒绝、**绝不 allocate(length)**(:153)。net：`ReadChunk()` 统一预算（字节/次数/无进展时长）；`ReadResponse`/`ProcessIncoming`/`Read`/`Exchange` 全部有界；`InvalidLength` 报 "exceeded a size limit" **不重试放大**。动态配置经 `Limits()` 注入，有专门用例证明「默认拒 200000B → 抬到 256KiB 后放行」。
- **[父代理裁决]** ①`http_message_parse_does_not_keep_stale_headers:718` 的 `size()==1` 是**笔误**（该 wire 实含 `X-Second` + `Content-Length` 两条），授权改为 2 并加注释（保留 `X-First==nullptr` 防残留断言）；②`max_session_read_bytes` 默认 8MiB 对真实会话过小，内存安全实际由每消息上限保证 → 改为 0(不限) 或 1GiB（说明理由），测试侧显式传值验证上限仍有效；③`session_timeout_ms` 实现为**无进展超时**正确，保留。
- **[测试端口]** 全仓硬编码端口清单已摸清：`test_server.cpp` 3390-3398/3480-3488（18 处）、`test_gateway.cpp:601-602` 3401/3402、`test_gui_send.cpp:90` 3396、`test_rdp_standard_security.cpp:259/326` 3394/3395。已派 EXEC-PORT `ses_e7f660d3effeTggdZeeKXYivMV` 改为运行时分配（推荐 ServerConfig.port=0 + 暴露 bound_port()，无 TOCTOU），要求 RED（外部占端口→用例失败）+ GREEN（30 次连跑 0 失败 + 并发两份各 5 次 0 失败）。

## 第612轮：A1 双审完全收敛，契约锁定 E13/E14/E15（三条正交验收判据）

- **[双审收敛]** 甲、乙就以下四点完全一致（各自独立探针互证）：①**E8=C 式**（`((2d+1)*S-1)/(2D)`，双轴同式）；②**降采样=面积平均**（乙 `evidence.exe` P-A：0.5x 条纹 ours 全 0 vs area 128×8、0.25x ramp ours `0 128` vs area `48 176`、0.8x ours `0 64 128 191` vs area `10 71 133 194`）；③**D7 必须修 x+y 双偏移**（乙 P-C：naive 放宽 `vt=1920x1080@(0,60)` 越界 60 行、错 2,071,680 像素）；④**`test_view.cpp:477-504` 需重写**（乙 P-D4b：ours `(142,170,170)` vs GDI/E8 `(255,0,0)`）。
- **[E13 三条正交判据（取代"⊆ 源集合"）]** (A) **低频内容**必须逐像素等于 E8/C 相位（生产宽度 4 组 `maxdiff=0`，可作黄金标准）；(B) **变异守卫**：`dst` 颜色集合 ⊆ `src`，新值占比必须 0（不依赖 GDI；nearest 恒 0%，双线性/面积 >0）；(C) **1px 2D 棋盘不设断言**，仅记偏离（乙扫描 S=2..482：`≤46→128`、`50..122→0/255`、`≥130→128`；甲 ≤48/56..128/≥160，结论一致）。
- **[E14 单轴/双轴区分]** `16x8: 单轴(→8x8)=127, 双轴(→8x4)=128`（16x16/16x32 同型）。本仓统一 round-half-up，单轴也得 128 → **有意偏离 D-1**，测试按实现口径写并注释 GDI 单轴为 127。
- **[E15 非整数相位容差]** `1.375x`(8→11) GDI `0 36 36 72 108 108 144 180 216 216 252` ≠ 端点锚定式（差 1 格）→ 非整数升采样按 E8 实现、验收允许 **≤1 源像素差**；整数倍与 1.5x/2x/3x 仍精确断言。
- **[乙的关键洞察·写入 E13-B]** GDI 在二维高频内容上注入 1.71% 源外新值（P-H，`natural 1920x240→3840x480` GDI-vs-C `maxdiff=36`）→ **GDI 不能作唯一黄金标准**，必须配"不依赖 GDI 的变异守卫"。
- **[在途]** EXEC-A1 已收到 E13/E14/E15 全部口径，继续红用例→实现→绿证→五套变异反证。EXEC-PORT 同步在改测试端口为运行时分配（消除伪造失败）。

## 第613轮：审计乙复验 H-4 增量——R-C/R-D/D-1 盖章，R-A/R-B 各驳回 1 项（均附红证/汇编）

- **[R-C 盖章·汇编级证据]** `SecureWipe` 用 `volatile char*` 逐字节写 0；审计用 `dumpbin /disasm` 定位 `ScrubCredentials`（106 条指令）确认 **5 × `mov byte ptr [r8+rax],r11b` 逐字节 0 循环未被优化掉**、`5 × mov qword ptr [r+x10h],r11` 长度清 0、`5 × mov byte ptr [r],r11b` 写 NUL → 5 字段全覆盖 + volatile 生效；`~RdpSession(){ ScrubCredentials(); }` 幂等。
- **[R-D 盖章]** `test_server_multisession.cpp:229/268/300` 三处 `session_count()==0` 均在 `Stop(); runner.join();` 之后；checks 49→**52**；5 次连跑 0 失败。
- **[D-1 盖章]** `test_server.cpp:854-859` 阈值 `>=5` + 注释写明推导；审计独立分布 **52 次 0 失败**（12+40），与其修复前同判据 3/22（14%）一致。
- **[R-A 驳回·双重扣减]** `:1622-1627` launcher 若**先启动 body 再返回 false/抛异常**，回滚 `:1642-1652` 再 `--live`，body 已扣过一次 → **size_t 下溢**。审计红证 `probe_r5.exe`（launcher 内 `thread(body).join(); return false;`）：`live=18446744073709551615`、`Stop_returned=0 HUNG=1` → **Stop() 永久阻塞**。修复采用**计数交接原子化** `if (counted->exchange(false)) { --live; notify_all(); }`，不依赖 launcher 诚实度。
- **[R-B 驳回·递减可被异常跳过]** `:1606-1613` 把 `erase`（可抛）与 `--live` 放同一 try；`:1643-1651` 回滚块**完全无 try**（抛则逃出 accept → terminate）。要求：`--live` 与 `notify_all` 移出可抛区或用 scope guard。
- **[测试缺口]** 现有用例只测"不启动即 false"，测不到"启动后报失败"。要求新增第二分支：launcher `thread(body).join(); return false;` → 断言 `live==0`、`total==0`、`Stop()` 1s 内返回、后续连接仍可服务。
- **[审计自我更正（好行为）]** 其首次 12 次跑得 11 次失败（含 unhandled-seh），查因是**上一轮探针僵尸进程 PID 34960 占用 3395 端口**；杀掉后 12/12 + 40/40 全绿，主动撤回。→ 已入 discover.md，并强化 EXEC-PORT 的必要性。
- **[仍存风险]** `server.h:69 accept_any_credentials` 仍为 true（嵌入方静默 accept-all）；Standard RDP 路径只校验用户名/域不校验口令。已要求同批处理。

## 第614轮：服务器批次全绿（含 R-A/R-B 与默认值）+ GW-MEM 收尾 41/41 + 发现主树未含 GW 改动

- **[服务器批次·父代理亲核]** `server.cpp:1607 counted = make_shared<atomic<bool>>(true)`、`:1620 if (counted->exchange(false, acq_rel))`、`:1625/:1629 fetch_sub 双路径兜底；`Registry::live` 改 `std::atomic<size_t>`（`:1489`）；`server.h:73 accept_any_credentials = false`（原 true，嵌入方不再静默 accept-all）。全仓 UTF-8 合法性检查通过（无非法字节）。
- **[服务器绿证]** server **20 tests/186 checks/0 fail**（`handles: baseline=116 after8=116`）、multi 3/52/0、security 7/60/0、`ctest -R server` 3/3、Linux 四文件 -Werror 通过；CLI 探针：`otheruser@WRONG` 被拒（`MISMATCH_EXIT=1` + peer closed）、`rtsc@NTDEV` 通过（`MATCH_EXIT=0` + ACTIVE）、stdout `credentials: enforced (account rtsc@NTDEV from the Client Info PDU)`。
- **[GW-MEM 收尾]** `:718` 断言按授权改为 `headers.size()==2`（保留 `X-First==nullptr` 防残留核心）；`max_session_read_bytes` 默认改 **0=不限**（理由：内存安全由每消息上限保证，会话累计与内存无关；1GiB 仍是魔法数会在长会话误杀）；两类失败拆开报错（`exceeded its configured read budget` vs `stopped sending data within the session deadline`）；新增 `http_message_rejects_too_many_headers`（600 条被条数上限独立拒绝、`max_header_count=1024` 时接受）与 `session_ceiling_defaults_to_unlimited`（实测读 9,437,637 B = 9.0MiB > 旧 8MiB，证明确已不限）。
- **[GW 红证复测]** 修复前副本重跑：case1（CL=4294967295）`peakPriv=2744.5MB killed`、case2（头 85,109B）`peakPriv=1989.5MB killed` → 无界性稳定成立。修复后 41 条用例单跑全绿，`max peakWS=9.9MB / max peakPriv=5.4MB`；ctest gateway 1/1（childPeakWS=11.0MB）。
- **[调度失误（已入档）]** 同时派 EXEC-PORT 与 EXEC-C 改同一 `tests/test_server.cpp` → 冲突（3 处 C2039 + 1 个非法 UTF-8 字节）；EXEC-C 做最小外科修复并上报。教训：**并行隔离单位是文件，不是功能**；编辑后必须校验 UTF-8。
- **[待处理]** 主树 `tests/test_main.h`/`tests/test_gateway.cpp` 的改动来源是其他代理（非 GW-MEM），GW-MEM 的 4 处根因修复仍只在 `F:\rtsc-wt\gw` 工作树，**尚未合并**；合并需选择合入点避免与主树在跑代理冲突（当前有代理在反复创建 `rtsc_server_tests` 进程）。

## 第615轮：EXEC-A1 交付（三态分派 + resample 内核 + 五套变异反证）；派第三方审计丙独立复验

- **[交付内容·父代理亲核]** `src/client/resample.cpp`(16.6KB)/`resample.h`(1.7KB) 新增，`resample.h` 为 rtsc_client PRIVATE include（公共 API 仍只有 `ScaleSurface`/`ChooseResample`）；`view.cpp:87-98` `ChooseResample` 三态（**尺寸相等→kExact**（E5，非零偏移）；**任一轴缩小→kArea**；否则 kNearest）；`ScaleSurface:130-142` 三态分派；**双线性已彻底移除**（`bilinear` 计数 0、`what mstsc does` 计数 0）。
- **[关键技术点]** ①kNearest：整数倍（kx==ky，2..64）走 k×k 专用内层（先展开一行再 memcpy k 次）；非整数走 E8 相位 `((2d+1)S-1)/(2D)` 且索引一次性预计算。②kArea：覆盖面积加权、整数权重（单位和 1/dn 源像素、权重和恒等于 sn）、两趟按目标行融合（**不写 33MB 中间缓冲**）、四通道同权、**一次** round-half-up；整数比缩小走 kx×ky 求和快路径。③kExact：逐行 memcpy，**读写都带 vt.x/vt.y 偏移**（D7 修复）。
- **[判别性自测]** `probe_prodmap.exe` 链接真实 `rtsc_client.lib`：3→5 / 8→11 / 8→13 / 1920→2630 / 1920→2560 / 200→333 / 127→191 等 11 组 **E8 失配全 0**；若用 floor，1920→2630 错 **950 列**、1920→2560 错 **640 列** → 证明落地的是 C 式。
- **[实现中发现并修掉 3 个真实缺陷]** ①水平趟舍入常数写错（`>>8` 配 `2^15` 应为 `2^7`）→ 0.8x ramp 得 167/243（应 166/242）；②行和缓存用 `static thread_local` 跨帧污染 → 条纹得 3、alpha 得 254，改为函数内局部缓存（**像素派生数据不得跨调用存活**）；③0.5x/4K 首版 25.76ms 超预算 → 整数比快路径 + 去中间缓冲后 9.43ms。
- **[性能]** 1:1 0.13ms（预算 1.0）、letterbox 0.13ms（0.6，**原 1.92ms**）、2x 2.51ms（8）、0.8x 13.06ms（22）、0.5x 4K 9.43ms（25）、**1.33x 0.94ms（10，原 46.9-66.8）**、1.125x 0.66ms。
- **[变异反证 5/5 全红]** A 相位(→floor) 1 failing/10 checks；B 截断舍入 3 failing/241；C alpha 左上角 1 failing；D 抽点 8 failing/722；E 只放宽不改偏移 4 failing/389。恢复后 43 tests/6502 checks/0 failing。
- **[待裁决 2 点]** ①`scale_x/scale_y` 仅赋值未被 `ChooseResample` 读取（执行 AI 按 E5 用尺寸相等判定，理由：浮点 1.0 会漏掉 lround 后的差异）——父代理认同；②0.8x 13.06ms 未达早期 <12ms 但达最终工单 ≤22ms——父代理接受，不再追 SIMD。
- **[派第三方审计丙]** `ses_e88...`（新建，与甲/乙无接触），八项 V1-V8 独立复验（相位落地/1:1 不越界/降采样手算/alpha/变异守卫/性能/测试质量/回归），要求"契约也可被推翻，但必须有数据"。

## 第616轮：A1 缩放获审计乙盖章（hash 绑定）；工作树因 EXEC-GWLIM 中间态暂不可全量构建

- **[审计乙·盖章（PR-capable，绑 hash）]** 独立参考实现（不调生产码）复验 **32/32 PASS**：①降采样 == 精确 box（RGB+alpha，14/14 组 `max|dst-box|=0`）；②0.5x 1px 线（奇列/奇行）`min=128`（旧实现 255=线消失）；③alpha 同权；④升采样 == E8 相位（8→13 / 1920→2640 / 2400x1350 / 3840x2160，mismatch 0）；⑤不发明颜色（invented=0）；⑥fit 468 组合无"单轴缩+另一轴放"。边界 5 类全绿（偏移裁剪含负偏移/极端缩小/奇数质数尺寸/混合轴/单轴缩小）。性能：1:1 0.14ms、0.5x 2.30ms、2x 2.94ms、1.125x 0.71ms、0.8x 13.65ms 全达标。**pin hash**：resample.cpp `03C9EE2A…`、resample.h `B868D414…`、view.cpp `DBD7481D…`、view.h `9206F984…`、test_view.cpp `21EC4E14…`。
- **[乙的诚实自查]** 其最初两条 [FAIL] 均为**探针设计错误**（竖向缩小配竖向条纹→天然 0/255；0.8x 非整数比期望常数），已撤回未计入缺陷。另观察到执行 AI 10 分钟内 7 个 resample.cpp 版本，其中 2 版编译失败（C2065/C1075），属编辑中间态，最终 pin 全绿。
- **[当前树状态·不可全量构建（EXEC-GWLIM 中间态）]** `rtc_gateway_tests` 链接失败：`LNK2019 无法解析 HttpMessage::parse(..., const HttpLimits&)` —— 5 参重载**已在头文件声明、.cpp 尚未定义**。这是 EXEC-GWLIM 搬运内存上限的正常中间态；**父代理不跨代理修改**，等待其收口。核心库（`rtsc_proto`/`rtsc_client`/`rtsc_ui`/`rtsc_server`）构建 **CORE_BUILD=0**。
- **[结论]** A1 批次可提交（乙已盖章），但**必须与 EXEC-GWLIM 收口一起提交**，避免中间态入库。待 GW 收口后：串行跑全量 ctest（先清 `rtsc*` 残留）→ 分批提交（A1 / 服务器 / 端口 / GW 上限）。
- **[第三方审计丙在途]** `ses_e7f3c64e8ffeJQEbY4719JMAej`，八项独立复验中（不参考甲乙结论）。

## 第617轮：三份独立审计到齐 → 两批提交入库，A1 待修 F1/mutC

- **[提交 3ec4d66·服务器+端口]** `counted->exchange(false)` 原子计数交接（防 size_t 下溢）、`--live` 与可抛 `erase` 解耦、`SecureWipe` volatile 逐字节擦 5 字段 + 析构兜底、`accept_any_credentials` 默认 **false**、`session_count`=活跃/`total_session_count`=累计、`inputs>=10`→`>=5`（零余量修正）；测试端口全部改 `cfg.port=0` + `bound_port()`（`Listener::local_port()` 基于 getsockname，失败 fail-closed），新增 `RTSC_TEST_FILTER`。12 文件 +658/-128。
- **[提交 c08df4f·网关内存上限]** proto `kMaxHttpHeaderBytes=64KiB`/`kMaxHttpHeaderCount=512`/`kMaxHttpEntityBytes=128KiB` + 5 参 `parse(..., const HttpLimits&)`（3 参保留转发默认）；超限即 `InvalidLength`（**绝不 NeedMoreData**，防对端拖住解析器）；CL 逐位校验先于任何累加（**绝不按 CL 分配**）；net 层 4KiB 栈缓冲 + 会话预算（默认 0=不限）+ 读取次数 + 无进展超时，三类错误文案可区分、不重试放大。修复前 peakPriv 2,745MB → 修复后 **9.9MB**，41 用例单跑全绿。3 文件。
- **[审计丙·真实缺陷 F1（甲/乙均漏）]** `resample.cpp:360` `inv_total=1.0/total` + `:384-386` `(double)acc*inv+0.5` 截断 → 精确 `.5` 平局被截断为 N。父代理独立验算确认：`total=1296000, w=729000, v=56` → exact 31.5、double 31.499999999999996、trunc **31**（应 32）。端到端红证：**1440x900 @ zoom 0.75（标准预设）→ 1080x675**，随机内容失配 **0.866%**（全 –1）；而 1920x1080/1366x768/1280x1024 恰好 0% → **只在特定缩放比炸**。修法：整数除法 `(acc+total/2)/total`。已写入契约 **E16**（含混合轴规则）。
- **[审计甲·前置 2 项]** ①**mutC 变异存活**：`uniform 2D 快路径 alpha 取左上角`（`resample.cpp:330`）现有测试检测不到（8x1→4x1 只覆盖 generic 路径），需补 `8x2→4x1` 用例（期望 `0 128 255 255`）；②**阻断提交**：`src/client/resample.{h,cpp}` 是未跟踪文件（`??`）而 CMakeLists 已引用 → 任何只提交已跟踪文件的流程都会编译失败，必须显式 `git add`。
- **[审计甲的变异反证 5 套]** mutA 相位→floor 1 failing/10；mutB 去 +0.5 3/241；**mutC 存活**；mutC2 generic alpha 1/1；mutD 丢 x 偏移 4/43；mutE 缩小轴走 nearest 8/722。
- **[审计甲的额外观察]** `3840x2160→1536x864 (0.4x)` 实测 **27.86–28.92ms**（旧 17.6–23.5ms），契约无 0.4x 预算条目 → 待 A1 修复后复测并补档。
- **[验证]** 全量构建 `FULL_BUILD=0`；排除 A1 套件的 ctest **46/46 passed**。

## 第618轮：F1/mutC 已修；审计乙报交付完整性 3 阻断（2 项已解除、1 项注释待清）

- **[审计乙·驳回本版（功能 pass / 交付 fail）]** 3 个阻断：**A** `tests/test_view.cpp:468` 曾因非法字符 0x2581 编译失败（属执行 AI 编辑中间态，hash 从 `21EC4E14`→`F28966D8`→`14C25E34`）；**B** `resample.{h,cpp}` 未跟踪而 CMake 已引用（干净副本构建必失败）；**C** uniform 2D 快路径 alpha 无覆盖（其变异体 `0 0 255 255` 能存活）。
- **[父代理亲核·A 与 C 已解除]** `test_view.cpp` UTF-8 合法（仅文件首 BOM）、`:468` 内容正常、`--target rtsc_view_tests` **EXIT=0**；`mutC` 用例已加 `:415 view_downscale_2d_fast_path_averages_alpha`（`Surface src(8,2)`）。全套 **46 tests / 6529 checks / 0 failing**。
- **[F1 已修]** `resample.cpp` 已无 `inv_total`/`inv_area`，改 `ExactDivider` + `(acc + total/2)/total`；平局专项用例 `:433 view_downscale_exact_half_tie_rounds_up` 用 `ComputeViewTransform(1440,900,1440,900,0.75)` 的 `src(0,0)=56`（31.5 平局）断言 32。
- **[B 待提交时解决]** `src/client/resample.{h,cpp}` 仍未跟踪 → 提交时必须显式 `git add`（已列入提交清单）。
- **[待清·陈旧注释]** `resample.cpp:381-384` 仍写"One reciprocal … +0.5 before truncation"，与 `:387-389` 新注释及实际实现矛盾（正是 F1 的错误做法）→ 已要求执行 AI 删除/改写后再给终报与 5 个文件 hash。
- **[契约新增 E17]** `0.4x (4K→1536x864)` 实测 27.9–30.9ms，原预算缺此档（0.4x 非整数比走 generic tap，是 0.5x uniform 快路径的约 2 倍）→ 补入 **≤35ms**，并禁止后续优化突破。
- **[审计乙的诚实做法]** 明确指出"ctest 4/4 那次是旧产物"，未用旧二进制冒充绿灯；并撤回自己上一轮绑定的 hash（因文件已变）。

## 第619轮：A1 缩放提交 `5b1e00a`（含 F1/mutC/注释清理）；三方终验已派

- **[提交 5b1e00a]** 新增 `src/client/resample.{h,cpp}`（**显式 git add，解除审计乙的阻断 B**）、`view.cpp` 三态分派 + 双偏移、`view.h` Resample 枚举、`tests/test_view.cpp` +21/−2（46 tests/6529 checks）、`CMakeLists.txt` 注册。工作树干净。
- **[F1 修复已验证]** `ExactDivider`：`ceil(2^44/den)` 倒数 + `q*den>num` 修正 + 2 的幂移位快路径。父代理**穷举 7600 组 (num,den)**（含真实分母 3/7/1296000/8294400）floor 与 half-up **零失配**；`num*recip ≈ 255×2⁴⁴ ≈ 4.5e15` 与 den 无关、不溢出 uint64。
- **[陈旧注释已删]** `resample.cpp` 中"One reciprocal … +0.5 before truncation"已移除（残留扫描 clean），保留说明 F1 事故的正确注释（`:21-24`）。
- **[mutC 缺口已补]** `tests/test_view.cpp:415 view_downscale_2d_fast_path_averages_alpha`（`Surface src(8,2)` → 4x1，期望 `0 128 255 255`）；把 2D 快路径 alpha 改成取块角该用例转红（执行 AI 实测 1 failing/1 failed check，恢复后 46/6529/0）。
- **[平局回归守卫]** `:433 view_downscale_exact_half_tie_rounds_up` 直接复用审计丙发现的真实路径 `ComputeViewTransform(1440,900,1440,900,0.75)`、`src(0,0)=56`（31.5→32）。
- **[性能取舍（F1 代价）]** 0.8x 13.06→**16.74ms**、0.5x-4K 9.43→9.90ms（均在预算内），0.4x **30.42ms**（契约 E17 ≤35ms）；换来的是精确 half-up（消除 0.866% 像素偏 –1）。1.33x 1.56ms（原 46.9–66.8ms）、letterbox 1:1 0.20ms（原 1.92ms）。
- **[执行 AI 的自我纠正]** 主动更正上轮计数口径："12 新 + 2 改 + 1 改名"是错的，实为 **+21/−2**（19 纯新增 + 2 替换旧用例）。

## 第620轮：审计乙盖章 A1（绑 hash）+ 全量 51/51 绿

- **[审计乙·盖章（绑 hash）]** 独立复算五文件 hash 与父代理一致；上轮 3 阻断全部关闭（①`:468` 语法错误已修、view 批次构建 WARN 0/ERR 0；②`resample.{h,cpp}` 已在 `git ls-files`、`git status` 空；③`test_view.cpp:415-431` 2D 快路径 alpha 用例在册，**其自建 mutC 变异实测转红**：`FAIL :430 ChannelOf(dst,x,0,3)==128 (got 0)`）。32/32 独立断言 + 边界 5 类全绿；性能 1:1 0.15 / 0.5x-4K 10.3 / 0.8x 16.2–16.9 / 0.4x 31.4 / 1.33x 1.09 / 2x 3.13 ms 全在 E15/E17 内。
- **[乙的两次诚实自查]** ①`edge9.exe` 里 2 行 [FAIL] 是其**探针期望错误**（0.8x 非整数比每列权重不同，期望不该是常数），用独立精确 box 参照复验 `bad=0/1658880`，不计缺陷；②性能与甲差异（0.8x 16.2–16.9 vs 14.5–15.3）归为机器负载噪声，同量级且在预算内。
- **[全量验证（父代理串行）]** 清空 `rtsc*` 后：`cmake --build build --config Release` → **FULL_BUILD=0（零 error 零 warning）**；`ctest -C Release` → **100% tests passed, 51/51**。至此 A1 缩放批次可在干净树上复现全绿。
- **[本日已入库 4 笔]** `3ec4d66` 服务器+端口、`c08df4f` 网关内存上限（2745MB→9.9MB）、`5b1e00a` 缩放重采样（二进制对齐）、`26bf98c` 协调日志。
- **[下一步]** 转入 **A2 输入/快捷键对齐**：证据文档 `docs/spec/input-evidence.md` 已含 E1-E4（`FUN_1801185e0` 用 `MapVirtualKeyW(vk,MAPVK_VK_TO_VSC)` + `FUN_1800e8dfc(inst,0x100/0x101,vk,sc)` 合成键消息；右 Win 置 `|0x8100`；焦点变化时重放 Shift/Win 归位并清零 `+0x414/+0x418`；本地 `keybd_event` 恒带 `dwExtraInfo=0x4321DCBA`；`FUN_180118940` 用 `0x414/0x418` 跟踪 LWIN/RWIN）。

## 第621轮：A1 完成（乙二次盖章）→ 转入 A2 输入/快捷键对齐，双审已派

- **[A1 状态]** 审计乙二次盖章，绑定 hash `5b1e00a`（resample.cpp `f52ab0c8…`、resample.h `b868d414…`、view.cpp `dbd7481d…`、view.h `9206f984…`、test_view.cpp `b62ab855…`）；依据 32/32 独立断言、边界 5 类、mutC 变异转红、46/6529/0、ctest 4/4、性能全在 E15/E17 内。
- **[全量门禁]** 父代理串行：`cmake --build build --config Release` **零 error 零 warning**；`ctest -C Release` **51/51 passed**。
- **[A2 派发]** 组A=输入/快捷键对齐，甲 `ses_e7f015642ffegVUtm2xZmQuwTE`、乙 `ses_e7f00d819ffe7Zcg98uyLMsmuE`（互相独立，已双向告知 ID）。审计重点：①`TranslateWin32KeyMessage` 全分支（set-1/extended/AltGr/WM_SYSKEY*/Alt+F4）；②FastPath 编码与 [MS-RDPBCGR] 2.2.8.1.2.2 一致性；③Win 键转发（mstsc 有 `keybd_event(VK_LWIN, EXTENDED)` + `Win+L` 合成）；④**修饰键归位**（mstsc 焦点变化时重放 Shift/LWIN/RWIN 并清零 `+0x414/+0x418`）；⑤输入坐标逆映射（与 A1 的 `ViewTransform` 联动）；⑥Ctrl+Alt+End / Alt+Tab 可达性。
- **[父代理初步观察（待审计确认）]** 全仓 `VK_LWIN|VK_RWIN|0x5B|0x5C|resync|release.*modifier` 零命中 → 疑似完全没有 Win 键转发与修饰键归位；`input.cpp:78-85` 已有 Ctrl+Alt+Del 合成序列可作参照。

## 第622轮：A1 收口（双审已解散）+ A2 输入双审在途

- **[A1 最终状态]** 乙三次发送同一盖章文本（内容一致、hash 未变），已判定闭环；对应的两个审计会话与执行会话已 delete 解散（按第 9 条：任务完成后清理）。
- **[当前树]** `git status` 空、无 `rtsc*` 残留进程、Free 27.8GB。全量构建零 error 零 warning、ctest **51/51**。
- **[A2 在途]** 甲 `ses_e7f015642ffegVUtm2xZmQuwTE` / 乙 `ses_e7f00d819ffe7Zcg98uyLMsmuE`（均 busy），已双向通告知会话 ID；审计重点为 `TranslateWin32KeyMessage` 全分支、FastPath 编码与 [MS-RDPBCGR] 2.2.8.1.2.2 一致性、Win 键转发、修饰键归位、坐标逆映射、Ctrl+Alt+End/Alt+Tab。
- **[待确认事实]** 全仓 `VK_LWIN|VK_RWIN|0x5B|0x5C|resync|release.*modifier` 零命中（父代理亲检）→ 疑似完全没有 Win 键转发与修饰键归位；`input.cpp:78-85` 已有 Ctrl+Alt+Del 合成序列可参照。

## 第623轮：A2 乙审报告（父代理亲核 2 条为真）

- **[P0-3 命令 ID 冲突·已亲核为真]** `include/rtsc/ui/window.h:83 kCmdSendCtrlAltDel = 19` 与 `:96 kCmdHelp = 19` **重复** → 点「帮助」会发出 Ctrl+Alt+Del（SAS）。同时 `window_win32.cpp` 无 Ctrl+Alt+End 映射、菜单只有「查看」、tools 从不调 `Client::SendCtrlAltDel`、`EncodeCtrlAltDel` 无测试 → **SAS 完全不可达**。
- **[P1-4 点击映射相位不一致·已亲核为真]** `MapViewportPoint` 用 `sx=(vx-vt.x)*src_w/vt.width`（左边缘/floor），而 A1 渲染用中心相位 `((2d+1)S-1)/(2D)`。审计实测 `S=100,D=4,d=1`：映射 25、渲染 37 → **偏差 12 像素**；`5→8,d=3` 映射 1、渲染 2。修法：映射改用同一 E8 相位（`NearestIndex` 的逆），或按渲染表反查。
- **[其余待甲复核]** P0-1 无修饰键归位（无 `WM_KILLFOCUS/WM_ACTIVATE/WM_SETFOCUS`，`WM_CLOSE(:260-263)` 与 Alt+F4 不释放 Alt）；P0-2 Win 键无策略（`window.h:84-95/212-217` 声明 `WinKeyMode` 三档但 `src`/`tools` 零实现，`SetWinKeyMode` 是 no-op；通用路径 `window_win32.cpp:641-654` 无条件透传 LWIN/RWIN）；P1-5 多屏负 origin 直接 `m.left/m.top` 相加（`main.cpp:533-537`）而 span 用 union 相对 → 负值转 uint16 回绕、同一点两模式 wire 值不同；P1-6 无 `SetCapture`（拖出窗丢 button-up）、span 模式滚轮恒被本地缩放消费；P1-7 `Pause`/`EXTENDED1` 不能编码（`input.h:22` 死常量）、lParam scancode=0 的合成扩展键丢 bit24、`EncodeUnicodeEvent`/`EncodeSyncEvent` 死代码；P1-8 Alt+Tab 转发能否阻止 shell 全局热键 **未验证**。
- **[Q2 结论（正面）]** FastPath 键盘编码与 dump/规范一致：`eventHeader=(code<<5)|flags`（`input.cpp:15-17`）、`RELEASE=1/EXTENDED=2/EXTENDED1=4`（`input.h:19-23`）、`docs/spec/share-data.md:691-702`；SAS 六事件序列正确（`input.cpp:76-87`，字节 `180e001d0038025303530138011d`）。**缺口只在 EXTENDED1**。
- **[方案建议（乙）]** Win 键：W1 透传（驳回）/ W2 `WH_KEYBOARD_LL` + 本地重注入（最保真、风险最高）/ **W3 无钩子按 WinKeyMode 门控（推荐先落，W2 作可选后端）**；归位：R1 仅失焦释放（最小）/ **R2 mstsc 式 Shift 重放 + Win up（推荐默认）** / R3 `GetKeyboardState`（不推荐）。12 条先红后绿测试已列（含 T6 SAS 字节、T7/T8 中心映射、T9 负 origin 不回绕）。

## 第624轮：A2 取证补强——反编译定案「Win 键默认发给远端」

- **[新二进制证据]** 反编译 `mstscax.dll!FUN_1800e8f08`（20,577 字节，`FUN_1800e8dfc` 组好 MSG 后调用的「消息→输入事件」分派）：键盘分支处理 `0x100/0x101/0x104/0x105`（normal + sys 四类）；keyup 判定 `(local_a0 - 0x101 & 0xfffffffb) == 0`（即 0x101 或 0x105）；`VK_PACKET(0xE7)` 有独立 Unicode 分支；**统一发送点 `vtable+0x38` 无 0x5B/0x5C 排除分支**，且 `0x5B→+0x41C`、`0x5C→+0x420` 的按下态记录发生在**发送成功之后**。
- **[定案]** **mstsc 默认把 Win 键发到远端**（推翻审计"默认策略未验证"）；`+0x41C/+0x420` 是"已发远端的按下态"，正是 `FUN_1801185e0` 补发 up 的依据。→ A2 的 Win 策略默认应为 **kRemote**，kLocal 作可选，kFullScreenOnly 待全屏接通。extended 位仍为 lParam bit24（与现有实现一致）。
- **[A2 缺陷清单（乙版，父代理已亲核 2 条）]** 必修：**P0-3** 命令 ID 冲突（`window.h:83 kCmdSendCtrlAltDel=19` 与 `:96 kCmdHelp=19`，点帮助会发 SAS）+ Ctrl+Alt+End 无映射 + `SendCtrlAltDel` 无调用；**P1-4** 点击相位（`view.cpp:154-155` 左边缘 vs `resample.cpp:62-67` 中心相位，S=100/D=4/d=1 得 25 vs 37）；**P1-5** 跨屏 union origin（`main.cpp:533-537` 直接加 `m.left/m.top`，负值转 uint16 回绕；spec: pointer 坐标是无符号、相对 union 桌面左上，monitor 的 left/top 为 signed 相对 primary）。高危：**P0-1** 无修饰键归位（无 `WM_KILLFOCUS/WM_ACTIVATE`）；**P0-2** Win 策略门未实现（`SetWinKeyMode` 空实现）。中：P1-6 滚轮坐标未填/span 恒被本地缩放消费、P1-7 全屏/连接栏死路、P1-8 无 SetCapture。低：P2-9 EXTENDED1 不可表达、P2-10 Ctrl+数字吞键、P2-12 消息白名单。
- **[正面结论]** FastPath 键盘编码本身正确：`eventHeader=(code<<5)|flags`（`input.cpp:15-17`）、`RELEASE=1/EXTENDED=2/EXTENDED1=4`（`input.h:19-23`）、SAS 六事件字节 `180e001d0038025303530138011d`（`input.cpp:76-87`）。缺口只在 EXTENDED1。
- **[仍未验证]** `param_1+0x424` 字段语义；`0x4321DCBA` 含义；归位**触发时机**（`FUN_1801185e0` caller 未定位）；三档 Win 策略默认归属；mstsc 负 origin 实际 wire 值；Ctrl+Alt+End→SAS；吞 `WM_SYSKEYDOWN` 能否阻止 shell 热键。

## 第625轮：A2 双审收敛 → 定案并派两个执行 AI（文件域互斥）

- **[双审一致]** 甲/乙各自独立得出同表（甲侧 S1-1..S3-12，乙侧 P0-1..P2-12），并互相盖章；差异仅方案取舍。
- **[必修 6 项（已派 A2-1 输入/窗口层）]** ①**命令 ID 冲突**（`window.h:83/96` 皆 19 → 点帮助发 SAS）+ 编译期唯一性断言；②**Ctrl+Alt+End→SAS**（现状只发 6 个裸 scancode；`Client::SendCtrlAltDel` 无调用；SAS 字节 `180e001d0038025303530138011d`，`EncodeCtrlAltDel` 无测试）；③**修饰键归位 R1**（无 `WM_KILLFOCUS/WM_ACTIVATE/WM_CLOSE` 释放 → Ctrl 粘滞；甲实测 `events emitted on WM_KILLFOCUS: 0`）；④**Win 策略门真实现**（`SetWinKeyMode` 是 no-op；默认 kRemote 有 E5 证据）；⑤**Pause/Break 编码**（实测 `wire=0045`，规范要求 `04 1D`/`00 45`/`05 1D`/`01 45`）；⑥**合成消息丢扩展位 + msg 白名单**。
- **[必修 4 项（已派 A2-2 视图/坐标层）]** ⑦**点击相位统一为 E8 中心式**（`100→4,x=1` 现 25、应 37）；⑧**多屏 union origin**（spec：pointer 为 u16 相对 union 桌面、monitor left/top 为 signed 相对 primary → `main.cpp:533-537` 负值回绕 `(uint16)(0-1920)=63616` 且与 span 不一致）；⑧**滚轮路由（产品决策：普通滚轮转发、Ctrl+滚轮缩放、边界必须 consume、`WM_MOUSEWHEEL` 填 x/y）**；⑨**Ctrl+数字改 opt-in**（默认不吞，修文案 1..4 vs 1..7）。
- **[甲的重要勘误]** 其先前"滚轮指针跳 (0,0)"结论撤回：`[MS-RDPBCGR]` 明写 WHEEL 时 xPos/yPos **SHOULD be ignored**。
- **[未验证保留]** `param_1+0x424` 语义、`0x4321DCBA` 含义、归位触发时机、三档 Win 默认归属、mstsc 负 origin 实际 wire、Ctrl+Alt+End→SAS、吞 `WM_SYSKEYDOWN` 能否拦 shell 热键、`INFO_DISABLECTRLALTDEL` 语义。
- **[产品决策（本次定了，后续可改）]** 滚轮默认转发、缩放改 Ctrl+滚轮；Ctrl+数字默认不吞；Win 默认 kRemote、kLocal 可选；R1 归位而非 R2（R2 需 REA 回证 caller）。

## 第626轮：U7 实测（Win up 被 shell 吃掉 / IME 换 VK_PROCESSKEY）→ 并入执行要求

- **[自建探针实测]** `%TEMP%\opencode\winprobe\probe2.exe`（自建窗口 + SetForegroundWindow + keybd_event + 泵消息）：`A_key: [KEYDOWN 0xE5][KEYUP 0x41]`；`WIN_key: [KEYDOWN 0x5B]`（**无 KEYUP**）。
- **[结论 1：Win up 不到达]** Win 键的 `WM_KEYDOWN` 能到达普通窗口，但 `WM_KEYUP` 被 shell（开始菜单）消费 → **kRemote 不需 LL hook 即可收到 Win down，但必须自行补 Win up**，否则远端 Win 永久粘滞。这解释了 `FUN_1800e8f08` 的 `+0x41C/+0x420` 记录与 `FUN_1801185e0` 的补 up。
- **[结论 2：IME 替换 VK]** IME 激活时 `WM_KEYDOWN` 的 `wParam` 可能是 `VK_PROCESSKEY(0xE5)`（A 的 down=0xE5、up=0x41）→ **必须用 lParam bits16..23 扫描码**（A1 的扫描码修复因此是必要的）；但 `vk==0xE5 && 扫描码==0` 时回退 `MapVirtualKeyW(0xE5)` 会得到垃圾 → 必须丢弃。
- **[已以 relay 并入 A2-1 执行要求]** 新增三条断言：T-WinUp（只发 Win down、失焦必须补 `03 5B`）、T-IME（wParam=0xE5 + lParam 扫描码 0x1E<<16 → 发 0x1E）、T-IME2（wParam=0xE5 + lParam=0 → 丢弃）。
- **[证据入档]** `docs/spec/input-evidence.md` 新增 E6（提交 a967918），并明确"基于 keybd_event 注入、非物理键；LL hook 能否看到 Win up 未测；三档默认值未知"。
- **[在途]** A2-1 `ses_e7eef6e8dffeuhgN6mLM0qpjLl`（输入/窗口层 6 项）、A2-2 `ses_e7eef50d9ffe1V1Z1HPO3jDJB1`（视图/坐标层 4 项）；A2 双审甲乙已收敛并盖章（甲终版 D1-D12 + Phase 0-6 顺序）。

## 第627轮：模型计费组硬阻塞（子代理全挂）→ 父代理亲自收口 A2 并提交 959aaa7

- **[阻塞上报]** 子代理全部因 `APIError: API key pinned to a billing group with no available provider for "deepseek-v4.1-flash"` 失败（账户/额度类硬阻塞，重试必再失败）→ 已停止派发。用户重新唤醒后由**父代理亲自完成** A2 收口。
- **[修复半成品]** 执行代理留下不可构建状态：①`input.h` 已改 4 参 `EncodeKeyboardEvent(..., bool extended1=false)` 而 `.cpp` 仍 3 参 → **C2668 重载歧义**；②`EncodePauseKey()` 停在 RED 版本（单 `0x45`）；③`MapViewportPoint`/`MapMonitorPointToDesktop` 停在 "RED PHASE" 旧实现（测试已按 E8/union 写好，4 个用例红）；④`main.cpp` 未接线（仍是 `m.left` 直接相加 + 滚轮先被 zoom 吞）。
- **[父代理修复]** ①`.cpp` 补 4 参定义 + `kKbdExtended1` 置位；②Pause 改 `CTRL(0x1D,EXT1)↓ / 0x45↓ / CTRL↑ / 0x45↑`（字节 `04 1D`/`00 45`/`05 1D`/`01 45`，`kScancodeNumLock` 不存在 → 复用 `kScancodePause=0x45`）；③`MapViewportPoint` 改 E8 中心相位 `((2d+1)S-1)/(2D)`；④`MapMonitorPointToDesktop` 改 `monitor_left - origin_x + local_x`（去 u16 强转）；⑤`main.cpp` 用 union 原点（`min(left)`/`max(right-origin+1)`）并接线 `MapMonitorPointToDesktop`；⑥滚轮路由改「普通滚轮转发 / Ctrl+滚轮缩放」。
- **[A2-1 已落地部分（父代理亲核）]** 命令 ID 唯一化（SAS=19 / winKey=20 / help=21 / pause=22）、`WM_KILLFOCUS`+`WM_ACTIVATE` 归位、`win_key_mode_` 默认 `kRemote`、SAS chord → `PushCommand(kCmdSendCtrlAltDel)`、`VK_PROCESSKEY(0xE5)` 特判、Pause 特判、合成键固有扩展表。
- **[验证]** `FULL_BUILD=0`；`ctest -C Release` **51/51 passed**；view **50/6564/0**、ui **27/141/0**、input **12/42/0**。提交 `959aaa7`（10 文件）。工作树干净。
- **[教训]** 计费组阻塞期间必须先查子代理错误类型再决定"重试 vs 上报"；且**执行代理被中断会留下不可构建的半成品**（本轮 4 处），父代理接手时必须先构建并以测试红清单定位未完之处。

## 第628轮：A3 取证入档 + 实网验证（0.75x 缩放、输入探针）

- **[提交 a7c43ce]** `docs/spec/bitmap-evidence.md`：mstsc 字符串表取证（`NSCODEC (%d)`@0x1806c8bb0、`PLANAR (%d)`@0x1806c8c90、`PROGRESSIVE V1/V2`@0x1806c8bd0/0x1806c8d88、`GfxClearCodec`@0x18078dc80、`CaDecProgressiveRectContext`@0x1806b06f0 等）+ 本仓已实现路径（raw 8/15/16/24/32、RLE、RDP6 planar、NSCodec）+ 差距（ClearCodec/Progressive V1/V2 未实现；RemoteFX 未验证）+ 下一步取证顺序（解码分派表 → Progressive 启用条件 → 真机抓包）。**仅取证、未改实现**。
- **[实网验证·0.75x 缩放]** `rtsc_gui 192.168.1.7 ... 1280 1024 win32 0.75 0 --seconds 50` → 日志 `view: 1280x1024 -> 960x768 at (160,128), scale 0.750`、`734643 non-black`（源 1299592 × 0.5625 ≈ 731020，与面积平均预期一致）、826 colours、跑满 50s 正常退出。
- **[实网验证·输入]** `--input-probe`（headless）→ `input probe queued: key 0x1E, mouse (11,13)` + `application sends: input=2`（键与鼠标事件均真实发出）。
- **[帮助文本修正 30b559c]** `main.cpp:132` 原写"wheel zooms, Ctrl+wheel zooms finely"，与 A2 新路由（普通滚轮转发、Ctrl+滚轮缩放）不符 → 已改。
- **[A5 取证]** mstsc 字符串：`DisableRDPSNDSVC`@0x1807a4a68 / `TS_PROP_WIN32CORE_DISABLE_RDPSND_SVC`@0x1807a4ae0 / `CRdpSndPlugin`@0x1807e7020 / `rdpsnd static channel connected`@0x1807e6ef0；cliprdr 侧 `CClientClipRdrPduDispatcher`@0x1807f8600 / `RdpClipRdrWindowClass`@0x1807f82d0；RAIL 509 条（`RAIL_WINDOW`@0x1806b1578、`Couldn't determine if connection is RAIL`@0x1806b6270）。
- **[阻塞未解]** 子代理 API key 计费组仍无 `deepseek-v4.1-flash` provider → 所有后续批次只能由父代理串行推进（无法并行双审）。当前 51/51 全绿、工作树干净。

## 第629轮：横向滚轮 / X 键 / 拖拽捕获（审计 P1-8 闭环），提交 2368b88

- **[缺口]** `window_win32.cpp` 完全丢弃 `WM_MOUSEHWHEEL`/`WM_XBUTTON*`，且无 `SetCapture` → 横向滚动与侧键无效、拖出窗口丢 button-up（远端卡拖拽）；`WM_MOUSEWHEEL` 也不填坐标（审计实测 `x=0 y=0`）。
- **[实现]** ①`InputEvent` 增 `horizontal`（复用 `kMouseWheel`）；②`WM_MOUSEHWHEEL` → `horizontal=true`，编码走 `kPtrHwheel(0x0400)` 而非 `kPtrWheel`（否则远端滚错轴）；③`WM_XBUTTON*` → button 4/5，编码为 `MOUSEX`（eventCode 2）+ `BUTTON1/BUTTON2`；④首个按下的按钮 `SetCapture`、最后一个释放时 `ReleaseCapture`；⑤滚轮事件补 `ScreenToClient` 得到的客户区坐标。
- **[测试]** 新增 2 条客户端字节级断言：HWHEEL = `0x0401`（`pdu[3]=0x01,pdu[4]=0x04`，且**不得**含 `0x0200`）、X1 = MOUSEX `0x9000`、X2 = MOUSEX `0xA000`。client 套件 **13 tests/52 checks/0**；全量 **51/51**。
- **[A3 取证进展]** codec 命中串簇 `0x180699cb8..0x180699d40` 经 `inspect_native_instruction` 判定为 **data（统计表）**，非解码分派代码 → 不能用来定位解码器选择；`PLANAR (%d)`@0x1806c8c90 的引用点也在同一数据区。下一步需换路径（按 `bitmapCodecId` 常量或 caps 协商处切入）。
- **[阻塞未解]** 子代理 API key 仍无 `deepseek-v4.1-flash` provider → 本批为父代理单人执行，未走双审（补审需额度恢复后补）。

## 第630轮：模型恢复 + 甲乙双审重开

- **[模型]** 用户确认 `unorouter-ai/deepseek-v4.1-flash` 恢复可用；minimax 甲（`ses_e7e865b02ffeQWqZICCt6vYVG7`）已 abort，改派 unorouter。
- **[在途]** 甲 `ses_e7e842838ffeIGRQcbegi1aB5n`（逐条断言 + 变异反证）／乙 `ses_e7e8419cdffeeERUqrk1CUc63H`（需求反推 + 分支完备 + 状态机收敛），审 `959aaa7` + `2368b88`；组内 ID 已双向补发。
- **[待办]** 磋商定案后：若驳回则回①修复→复验；通过则由甲乙一致盖章，再推进 A4-A7。

## 第631轮：甲回复核复审 → 双驳回 → 派执行修复

- **甲乙双审结论**：`959aaa7` + `2368b88` **双驳回**，磋商收敛无未决点（`ses_e7e842838ffeIGRQcbegi1aB5n` 甲、`ses_e7e8419cdffeeERUqrk1CUc63H` 乙，均 taotoken/deepseek-flash）。
- **P0×2**：①SAS/Pause 断链（`main.cpp` kUiCommand 无消费→SendCtrlAltDel/SendPauseKey 接通）；②X 键字节（PTRFLAGS 0x1000/0x2000 ⇒ 规范 PTRXFLAGS 0x0001/0x0002，X1 down=0x8001、up=0x0001；X2=0x8002/0x0002；server.cpp kMouseX 同步）。
- **P1×4**：NumLock/numpad 扩展位回归（真实消息只信 bit24，删 VK_NUMLOCK，禁 MAPVK）；Capture 生命周期（WM_CAPTURECHANGED/失焦释放+位图，防计数>0 粘滞）+ 负坐标 GET_X/Y_LPARAM clamp；HWHEEL 能力门（TS_INPUT_FLAG_MOUSE_HWHEEL 0x0100｜解析服务端 InputCapabilitySet）。
- **P2**：滚轮量化累积/delta0 不事件；Ctrl+wheel 极限 consume；Pause 跨失焦复位；SAS End 泄漏补 up；P3 wp→lp 同批。
- **执行**：`ses_e7dedad5affeah0vJuuPnNXnxg`（taotoken）已派发，定案 TDD + 变异探针 + 全量 build；甲乙已被通知复核。
- 全程 C0 门：执行在途，主侧未改代码；记忆文件本轮只增台账，无裁剪。

## 第632轮：甲乙收口确认

- 甲/乙收到派发通知均确认：终审定案无异议、全部断言有探针实证、执行报告到达后按逐条判定项独立复验（先红/绿再判断）才盖章。
- 在途：执行 `ses_e7dedad5affeah0vJuuPnNXnxg` TDD 修复中；甲乙待其报告复核。主侧无代码改动，静默待命。

## 第633轮：执行交付 fb20d65 + 旧批次子代理清理

- **执行子提交 `fb20d65`**（20 文件 +1069/-72，工作树干净）：P0-1 SAS/Pause 端到端（main 消费 kUiCommand→SendCtrlAltDel/SendPauseKey，字节断言）、P0-2 X 键改 PTRXFLAGS 0x0001/0x0002 + server kMouseX 同步、P1-1 NumLock/numpad（真实消息只信 bit24、删 VK_NUMLOCK）、P1-2 capture 生命周期（held_buttons_ 位图+WM_CAPTURECHANGED+负坐标 GET_X/Y_LPARAM clamp）、P1-3 HWHEEL 能力门（0x0100 解析+门禁）、P2 六项、MapMonitor clamp。受影响套件全绿（client 14/63、ui 40/226、input 13/43、view 53/6582、server 21/193、capabilities 42/315、session 13/80）。
- **待复核**：甲乙已从执行子报告收到，进入复核。
- **旧批次子代理**：`ses_e7eef50d9ffe1V1Z1HPO3jDJB1`（视图坐标层修复）报额度硬阻塞（usage up），其任务范围已被 fb20d65 整批覆盖且无未提交代码 → **abort 清理**；`ses_e7eef6e8dffeuhgN6mLM0qpjLl`（输入窗口层修复）pending，已 relay 核对是否重叠，待回报决定（abort/prompt）。
- **上报用户**：旧子代理额度 `Your subscription allowance for this period is used up`——免费模型仍可用；现役执行/审计均用 taotoken/deepseek-flash 未受阻塞，仅旧批次冗余子代理受影响。

## 第634轮：旧批次清理完成 + 派甲乙复核 fb20d65

- 旧批次两个子代理（视图坐标层 `ses_e7eef50d9ffe1V1Z1HPO3jDJB1`、输入窗口层 `ses_e7eef6e8dffeuhgN6mLM0qpjLl`）均报额度硬阻塞（usage up，free models still work）；两者任务范围均已被 fb20d65 整批覆盖、无未提交代码 → 已 abort 清理。
- **甲乙复核已派发**（prompt 续既有会话，taotoken/deepseek-flash）：要求逐条亲证（红绿/探针），重点含执行子自述的 5 处偏离（server up 缺 button、滚轮量化、delta0 语义、SAS End 防御分支、HWHEEL 门禁连接期默认、desktop 尺寸协商）。
- **上报用户**（额度阻塞）：旧批次冗余子代理受影响已清理；现役审计/执行均为 taotoken/deepseek-flash（free）无阻塞。若后续需非免费模型并行扩能，需用户处理额度。
- 在途：甲乙复核中。

## 第635轮：输入批次 fb20d65 双审盖章完成

- **C0 独立验收**：全量 build 0 err/0 warn；ctest Release **51/51** [BASH]。
- **双审盖章**：甲（`ses_e7e842838ffeIGRQcbegi1aB5n`）乙（`ses_e7e8419cdffeeERUqrk1CUc63H`）各自独立探针/变异/套件后一致「可盖章」；主代理已记录 `docs/spec/input-evidence.md` §6 的 7 条 P3 观察项（排期后续）。
- **批次状态**：A2 输入（SAS/Pause/X键/HWHEEL/capture/NumLock/坐标/clamp）**闭环完成**。
- **历史实现批次待审**：`5b1e00a` 缩放、`c08df4f` 网关内存、`3ec4d66` 服务器生命周期此前为父代理单人（模型阻塞期），未走双审——与 FB 一致的补审另行排期。
- **下一步**：排期项（P3 观察 1-7）或 A4-A7 新功能；真机验证 A2 输入批次。

## 第636轮：A4 cliprdr 取证启动（REA 打开 mstscax.dll d73c76d6…）

- 复验 `G:\sre` 无目标 → 用 `C:\Windows\System32\mstscax.dll`（9,166,848B，sha256 前缀 d73c76d65721043c 与立项一致）。
- **取证锚点**：通道字符串 "CLIPRDR"@0x1807f8150、"RdpClipRdrWindowClass"@0x1807f82d0、dispatcher 工厂串@0x1807f8600；构造器 FUN_180658114（类型标记 0xdbcaabcd）。
- **关键发现**：CClientClipRdrPduDispatcher 三虚表（0x1806991a8/1c8/0x18066f120）已解码；`FUN_180658eb0`=Init 按 **event source ID 0x9b/0x9c…** 创建 FORMAT_LIST/RESPONSE 等事件源；`FUN_180659680`=析构逐源移除。**mstsc cliprdr 是事件驱动异步发送架构**，与仓内同步 OnPdu 直发不同——列为差异点待对照决策。
- 证据已入 `docs/spec/cliprdr-evidence.md`（commit 4c49c41）。
- **下一步**：分派表取证（FORMAT_DATA_REQUEST/RESPONSE/锁/TempDir）→ Capability set 固定值 → 与 cliprdr_client.cpp 对照出偏差清单。
- 本互审计流程：A4 为主代理取证（REA 仅主侧）；取证书面后如需改代码再走 W11（审计成对）。

## 第637轮：A4 cliprdr 取证三阶段完成（4 提交）

- 分派表完整解码 `FUN_180658670`：msgType→handler（1 FORMAT_LIST、2 RESP、3 DATA_REQ、4 DATA_RESP、5 CLIP_CAPS、7 FC_REQ、8 FC_RESP、10 LOCK、11 UNLOCK、12/13 DATA_CHANNEL_REQ/RESP、else UNKNOWN）。
- **新发现**：mstsc 有 DATA_CHANNEL 扩展（0xC/0xD）+ UNKNOWN_PDU 独立 handler；TEMP_DIRECTORY(6) 无独立分派。
- capset payload 全为运行时构造（search_bytes 全段无命中）→ msgType 编号与 CAPS 数值归入真机抓包裁决。
- 偏差清单 v0.1 入库（005c499）：仓内缺 DATA_CHANNEL/FILECONTENTS 路径、UNKNOWN_PDU 静默差异。
- **决策点（待用户/W11）**：FILECONTENTS（文件拖放）与目标功能相关，建议优先实现；走 W11 双审定案。
- **下一步选择**：①A4 FILECONTENTS 实现（需定案+执行子）；②先 A5 rdpsnd 取证；③真机 wire 裁决。

## 第638轮：C0 复验 → view bench 超预算定位为环境争用

- 全量 ctest 51 套件：**view 1 项红**（view_scale_benchmark_1280x1024 0.8x 25.58ms>22.00ms），其余 50/51 绿 + 全量 build 0err/0warn。
- **根因排查（非代码回归）**：同期 `F:\il2cpp` 项目 4-6 个 cmake 构建进程占满 CPU（LoadPercentage 持续 99-100%），基准计时被争用膨胀。discover.md bf052fc 已记录。
- **基线**：独占环境 0.8x≈19.54ms（审计乙曾独占复跑绿）；本机 CPU 争用消除后复跑应复绿。
- **C0 结论**：代码层无回归；基准敏感项已记录处置路径（等独占/其他项目构建结束）。
- **下一步**：A4 决策（FILECONTENTS 实现 vs A5 rdpsnd 取证）待用户/定案。

## 第639轮：FILECONTENTS 双审开跑 + A5 rdpsnd 锚点

- **FILECONTENTS 定案双审在途**：甲 `ses_e7ceadf43ffe9TqwJeeOyFu6Xl`（wire 结构/集成点）、乙 `ses_e7ceaa238ffejunTsXnTTyMGhq`（状态机/失败路径）；均已 relay 互告成员 ID。任务：CB_FILECONTENTS_REQUEST/RESPONSE（0x0008/0x0009）客户端实现定案。
- **A5 rdpsnd**：`docs/spec/rdpsnd-evidence.md`（0e96110）锚点：rdpsnd 通道串 @0x1807e6xxx、"CRdpSndPlugin"@0x1807e7020、插件工厂 FUN_1804f5274、通道初始化 FUN_1804f3d18（本批发现其仅生命周期日志，非格式协商→需更深层定位 TSSNDCAPS 构造）。
- **C0**：去重 view bench 已确认非代码（il2cpp 争用）；50/51 绿基线。
- **下一步**：等 FILECONTENTS 双审定案 → 报主定案 → 执行 TDD → 双审复核 → 盖章；A5 TSSNDCAPS 深挖。

## 第640轮：FILECONTENTS 执行完成 + 甲乙复核派发

- 执行子 `ses_e7cda5bbeffeX4X5wjC9sjeRSC` 完成方向 A（86/422，5 变异红→绿）：proto+channel+clipboard 接口、F1-F15、Serve/Take 门、4 缺陷修复、main.cpp 接线（EnableFileClip+Poll）。工作树 7 文件改动未提交。
- **执行子登记 2 处需审计裁决**：①FCR parse 白名单扩到 {24,32}（删 28-32 判定取舍）；②§6 测试清单未逐条对表（缺失测试风险）。
- 甲乙复核已派发（prompt 续既有会话）：甲对 §6 逐条对表+FCR 白名单 wire 裁决；乙独立探针抽查 F 路径+状态机收敛。
- **下一步**：复核结果→若驳回转执行子修→盖章后我做 C0 全量+提交。

## 第641轮：FILECONTENTS 复核驳回 → 返修派发

- 甲驳 D1(wire 24/28 parse/encode)/D2(广告不对称)/D4/D5+缺测；乙驳 D1-D5+9 缺测，独立探针 10 checks（A2/A3/B1 白名单/锁门红证；C1/D1/E1 门 PASS）。甲乙一致。
- 执行子已接返修指令：D1 parse/encode 改 {24,28} 无 presence 字 + 头注修正；D2 OnFormatDataRequest 加 provider FILELIST 应答（方向B Serve 侧完成件）；D3 take 侧 4GiB 上限；D4 pending_format_==0 卫；D5 注释；9+ 项缺测补齐。
- 在途：执行子返修 → 甲乙复验 → 盖章。
## 第642轮：FILECONTENTS 双审一致盖章放行 → 提交 d29ec55
- 甲乙双审一致放行（甲 105/546 + D1 探针绿；乙 19/19 探针 + 本地重建 105/546）。
- 主侧 C0：全量 build 0err/0warn；ctest 51/51（含 view，il2cpp 争用消除）。
- 提交 d29ec55（feat: cliprdr CB_FILECONTENTS）+ 证据 f88b3b5。工作树干净。
- 遗留 ticket（排期）：方向B backend；真机抓包（UNVERIFIED 五项）；D4 可选加固；A5 rdpsnd 深挖。
## 第643轮：方向B 执行子开跑 + A5 取证结论
- **方向B backend**（DropFileList：Win32 CF_HDROP→FileListProvider）：执行子 `ses_e7c8294a5ffeToJLdRon4Agorb` TDD 在途（接口契约已核 d29ec55 的 file_list.h；DROPFILES 布局/pFiles 偏移/双 null 表/fWide 防御/read_range 磁盘读）。
- **A5 rdpsnd**：CRdpSndPlugin 工厂/主 vtable 定位；TSSNDCAPS 格式数组 search_bytes 无静态匹配 → **运行时构造，转为真机抓包裁决项**（77e0514）。仓内 rdpsnd 实现已有套件 Test #31/#32。
- 下一步：等方向B 执行子报告→双审→盖章→C0+提交；真机抓包（cliprdr capset/A5 TSSNDCAPS 同为 wire 裁决项）。
## 第644轮：方向B 执行完成 → 甲乙复核派发
- 执行子 `ses_e7c8294a5ffeToJLdRon4Agorb` 完成 DropFileList（DROPFILES 头解析/fWide 门/pFiles 防御/basename/惰性 size/read_range append+截断），30/84 绿 + 3 变异红→绿；main.cpp 方向B 集成（WM_CLIPBOARDUPDATE→provider 会话级）；CMake 新增 rtsc_clipboard_tests。
- 已派甲乙复核（prompt 续 FILECONTENTS 组会话）：甲=解析正确性/生命周期/CMake；乙=分支完备/失败路径/悬垂判定。
- 下一步：复核章→C0+提交；真机抓包 wire 裁决（cliprdr+rdpsnd）。
## 第645轮：方向B 双审盖章入库 b09c4cf
- 甲乙一致盖章（甲：解析/生命周期/CMake 全过 + D-B1 复验；乙：分支完备/失败路径 + D-B1 端到端 FAIL）。返修 1 项（缺失文件 SIZE MUST FAIL）。
- 主侧 C0：build 0err/0warn；ctest 52 套件中 51 绿，view bench 因外部 il2cpp 构建 CPU 争用红（已知非代码，discover.md）。
- 提交 b09c4cf（direction-B backend）+ 证据文档。
- 剩余：①view 独占复跑待争用窗口；②真机 wire 裁决（cliprdr capset/rdpsnd TSSNDCAPS）；③GUI 真拖放端到端；④A5-A7 富余项（EnableSmartSizing/多屏 UI）。
## 第646轮：A6 EnableSmartSizing 语义裁定（逆向取证里程碑）
- 诉求：取证 mstsc 的 EnableSmartSizing 精确语义（plan.md:358）。
- 结果（58989b1 证据文档）：mstscax!FUN_18003444c@0x18003444c 读取 "EnableSmartSizing"（@79/81）与 "ZoomLevel"（@88）：
   * EnableSmartSizing=0 → 恒 1:1 BitBlt 直拷（即使窗口≠桌面）；
   * EnableSmartSizing=1 → 窗口≠桌面时 StretchBlt+HALFTONE(SetStretchBltMode(4)+SetBrushOrgEx(0,0))；
   * FUN_180036ba0 = 尺寸相等检测（相等跳过缩放）。
- 仓内现状：view.h 头注自称"smart sizing"且 fit 无条件缩放——与 mstsc 门控语义存在偏差待对齐（scale 默认 1.0 已隐含 1:1）。
- 下一步：A6 对齐实现（先红测试：未启用 smart sizing + resize → 期望 1:1）需 W11 定案（涉 UI 行为），下轮开。
- 环境：il2cpp 仍占 CPU（5 进程 97+%），view 独占复跑待争用消退。
- 在途：无子代理（全部 idle）。已归档 4 证据文档（scaling/input/bitmap/cliprdr/rdpsnd/smart-sizing）。
## 第647轮：A6 SmartSizing 双审定案派发
- 甲 `ses_e7c538e60ffeowybLvadUBYoH4`（语义对照/测试设计）、乙 `ses_e7c53662effeV20xc90AEk5qbL`（消费方/状态机）已开跑；成员 ID 双向补发。
- 输入：反汇编证据（FUN_18003444c 门控缩放 vs 1:1）→ 仓内 view 现状（ComputeViewTransform fit/zoom/默认 1.0）。核心判别=窗口 resize 后仓内是否错误自动缩放。
- 下一步：双审定案（无需改动|需改动）→ 执行/测试 → 双审盖章。
## 第648轮：A6 双审盖章入库 3414ece
- 甲/乙复验盖章（默认翻转无消费方回归、菜单接线完整、R3 语义正确、红证真实、bench flake 与本批无关）。
- 主侧：build 0err/0warn；提交 3414ece（fix: smart-sizing defaults align with mstsc）+ 证据文档；工作树净。
- 遗留：N1 全屏 no-op、N2 view_transform resize 链、view 独占复跑待争用。
## 第649轮：N1 全屏接线执行子派发 + A7 目标确认
- N1：执行子 `ses_e7c293be1ffedqG5mqX44lcMy0`（修复全屏菜单 no-op：main.cpp kUiCommand 分支加 kCmdToggleFullscreen→SetFullscreen；Window 接口加 fullscreen() 查询；unit+命令级测试+变异反证）。根因由 A6 审计乙定位。
- A7：目标 mstsc.exe（C:\Windows\System32, 1,114,112B）确认存在；A7 为窗口管理行为取证，产出=理解文档（仓内 rtsc_gui 自绘不直接复用），拟作独立批次。
- 在途：N1 执行子。
## 第650轮：N1+N2-① 菜单 no-op 修复双审双章入库
- N1 全屏（296fcfd）、N2-① 连接信息（4942812）双审盖章，工作树净。
- N1：ToggleFullscreen 接线+菜单同步+4 测+守卫（ui 44/243）。
- N2-①：kCmdConnectionInfo→ShowConnectionInfoDialog（真实 getter 不伪造；rtt 诚实 N/A）；NoteFrame 接线 fps；CMake 补对话框源（死代码根因）；守卫含 continue 断言（补 N1-D1）。ui 45/249、session_info 14/53。
- 遗留跟进：N-csi-1 RTT 接线（需真实写 PDU 输入点）；N-csi-2 守卫换绑变异盲区；N2-②③ SmartCard/Help no-op；A7 多屏 UI 取证。
## 第651轮：卡顿根因定位 + 性能修复执行子派发
- 根因（用户实测"整体都卡"，会话 A 数据 4440loop/234rendered）：
  ① transport.h:35 kReadTimeoutMs=30 → Pump 每轮干等最多 30ms，输入/画面响应量化 30ms，静止时冻结；
  ② window_win32.cpp:248 Present 每帧全屏逐像素 RGBA→BGRA（1280x1024=1.3M 循环/帧）纯软件。
- 用户裁定修复方向="改 Present+读节流"（非 GPU 重构）。
- 执行子 ses_e79d90772ffembaE4kwnz0sXZD 在途：Phase 3 先探针量化（convert/memcpy/render 单帧 us）→按数据定方案→验收含性能回归测试+真机对比。
- 纪律：不 git 写；禁 gateway；探针存 %TEMP%。
## 第652轮：性能修复双审盖章入库 f77b90f（ctest 52/52）
- 根因（真机会话 A 4440loop/234rendered + 用户"整体卡"）：①transport.h kReadTimeoutMs 30→2（Pump 读节流，响应量化 30ms）；②Present 逐像素 RGBA→BGRA（~967µs/帧 1280x1024）。
- 修复：①读节流 30→2（Windows select 按 tick 量化，实测 idle 31.4→15.6ms、loop 30→64/s；注释按实测不虚标）；②新增 RgbaToBgra 两像素三掩码 64 位交换（bit-exact、in-place、任意像素数）：967→355µs（2.7x）。
- 回归：perf 守卫改为**相对断言**（new≤0.6×old，回退旧实现必红）+ 3/5 像素混排与奇数原位边界用例。ui 50/265；**全量 ctest 52/52**（view 恢复，争用消退）；build 0err/0warn。
- 双审：甲乙无条件盖章（各自独立探针复现 ratio 0.30-0.39、回退红证）。
- 跟进项（记录）：真机再测延迟/帧率；POSIX idle ~500/s（poll 不 tick 量化）；gateway read budget 消耗速率随常量缩放；服务器回环关接问题；rendered 14/s 本质为服务器 dirty 内容率（两修提延迟非帧率）。
## 第653轮：旧会话 H-4 复验报告核对——全部已落实
- 被 abort 会话 ses_e8150e46（复验线程泄漏）交付 H-4 第 2 轮复验：6 项裁定可盖章（句柄 98 持平/UAF 无/Stop 语义/counts exactly-once/回落）。
- 主代理核对**当前位置**（对当前 HEAD）：
  ① `++live` 回滚守卫 + exactly-once 双锁防护已在 server.cpp:1590-1640（与报告指出的死锁路径方案一致）；
  ② `accept_any_credentials` 默认已 false（server.h:69）——报告风险 6 已不存在；
  ③ `server_refresh_continues_during_input` 断言已 `>=10`→`>=5` 并注释 14% 抖动原因（test_server.cpp:923-927）——报告抖动项已修复。
- 结论：报告的 6 项+2 后续项在当前位置全部已满足；该修复（3ec4d66 服务器生命周期 + 88c2734 相关）此前已双审入库。无新增工作。
- 注：该旧会话因模型计费组问题已 abort（taotoken 现工作流不受影响）。
## 第654轮续：真机会话 B——性能修复效果验证
- real-server-test 20s headless 实测（f77b90f 后）：
  | 指标 | 会话 A（前） | 会话 B（后） |
  | idle loop | 30-31.5/s | 64-67/s |
  | 极端波动 | 878-948/s | 峰值 112.6/s 平缓 |
  | avg | 221/s 波动 | 68.7/s 稳定 |
- 响应量化 31.4→15.6ms 真机确认；view 1.000 渲染正常；cliprdr 握手正常。
- 用户主观跟手性改善待确认。
## 第655轮：回环关接排查——根因=凭据不匹配（非代码 bug）
- 现象：rtsc_connect 127.0.0.1 回环到 rtsc_server_host，round 4 后 peer closed (n=0)。
- 排查：服务器 Capability CredSSP step3（NTLM AUTHENTICATE 478B）后关闭 → server 日志空 → 怀疑代码。深入读 credssp_server.cpp BuildPubKeyEcho：lookup_ 用 domain/user 查密码 → Ntowfv2 验算 → 不匹配则失败。
- **根因**：rtsc_server_host 默认 --user=rtsc --domain=NTDEV --password=password；而之前 rtsc_connect 用 test/test → NTLMv2 校验失败 → 正常关闭。**非代码 bug**。
- 验证：rtsc_connect 127.0.0.1 33895 MicrosoftAccount rtsc password → **13 轮握手成功、Client Info PDU sent**（CredSSP server 全状态机 OK，execute 100%）。
- 结论：此前执行子"服务器回环关接环境问题"= 凭据不匹配误报；回环服务器 CredSSP 正常。真机 192.168.1.7 与凭据也验证过（会话 B）。
- 更新 discover.md：回环测试必须使用 rtsc_server_host 的默认凭据（rtsc/password, NTDEV）或显式 --user/--password。
## 第656轮：历史批次补审完成（缩放/网关/服务器全部双审通过）
- 缩放 5b1e00a：甲乙盖章。乙独立暴力对拍 88,872 cases 0 失配 + 4 变异红绿分离。确认 N1(D-7 悬空)/N2(E17 无守卫)+新 P3-B4(DrawCursor 左边缘相位残留)/P3-B5(边界用例)。
- 网关 c08df4f：甲乙盖章。28/28 + 乙探针 16/16。整改 A(session_timeout 默认 30s 切断 idle)/B(ContentLength 乘前判可绕回)。
- 服务器 3ec4d66：甲乙盖章（死锁证明+压力 4 场景 0 失败）。F1-F6 + main.cpp:242 注释矛盾。
- 整改批次已派执行子 ses_e7943a646fferSXQAz6q3GNKRk（D-4 文档/DrawCursor 相位/网关 A+B/服务器 F4-F6）。
## 第657轮：发现的 flood-vs-Stop 挂死【最终证伪为测试挂死】
- 复现：rtsc_server_tests 套件 `server_flood_vs_stop_race_converges` 挂死（>60s），此前审计"绿"为偶发/旧二进制。
- 根因（Phase 1）：注册（server.cpp:1615-16 锁内 live++）与线线程启动（:1695 detach）分离；Stop 快照（:1760-64）可在两者间取得 → 漏掉该 session → 未被 s->Stop() → body 阻塞 Read → live 恒 1 → Stop 永等。乙审计"孤儿计数不可达"结论有缺陷。
- 影响：真实服务器并发停止 + 洪水连接时可能死锁（Stop 永挂）。低概率但真实。
- 发展：待派执行子修复（TDD 红证：flood 测试改保持连接句柄 open + runner.join 超时检测）。

## 第658轮：审计整改批次入库 a598931（51/51 绿）
- 内容：缩放 D-4/E17/DrawCursor 相位/边界；网关 session_timeout 默认0/CL 乘前判；服务器 total 口径/3 并发测试/WarnIfAcceptAll/main.cpp 注释；flood 测试改造（根因证伪=环境物 connect 2s×64+无界 join，非服务器死锁——甲乙锁序终裁）。
- 验证：build 0err/0warn；ctest 51/51（禁 gateway 完整套件）；server 24/216 ~13s。
- 后续排期：transport connect 无超时加固（阻塞 connect 死主机无限阻塞，乙 A 档建议）；真机 wire；rdpdr.dll；SmartCard。
- process round 记录已更正（00d5bec）。
## 第659轮：connect 加固双审盖章入库 ab0aad1
- 内容：非阻塞 connect+超时（select write|except/poll POLLOUT+SO_ERROR）+ kConnectTimeoutMs=10s + N-aware per-address slice（F1 修复共享预算黑洞独吞）+ F2 CI SKIP + V4-HANG 有界 accept。
- 双审：甲乙独立 V1-V6 对表盖章（F1 反证采纳、甲撤回 O2、V4 注入双轴变异守卫）。
- 验证：build 0err/0warn；ctest 51/52（view bench 偶发 flaky 与批次无关，单跑绿）；rtsc_net_tests 7/34 双平台。
- 后续排期：真机 wire / rdpdr.dll / SmartCard。
## 第660轮：服务器模式完整会话验证成功（自研 server ↔ 自研 client）
- 命令：rtsc_server_host --port 33922 --any-user --test-pattern ⇄ rtsc_gui 127.0.0.1 ... 800x600 headless --seconds 10
- 结果：surface 1280x1024 1310708 non-black；view scale 1.000 渲染正确；**loop 399-434/s（2.5ms/帧）**——服务器模式全链路性能优异。
- 证实：自研 RdpServer 完成 CredSSP/激活 → 自研客户端渲染桌面 → 服务器模式核心达成（objective 服务器模式项推进）。
- 服务器侧缺失（后续）：cliprdr caps_sent=0（服务器未实现剪贴板通道）、rdpdr=0、rdpsnd server version 0（服务器未播格式）。这些是服务器方向通道实现后续项。
- 家庭版解禁/多远程用户：本实现自带 RDP server（非依赖 Windows termsrv）→ 理论上天然绕过家庭版限制；多用户需会话隔离扩展（有 multisession 测试基础）。
## 第661轮：服务器侧 cliprdr 设计定案双審派发
- 服务器现状：channel join 接受但运行期 static channel 数据静默丢弃；cliprdr(1005) 无 handler。
- 目标：自研服务器↔客户端剪贴板互通（服务器侧运营剪贴板宿主=真实交互桌面，如可访问 Win32 剪贴板则服务器剪贴板即为桌面剪贴板）。
- 甲乙定案中（甲=状态机/后端集成；乙=时序/失败路径/复用）：接口/集成点（server.cpp shared PDU 路径）/并发/多 session/TDD/正常序（防双方死等 MonitorReady）/何为"互通达成"scope。
- 下一步：合并定案→按设计执行（服务器 channel 分发 + cliprdr handler + 剪贴板后端抽象 + TDD）→ 双审复验 → 服务器模式剪贴板闭环。
## 第662轮：服务器侧 cliprdr 定案盖章 + 实施派发
- 乙/甲定案双审完全收敛（防死锁时序=服务器先发；channel 名映射+count u16→u32 既有缺陷修复；MCS 三分支集成；全局剪贴板+seq 轮询+last-writer-wins；scope v1=文本+DIB）。
- 设计落盘 docs/spec/cliprdr-server-design.md（b79be95）。
- 实施执行子 ses_e77f5b937ffexzgJ0sMPQO7w0G 在途：CliprdrServer + server 集成 + 测试 S1-S15/E1-E3 + count 修复；客户端零改动。
- 下一步：实施→甲乙复验→服务器模式剪贴板闭环。
## 第663轮：服务器侧 cliprdr 双审盖章入库 ea925c2（54/54 绿）
- 实现：CliprdrServer（服务器先发 caps→MR→FL 防死锁）+ ActiveLoop 按 channel_id 分发（先解密全部帧保 RC4 流同步）+ CS_NET count u32/名字解析修复（cliprdr=1005）+ 剪贴板 sequence_number 变更检测 + 全局 mutex/last-writer-wins。
- 测试：S1-S13 单测 20/161、S14/S15 集成(server 26/230)、E1-E3 loopback e2e 3/29；全量 ctest 54/54；build 0err/0warn。
- 双审：设计(甲乙收敛)与实现(甲乙复验)双盖章；RC4 失步修复由既有 gui_send 加密测试守卫。
- scope：v1 文本+DIB 双向；FILECONTENTS 二期。
- 服务器模式闭环进度：桌面渲染 ✓、剪贴板 ✓；待：rdpdr 服务器侧、家庭版解禁部署、多用户隔离加强、真机 mstsc 互通。
- 下一步：服务器↔客户端剪贴板实测（headless loopback 已在 e2e 覆盖；GUI 真剪贴板验证待用户配合）。
## 第664轮：服务器模式剪贴板闭环（ea925c2 + 877fcac）
- ea925c2：服务器侧 CLIPRDR 实现（CliprdrServer/ActionLoop 分发/CS_NET 修复/剪贴板 seq 后端）+ 双审。
- 877fcac：rtsc_server_host 接线 SetClipboard（此前零调用，通道休眠）→ 实测 cliprdr chunks 0→6、caps 1/1、data 双向各 1、remote_formats=6（真 Win32 剪贴板）。
- 教训入档：核验前必须先重建目标 exe（discover 6aed5a2）。
- 服务器模式进度：桌面渲染 ✓、剪贴板 ✓（文本+DIB v1）；待 rdpdr 服务器侧 / 多用户隔离 / 家庭版部署 / 真机 mstsc 互通。
## 第665轮：多会话剪贴板测试（工作树 4 测试，待复核）
- 新增 4 测试：concurrent_handshake / concurrent_writes_last_writer_wins / disconnect_keeps_peer_alive / stress_8_sessions。
- 实测：multisession 7 tests/173 checks 全绿；8 会话压力 2441ms（163 writes/111 reads，无崩溃）。
- 原执行子报告在重启中丢失，已派甲乙独立复核（有效性/并发真实性/断言强度/FakeClipboard 线程安全）。
- 复核通过后提交。
## 第666轮：多会话剪贴板并发测试入库 998d7cd
- 4 测试（并发握手/收敛无陈旧复活/断开保活/8 会话压力），multisession 7/184 绿、5 次连跑无 flaky。
- 甲乙双审盖章；N2（硬编码 1005→ChannelIdForName）与 N3（改名+契约注释）已修；D7（异值强 winner 断言）父裁决不采纳（必 flaky）。
- 覆盖边界记档：Win32 后端 g_clipboard_mutex 不被本组测试约束（fake 自带锁）；测试零宿主剪贴板污染（seq 前后恒等实证）。
- 服务器模式进度：桌面 ✓ 剪贴板 ✓ 多会话并发 ✓（v1 文本+DIB）。
- 后续：rdpdr 服务器侧 / 家庭版部署 / 真机 mstsc 互通。
## 第667轮：服务器侧 rdpdr 最小握手入库 bf9d2ec
- RdpdrServer：Start=Server Announce；收 Client Announce 即发 Capability+ClientId Confirm+User LoggedOn（防与树内客户端互等死锁）；空设备列表（合法）、DeviceIoRequest 忽略+计数；剥 RDPDR 头修复 16B 截断体误判。
- 集成 server.cpp channel 分发（先解密再路由）+ enable_rdpdr_handshake。
- 测试：rdpdr_server 7/88、server 27/239、rdpdr 50/309 等 10 套件绿；build 0err/0warn。双审盖章。
- 环境：ui/view 在 ctest 全量时因 il2cpp CPU 争用红（单跑均绿，非本批）。
- 审计组与执行子已 delete 解散。
- 服务器模式进度：桌面✓ 剪贴板✓ 多会话✓ rdpdr 握手✓（设备列表/IRP 二期）。
## 第668轮：rdpdr 12字节修复 + e2e 入库 d1191a3
- 真缺陷修复：ClientIdConfirm 8→12 字节（[MS-RDPEFS] 2.2.2.6 权威证据 8b1c9ca）；服务器填 version 1/0x000C；官方字节串逐字节断言；8/11 字节拒绝；客户端旧 8B 停 kAwaitClientIdConfirm。
- rdpdr e2e 配对测试 4/119（handler 级真编码配对 + loopback 全栈 + 重复 announce + 断开释放）。
- 验证：rdpdr 52/325、rdpdr_server 7/91、6/6 rdpdr 家族套件绿；build 0err/0warn。
- 双审：新审计组甲乙一致盖章（规范原文独立 web 核验 + 变异红复现）；观察项 D1-D7 非阻塞。
- 审计组/执行子已 delete 解散。
- 环境：il2cpp 100% CPU 争用持续 → C0 全量（view/ui bench）待争用消退后跑。
- 服务器模式：桌面✓ 剪贴板✓ 多会话✓ rdpdr 握手✓+12B 规范修正✓。
## 第669轮：C0 全量 56/56 通过（il2cpp 争用消退后）
- ctest -C Release -E gateway --timeout 120：**56/56 passed，0 failed**。
- 包含新增套件：server_rdpdr_e2e、rdpdr_server、cliprdr_server、server_cliprdr_e2e、clipboard。
- 环境：CPU 37%、无构建进程争用（此前 view/ui bench 超预算均为 il2cpp 争用，非代码回归，本轮消除后全绿）。
- 至此基线：build 0err/0warn + ctest 56/56。
## 第670轮：新批次启动 — 服务器侧 rdpsnd（音频）
- 现状取证：src/server/server.cpp:1002-1009 只识别 cliprdr/rdpdr 通道名；无 rdpsnd_server.cpp/rdpsnd_server.h；客户端侧 rdpsnd_client + audio_win32(waveOut sink) + audio_sink.h 完整。
- 缺口：服务器模式无法把本机声音送到客户端（目标 G/C 项 RDPSND 音频）。
- 本轮动作：W11 派双审计（甲 ses_e7577b947ffe0u079GJhkmmY3y / 乙 ses_e7577858cffeF4E1KTM6NePgY0），独立产出方案+缺陷清单，已双向互告 ID。
- 审计要求：协议字段契约（对照客户端解析）、音频源路线对比（WASAPI loopback vs 注入式 AudioSource）、失败路径优先、多会话并发、接线点、测试策略（B1 模拟边界）。
## 第671轮：rdpsnd 服务器证据骨架入库 4876542
- 建 docs/spec/rdpsnd-server-design.md：客户端契约表（13 项，全部路径:行证据）+ proto 层缺口（BuildServerFormatsBody / SndWave2::write 缺失）+ 服务器状态机 + 待裁决 5 项。
- 甲仍在审计（busy），乙待命中。
## 第672轮：rdpsnd 双审分歧裁定取证 69918d9
- 独立核实三点：①客户端 OnWave2 无 phase 门（rdpsnd_client.cpp:159-166）→ Training 顺序非客户端硬门，但规范保真需遵守；②D12 wedge 成立（audio_win32.cpp:110 return 后 started_ 仍 true）；③proto 缺 Wave2 write/server formats builder。
- 已 relay 甲乙要求按此收敛。
## 第673轮：rdpsnd 定案 + 派执行
- 甲乙三轮互审收敛联署，主代理定案落 docs/spec/rdpsnd-server-design.md §7（39edbee）；甲方联署终稿细化项已转执行 AI。
- 执行 AI：ses_e755e22c6ffectQ5JL0PI32kzA（TDD，含 D12 修复）。
- 审计组甲 ses_e7577b947ffe0u079GJhkmmY3y / 乙 ses_e7577858cffeF4E1KTM6NePgY0 保持待命，交付后复核。
- 关键裁决：Phase 六态（含 kAwaitQualityMode）；超时分档（formats/train-confirm 致命、quality 放行）；v1 每会话独立源实例（工厂 seam），广播总线=二期；enable_rdpsnd=true 默认但无源不建 handler；Training 按规范先发但客户端无 phase 门（双用例覆盖）。
## 第674轮：D12 方案修正 + 等待执行
- 乙发现 D12 简单复位 started_ 会 std::terminate（audio_win32.cpp:55-76 thread_ joinable 重赋）；采纳方案 B（Worker 常驻+reopen_ 重试+退避），已落证据 c857303 并 relay 执行 AI。
- 甲乙审计闭合待命（重点 6 项已记录）。
- 执行 AI ses_e755e22c6ffectQ5JL0PI32kzA busy 中，工作树尚无改动（TDD 红阶段）。
## 第675轮：D12 甲乙冲突 → 回①磋商
- 甲：失败前持锁 started_=false + thread_.detach()；否决常驻 worker（称 reopen_ 恒真→忙等）。
- 乙：常驻 worker + 重试门。
- 主代理核实（audio_win32.cpp:100-101 精确读取）：谓词 stopping_||reopen_||!queue_.empty()；失败路径 queue_.clear()+reopen_=false+continue → 三支全假 → cv 正常阻塞，甲"忙等"理由不成立。
- 甲方案真实风险：detach 后 Worker 返回时解锁 this->mu_，析构因 joinable()==false 跳过 join → UAF（audio_win32.cpp:43）。
- 决定：回①要求甲乙直连磋商输出唯一方案；执行 AI 已收「D12 暂缓，先做步骤1-5」。
## 第676轮：D12 双章闭合（4d2f4fd）
- 甲乙终报一致：常驻 worker + next_retry_ 1s 退避 + have_format_/reopen_=false + continue，零 detach。
- 乙红探针实证 joinable std::thread 重赋 → terminate（EXITCODE=-1073740791）。
- 执行 AI 已收最终字段名定稿，busy 中；工作树尚无改动（步骤 1-5 进行中）。
- 甲乙待命，审查点①-⑥已固化。
## 第677轮：执行 AI 开始落盘（proto 层）
- 工作树：include/rtsc/proto/rdpsnd.h、src/proto/rdpsnd.cpp、tests/test_rdpsnd.cpp 已改（步骤 1 proto 补齐）。
- 乙 D12 缺陷档案已入 discover.md（186564b）；审计侧断言证据齐备，静默待命。
## 第678轮：proto 层阶段性独立验证
- 工作树 3 文件（proto.h +47/proto.cpp +50/test +98）；主代理独立构建 rtsc_rdpsnd_tests 并跑：17 tests/118 checks 全绿（原 6 tests/30 checks → 新增 11 tests/88 checks）。
- 执行 AI 继续推进音频源/RdpsndServer/接线/e2e。
## 第679轮：执行 AI 进度（9 文件）
- 新增：include/rtsc/audio/audio_source.h、include/rtsc/channel/rdpsnd_server.h、src/audio/sine_source.cpp、src/channel/rdpsnd_server.cpp、tests/test_audio_source.cpp；CMakeLists 已改。
- 乙撤回 D5（proto 缺口已补，转为"执行新增待复核"）。
- 剩余：server.cpp 接线、server.h enable_rdpsnd、test_rdpsnd_server.cpp、test_server_rdpsnd_e2e.cpp、main.cpp --audio、D12。
## 第680轮：执行 AI 中途态核查
- 工作树 9 文件；rdpsnd_server.cpp 仍 12 行占位，test_audio_source.cpp 77 行、sine_source.cpp 21 行。
- CMakeLists 已引用 rtsc_rdpsnd_server_tests 但源文件未创建 → configure 失败（中途态，非缺陷；执行 AI 仍在写）。
- 已与定案对齐项：AudioCaptureSource 接口（Start/Stop/Poll/format/ok）、每会话源工厂 seam、正弦源 44100/16/2 20ms 块。
## 第681轮：CMake 已就绪，等待 server 实现与测试
- CMakeLists 已加 rtsc_rdpsnd_server_tests / rtsc_audio_source_tests（含 /W4 /WX 与 add_test）→ configure 因 test_rdpsnd_server.cpp 缺失而暂失败（中途态）。
- rdpsnd_server.cpp 仍 12 行占位；执行 AI busy（wrote 时间戳新鲜）。待其完成。
## 第682轮：执行 AI 停滞询问
- 执行 AI wrote 时间戳连续多轮未变（1793328483225），rdpsnd_server.cpp 仍 12 行占位，test_rdpsnd_server.cpp 缺失 → CMake configure 失败。
- 已发进度询问，要求小步落地（先骨架测试 → 最小实现 → S2-S10 逐个 → 接线/e2e/D12），每步可编译。
## 第683轮：熔断旧执行子，新执行子开工
- 熔断 ses_e755e22c（零输出×6，wrote 停滞），已 abort+delete 解散；discover 记录 c8e02d3。
- 新执行子 ses_e75442500ffeT4eCFXqR2YxuNV 已派（复用 proto/audio_source/CMake 半成品，要求每步 relay 进度）。
- 新执行子已创建 tests/test_rdpsnd_server.cpp（487 行）。
## 第684轮：新执行子 TDD 红阶段
- test_rdpsnd_server.cpp 487 行已建；rdpsnd_server.cpp / sine_source.cpp 仍占位（符合先红顺序）。
- 执行子 busy，wrote=null（尚未写入新文件）；等待其实现步骤。
## 第685轮：新执行子测试设计已核
- test_rdpsnd_server.cpp 12 用例：S1 首帧字节 / S2 收 formats+ALIVE / S3 training 门 / S4 cBlockNo 回绕 / S5 窗口满丢新 / S6 train-confirm 超时 CLOSE / S7 ALIVE=0 静默 / S8 畸形忽略 / S9 formats 超时 CLOSE / S10 计数 / version7 不发 Wave2 / version5 跳过 QualityMode。FakeSource 可脚本化。
- rdpsnd_server.cpp、sine_source.cpp 仍占位（红阶段），执行子 busy。
## 第686轮：rdpsnd_server 实现完成，主代理独立验证
- sine_source.cpp 59 行（真实 44100/16/2 正弦）、rdpsnd_server.cpp 297 行（六态状态机）。
- 主代理独立重建并跑：rtsc_rdpsnd_server_tests **12 tests/368 checks 全绿**；rtsc_audio_source_tests **2 tests/24 checks 全绿**；build 0 error/0 warning。
- 执行子下一步：server 接线 + main.cpp --audio → e2e → D12。
## 第687轮：server 接线已完成（主代理审阅 diff）
- server.h：enable_rdpsnd=true + audio_source_factory seam（注释明确"无工厂不建 handler→默认零可观察变化"）。
- server.cpp：rdpsnd 名表分支 + 复位 + 每会话 handler（有工厂才建）+ Start 序 cliprdr→rdpdr→rdpsnd + 分发 + 每 tick Poll 泵（与 cliprdr 同在 timeout 分支，rdpsnd 内部 20ms 发射窗门）。
- main.cpp：--audio off|sine，默认 off（隐私默认关门）。
- 执行子 busy 继续 e2e + D12。
## 第688轮：执行交付 + 主代理验证 + 派双审复核
- 执行子（ses_e75442500ffeT4eCFXqR2YxuNV）六步完成交付。
- 主代理独立验证：rtsc_server_rdpsnd_e2e_tests 构建成功；ctest 9/9 全绿（rdpsnd/audio_source/server/server_multisession/server_cliprdr/server_rdpdr 家族）。
- 已派甲乙复核①-⑥（甲侧重实现正确性，乙侧重失败路径/并发/协议边界/D12 逐行）。
## 第689轮：复核驳回 F-A（真缺陷）→ 派执行修复
- 乙复核：①②③⑤⑥ PASS；④ 部分驳回 —— src/channel/rdpsnd_server.cpp:233-241 Poll 把 kAwaitQualityMode 超时也 SendClose()，定案要求"放行到 Training（非致命）"。
- 主代理核实：确认缺陷成立（:236-240 三态合并处理）。
- 已派执行子修 F-A（分档超时）+ 补 quality 超时放行单测；同时要求核对 F-C（QualityMode 方向，rdpsnd_client.cpp:151-155 显示客户端发 → 服务器不应发）。
- F-B 防御校验、F-D 单测、F-E 加密路径 W5、F-F 阻塞文档化待处理。
## 第690轮：双审联署终稿（D-A~D-E 必修）→ 执行子整改中
- 规范权威核验（Microsoft Learn [MS-RDPEA] 2.2.2.3 + 3.1.5 事件5/6 + 脚注16/19）：QualityMode 由客户端发、服务器仅等待；超时→DYNAMIC_QUALITY 放行进 Training。→ D-A/D-B 确认为真缺陷。
- 双章：①②③⑤⑥ PASS；④ 驳回。必修 D-A（删服务器发 QualityMode）D-B（quality 超时放行+单测）D-C（Start 门控 channel_id!=0）D-D（泵移入每轮迭代）D-E（formats 防御校验）。
- 契约修订：静默分支（ALIVE=0 / formats 无效）须 source_->Stop() 释放采集；协商超时 formats/train-confirm 仍 CLOSE。
- 执行子已收两轮指令（D-A~D-E + 静默停源/泵 now 采样），整改中。
## 第691轮：等待执行子整改（D-A~D-E）
- rdpsnd_server.cpp 327 行，quality_mode_sent_count_ 仍在、quality_mode_timeout 未出现 → D-A/D-B 尚未落地。
- 执行子 busy，wrote 时间戳未推进（1793332186445）。持续观察，若再现零输出停滞按熔断处理。
## 第692轮：整改进度（D-C 已落地）
- server.cpp 已有 rdpsnd_channel_id_ != 0 的 Start 门控（D-C ✓）。
- rdpsnd_server.cpp 仍 327 行、quality_mode_sent_count_ 在、quality_mode_timeout 未出现（D-A/D-B 待落地）。
- tests 已新增 rdpsnd_server_quality_timeout_advances_to_training 用例（红阶段）。
## 第693轮：等待 D-A/D-B 落地
- rdpsnd_server.cpp 最后写入 11:49:46，仍 327 行，quality_mode_sent_count_ 未删、quality_mode_timeout 未出现。
- 执行子 busy 且 wrote 时间戳已推进（说明在别处活动，可能先改测试/server）。
## 第694轮：ActiveLoop 现状核查
- server.cpp ActiveLoop：rdpsnd_->Start() 仍无条件（D-C 未落地，此前 grep 误判）；泵仍在 read-timeout 分支（D-D 未落地）。
- rdpsnd_server.cpp 未变（327 行，D-A/D-B 未落地）。
- 结论：执行子尚未开始实际改码（可能仍在规划/读文件）。持续观察 wrote 时间戳。
## 第695轮：执行子缓慢推进中
- server.cpp: rdpsnd_->Poll(now) 已出现（D-D 部分落地）；Start 门控仍无（D-C 未落地）。
- rdpsnd_server.cpp 未变（D-A/D-B 未落地）。
- 执行子 busy，wrote 持续更新。继续观察，不干预。
## 第696轮：向执行子发最小化 4 处编辑指令
- 观察：rdpsnd_server.cpp 被触碰但 D-A/D-B 内容未改（多轮空转）。
- 已发最小化指令（编辑1 D-A 删 QualityMode 发送+计数器；编辑2 D-B Poll 分档+quality_mode_timeout_count_；编辑3 D-C Start 门控；编辑4 D-E formats 防御+source_->Stop），要求每处编辑后 build+跑测并回报。
## 第697轮：D-A/D-B 已落地
- rdpsnd_server.cpp 352 行；quality_mode_sent_count_ 已删、quality_mode_timeout 已出现 → D-A（删发送）D-B（超时放行）落地。
- D-C（Start 门控）仍未落地。等待执行子继续。
## 第698轮：等待 D-C（避免编辑冲突）
- D-A/D-B/D-E 已落地；D-C（server.cpp:1406 Start 门控）未落地。
- 执行子 busy 且 wrote 时间戳持续更新（1793334001622），主代理暂不直接编辑以免写冲突。
