# 批 12 审计 I：`input-injection-seam.md` 全文对账（对象提交 `a59a594`）

状态：2026-11-01。审计 I（只读）。唯一写入：本文件。
范围：`docs/spec/input-injection-seam.md` 全文（§0–§7、附录 A）对当前工作树（`a59a594` + 其后 `d457eaf` 记忆提交）逐条对账。
证据口径：`[READ:路径:行]` 指当前工作树行号；`[BASH:...]` 为本次实际执行输出。官方文档 URL 本轮未重新抓取，凡只依赖文档原文的引用标 **【未复验】**。

已运行（红/绿基线，不改代码）：

```
[BASH: build\Release\rtsc_desktop_input_tests.exe]
41 tests, 13713 checks, 0 failing tests, 0 failed checks
[BASH: build\Release\rtsc_server_tests.exe]
49 tests, 560 checks, 0 failing tests, 0 failed checks
```

## 0. 结论摘要

1. **§1.8 是全文唯一行号完全准确的节**：7 条 `desktop_input_win32.cpp:行` 与 4 条 `CMakeLists.txt:行` 全部命中所述内容；"win32 后端不在任何 ctest 编译/链接闭包"成立。
2. **§1.3 / §1.4 整体失效**：文档中的 `InputSink`、`input_sink.h`、`input_inject.h`、`input_inject_win32.cpp`、`input_inject_null.cpp`、`CreatePlatformInputSink`、`ReleaseAll()`、`bool Inject(...)`、`SetGeometry(const InjectGeometry&)` 当前均不存在；实际接口是 `DesktopInputSink`（`desktop_input.h:62-86`）、`MakeWin32DesktopInputSink()`（`:90`）、`void Inject(uint32_t, const InputEvent&)`（`:73`）、`SetGeometry(uint32_t, const InjectGeometry&)`（`:68`）、`Stats()`（`:85`）。
3. **§1.7 第 1 条成立**（`session_id` 已实现、非零且互异），只有"日志无 session_id"仍真；**第 2 条不成立**：实现用**协商 framebuffer**，不是捕获源真实矩形，且 `InjectGeometry` 没有 `origin_x/origin_y/virtual_desktop`。
4. **§3 状态列大面积过期**：P-1/P-2/P-3（解码）/P-4/P-5/P-9/P-10 已落地，表仍写 `EXEC`/`OPEN`；P-11 部分落地。
5. **P-6 不是单纯"平台边界"，而是仍在错误注入**：`extended1` 已解码但注入层完全忽略，Pause 的 E1-CTRL 会被当裸 CTRL 注入，NumLock 被切换（直接违反 P-6 ④）。**这是本次最严重的 FAIL（代码侧）**。
6. **§4.1/§4.2 的"待做测试"大多已完成**；但 T4 中点位期望数值本身错误，T6/T10/T12/T14/T15 与实现或现状不符；§4.4 的 M5/M6 没有真实用例，M2 的 Win32 侧变异仍无覆盖。
7. **CLI 漂移**：`--input-share`、`--input-owner` 不存在；实际是 `--max-input-sessions N`（`main.cpp:279-285`）。
8. 常量本身没有漂移：256/1024/400/800/1000/2000/515/1539/1 s/255/120/0x52545343 全部与代码一致；漂移只发生在**行号与状态描述**。

---

## 1. 常量对账（文档值 vs 代码值）

| 文档常量（位置） | 文档值 | 代码事实 | 判定 |
|---|---|---|---|
| 软上限（§1.5，:135） | 256 | `kMaxQueue = 256` [READ:src/server/desktop_input_win32.cpp:82] | 一致 |
| `kHardQueueLimit`（§1.5，:136） | 1024 | `4 * kMaxQueue` = 1024 [READ:src/server/desktop_input_win32.cpp:87] | 一致 |
| `pressed` 上限（§1.5，:137） | 510 键 + 5 按钮 = 515 | `KeyId{uint16_t scancode,bool extended}`，键域 255×2=510；`uint8_t` 按钮 1–5 [READ:include/rtsc/server/desktop_input_map.h:93-110] | 一致（结构上界） |
| 峰值 1539（§1.5，:137） | `1024+515·K`，默认 K=1 → 1539 | 与 `DecideEnqueue` 的 held-release 越限路径 + `AppendReleasesLocked` 配额共用推导一致 [READ:include/rtsc/server/desktop_input_map.h:107-119, READ:src/server/desktop_input_win32.cpp:236-258] | 一致（文档新公式正确） |
| 每会话 400/s、突发 800（§2.3，:286） | 400 / 800 | `kSessionEventsPerSecond=400.0`、`kSessionBurst=800.0` [READ:include/rtsc/server/desktop_input_map.h:259-260] | 一致 |
| 全局 1000/s、突发 2000（§2.3，:288） | 1000 / 2000 | `kGlobalEventsPerSecond=1000.0`、`kGlobalBurst=2000.0` [READ:include/rtsc/server/desktop_input_map.h:261-262] | 一致 |
| 移动间隔 4 ms / 250 Hz（§1.5，:133；§2.3，:292） | 4 ms | `kMoveInterval = milliseconds(4)` [READ:src/server/desktop_input_win32.cpp:88] | 一致 |
| `kRefreshInterval`（§2.3，:293） | 约 1 s | `milliseconds{1000}` [READ:src/server/server.cpp:109]；调用点 `:928`、`:1627` | 值一致；引用失效（见 §2） |
| 滚轮单位 120（§3 P-2） | 120 | `kWheelUnitsPerNotch = 120` [READ:src/client/client.cpp:23] | 一致 |
| 单位域 ±255（§3 P-2） | ±255 | `kWheelStep = 255` [READ:src/client/client.cpp:31] | 一致 |
| `kMaxWheelChunksPerEvent`（文档未列） | — | `= 8` [READ:src/client/client.cpp:40]；文档没有该常量，未冲突但属漏记 | 无断言 |
| `dwExtraInfo` 建议值（§2.4，:320） | 0x52545343 | `kInjectTag = 0x52545343` [READ:src/server/desktop_input_win32.cpp:92]，`:392,420,460,471` 使用 | 一致（但文档仍写"建议"，已是实现） |

补充：文档 §1.5 的峰值公式在 `desktop_input_win32.cpp:27-31` 的**代码注释仍写旧式** "hard_limit + |pressed| at saturation (1024+515=1539)…sessions x 515 on top"，与 seam.md 新公式（≤1024+515·K）不一致。按代码语义 seam.md 正确、代码注释过期，应改注释（不属于文档 FAIL，但属同源漂移）。

---

## 2. 失效引用总表（文档行号 → 实际行号）

判定：**失效** = 指向另一段内容；**漂移** = 内容边界略偏但语义仍可找到。以下均为 `[READ:]` 核对结果。

### 2.1 `tools/rtsc_server/main.cpp`

| 文档引用（文档行） | 文档所述 | 实际位置 | 判定 |
|---|---|---|---|
| `:15-55` usage 块（:325；附录 :685） | usage/危险说明 | 帮助注释在 `:15-66`；`usage()` 在 `:129-142`，且只打印旗标名 | 失效 |
| `:90` `std::string password = "password"`（:251） | 默认口令 | `:102` | 失效 |
| `:105` 音频默认 off（:229） | `AudioSource::kOff` | `:117` | 失效 |
| `:295-298` 退出码 2（:254） | ParseOptions 失败 | `:356-359`（ParseOptions 失败）、`:385`（门禁失败） | 失效 |
| `:300-312` 配置装配（附录 :686） | 配置装配 | `:388-407` | 失效 |
| `:331-340` credential_lookup（:251） | 只比对 user/domain | `:426-435` | 失效 |
| `:342-345` 音频 opt-in（:230） | `--audio sine` | `:437-445` | 失效 |
| `:352-366` 剪贴板默认 on（:231） | 无条件创建 | `:447-461` | 失效 |
| `:358-361` clipboard 生命周期注释（:104） | "must outlive the server" | `:453-455` | 失效 |
| `:363-366` NullClipboard（:100） | null 后端 | `:459-461`；整体 `:447-461` | 失效 |
| `:368-391` 启动日志 + accept-all 警告（附录 :687） | 启动日志 | `:473-508` | 失效 |
| `:383-387` accept-all 仅一行日志（:25, :262） | 警告先例 | `:490-494` | 失效 |
| `:393-395` "same source to every session"（:270） | 同源桌面 | `:530-531` | 失效 |
| `:421-448` authenticator 边界（附录 :687） | 认证边界 | `:419-435`（lookup）、`:564-569`（边界注释） | 失效 |
| `:428-432` "no password check at all"（:250） | 原文 | `:569` | 失效 |
| `:453-463` 仅日志回调（:19, :38, :235） | 唯一生产调用只写日志 | 回调在 `:591-601`；`:453-461` 是剪贴板生命周期注释 | 失效 |
| 运行期 `"session active: key event forwarded"`（§1.7） | 无 session_id | 仍在 `:591-601`；确实不带 id | 内容一致 |

### 2.2 `include/rtsc/server/server.h`

| 文档引用 | 文档所述 | 实际位置 | 判定 |
|---|---|---|---|
| `:57-59` | 协商几何 | `:57-58`（`:59` 是 color_depth） | 基本有效 |
| `:66-76` | accept-all/认证边界 | `:66-76` | 有效 |
| `:73-75` | "Start() emits a WARNING" | `:73-75` | 有效 |
| `:142-159` | 8192×8192 / 32 MiB 上限 | `:163-180` | 失效 |
| `:191-224` | `InputEvent`/`InputCallback` | `:216-275` | 失效 |
| `:193-194` | 回调不得阻塞 | `:214-215` | 失效 |
| `:195-221` | `InputEvent` 字段 | `:216-272` | 失效 |
| `:204` | 默认 `kind = kKey` | `:226` | 失效 |
| `:206-210` | "无 extended1 字段" | `:236-241`（extended1 **已存在**） | 失效且事实过期 |
| `:208` | `uint16_t unicode_code` | `:230` | 失效 |
| `:219-220` | `sync_flags` | `:270-271` | 失效 |
| `:224` | `InputCallback` 签名 | `:275` | 失效 |
| `:240` | `SetDesktopSource` | `:295` | 失效 |
| `:249-256` | `SetClipboard` + 生命周期 | `:317-324` | 失效 |
| `:253-255` | clipboard 契约原文 | `:320-322` | 失效 |
| `:264-266` | `Stop()` 语义 | `:332-334` | 失效 |
| `:288-295` | 会话计数 | `:356`、`:363` | 失效 |

### 2.3 `src/server/server.cpp`

| 文档引用 | 文档所述 | 实际位置 | 判定 |
|---|---|---|---|
| `:438-439` | 能力广告 | `:441-442` | 失效 |
| `:546` / `:546-602` | `RdpSession` 起点/构造 | `:665` / `:665-730` | 失效 |
| `:1410-1412` | `kRefreshInterval` 刷新 | 常量 `:109`；使用 `:928`、`:1627` | 失效 |
| `:1415-1470` | `ActiveLoop` | `:1606-1693` | 失效 |
| `:1419-1421` | `rdpsnd_->Poll` | `:1634-1636` | 失效 |
| `:1430-1432` | `rdpdr_->Poll` | `:1645-1647`（且有 `outstanding_count()!=0` 门） | 失效 |
| `:1433` | `ReadFrame` | `:1648` | 失效 |
| `:1479-1521` | 慢路径处理 | `:1695-1769` | 失效 |
| `:1488-1519` | `HandleSlowPathPdu` | `:1706-1767` | 失效 |
| `:1520` | 其余 `return true` | `:1768` | 失效 |
| `:1523-1531` | fast-path 门 | `:1905-1913` | 失效 |
| `:1534-1616` | 解码段 | `:1916-2029` | 失效 |
| `:1543` | 默认构造 `InputEvent` | `:1925` | 失效 |
| `:1549-1550` | E1 丢失 | `:1931-1938`（extended1 **已读**） | 失效且事实过期 |
| `:1553-1561` | Unicode 解码 | `:1941-1948` | 失效 |
| `:1567-1568` | x/y 的 u16 域 | 快路径 `:1955-1958`；慢路径 `:631-632` | 失效 |
| `:1571` | 只判 `kPtrWheel` | `:609-622`（已判 HWHEEL） | 失效且事实过期 |
| `:1573-1578` | 双重计数 | `:619-622`（已改 9 位补码） | 失效且事实过期 |
| `:1580-1596` | 按钮位只在 down 内 | `:589-599`（已独立解码） | 失效且事实过期 |
| `:1599-1602` | sync 透传 | `:1967-1969` | 失效 |
| `:1603-1606` | `kMouseRel` 只 `pos+=6` | `:1971-2003`（已解 rel_x/rel_y） | 失效且事实过期 |
| `:1607-1610` | QoE 落回调 | `:2004-2011`（`continue`） | 失效且事实过期 |
| `:1611-1612` | `default: return` | `:2012-2024`（计数后 return） | 失效 |
| `:1614` | 无条件 `input_callback_` | 快路径 `:2026-2027`；慢路径 `:1900-1901` | 失效 |
| `:1622-1623` | 成员 | `:2035-2036` | 失效 |
| `:1755-1756` | setter | `:2200-2204` | 失效 |
| `:1843`、`:1962` | 两条构造传 0 | `:2290`、`:2418`（`session_id_=0`）；输入 id 在 `:2291-2292`、`:2419` | 失效 |
| `:2160` | `next_input_session_id` | `:2165` | 失效 |
| `:2286-2287` | 线程路径取 id | `:2291-2292` | 失效 |
| `:2414` | `ServeOne` 取 id | `:2418-2419` | 失效 |
| `:2036` | 成员默认 0 | `:2041` | 失效 |
| `ReleaseInput`（H 报告口径） | teardown | `:762-784` | 有效（与 H 一致） |

### 2.4 `include/rtsc/proto/*`、`src/client/client.cpp`、`src/proto/input.cpp`

| 文档引用 | 文档所述 | 实际位置 | 判定 |
|---|---|---|---|
| `input.h:22` | `kKbdExtended1` | `:22` | 有效 |
| `input.h:26-31` | sync flags | `:27-30` | 基本有效 |
| `input.h:41` | `kPtrHwheel` | `:41` | 有效 |
| `input.h:97-104` | `EncodeCtrlAltDel` | 声明 `:102-109`，定义 `src/proto/input.cpp:78-88` | 失效 |
| `input.h:61-81` | 编码器 | `:60-86` | 基本有效 |
| `input.h:88-95` | scancode | `:88-100` | 失效（范围偏短） |
| `input.h:97-110` | SAS/Pause | `:102-115` | 失效 |
| `input.cpp:90-102` | Pause 序列 | `:90-102` | 有效 |
| `client.cpp:208-223` | 按钮释放不带 DOWN | `:230-245` | 失效 |
| `client.cpp:231-238` | 旧滚轮缺陷 | `:259-307`（已重写为 120 单位 + 255 分块） | 失效且事实过期 |

### 2.5 其它文档引用

| 文档引用 | 文档所述 | 实际位置 | 判定 |
|---|---|---|---|
| `capabilities.h:225-234` | 默认 `input_flags` | 默认值 `:262-264`；常量表 `:234-255` | 失效 |
| `capabilities.h:230-234` | 默认含 Unicode | `:246`、`:262-264` | 失效 |
| `capabilities.h:220-234` | InputCapabilitySet 注释 | `:219-233` | 基本有效 |
| `server-mode.md:14` | GDI 捕获 | 能力矩阵 `:23`；架构说明 `:10` | 失效 |
| `server-mode.md:24-27` | 多会话 | `:22-31`（多会话在 `:26`） | 失效 |
| `server-mode.md:37` | 7 tests/184 checks | 该数字在 `:26`；`:37` 是 mstsc 互通 | 失效 |
| `server-mode.md:42` | USB 未实现 | `:31` | 失效 |
| `input-evidence.md:45` | `0x4321DCBA` | `:54`（且原文标 **未验证**） | 失效 |
| `input-evidence.md:64` | `SetCursorPos` 7 处 | `:52` | 失效 |
| `input-evidence.md:100-103` | `VK_PACKET` | 该段是 probe 输出；`VK_PACKET` 在 `:107` | 失效 |
| `input-evidence.md:144/147` | 旧审计 P3 | 文件仅 122 行，**越界** | 失效 |
| `.opencode/discover.md:600-616` | `-1→0x0301→-257` | `:351-364` | 失效 |
| `.opencode/discover.md:622-623` | 机制修正 | `:448` 起（第 12 例）、`:670`（774 次） | 失效 |
| `process.md:297` | `horizontal` 改动 | `:297` 是滚轮分块测试注记，不是该契约 | 失效 |
| `process.md:261-284` | P-2 契约定案 | `:260-262` 是 kMouseRel/X1X2；契约不在此段 | 失效 |
| `process.md:272` | 滚轮方向待验项（§4.3） | `:272` 是 `kMaxWheelChunksPerEvent` 说明 | 失效 |
| `tests/test_server.cpp:615/:655/:2017` | 依赖回调签名的 4 处测试 | `:615`/`:655` 在 mock sink；`:2017` 是慢路径相对鼠标用例；实际 `SetInputCallback` 见 `:952, 992, 1073, 1141, 1225, 1283…` | 失效 |
| `tests/test_server.cpp:669-675` | 客户端释放事件 decode | `:667-673` 是 mock sink 字段 | 失效 |
| `tests/test_server.cpp:695-703` | "只数个数"固化缺陷 | `:690-703` 是 `ReleaseThrowingSink::Inject`；语义断言现已改为 `:1269-1327` | 失效且事实过期 |
| `share-data.md:704-708` | Pause | 有效 | 有效 |
| `share-data.md:710-718` | Unicode | 有效 | 有效 |
| `share-data.md:729/739/745` | wheel/flags | 有效 | 有效 |
| `share-data.md:770-783` | SYNC | 有效 | 有效 |
| `share-data.md:796-807` | 相对指针 | 有效 | 有效 |
| `share-data.md:821-833` | 遍历不变量 | `:823-833` | 基本有效 |
| `share-data.md:309/683` | 0x1C / 未知类型 | 有效 | 有效 |
| `capabilities.md:312`、`:1732-1748` | 0x1C、inputFlags | 有效 | 有效 |
| `desktop_gdi.h:27-42`、`:38-39`、`:40-42` | 捕获矩形/缩放/工厂 | 有效 | 有效 |
| `CMakeLists.txt:676-682/691/704/608-609` | §1.8 闭包 | 有效 | 有效 |

**统计**：核到约 75 条 `文件:行` 引用，其中约 **48 条失效/事实过期**，约 18 条有效，其余为范围偏差。§1.8 与 `share-data.md`/`capabilities.md`/CMake 的引用整体可靠。

---

## 3. 逐节断言对账

### §1.1 现状

| 文档断言 | 代码事实 | 判定 |
|---|---|---|
| "唯一生产调用只写日志"（:38） | 主机已创建 sink 并 `SetInputSink` [READ:tools/rtsc_server/main.cpp:467-470,587]；仅当 `--allow-input` | 漂移（已实现注入） |
| 回调签名无 session ID、无返回值（:39） | `using InputCallback = std::function<void(const InputEvent&)>` [READ:include/rtsc/server/server.h:275] | 一致（仅行号失效） |
| 回调在会话线程、不得长阻塞（:40） | 同注释 [READ:server.h:214-215] | 一致（行号失效） |
| 两条构造路径 `session_id_=0`（:41） | `:2290`、`:2418` 仍传 0；但另有非零 `input_session_id_` | 部分过期（见 §1.7） |
| 解码后统一回调、无 kind 过滤（:42） | `:2026-2027`、`:1900-1901`；QoE 不回调 | 漂移（已过滤） |
| 库不知道几何给谁用（:43） | 已有 `InjectGeometry`+`SetGeometry(session_id,…)` [READ:desktop_input.h:31-34,68] | 漂移 |
| 借用指针范式（:44） | `SetDesktopSource` [READ:server.h:295]、`SetClipboard` [READ:server.h:317-324]、`SetInputSink` [READ:server.h:304-315] | 一致（行号失效） |

### §1.2 三方案

- A 的三条否决理由仍成立（无 session id、无返回值、生命周期）；行号 `server.h:224`→`:275`、`:253-255`→`:320-322`。
- B 的 `server.cpp:546`→`:665`；`RdpSession` 仍在匿名命名空间内（`:665` 起）。
- C 已采纳，但**接口名与签名不同**（见 §1.3）。

### §1.3 接口（设计草案）

**整体判定：漂移（设计与实现不同名/不同签名），且文档内部自相矛盾。**

| 文档 | 代码 | 判定 |
|---|---|---|
| `include/rtsc/server/input_sink.h` 新增 | 不存在；接口在 `include/rtsc/server/desktop_input.h` | 失效 |
| `class InputSink` | `class DesktopInputSink` [READ:desktop_input.h:62] | 漂移 |
| `bool Inject(uint32_t, const InputEvent&)` | `void Inject(...)` [READ:desktop_input.h:73] | 冲突；与 §1.6 "Inject 无返回值"（:171）自相矛盾 |
| `void ReleaseSession(uint32_t)` | 同 [READ:desktop_input.h:81] | 一致 |
| `SetGeometry(const InjectGeometry&)`（无 session） | `SetGeometry(uint32_t session_id, const InjectGeometry&)` [READ:desktop_input.h:68] | 漂移 |
| `InjectGeometry{origin_x,origin_y,width,height,virtual_desktop}` | `{uint16_t width,height}` [READ:desktop_input.h:31-34] | 漂移 |
| `SetInputSink` 指针活过 Stop | 同 [READ:server.h:304-315] | 一致 |
| 先 `Inject` 再 `input_callback_` | `InjectIfLeasable` 后回调 [READ:server.cpp:2026-2027] | 一致（行号失效） |
| "4 处测试不需要修改" | 现有多处 mock sink 与回调；`test_gui_send.cpp:200` 仍准确，`test_server.cpp:615/655/2017` 失效 | 漂移 |

### §1.4 注入器位置与生命周期

- 文件名 `input_inject.h` / `input_inject_win32.cpp` / `input_inject_null.cpp` **均不存在**；实际为 `desktop_input.h`、`desktop_input_map.h/.cpp`、`desktop_input_win32.cpp`、`desktop_input_null.cpp`。判定：**失效**。
- 工厂 `CreatePlatformInputSink(std::string*)` 不存在；实际 `MakeWin32DesktopInputSink()` [READ:desktop_input.h:90, src/server/desktop_input_win32.cpp:565-567]，非 Windows 同名工厂返回计数 no-op [READ:src/server/desktop_input_null.cpp:49-51]。判定：**失效**。
- "必须在 `RdpServer server(cfg);` 之前声明"：成立，sink 声明 `main.cpp:467`，server `:558`。判定：**一致**。
- "关闭顺序 Stop() → ReleaseAll() → 析构"：`ReleaseAll()` 不存在；实际 `server.Stop()`（`main.cpp:642/719`）→ sink 析构 `~Win32DesktopInputSink` → `Shutdown()`（`desktop_input_win32.cpp:114,513-530`）补发 synthetic up 并 join worker。判定：**漂移**（顺序成立、名字失效）。
- 引用 `main.cpp:363-366`（NullClipboard）、`:358-361`（clipboard 生命周期）、`server.h:264-266`（Stop）全部行号失效。

### §1.5 线程模型与队列

| 断言 | 代码事实 | 判定 |
|---|---|---|
| 会话线程不 `SendInput`，单 worker 出队 | `Inject` 只入队 [READ:desktop_input_win32.cpp:124-148]；worker `:261-291`；`SendInput` 只在 `Emit` `:484` | 一致 |
| 软 256 驱逐最旧纯移动 | `find_if` 首个 move + `DecideEnqueue` [READ:desktop_input_win32.cpp:204-209,222-224] | 一致 |
| 硬 1024 仅豁免 held release | `DecideEnqueue` `:107-119`（held release 先于 hard limit） | 一致 |
| 未持有 up 不免硬限/限流 | `IsHeldRelease` [READ:desktop_input_map.cpp:144-156]；`AdmitAndTrack` 先限流后记账 [READ:desktop_input_map.h:226-237] | 一致 |
| 移动合并、250 Hz、按键 flush | `:197-203`、`:368-385` | 一致 |
| 峰值 1539（K=1） | 与实现路径一致；但代码注释仍写 "sessions × 515" 旧式 | 文档一致，注释漂移 |
| `kSync` 不注入 | `TranslateInput` 返回空 [READ:desktop_input_map.cpp:100-102] | 一致 |
| `kMouseRel` 已上送但不注入 | 事件已解 [READ:server.cpp:1971-2003]；翻译返回空 [READ:desktop_input_map.cpp:100-102] | 一致 |
| `dropped_unsupported` 含零码事件 | 零码在 `TranslateInput` 返回空；只有**已持租约**时才到 sink 计数（`InjectIfLeasable` 对 `IsInjectable==false` 直接 return）[READ:server.cpp:819-826]；零码事件因此通常**不进任何计数器** | 漂移（夸大） |
| 引用 `desktop_input_win32.cpp:232-254` / `:307-315` | 实际 `236-258` / `311-319` | 失效（与 H 独立复核一致） |
| 引用 `server.cpp:1415-1470`、`:1419-1421`、`:1430-1432`、`:1433` | `1606-1693`、`1634-1636`、`1645-1647`、`1648` | 失效 |

### §1.6 失败传播

- "注入失败不断连"：成立（`Inject` 无返回、无断连路径）[READ:desktop_input.h:73, desktop_input_win32.cpp:478-511]。
- "每 5 s 至多一行"：`kFailureLogInterval=seconds(5)`、`LogFailure` [READ:desktop_input_win32.cpp:89,493-511]。一致。
- `InputStats` 四字段：一致 [READ:desktop_input.h:51-56]。
- `dropped_unsupported` 未接出结构体：一致（无成员/无访问器）。
- 主机 5 s 采样、仅变化时打印、`(final)`：一致 [READ:main.cpp:660-661,709-712,640,721]。
- 无界模式无 Ctrl+C 处理、无 final：一致（全仓无 `SetConsoleCtrlHandler`）。
- "回压：Inject 无返回值"：一致，但与 §1.3 的 `bool Inject` 矛盾（文档内部 FAIL）。

### §1.7 两条"接口余量"（专项）

**第 1 条（session 归属）：成立。**
- `next_input_session_id` 在 `server.cpp:2165`；两条路径 `fetch_add(1)+1`：`:2291-2292`、`:2419`；`0` 保留为未分配：成员 `:2041`。
- 测试 `server_input_lease_one_session_then_handoff` 断言两个不同 id、非零 [READ:tests/test_server.cpp:3681-3733]。
- 文档行号 `2160/2286-2287/2414/2036` 全部失效。
- 唯一仍真的"待办"：日志行无 session_id（`main.cpp:591-601`）。

**第 2 条（几何来源）：不成立。**
- 文档要求 `InjectGeometry` 来自**捕获源真实矩形**，含 `origin_x/origin_y/virtual_desktop`（:180-184）。
- 实际 `InjectGeometry` 只有 `width/height` [READ:include/rtsc/server/desktop_input.h:31-34]；服务器把**协商并钳制后的 framebuffer** 填入：`inject_geometry_ = InjectGeometry{desktop_width_, desktop_height_}` [READ:src/server/server.cpp:1303-1308]；sink 恒发 `MOUSEEVENTF_VIRTUALDESK` [READ:src/server/desktop_input_win32.cpp:413-421]。
- 测试还把"协商 64×48"固化为期望 [READ:tests/test_server.cpp:3691-3698]。
- 结论：文档设计与实现是两条不同路线；默认 `--monitor -1`（整个虚拟桌面）下归一化到协商 framebuffer 可工作，但 `--monitor N` 抓**子矩形**时坐标会整体错位（原点/尺寸均未传入）。**判定：FAIL（文档/代码二选一，不能保留现状）**。
- 文档的换算公式（含 `origin_x/origin_y`，:188-192）与实现不符；`width/height <= 1 → 拒绝注入`（:200）也不成立：`NormalizeAxis` 在 `extent<=1` 时直接 1:1 透传 [READ:src/server/desktop_input_map.cpp:21-27]。
- 越界钳制成立（`value>=last → 65535`），但引用 `server.cpp:1567-1568` 失效（实际 `:1955-1958`）。

### §1.8 Win32 接线缺口（专项）

**全部准确，与审计 H 独立复核一致。**

| 文档 | 实际 | 判定 |
|---|---|---|
| 合并移动 `197-203` | `197-203` | 准确 |
| `oldest_move` 先取 `204-209` | `204-209` | 准确 |
| `kEvictMove/kDrop` `221-228` | `221-231`（`:228` 是 `return false` 前） | 基本准确（建议 221-231） |
| `AppendReleasesLocked` `236-258` | `236-258` | 准确 |
| `ForgetReleasedSessionsLocked` `301-322` | `301-322` | 准确 |
| `Dispatch` `368-384` | `368-385` | 准确 |
| `BuildNative` `388-476` | `388-476` | 准确 |
| CMake `676-682/691/704/608-609` | 同 | 准确 |
| "不在任何测试闭包，变异无法让 ctest 转红" | 确认：`rtsc_server_desktop_input` 只被 host 链接；无 host add_test [READ:CMakeLists.txt:691,703-704,732-796] | 准确 |

唯一提醒：§1.8 说"详见 `input-batch10-review-F.md` §2.1 的变异 M6/M7/M8"，那里的 M6/M7/M8 与本文 §4.4 的 M1–M6 是两套编号，易混。

### §2.1 默认 off

- `enable_desktop_input=false` 默认 [READ:include/rtsc/server/server.h:144]，主机 `cfg.enable_desktop_input = opt.allow_input` [READ:main.cpp:400]，只有 `--allow-input` 才创建 sink [READ:main.cpp:467-470]。**一致**。
- 启动行 `input=off|on`、`input_max_sessions=N`：一致 [READ:main.cpp:487-489]。
- 首次租约拒绝+≥1 s 汇总：一致 [READ:main.cpp:685-708]。
- 行号 `main.cpp:105/342-345/352-366/453-463`、`server-mode.md:42` 全失效。

### §2.2 组合门禁

- 拒绝启动、退出码 2、点名两个危险选项、`--allow-input-unverified` 逃生门：一致 [READ:main.cpp:367-386]。
- 默认口令与 lookup：一致（`main.cpp:102`、`:426-435`）。
- `server.h:66-76`、`:73-75` 有效；`main.cpp:90/295-298/331-340/383-387/428-432` 失效。
- **漂移**：文档称 banner "5 行"且"写进日志首行"；实际 6 次 `log.line`（`:511-527`），且位于启动行与凭证行之后，不是首行。

### §2.3 多会话共享桌面

- 租约实现与文档语义基本一致：`InputLease` [READ:server.cpp:640-660]，首次可注入事件取租约 [READ:server.cpp:819-826]，断连释放 [READ:server.cpp:762-784]。
- **漂移 1**：文档称"租约释放给下一个等待者（先到先得）"；代码**没有等待队列**，被拒会话只在下一个可注入事件重试（代码注释明确 "deliberately no wait queue"）[READ:server.cpp:646-650]。
- **漂移 2**：文档的 `all` 模式"仅 `--input-share` 时"、`none` 模式；代码没有模式枚举，只有 `max_input_sessions` 槽位。`--input-share` 不存在 [READ:main.cpp:279-285]。
- **FAIL**："锁：只有一个锁"不成立：除队列 `mu_` 外还有 `log_mu_` [READ:src/server/desktop_input_win32.cpp:532,558]。
- 400/800/1000/2000、held-release 例外、全局拒绝不扣会话令牌、合成 up 绕过：全部一致 [READ:desktop_input_map.cpp:191-210]。
- 行号 `main.cpp:393-395`、`server.cpp:1410-1412`、`server-mode.md:24-27/37` 失效。

### §2.4 输入回显/隐私

- `dwExtraInfo` 自有常量：已实现（`0x52545343`，`desktop_input_win32.cpp:92`），文档仍写"建议"。
- **FAIL**：文档要求"文档与 `--help` 都要这么写（`main.cpp:15-55` 的 usage 块）"。实际 `usage()` 只打印旗标名 [READ:main.cpp:129-142]；"hand the local interactive desktop" 只在源码注释与运行期 WARNING，**`--help` 不显示**。
- `input-evidence.md:45` 失效（实际 `:54`，且原文标未验证）；`server-mode.md:14` 失效。

### §2.5 UIPI/完整性

- 第 1 条（`SendInput` 返回值/`GetLastError`/不重试）：一致 [READ:desktop_input_win32.cpp:484-510]。
- 第 2 条（启动打印完整性级别/进程会话 ID）：**未实现**。全仓无 `GetTokenInformation` / `ProcessIdToSessionId`。
- 第 3 条（前台窗口完整性只读诊断）：**未实现**。全仓无 `GetForegroundWindow`。
- 第 4 条（不做 SAS）：一致（无 `SendSAS`）。
- 结论：§2.5 是"暴露手段"设计，文档未标注哪些未实现 → **漂移/FAIL（文档应标未实现，或执行 AI 补实现）**。

### §2.6 卡键

- 按会话跟踪 + `ReleaseSession` 补 up：一致 [READ:desktop_input_map.h:103-122, src/server/desktop_input_win32.cpp:236-258]。
- `ReleaseSession` 的调用点：`ReleaseInput` [READ:server.cpp:762-784]。
- 文档列"会话结束、Stop()、租约被撤销"三个触发；**租约撤销事件不存在**（槽位只在会话结束时释放）→ 轻微漂移。

### §3 P-1…P-12 状态对账

| ID | 文档状态 | 当前事实 | 判定 |
|---|---|---|---|
| P-1 | `EXEC` | HWHEEL 已解码 [READ:server.cpp:609-630]；`horizontal` 已入事件 [READ:server.h:262]；注入 `MOUSEEVENTF_HWHEEL` [READ:desktop_input_win32.cpp:463-473]；广告含 0x0100 [READ:capabilities.h:262-264]；测试 [READ:test_server.cpp:1495-1528] | **状态过期，已修** |
| P-2 | `EXEC` | 9 位补码 [READ:server.cpp:619-622]；编码格×120+255 分块 [READ:client.cpp:259-307]；注入不乘 120 [READ:desktop_input_win32.cpp:463-470] | **状态过期，已修** |
| P-3 | `OPEN/BLOCKER` | 已解 `kMouseRel`+`rel_x/rel_y` [READ:server.cpp:1971-2003]；注入按裁决不注入 [READ:desktop_input_map.cpp:94-102] | **状态过期（解码已修；注入按设计）** |
| P-4 | `OPEN` | QoE `continue` 不回调 [READ:server.cpp:2004-2011]；`kMouseRel` 不再伪 kKey [READ:server.cpp:1986] | **状态过期，已修** |
| P-5 | `OPEN/BLOCKER` | 按钮位独立解码 [READ:server.cpp:589-599]；`is_move` [READ:server.h:258]；测试语义断言 [READ:test_server.cpp:1269-1327] | **状态过期，已修** |
| P-6 | `OPEN（平台边界）` | `extended1` 已解码 [READ:server.cpp:1938,1834]；**注入层忽略** [READ:desktop_input_map.cpp:42-47]，`IsInjectable` 仍判可注入 [READ:desktop_input_map.h:132-135]，win32 发裸 Ctrl [READ:desktop_input_win32.cpp:404-410] | **OPEN 正确，且比文档更严重**：不是"不注入"，是错误注入（Pause→切 NumLock） |
| P-7 | `OPEN` | `kSync` 不注入 [READ:desktop_input_map.cpp:100-102]；但"期望状态决策函数"未实现、无单测 | **状态过期（裁决已落地；决策函数未做）** |
| P-8 | `通过` | Unicode 解码 [READ:server.cpp:1941-1948]、翻译 [READ:desktop_input_map.cpp:50-59]、零码丢弃；广告 [READ:capabilities.h:262-264] | 一致（行号失效） |
| P-9 | `OPEN/BLOCKER` | 默认 `input_flags=0x013D`，含 0x0008 与 0x0020 [READ:capabilities.h:262-264]；测试 [READ:test_server.cpp:928-933] | **状态过期，已修** |
| P-10 | `OPEN/BLOCKER` | 慢路径已解码 [READ:server.cpp:1762-1767,1788-1903]；有测试 | **状态过期，已修** |
| P-11 | `OPEN（有意偏离）` | 未知 code 计数 [READ:server.cpp:2012-2024]；慢路径畸形计数 [READ:server.cpp:1789-1800]；快路径截断仍直接 `return` 不计数，无 `remaining==0` 强校验 | **部分落地**（"不断连+计数"已做，严格长度未完） |

**附带过期**：§0 结论 5 说三个协议前置缺陷（不广告 0x0020 / 慢路径丢弃 / 未知事件只 return）——前两个已修，第三个已计数；整段应重写。P-1/P-2/P-4/P-9/P-10 的"证据"行全部指向已修代码。

### §4.1 纯映射测试（T1–T20）

| 用例 | 文档期望 | 现状 | 判定 |
|---|---|---|---|
| T1/T2/T3 | scancode/extended/unicode | 有测试 [READ:test_desktop_input.cpp:48-112]；T3 只测 down | 基本一致 |
| T4 | `x=w-1→65535`；`x=w/2→32767/32768` | 0/65535 有测试 [READ:test_desktop_input.cpp:115-135]；中点**无测试**，且算法对 1920 给 **32785** [BASH: (960*65535+959/2)/1919 = 32785] | **FAIL（期望值错误）** |
| T5 | `origin_x=1920,…→dx=0` | `InjectGeometry` 无 origin 字段 [READ:desktop_input.h:31-34] | **FAIL（设计不存在）** |
| T6 | `width<=1 → 空 + unsupported` | `extent<=1` 1:1 透传 [READ:desktop_input_map.cpp:21-27]；无测试 | **FAIL（实现与计划相反）** |
| T7 | 越界钳制 | `value>=last→65535` [READ:desktop_input_map.cpp:24]；无 65535 入参测试 | 实现一致，测试缺 |
| T8 | `wheel_delta=-120→mouseData=-120，无 MOVE` | 翻译层有测试 [READ:test_desktop_input.cpp:182-191]；`mouseData` 属 Win32 后端，不在测试闭包 | 部分（M2 见 §4.4） |
| T9 | 横向滚轮 | 有 [READ:test_desktop_input.cpp:194-204] | 一致 |
| T10 | `wheel_delta==0 → 不产生 PlatformInput` | **无条件产出** [READ:desktop_input_map.cpp:82-92]；无测试 | **FAIL（未实现）** |
| T11 | 1/2/3/4/5→按键 | 翻译层只拷贝 button [READ:desktop_input_map.cpp:71-78]；4/5 映射在 Win32 后端 [READ:desktop_input_win32.cpp:442-453]，未测 | 部分 |
| T12 | 旧解码形态 `down=false,button=0` 重建 LEF TUP | 解码已改为 release 保留 button=1 [READ:server.cpp:589-599]；测试走新形态 [READ:test_desktop_input.cpp:152-165] | **FAIL（前提过期）** |
| T13 | 未知释放 → `unknown_release++` | 无该计数器；空翻译只在持租约时计入 `dropped_unsupported` | **FAIL（计数器不存在）** |
| T14 | sync 决策函数 | 只测 "不注入" [READ:test_desktop_input.cpp:216-221]，无决策函数 | **FAIL（未实现）** |
| T15 | `extended1 → 0 个 PlatformInput, unsupported++` | **未实现**、无测试 | **FAIL（最严重）** |
| T16 | `kMouseRel → 空` | 有 [READ:test_desktop_input.cpp:207-213]；`unsupported++` 同 T13 条件性 | 基本一致 |
| T17/T18 | 队列合并/硬限丢移动 | T18 策略测试 [READ:test_desktop_input.cpp:287-326]；T17 属 Win32 后端，无测试 | 部分（§1.8 已承认） |
| T19 | `ReleaseSession → CTRLUP+LEFTUP` | Win32 后端，无测试 | **FAIL（无覆盖）** |
| T20 | 限流 | 有 [READ:test_desktop_input.cpp:601-620,647-721] | 一致 |

### §4.2 集成测试（I1–I8）

全部已有真实用例，文档"待做"口径过期：

- I1 `server_input_qoe_timestamp_is_not_an_input_event` [READ:test_server.cpp:1058]。
- I2 `server_input_relative_mouse_keeps_signed_deltas` [READ:test_server.cpp:1114]。
- I3 语义断言在 `server_input_pointer_move_and_release_are_distinguishable` [READ:test_server.cpp:1269-1327]；文档引用的 `695-703` 已变成 sink mock。
- I4 同 I3（`is_move`）。
- I5 `server_decodes_wheel_rotation_in_wire_units` [READ:test_server.cpp:1466-1541]。
- I6 `server_advertises_fastpath_input_capability` [READ:test_server.cpp:899-933]。
- I7 慢路径输入与畸形计数 [READ:test_server.cpp:1807,2086,2170]。
- I8 租约/会话 id [READ:test_server.cpp:3681-3733]。

判定：**§4.2 整节状态过期**。

### §4.3 真机 UNVERIFIED

清单本身仍是未验证项；但引用 `process.md:272` 失效。未执行真机验证（审计角色无 mstsc/GUI 环境）。

### §4.4 变异表 M1–M6（专项）

| 变异 | 期望 | 现有真实用例 | 判定 |
|---|---|---|---|
| M1 `dx=x` 不归一化 | T4/T5 红 | T4 全范围用例 [READ:test_desktop_input.cpp:115-135] 会红 | **有真实用例** |
| M2 `mouseData=wheel_delta*120` | T8 红 | 若改 `TranslateInput`，`desktop_input_wheel_*` [READ:test_desktop_input.cpp:168-205] 会红；若改 `BuildNative`（真正危险点，`win32.cpp:470`），无测试闭包，**不会红** | **部分**：后端变异存活 |
| M3 释放猜 button=1 | T12/T13 红 | X1/X2 释放身份用例 [READ:test_server.cpp:1007-1050] 可捕；左键单用例 `1269-1327` 捕不到 | **部分** |
| M4 满队列丢键而非移移动 | T18 红 | `desktop_input_queue_evicts_move_when_available` [READ:test_desktop_input.cpp:292-300] 会红 | **有真实用例** |
| M5 `ReleaseSession` 不补 keyup | T19 红 | 无 T19；win32 后端不在测试闭包 | **无覆盖（变异存活）** |
| M6 `extended1` 当普通 CTRL | T15 红 | 无 T15；**当前实现已经是该变异** [READ:desktop_input_map.cpp:42-47] | **无覆盖，且缺陷已在** |

结论：M1/M4 真覆盖；M2/M3 部分；M5/M6 假测试（改坏仍全绿），与 §1.8 自述一致。按第 16 条，M5/M6 必须补测试或明确降级为"仅读码审查"。

### §6 最小改动清单

| 步骤 | 现状 | 判定 |
|---|---|---|
| 1 解码诚实性 | P-4/P-5 已做；`extended1` 已入结构但注入未按 P-6 丢弃；`has_payload` 未加（改用 per-case `continue`） | 部分 |
| 2 能力广告 0x0020 | 已做 [READ:capabilities.h:262-264] | 完成 |
| 3 接缝 `InputSink`/真 session_id | 已做，但名字是 `DesktopInputSink`；session id 非零 | 完成（命名漂移） |
| 4 纯翻译层+单测 | 已做 | 完成 |
| 5 Win32 后端/worker/限流/计数/ReleaseSession | 已做（M5 无测试） | 完成（测试缺口） |
| 6 CLI/默认值/门禁 | `--allow-input`、`--allow-input-unverified`、`--max-input-sessions` 已做；**`--input-share`、`--input-owner` 不存在** | FAIL |
| 7 变异测试 M1–M6 | M1/M4 红；M2/M3 部分；M5/M6 缺 | 部分 |

### §7 与附录

- §7 仍写"已向甲发出对账请求，尚未收到回执 → 未收敛"——与当前批次（H/I 双方审计已交叉、实现已落地）不符，状态过期。
- 附录 A 的 `main.cpp`、`server.h`、`server.cpp`、`tests/test_server.cpp` 行号大面积失效（见 §2）；`share-data.md`、`capabilities.md`、`desktop_gdi.h`、CMake 引用有效。

---

## 4. FAIL 清单与最小修法

### A. 代码侧（安全/行为，建议执行 AI 修）

| # | FAIL | 证据 | 最小修法 | 验证 |
|---|---|---|---|---|
| C1 | **P-6 extended1 仍被当裸键注入**：Pause 会切换本机 NumLock | `desktop_input_map.cpp:42-47` 不看 `extended1`；`map.h:132-135` 仍判可注入；`win32.cpp:404-410` 发普通 Ctrl | 在 `TranslateInput` 的 `kKey` 分支：`if (ev.extended1) return out;`（调用方按空翻译计 `dropped_unsupported`）；**不改** `IsInjectable` 可在 server 侧提前跳过（若改，保证计数一次） | 新增 T15：`extended1=true → TranslateInput 为空`；server 侧 `Pause 序列 → sink 收到 0 个 kKey`；先红后绿 |
| C2 | **几何来源错误（子矩形捕获）**：`--monitor N` 时注入坐标错位 | `desktop_input.h:31-34` 无 origin；`server.cpp:1308` 用协商几何；`win32.cpp:419` 恒 VIRTUALDESK | 二选一：① 给 `InjectGeometry` 加 `origin_x/origin_y/virtual_desktop`，由 `DesktopSource` 暴露捕获矩形（GDI 源的 `rect_` 已有，`desktop_gdi.cpp:242`）；② 若短期不扩展，在 `--monitor N` 时拒绝/告警注入，并把文档改为"仅支持整虚拟桌面" | 单测 T5（origin 偏移）；真机/多屏 UNVERIFIED |
| C3 | **T6 几何不可用未拒绝**：`width<=1` 时 1:1 透传，可能把 0 当 65535 归一化坐标 | `desktop_input_map.cpp:21-27` | `NormalizeAxis` 前判 `g.width<=1 || g.height<=1 → return {}`（或 `TranslateInput` 开头拒绝 kMouseMove） | 新增 T6：`InjectGeometry{0,0}`/`{1,1}` → 空 |
| C4 | **T10 零滚轮仍入队** | `desktop_input_map.cpp:82-92` 无条件 `push_back` | `if (ev.wheel_delta == 0) return out;` | 新增 T10 用例 |
| C5 | **§2.5 诊断未实现**：文档承诺的启动完整性级别/前台窗口诊断不存在 | 全仓无 `GetTokenInformation`/`ProcessIdToSessionId`/`GetForegroundWindow` | 要么实现（新增只读诊断，失败不阻断），要么在 §2.5 逐条标 **未实现** | 编译零警告 + 启动日志断言 |
| C6 | **`--help` 不描述危险**：§2.4 要求 | `usage()` 只打印旗标名 `main.cpp:129-142` | 在 usage 的 `--allow-input` 行后补一行 "hands the local interactive desktop to the peer"（或扩成旗标说明块） | 运行 `--help` 断言包含该串 |
| C7 | **CLI 幻觉**：`--input-share`/`--input-owner` 不存在 | `main.cpp:279-285` 只有 `--max-input-sessions` | 文档改为实际旗标；若确需模式，另立实现任务（勿在文档写已存在） | `--help`/ParseOptions 对账 |
| C8 | **P-11 快路径长度强校验缺失** | `server.cpp:1921-2024` 截断直接 `return`、无计数；无 `remaining==0` | 在快路径 `pos+need>n` 时 `malformed_input_pdus_++`；PDU 结束后 `pos!=n` 视为畸形（可选） | 新增快路径截断用例，断言计数+1 且不断连 |
| C9 | **M5/M6 变异存活** | 无 T15/T19；win32 不在测试闭包 | 至少把 `BuildNative` 的 `INPUT` 构造抽成平台中立纯函数（或注入 `SendInput` 函数指针），把 `AppendReleasesLocked`/`Dispatch` 纳入 `rtsc_desktop_input_tests`；否则在文档明确"不可变异验证" | 变异 M5/M6 必须红 |

### B. 文档侧（行号/状态，必须更新）

| # | FAIL | 最小修法 |
|---|---|---|
| D1 | §1.3/§1.4 接口与文件名整体失效 | 用 `DesktopInputSink`/`desktop_input.h`/`desktop_input_map.*`/`MakeWin32DesktopInputSink`/`Shutdown()` 重写 §1.3–§1.4；删除 `InputSink`、`input_inject*`、`CreatePlatformInputSink`、`ReleaseAll` |
| D2 | §1.7 第 2 条与实现相反 | 二选一：改成"当前实现 = 协商 framebuffer + VIRTUALDESK（仅整虚拟桌面正确）"，并记录 `--monitor N` 缺口；或按 C2 实现后再保留原文 |
| D3 | §3 状态列过期 | P-1/P-2/P-3/P-4/P-5/P-9/P-10 改"已修"；P-6 改"部分（extended1 已解，注入丢弃未做）"；P-7 改"裁决已落地，决策函数未做"；P-11 改"部分"；P-12 汇总表同步 |
| D4 | §0 结论 1/2/5 过期 | "注入层已实现"；"三个协议前置缺陷：0x0020 已广告、慢路径已解、未知事件已计数" |
| D5 | §4.1 T4/T6/T10/T12/T13/T14/T15 | T4 中点改 `32785`（或删除中点断言）；T6/T10 与 C3/C4 同步；T12 改新解码形态；T13/T14/T15 标"未实现" |
| D6 | §4.2 I1–I8 | 标"已实现"并换成当前用例名（见 §3/§4.2），删除"现有测试固化缺陷"的过期表述 |
| D7 | §4.4 M1–M6 | 标 M1/M4 有真实用例；M2/M3 部分；M5/M6 无覆盖（或 C9 后更新） |
| D8 | §1.5 `232-254`/`307-315` | 改 `236-258` / `311-319` |
| D9 | §1.1/§2.x/附录全部行号 | 按 §2 表批量替换；至少覆盖 main.cpp 16 处、server.h 13 处、server.cpp 25 处、tests 3 处、input-evidence 4 处 |
| D10 | §2.3 "只有一个锁" / "等待者" / `--input-share` | 改为"队列 `mu_` + 日志 `log_mu_`"；"无等待队列，下一事件重试"；`--max-input-sessions` |
| D11 | §2.2 "5 行 banner + 日志首行" | 改"6 行 banner，位于启动/凭证行之后" |
| D12 | §2.4 `--help` | 与 C6 同步 |
| D13 | §6 CLI 清单 | 删除 `--input-share`/`--input-owner`，补 `--max-input-sessions` |
| D14 | §7 未收敛状态 | 改"已与 H/I 交叉审计；剩余 FAIL 见本文件" |
| D15 | §1.7 第 1 条行号 | `2160→2165`、`2286-2287→2291-2292`、`2414→2418-2419`、`2036→2041` |

**优先级**：C1 > C2/C3 > C5/C6 > C4 > C7 > D3/D1 > 其余文档更新。C1 是唯一"会实际改变本机状态"的缺陷（Pause→NumLock），必须先修。

---

## 5. §1.8 复核结论（逐条）

| # | 文档行 | 实际 | 结论 |
|---|---|---|---|
| 1 | 204-229 引言 | `desktop_input_win32.cpp` 不在 `rtsc_desktop_input_tests`/`rtsc_server_tests` 闭包 | 成立 |
| 2 | `197-203` 移动合并 | 197-203 | 准确 |
| 3 | `204-209` oldest_move | 204-209 | 准确 |
| 4 | `221-228` evict/drop 计数 | 221-231 | 基本准确 |
| 5 | `236-258` AppendReleasesLocked | 236-258 | 准确 |
| 6 | `301-322` ForgetReleasedSessionsLocked | 301-322 | 准确 |
| 7 | `368-384` Dispatch | 368-385 | 准确 |
| 8 | `388-476` BuildNative | 388-476 | 准确 |
| 9 | `CMakeLists.txt:676-682` | 676-683 | 准确 |
| 10 | `CMakeLists.txt:691` | 691 | 准确 |
| 11 | `CMakeLists.txt:704` | 703-704 | 准确 |
| 12 | `CMakeLists.txt:608-609` | 608-609 | 准确 |

**判定：§1.8 一致**（仅建议把 `221-228` 扩到 `221-231`）。

---

## 6. 与审计 H 的互审

H（teardown 异常安全）本轮来信的 4 点：

1. `seam.md:137` 的 `232-254→236-258`、`307-315→311-319`：**我方独立复核一致**；并确认 `!it->synthetic` 在 `desktop_input_win32.cpp:312`。
2. §1.8 全部准确：**一致**（见 §5）。
3. `ReleaseInput` = `server.cpp:762-784`：**一致**。
4. `input-batch10-review-F.md:340/:249` 状态过期：**属实**，本文件不引用 F.md 状态列。

我方已向 H relay 三条待复核项（P-6 注入、§1.7#2 几何、T6/T10），但 relay 连续 3 次返回 `SEND_TIMEOUT`（确定未送达），故 H 的独立确认**尚未取得**。这不影响上述结论的证据（均为本工作树读码），但按"双审一致盖章"要求，H 的复核仍是未完成项。

【未验证】H relay 失败原因（平台侧）；H 是否在线。

---

## 7. 未验证与限制

1. **未做变异实测**：本角色只读（禁止改 src/include/tests），M1–M6 的"改坏→红→恢复→绿"未在本轮执行；§4.4 的覆盖判断基于测试源码与 CMake 闭包静态分析，已用现有两套测试做绿基线。
2. **未重新抓取官方文档**：`SendInput`/`KEYBDINPUT`/`MOUSEINPUT`/`SendSAS`/`[MS-RDPBCGR]` 引文沿用 seam.md，标 **【未复验】**。
3. **未做真机**：§4.3 的 10 条 UNVERIFIED 保持未验证。
4. **构建产物时间**：`rtsc_server_tests.exe` 16:42、`rtsc_desktop_input_tests.exe` 16:04（提交 a59a594 17:02），测试二进制可能未包含提交后的最后一处 `server.cpp`/测试改动；绿基线仅代表该构建。未重新编译（环境无 cmake/ctest 在 PATH）。
5. **`--monitor N` 错位的实际表现**：基于代码推导（`VIRTUALDESK` + 子矩形捕获），未做多屏真机复现，标 **【UNVERIFIED】**。

---

## 8. 附：本次运行的命令与输出

```
[BASH: build\Release\rtsc_desktop_input_tests.exe] 41 tests, 13713 checks, 0 failing tests, 0 failed checks
[BASH: build\Release\rtsc_server_tests.exe]       49 tests, 560 checks, 0 failing tests, 0 failed checks
[BASH: (960*65535+959/2)/1919 = 32785]             （T4 中点实际值）
[BASH: decode 0x0301 = -255; decode 0x02FF = +255; decode 0x0600：vertical wins]
```

（完）
