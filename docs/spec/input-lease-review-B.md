# 输入租约独立审计（乙3）

范围：只读审计 `4eb3344`（慢路径 MOUSEREL / 队列硬上限 / Stats / ReleaseSession 清
`last_move_sent_` / malformed 计数 / `was_share_data` 白名单）与 `3f30939`（单会话租约 /
`scancode==0` 过滤 / sink 集成测试）。

证据口径：每条论断给出 `文件:行` 或命令原始输出。审计期间未改动 `src/`、`include/`、
`tests/`、`tools/`、`CMakeLists.txt`；仅新增本文件。`git -C F:\rtsc rev-parse HEAD` =
`3f30939b4362106fc1ab3f08f8dd7067734993f3`，`git -C F:\rtsc diff HEAD --stat -- src include
tests tools CMakeLists.txt` 输出为空（工作树与提交零差异）。

**变异源码说明（偏离任务字面）**：任务建议 `git archive 4eb3344` 后删 `ReleaseInput` 的租约
erase。但 `4eb3344` 早于 `3f30939`，该提交的 `ReleaseInput` 只有 sink drain、没有租约
（`git show 4eb3344:src/server/server.cpp` 中 `input_lease|InputLease` 命中 0，只有
`ReleaseInput` 自身与两处调用），删无可删。故变异在 `3f30939`（=HEAD）归档副本上执行，删除对
象就是租约 erase。理由与偏差一并记录于此。

---

## 0. 结论摘要

| # | 项 | 结论 |
|---|---|---|
| 1a | B 每事件尝试获取 / denied 单调 / 饥饿 | **PASS**（机制成立；饥饿是设计使然，见 F3 放大条件） |
| 1b | A 在 Inject 进行中断开，ReleaseSession 与 worker drain 顺序 | **PASS**（顺序安全）；另报告 F1（丢 up 卡键，独立证实甲3）与 F2（交接窗口竞态，低） |
| 1c | max=2 时 A 断开后 C 进入，slot 回收 | **PASS**（可执行探针：denied=0，distinct_inject=3） |
| 2 | 与 `input-injection-seam.md` §1/§2 定案一致性 | **FAIL**（§1.5 队列 256/硬上限、§1.5 kMouseRel、§2.3 限流与告警均与定案不符；§2.1/§2.2 默认 off 与拒绝启动 PASS） |
| 3 | 代码质量（单一写者 / TOCTOU / 生命周期） | **PASS**（holders 单锁单写者；无 TOCTOU；`input_lease_` 由 Impl 拥有、session 共享活着；唯一隐患 F3） |
| 4 | 性能（每事件一次 mutex） | **PASS**（量级 <1 ms/s；持租者走免锁快路径） |
| 5 | 变异（删租约 erase） | **PASS**（红：1 test / 5 checks；恢复：hash 双证 + 绿 46/46） |
| 6 | 独立新增发现 | F1（丢 keyup 永久卡键，与甲3一致）、F2（交接竞态，低）、F3（不可注入事件也占租约，中）、F4（未定义 type2 回落 fast-path，独立证实甲3） |

---

## 1. 行为语义（自设计场景，测试未覆盖）

### 1a. 会话 A 持租，B 每秒 1 事件持续 10 秒

机制（读代码）：`AcquireInputLease` 在每个解码事件后无条件调用，且**持租者走无锁快路径、非持租者
每事件重试一次**：

- `[READ:src/server/server.cpp:806-832]` `AcquireInputLease()`：`if (input_lease_held_) return true;`
  （:808 快路径）→ 锁内 `if (max_sessions==0 || holders.size()<max_sessions) insert` （:815-819）
  → 未取到则 `denied->fetch_add(1)`（:822）。
- 调用点：`[READ:src/server/server.cpp:1863-1864]`（慢路径）与
  `[READ:src/server/server.cpp:1991-1992]`（fast-path）在 `Inject` 之前无条件调用。

结论：B 的每个事件都尝试（持租者 A 不占锁快路径；B 每事件进锁一次 size 检查），失败即
`fetch_add`，故 **denied 严格单调 +1/事件**；因为**没有等待队列、没有空闲超时、没有轮转**，
A 只要不断连（哪怕不再输入），B 无限饥饿——这是 `input-injection-seam.md:238` 的既定语义
（"租约在持有点断连时释放"）。

可执行探针（%TEMP% 归档副本临时加 1 个测试，随后删除；非仓库改动）：
`audit_probe_lease_starvation_and_slot_recycle`，10 次每 100 ms 一发：

```
[probe] denied=10 distinct_inject=1
[probe] max2 leaver=1 denied=0 distinct_inject=3
47 tests, 538 checks, 0 failing tests, 0 failed checks   (3 次重跑一致)
```

即：10 个事件 = 10 次 denied（每事件都尝试、单调），B 从未进入 `Inject`（distinct=1 恒为 A）。
**PASS**，但见 F3：若 B 发的是不可注入事件（kSync 等），它同样能取到租约却什么都不注入。

### 1b. A 在 Inject 调用进行中断开（worker 在跑）

服务端层与 sink 层分开看。

**服务端层：`Inject` 与 `ReleaseInput` 同线程，无并发窗口。**
`ParseInputEvents` / `ParseSlowPathInput` 跑在会话线程的 `ActiveLoop`（
`[READ:src/server/server.cpp:1643-1650]`、`:1863`、`:1991`）；`ReleaseInput` 只在会话线程
`Run()` 返回之后调用（
`[READ:src/server/server.cpp:2313-2335]` body 的 `Run()→Stop()→ScrubCredentials()→ReleaseInput()`；
`[READ:src/server/server.cpp:2383-2401]` ServeOne 同序）。`Stop()` 只调用 `RdpSession::Stop()`
（`[READ:src/server/server.cpp:2404-2434]`，不碰 `ReleaseInput`），故不存在"另一线程调
`ReleaseInput`"的路径。所谓"A 在 Inject 进行中断开"在服务端层被序列化为"该次 Inject 先结束、
teardown 才发生"。

**sink 层（真正的并发面）顺序安全。**
`Inject` / `ReleaseSession` 都在 `mu_` 下改 `sessions_`/`queue_`
（`[READ:src/server/desktop_input_win32.cpp:109-122]`、`:124-143`）；worker 在 `mu_` 下弹出
队首、**锁外** `Dispatch`
（`[READ:src/server/desktop_input_win32.cpp:243-261]`）。于是：worker 已把 key-down 弹出（或正在
`SendInput`）时，会话线程追加的 key-up 必然排在队尾，FIFO 保证 down 先于 up 被 `SendInput`。
`TrackPressedLocked` 在 `Inject` 入队时记录按下集（`:118-119`、`:158-176`），`ReleaseSession`
用该集合补 up（`:212-234`），故"down 曾被硬上限丢弃"也能被补 up。

**锁序**：`ReleaseInput` 先释放租约锁再调 sink
（`[READ:src/server/server.cpp:765-771]` 的 block 结束后才 `input_sink_->ReleaseSession`）；
`AcquireInputLease` 亦先出锁再 `SetGeometry`（`:811-830`）。租约锁与 sink `mu_` **从不嵌套**，
无死锁。

**但顺序安全不等于无缺陷**，见 F1（丢 up 卡键）与 F2（erase 早于 ReleaseSession 的交接窗口）。
两项都存在于读代码，非基准可测（Win32 `SendInput`），标注为静态推断。

### 1c. `max_input_sessions=2`，A/B 持租，A 断开后 C 进入

`ReleaseInput` 幂等守卫内 `holders.erase`（`[READ:src/server/server.cpp:760-772]`），新会话 id 由
原子递增分配（`[READ:src/server/server.cpp:2255-2261]`、`:2129-2132`，从 1 起、进程内不重用），
故 C 的 `holders.insert` 不会与残留 id 相互吞并。

可执行探针（同上测试的后半段）：A、B 同时持租（`denied=0`），断开一个后 C 进入，
`[probe] max2 leaver=1 denied=0 distinct_inject=3` —— slot 正确回收，C 未经历拒绝。
**PASS**。（`holders` 是 `std::set<uint32_t>`，按 id 去重；进程内 id 单调，无别名风险。）

---

## 2. 规范/文档一致性（`docs/spec/input-injection-seam.md` §1/§2）

| 定案 | 规范位置 | 实现 | 判定 |
|---|---|---|---|
| 队列容量 256 | `input-injection-seam.md:135`（"队列满（容量 256）…永不丢键/按钮"） | 软限 `kMaxQueue=256`（`[READ:src/server/desktop_input_win32.cpp:59]`）+ **硬限 `kHardQueueLimit=4*256=1024`**（`:64`），到硬限**丢弃键/按钮**（`[READ:src/server/desktop_input_map.cpp:106-112]`） | **FAIL**：容量实为 1024、且硬限处明确丢键，"永不丢键/按钮"被打破；两个提交均未更新该行 |
| 硬上限 | 规范未提 1024 | `kHardQueueLimit=1024`，`DecideEnqueue` 在硬限 `kDrop` | **FAIL（文档丢失）**：行为存在且有单测（`tests/test_desktop_input.cpp:291-300`），但规范正文无此定案 |
| 默认 off | `input-injection-seam.md:191-201` §2.1 | `ServerConfig::enable_desktop_input=false`（`[READ:include/rtsc/server/server.h:144]`）+ main 默认 `--allow-input` 关（`[READ:tools/rtsc_server/main.cpp:120]`），双重门控在 `AcquireInputLease`:807 / `ReleaseInput`:769 / 装配 `main.cpp:400,469,586` | **PASS** |
| 组合门禁拒绝启动 | §2.2 `input-injection-seam.md:204-227` | `main.cpp:368-390` `unsafe_input && !allow_input_unverified → return false`（退出码 2） | **PASS** |
| 单会话门控默认 `first` | §2.3 `input-injection-seam.md:236-240` | `max_input_sessions=1`（`server.h:154`），`--max-input-sessions N`（`main.cpp:279-284`） | **PASS（能力）**，但见下条 |
| "其他会话被丢弃并计数 **+ 一次性告警**" | `input-injection-seam.md:238` | 只计数（`input_lease_denied_count()`，`server.h:389`），**全仓无任何日志/告警**：`rg`/Select-String `tools/rtsc_server/main.cpp` 对 `denied|Stats|input_lease` 命中 0 | **FAIL**：独立主机运维无从观测拒绝 |
| 逃生门 `--input-share` / `--input-owner` | `input-injection-seam.md:239` | 未实现；以数值 `--max-input-sessions`（0=不限）替代 | **偏差（可接受但文档需改）** |
| 限流：单会话 400/s、全局 1000/s、`dropped_rate_limited` | `input-injection-seam.md:242-248` | 未实现（全仓无 `kEventsPerSecond`/`kGlobalEventsPerSecond`）；仅 250 Hz 移动合并（`desktop_input_win32.cpp:65,278-320`） | **FAIL**：规范承诺的 DoS 护栏缺失 |
| 计数面 `injected_ok/injected_failed/dropped_queue_full/dropped_unsupported/last_error/sessions_with_input` | §1.6 `input-injection-seam.md:150-160` | `InputStats` 只有 `injected/dropped_queue_full/send_failures`（`[READ:include/rtsc/server/desktop_input.h:43-46]`）；`dropped_unsupported_` 内部存在（`desktop_input_win32.cpp:495`）但未暴露；null sink 把 drop 记成 injected（`desktop_input_null.cpp:32-39`） | **偏差（低）** |
| `kMouseRel` "当前解码层不上送" | §1.5 `input-injection-seam.md:137` | `4eb3344` 已解码并上送 `kMouseRel`（`[READ:src/server/server.cpp:1836-1853]`、`:1951-1967`），由注入层按不支持计数（`desktop_input_map.cpp:99-101`） | **FAIL（陈旧）**：改为"不上送"的旧表述 |

小结：§2.1/§2.2 的安全定案**已正确落地**；§1.5 队列容量/硬限、§2.3 告警与限流、§1.5 kMouseRel
描述存在**规范-实现漂移**，需要回写规范或补实现，二者不可两缺。

---

## 3. 代码质量

- **单一写者**：`holders` 只在 `AcquireInputLease`（`server.cpp:817`，锁内）与 `ReleaseInput`
  （`:767`，锁内）写；两处都持 `input_lease_->mu`。**PASS**。
- **TOCTOU**：检查 `holders.size() < max_sessions` 与 `insert` 在**同一临界区**
  （`server.cpp:812-819`）；`erase`（:766-768）同锁。无 check-then-act 间隙。**PASS**。
  （`input_lease_held_`/`input_released_` 为无锁 bool，靠"仅会话线程读写"成立——`ReleaseInput`
  只在会话线程（body/ServeOne）调用，`Stop()` 不调它。若将来有人从 `Stop()` 调
  `ReleaseInput`，即为数据竞争，属脆弱点，建议加注释或改 `std::atomic`。）
- **`input_lease_` 生命周期**：由 `RdpServer::Impl` 创建并持有
  （`[READ:src/server/server.cpp:2097-2100]`），`shared_ptr` 复制进每个会话
  （`:2261`、`:2388`），故 detached 会话线程可让 `InputLease` 活到自身最后一次语句；`denied` 又是
  `shared_ptr<atomic>`（`:657`），`Impl` 与所有会话共享，计数不会悬空。**PASS**。
- **F3（中，新）**：租约在**不可注入事件**上也获取。`AcquireInputLease` 在
  `server.cpp:1863/1991` 无条件调用，而 `TranslateInput` 对 `kSync`、`kMouseRel`、
  `scancode==0`、`unicode_code==0` 返回空（`desktop_input_map.cpp:38,51,99-101`）。后果：一个只发
  `kSync`（或 scancode 0、kMouseRel）的会话会**占住唯一租约直到断开**，把真正的键盘/鼠标操作者永久
  拒绝掉——"holder = 正在注入的会话"这一不变量被破坏。最小复现：`max=1` 时会话 B 发 1 个
  fast-path `kSync`（eventCode 0x3）→ B 进 `holders`；会话 A 之后发 `kKey` → 恒被 denied。
  建议：仅在事件可被注入（sink 至少产出一条 `PlatformInput`）后获取租约，或在
  `AcquireInputLease` 前按上述四类短路。

---

## 4. 性能

- 持租者每事件**不进锁**（`input_lease_held_` 快路径，`server.cpp:808`）。非持租者每事件一次
  `input_lease_->mu` 锁 + 一次 `denied` 原子自增（`:812-822`）。sink 侧每事件一次 `mu_` 锁，临界区
  含 `TranslateInput`（可能 `std::vector` 分配）与 `std::deque::push_back`
  （`desktop_input_win32.cpp:108-122`）。
- 量级：`std::mutex`（MSVC = SRWLOCK）无争用 ~20 ns/次，`SendInput` 单体 ~5–20 µs。240 Hz × 8 会话
  ≈ 2000 事件/s，开销 < 1 ms/s。最坏争用是 7 个非持租会话同压 1 把租约锁，但临界区只做 set
  size 检查/插入（O(log n)，n≤max_input_sessions），~100 ns 级。结论：**可接受，无需基准**。
  （注：`denied` 无上限增长，但只是 1 个 `size_t`，无内存放大。）
- 250 Hz 移动输出上限与合并逻辑在 worker 内（`EmitDueMoves`/`Dispatch`，`:278-335`），与本次改动
  无关，未被两提交回退。

---

## 5. 独立变异（第 16 条）

变异源：`git archive 3f30939` → `%TEMP%\rtsc-mut-src-b10`，构建目录
`C:\Users\liulilte\rtsc-mutbuild-b10`（VS 2022 x64 Release，非 %TEMP%）。变异：删除
`ReleaseInput` 内租约 erase（`server.cpp:765-768`），使持租者断开后 id 永留 `holders`。

```
$ git archive --format=zip -o %TEMP%\rtsc-mut-b10.zip 3f30939
$ & cmake --build C:\Users\liulilte\rtsc-mutbuild-b10 --config Release --target rtsc_server_tests
  rtsc_server_tests.vcxproj -> ...\Release\rtsc_server_tests.exe
$ ...\rtsc_server_tests.exe
  FAIL .../test_server.cpp:3503  handed_off
  FAIL .../test_server.cpp:3505  DistinctIds(geometry_after_handoff) == 2 (got 1, want 2)
  FAIL .../test_server.cpp:3510  survivor != 0
  FAIL .../test_server.cpp:3511  CountId(geometry_after_handoff, survivor) == 1 (got 0, want 1)
  FAIL .../test_server.cpp:3520  CountId(sink.release_ids(), survivor) == 1 (got 0, want 1)
  [ FAIL ] server_input_lease_one_session_then_handoff
  46 tests, 796 checks, 1 failing tests, 5 failed checks
  EXIT=1
```

**红证成立**：删掉 erase 后租约移交测试转红（正是 `server_input_lease_one_session_then_handoff`
的 handoff 断言）。

恢复与哈希双证（恢复=反向编辑，并用归档原件独立比对）：

```
restored(server.cpp) = 63AF43738F55BB66243EB0A915ED34EBD684F0C76577E0E82F935984F931E10D
archive (server.cpp) = 63AF43738F55BB66243EB0A915ED34EBD684F0C76577E0E82F935984F931E10D size=119935
```

恢复后重编译重跑：

```
  [ OK  ] server_input_lease_one_session_then_handoff
  46 tests, 497 checks, 0 failing tests, 0 failed checks
  EXIT=0
```

**绿证成立**。变异非假测试。

---

## 6. 与甲3（`ses_e6be4554cffeCGbfgAQwB7ugVJ`）交叉核对

甲3 的结论我方独立复核如下（未读其文档正文，仅按 relay 结论核对）：

- **F1（硬限丢 keyup 永久卡键）**：**成立，我方独立得出同一链**。`Inject` 先
  `TrackPressedLocked`（`desktop_input_win32.cpp:118-119`）→ release 在 `:160-167` 已从
  `pressed_keys` 删除 → 入队若命中硬限 `kDrop`（`:203-205` / `desktop_input_map.cpp:110`），则 up
  被丢且 `pressed_keys` 已空，`ReleaseSession`/`Shutdown` 的 `AppendReleasesLocked`（`:219-226` /
  `:468-472`）不会再补。与注释 `:14-21`、测试注释 `tests/test_desktop_input.cpp:292-295`
  （"a dropped key is released by ReleaseSession"）**直接矛盾**——该说法只对丢 **down** 成立，对丢
  **up** 不成立。**无其他兜底**：全仓无 `GetAsyncKeyState`/`SendInput` 全清/按键对账（`Select-String`
  `desktop_input_win32.cpp` 无 `AsyncKeyState`）。
- **F2（erase 早于 ReleaseSession 的交接窗口）**：**成立（低）**。`server.cpp:765-768` 先出锁并
  erase，`:769-771` 才 `ReleaseSession`；窗口内新会话可取租并 `Inject(keydown)`，随后旧会话的合成
  up（scancode 级、不区分会话）可能抬起新持有者刚按下的同一键。sink 的 per-session 状态不能阻止
  （`SendInput` 无会话概念，只有队列顺序能防）。最小修法：把 `ReleaseSession` 移到 erase 之前
  （仍持 slot，禁止新会话插入）。
- **F3（不可注入事件也占租约）**：**成立（中）**，见 §3。甲3 未列此条，属我方新增。
- **F4（未定义 type2 回落 fast-path）**：**独立证实**。`HandleSlowPathPdu` 对未知 `pdu_type2`
  直接 `return true` 且**不置 `handled`**（`server.cpp:1692`），调用方
  `if (!was_share_data) HandleInputPdu(payload)`（`:1650`）→ 24 字节前缀 `total_length=0x1804`
  低 2 位为 0，通过 `(payload[0]&0x03)!=0` 门（`:1872`）后被当 fast-path 解码。`GAP4` 修好了"吞掉
  真 fast-path 输入"，但把"未知/未列入白名单的 share PDU"变成了"幻影输入"。建议消歧：先用
  fast-path 动作位判定（低 2 位==0 优先 fast-path），否则 ShareDataHeader 解析成功即视为已消费
  （未知类型也吞掉 + 计数），不要把二者都当输入。
- **④ 释放旁路"无界"的口径**：应改为"**每次 teardown 有界（≤ 512 keys + 5 buttons），全局非绝对
  上界**"。`pressed_keys` 为 `set<KeyId{uint16 scancode,bool extended}>`（scancode 实际 8 位，≤512），
  `pressed_buttons` ≤5；且 `ReleaseSession` 随后 `sessions_.erase`（`:140`）销毁状态，同一 id 只补一次。
  因此硬限 1024 不是**绝对**上界，但旁路增量 = O(窗口内同时 teardown 的会话数 × ≤517)，非常态不可
  无界；仅当 worker 长期阻塞（如 `SendInput` 卡住）叠加大量连接断开才累积。判定：**低危，文档化即可**。

---

## 7. 交付建议（不改代码，仅给验收口径）

1. **F1（中，建议必修）**：`AppendReleasesLocked`/`Inject` 顺序修正——先决定入队（drop/evict/accept），
   仅在被接纳（或至少对 release 永不 drop）后才更新 `pressed_keys`；或在硬限只丢弃可丢弃类、release
   强制绕过硬限。并修掉 `:20-21`、`tests/test_desktop_input.cpp:292-295` 的错误保证文字。
2. **F3（中）**：租约获取前按"是否为可注入事件"短路（kSync/kMouseRel/scancode==0/unicode==0）。
3. **F2（低）**：`ReleaseInput` 把 `ReleaseSession` 提到 `holders.erase` 之前。
4. **F4（中，4eb3344 引入）**：IO 通道的 share/fast-path 消歧改为"fast-path 动作位优先"，未知 share
   类型视为已消费；补回归：发 24B 未定义 type2 → 回调 0 次。
5. **文档**：回写 `input-injection-seam.md:135`（1024 硬限 + 硬限处丢键）、`:137`（kMouseRel 已上送）、
   `:238`（无 `--input-share`，改数值门控；告警未实现）、`:242-248`（限流未实现）。二选一：补实现或
   改规范，不能维持现状。
6. **可观测性**：`rtsc_server` 至少打印一次租约拒绝计数（或启动行加 `lease-denied=`），否则 §2.3 的
   "计数+告警"对独立主机不可见。

---

## 附录：本轮命令原始输出（摘）

```
$ git -C F:\rtsc rev-parse HEAD
3f30939b4362106fc1ab3f08f8dd7067734993f3
$ git -C F:\rtsc diff HEAD --stat -- src include tests tools CMakeLists.txt
(空)

$ git -C F:\rtsc show 4eb3344:src/server/server.cpp | Select-String -Pattern "input_lease|InputLease"
(0 命中)
```

（完整变异与探针输出见 §1a/§5；探针测试文件仅存在于 `%TEMP%` 归档副本，已随副本保留，未进入仓库。）
