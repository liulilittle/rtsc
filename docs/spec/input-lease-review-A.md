# 输入租约 / 有界队列 / GAP④ 独立审查（甲3）

- 审查对象：`4eb3344`（慢路径 MOUSEREL、队列硬上限、Stats、ReleaseSession、SetInputSink 注释、malformed 计数、was_share_data 白名单）与 `3f30939`（`max_input_sessions=1` 单会话租约、`scancode==0` 过滤、sink↔server 集成测试）。
- 仓库：`F:\rtsc`；HEAD = `3f30939`（`git rev-parse HEAD`）。
- 只读约束：未修改仓库 `src/ include/ tests/ tools/ CMakeLists.txt`。所有改码实验都在 `git archive 3f30939` 的 `%TEMP%` 副本 + 独立构建目录 `C:\Users\liulilte\rtsc-mutbuild-a9` 中进行；仓库工作树仅新增本文件。
- 独立性：未读取 `docs/spec/input-injection-review-*.md`、`docs/spec/input-wheel-review-*.md`。
- 构建/运行环境：MSVC 19.44（VS2022 Enterprise `vcvars64.bat`）+ Ninja + CMake，`CMAKE_BUILD_TYPE=Debug`，`/W4 /WX`（`CMakeLists.txt:875-876`）。

工作树与提交一致性（后续所有 `file:line` 均以该已提交内容为准）：

```
[BASH] git diff 3f30939 -- src/server/server.cpp src/server/desktop_input_map.cpp \
        include/rtsc/server/server.h include/rtsc/server/desktop_input_map.h \
        tools/rtsc_server/main.cpp tests/test_server.cpp tests/test_desktop_input.cpp
(0 行输出)
```

## 结论总表

| # | 项目 | 结论 |
|---|------|------|
| 1 | 租约正确性（加锁/插入删除/0 语义/首事件/拒绝计数/重试/幂等释放） | PASS（附带 F2 释放顺序、F3 非注入事件也能取得租约） |
| 2 | 租约与几何（仅持租会话下发几何） | PASS |
| 3 | 并发安全（holders 加锁、denied 原子、无嵌套锁） | PASS |
| 4 | 队列硬上限（五分支一致 / 释放旁路是否无界） | 判定一致性 PASS；硬上限“绝对”FAIL（F1：旁路可越界；且硬限丢弃 keyup 会永久卡键） |
| 5 | GAP④ 白名单覆盖 | 覆盖 24/24 PASS；白名单外类型会落入 fast-path 解码 FAIL-风险（已红证：幻影按键注入） |
| 6 | `scancode==0` 仅影响 kKey、kUnicode 零码一致 | PASS（附带 F3：零码事件仍可取得租约并进回调） |
| 7 | 独立变异测试（恒收纳 → 租约测试必红，恢复必绿） | PASS（红/绿原始输出 + 哈希双证见 §7） |
| 8 | 总体 | 两个提交主功能成立；F1（卡键/硬限非绝对）与 F2/F3 建议执行 AI 修复后再盖章 |

---

## 1. 租约正确性 — PASS（附 F2、F3）

### 1.1 数据结构与锁范围

`src/server/server.cpp:649-658`：

```
struct InputLease {
    explicit InputLease(size_t max_sessions)
        : max_sessions(max_sessions),
          denied(std::make_shared<std::atomic<size_t>>(0)) {}
    std::mutex mu;
    std::set<uint32_t> holders;  // input session ids currently injecting
    const size_t max_sessions;   // 0 = unlimited (explicit opt-out)
    std::shared_ptr<std::atomic<size_t>> denied;
};
```

`AcquireInputLease`（`src/server/server.cpp:806-832`）的加锁范围只覆盖“判空位 + 插入”，`SetGeometry` 在锁外调用：

```
806: bool AcquireInputLease() {
807:     if (input_sink_ == nullptr || !config_.enable_desktop_input) return false;
808:     if (input_lease_held_) return true;
809:     if (input_lease_ == nullptr) return false;
810:     bool acquired = false;
811:     {
812:         std::lock_guard<std::mutex> lock(input_lease_->mu);
815:         if (input_lease_->max_sessions == 0 ||
816:             input_lease_->holders.size() < input_lease_->max_sessions) {
817:             input_lease_->holders.insert(input_session_id_);
818:             acquired = true;
819:         }
820:     }
821:     if (!acquired) {
822:         input_lease_->denied->fetch_add(1, std::memory_order_relaxed);
823:         return false;
824:     }
825:     input_lease_held_ = true;
828:     if (inject_geometry_known_) {
829:         input_sink_->SetGeometry(input_session_id_, inject_geometry_);
830:     }
831:     return true;
832: }
```

- `max_sessions == 0`：显式无限，直接插入；`holders` 仍按会话记录并在退出时删除（`3f30939` 提交信息与 `include/rtsc/server/server.h:145-154` 一致）。
- 首事件获取：`AcquireInputLease()` 在慢路径每个事件（`src/server/server.cpp:1863`）和快路径每个事件（`:1991`）调用前置于 `Inject`。
- 拒绝计数：按“事件”计（`fetch_add(1)`），不是按会话；与 `include/rtsc/server/server.h:384-389` 的文档一致。
- 下一事件重试：`input_lease_held_` 保持 false，下一次事件再次进入同一路径；无等待队列（设计如此，`src/server/server.cpp:644-648`）。
- 测试 `tests/test_server.cpp:3428-3521` 专门覆盖“先到先得 → 拒绝并计数 5 次 → 持有者断开 → 幸存者下一事件接手”，并断言 `ReleaseSession` 每会话恰好一次。

### 1.2 ReleaseInput 幂等 + 确实 erase

`src/server/server.cpp:760-772`（与 `git show 3f30939:src/server/server.cpp` 一致）：

```
760: void ReleaseInput() {
761:     if (input_released_) return;
762:     input_released_ = true;
763:     if (!input_lease_held_) return;
764:     input_lease_held_ = false;
765:     {
766:         std::lock_guard<std::mutex> lock(input_lease_->mu);
767:         input_lease_->holders.erase(input_session_id_);
768:     }
769:     if (config_.enable_desktop_input && input_sink_ != nullptr) {
770:         input_sink_->ReleaseSession(input_session_id_);
771:     }
772: }
```

- 幂等守卫在最外层（761-762），重复调用不会再 erase / 再调 sink。
- erase 在 `input_lease_held_` 为 true 时执行（763-768），键是 `input_session_id_`（与本会话插入时一致，817）。
- 两条 teardown 路径都调用且只调用一次：线程路径 `src/server/server.cpp:2332-2335`，`ServeOne` 路径 `:2400`。若 launcher 先跑完 body 再返回 false，body 内已释放，回滚分支只做计数释放（`:2358-2362`），不会二次释放租约。

```
[BASH] RTSC_TEST_FILTER=server_input_lease_one_session_then_handoff rtsc_server_tests.exe
[ RUN  ] server_input_lease_one_session_then_handoff
[  OK  ] server_input_lease_one_session_then_handoff
1 tests, 28 checks, 0 failing tests, 0 failed checks        (exit=0)

[BASH] RTSC_TEST_FILTER=server_input_lease_zero_means_unlimited ...
1 tests, 8 checks, 0 failing tests, 0 failed checks          (exit=0)

[BASH] RTSC_TEST_FILTER=server_input_sink_disabled_by_config ...
1 tests, 8 checks, 0 failing tests, 0 failed checks          (exit=0)
```

### 1.3 附 F2（低）：erase 租约早于 sink 释放，交接窗口可误释放新持有者的键/按钮

`ReleaseInput` 先在 765-768 删除租约，再在 769-771 调 `ReleaseSession` 追加旧会话的合成 up 事件。中间窗口里新会话可获租约并 `Inject` 新的 keydown；worker 之后才派发旧会话的 up（`src/server/desktop_input_win32.cpp:212-234`），可能把新持有者刚按下的同一个键/按钮抬起。影响仅限持有者交接瞬间（默认 max=1 时尤其明显）。建议顺序改为：先 `ReleaseSession`（把 ups 入队并保证顺序）再 erase 租约，或对 `holders` 使用“释放中”状态。**静态推断，未构造并发复现（W5）。**

### 1.4 附 F3（中低）：不可注入事件也能取得/占住唯一租约

`AcquireInputLease()` 对每个解码事件都调用（`src/server/server.cpp:1863`、`:1991`），而 `TranslateInput` 会把这些事件翻译成空集：

- `kSync`（`src/server/desktop_input_map.cpp:99-101`）
- `kMouseRel`（`:99-101`）
- `kMouse` 且既无 move 也无 button（`:59-79`）
- `kKey` 且 `scancode==0`（`:34-38`）
- `kUnicode` 且 `unicode_code==0`（`:49-51`）

于是任何已认证会话只发一个 SYNC/MOUSREL（或 scancode 0 事件）就能拿到唯一租约，并且只要不断开就一直占住；它一个像素也不会注入，真正会操作的另一个会话则被永久拒绝（denied 计数增长）。这是“先到先得 + 无空闲超时”设计的副产物。建议：仅在 `TranslateInput` 非空时才申请/持有租约，或至少对“将产生 0 个平台事件”的事件不参与租约仲裁。**静态推断；现有测试只证明“会注入的会话”的租约行为（tests/test_server.cpp:3428-3563）。**

## 2. 租约与几何 — PASS

全仓 sink 几何调用只有一处，且在“已获租约”分支内：

```
[BASH] Select-String -Path src/server/server.cpp -Pattern "input_sink_->SetGeometry"
829: input_sink_->SetGeometry(input_session_id_, inject_geometry_);

[BASH] Select-String -Path src/server/server.cpp -Pattern "inject_geometry_"
828: if (inject_geometry_known_) {
829:     input_sink_->SetGeometry(input_session_id_, inject_geometry_);
1279:    inject_geometry_ = InjectGeometry{desktop_width_, desktop_height_};
1280:    inject_geometry_known_ = true;
```

协商阶段（`:1274-1280`）只保存本会话几何，**不**通知 sink；非持租会话也从不 `Inject`（`Inject` 两处都在 `AcquireInputLease()` 为 true 的分支内：`:1863-1865`、`:1991-1993`），因此不会在 sink 里建立 `sessions_` 几何记录，也不会误改几何。

测试直接验证：第一次输入后 `DistinctIds(geometry_ids)==1` 且等于租约持有者（`tests/test_server.cpp:3469-3476`）；交接后第二个 id 才出现且每个 id 各一次（`:3504-3511`）。上面 28 项检查全绿。

说明：`DesktopInputSink::SetGeometry` 注释写“and again if it is renegotiated”（`include/rtsc/server/desktop_input.h:57-59`），但本服务器每会话至多下发一次（`AcquireInputLease` 在持租时提前返回，808）。当前无几何重协商路径，故不构成缺陷；若未来支持重激活需补调。

## 3. 并发安全 — PASS

- `holders` 的读写都在 `input_lease_->mu` 内：插入 `src/server/server.cpp:812-819`，删除 `:766-768`；`max_sessions` 为 const（`:656`）。
- `denied` 是 `shared_ptr<atomic<size_t>>`（`:652`、`:657`），写 `:822`（relaxed），读 `:2455-2457`（relaxed）。单调计数器无需更强序；不存在“锁内读非原子字段”的问题。
- 无嵌套锁：`AcquireInputLease` 的租约锁作用域 811-820 在 `SetGeometry`（829）之前结束；`ReleaseInput` 的租约锁作用域 765-768 在 `ReleaseSession`（770）之前结束。sink 的 `mu_`（`src/server/desktop_input_win32.cpp:478`）与租约 `mu` 从不嵌套持有；sink worker 线程不取租约锁，故无环、无锁序反转。
- `input_lease_held_`/`input_released_`/`inject_geometry_*` 都只由本会话线程访问（解析循环与 teardown 同线程），无跨线程数据竞争。

## 4. 队列硬上限 — 五分支一致 PASS；硬上限“绝对性”FAIL（F1）

### 4.1 五个分支与 EnqueueLocked 一致（PASS）

纯策略 `src/server/desktop_input_map.cpp:106-112`：

```
106: EnqueueAction DecideEnqueue(const EnqueueState& state) {
107:     if (state.size < state.soft_limit) return EnqueueAction::kAccept;
108:     if (state.has_movable_move) return EnqueueAction::kEvictMove;
109:     if (state.incoming_is_move) return EnqueueAction::kDrop;
110:     if (state.size >= state.hard_limit) return EnqueueAction::kDrop;
111:     return EnqueueAction::kAccept;
112: }
```

`EnqueueLocked` 用完全相同的状态字段并逐一处理三种动作（`src/server/desktop_input_win32.cpp:178-210`）：`kEvictMove` 删最老 move 后 push（`:199-202`），`kDrop` 计数后 return（`:203-205`），`kAccept` 直接 push（`:206-209`）。常量 `kMaxQueue=256`、`kHardQueueLimit=4*256=1024`（`:59-64`）与 `state.soft_limit/hard_limit`（`:193-194`）一致。判定顺序（先驱逐可牺牲的 move，再丢弃新 move，最后在硬限丢非 move）与注释（`include/rtsc/server/desktop_input_map.h:92-100`）一致。纯策略 5 个测试全绿：

```
[BASH] RTSC_TEST_FILTER=desktop_input_queue rtsc_desktop_input_tests.exe
5 tests, 11 checks, 0 failing tests, 0 failed checks        (exit=0)
```

### 4.2 例外分支：AppendReleases 绕过上限 — 单会话有界，但不是绝对上限（FAIL）

`AppendReleasesLocked` 直接 `queue_.push_back(...)`，不经过 `DecideEnqueue`（`src/server/desktop_input_win32.cpp:212-234`，调用点 `:139`、`:469`）：

```
212: void AppendReleasesLocked(uint32_t session_id,
213:                               const SessionInputState& session) {
...
219:     for (const KeyId& key : session.pressed_keys) {
225:         queue_.push_back({session_id, up});
226:     }
227:     for (const uint8_t button : session.pressed_buttons) {
232:         queue_.push_back({session_id, up});
233:     }
234: }
```

- 单个会话的规模确实有界：`pressed_keys` 是 `set<KeyId>`，`KeyId.scancode` 虽然声明为 `uint16_t`（`:71-78`），但唯一的填充来源 `TrackPressedLocked`（`:158-176`）拿到的是 `TranslateInput` 产物，快/慢路径解码出的 scancode 都是 `uint8_t`（`src/server/server.cpp:1895`、`:1794`），而 0 已在 `desktop_input_map.cpp:38` 丢弃 → 每个会话最多 255×2（extended 与否）+ 5 个按钮 = 515 条。**单会话单次 teardown 不会无界增长。**
- 但“硬上限 1024 是绝对上界”的注释（`src/server/desktop_input_win32.cpp:60-64`）不成立：队列已到 1024 时，一次 `ReleaseSession` 仍可再 push ≤515 条。若 worker 卡在 `SendInput` 且对端反复建立/断开注入过按键的会话，队列按“515 × 已 teardown 会话数”增长，不收敛于 1024。这与“absolute bound / never grow past this”的表述矛盾。**静态推断；未执行（需要真实 SendInput 语义的 worker 阻塞，W5）。**

### 4.3 F1（中）：硬限丢弃 keyup 会永久卡键，且自动释放兜底失效

这是本轮最重要的实现缺陷，链路：

1. `Inject` 先更新按键状态、再入队：`src/server/desktop_input_win32.cpp:117-120`
   ```
   118: TrackPressedLocked(session, input);
   119: EnqueueLocked(session_id, input);
   ```
2. `TrackPressedLocked` 在 keyup 到来时**立即**从 `pressed_keys` 删除：`:160-167`（`if (input.release) session.pressed_keys.erase(key);`）。
3. 若此刻队列 `size >= 1024` 且没有可驱逐 move，`EnqueueLocked` 返回 `kDrop`（`desktop_input_map.cpp:110` → `desktop_input_win32.cpp:203-205`），**keyup 被丢**。
4. 因此该键已经不在 `pressed_keys` 里；teardown 的 `AppendReleasesLocked` 只遍历 `pressed_keys`（`:219-226`），不会再补发 up。

结果：keydown 早已注入并生效，keyup 被硬限丢弃且从账本中抹去 → 本地桌面该键**一直按住**；即使会话随后断开，`ReleaseSession` 也不会释放它（集合已空）。这与提交说明及代码注释的承诺直接冲突：

- `src/server/desktop_input_win32.cpp:20-21`：“A dropped key cannot leave a stuck key because the sink also records what each session holds down and ReleaseSession emits the matching ups.”
- `4eb3344` 提交信息：“A dropped key cannot leave a stuck key…”。
- 该承诺只对“被丢弃的 keydown”成立；对“被丢弃的 keyup”不成立。

最小复现（静态构造，未执行真实注入）：`enable_desktop_input=true`、单会话，在一个 MCS PDU 内连发 >1024 个 scancode 事件（每事件 2 字节，解析远快于 1024 次 `SendInput`）把队列顶到硬限，然后发送某个已注入键的 keyup。该 keyup 命中 `kDrop` 分支，且 `pressed_keys` 已在第 2 步被清空，之后不再有任何 up。

建议修复（择一）：把按键账本更新移到 `EnqueueLocked` **接受之后**（被丢弃的事件不改变账本）；或让 keyup 走类似 `AppendReleasesLocked` 的“释放不丢弃”路径（但需重新论证 4.2 的越界问题）；或在 teardown 时对“曾经注入过 down、但账本已空”的键补发 up（需要额外状态）。现有 `tests/test_desktop_input.cpp` 只测纯策略与 null sink（`:302-321`，null sink 不跟踪按键），Win32 跟踪/丢弃交互没有任何测试覆盖（见 F4）。

## 5. GAP④ 白名单 — 覆盖 PASS；白名单外落入 fast-path 解码 FAIL（已红证）

### 5.1 覆盖完整性（PASS）

枚举共 24 个（`include/rtsc/proto/share.h:28-53`：0x02、0x14、0x1B、0x1C、0x1F、0x21…0x32、0x36、0x37）；`IsKnownShareDataPduType` 的 switch 也恰好 24 个 case（`src/server/server.cpp:551-580`）。脚本集合比较：

```
[BASH] enum_count=24 case_count=24
       missing_in_switch=
       extra_in_switch=
```

`HandleSlowPathPdu` 只有“已定义类型”才置 `*handled=true`（`src/server/server.cpp:1687-1693`），随后 `:1650` 才决定是否把 payload 交给 `HandleInputPdu`。已知类型不会再被二次当作 fast-path，符合 GAP④ 原意；回归测试 `server_fastpath_pdu_resembling_share_header_is_not_swallowed`（`tests/test_server.cpp:2039-2101`）绿：

```
1 tests, 4 checks, 0 failing tests, 0 failed checks         (exit=0)
```

### 5.2 白名单外的慢路径 PDU 会被误当 fast-path 解码（FAIL-风险，已实测）

`:1692` 对**未定义** pduType2 直接 `return true` 且不置 handled，`:1650` 于是把整段 share-data payload 送进 `HandleInputPdu`。`HandleInputPdu` 只用 `(payload[0] & 0x03) == 0` 做 fast-path 预判（`:1872`），而 share-data 头的前两字节是 `total_length`，低 2 位完全由对端控制；`FastPathPdu::parse`（`src/proto/share.cpp:267-282`）只校验长度字段并截取 body，不校验与 share 头的语义关系。结果是：一个 pduType2 未定义的 DATAPDU，只要长度字段凑对，就会按 fast-path 事件流解码。

红证（审计专用探针，放在 `%TEMP%` 副本里临时追加，未提交；跑完已用 `git show` 还原并校验）：

构造 24 字节 payload：`[0]=0x04 [1]=0x18`（total_length=0x1804 → 低 2 位 0，fast-path length=24）、`[2]=0x17 [3]=0x00`（DATA/version 1）、`[4]=0x03 [5]=0x1E`（fast-path body 的第二个事件：scancode code、键 0x1E）、`[14]=0x99`（未定义 pduType2）。发送后断言输入回调收到 `kKey scancode=0x1E`：

```
[BASH] RTSC_TEST_FILTER=audit_probe_undefined_share_type rtsc_server_tests.exe
[ RUN  ] audit_probe_undefined_share_type_becomes_fastpath_input
[  OK  ] audit_probe_undefined_share_type_becomes_fastpath_input
1 tests, 4 checks, 0 failing tests, 0 failed checks          (exit=0)
```

后果：一个**非输入、类型未定义**的 share PDU 能解码出任意幻影输入事件；解码后立即进入 `AcquireInputLease()`/`Inject()`（`src/server/server.cpp:1863-1865`，与真输入同一路径），在 `enable_desktop_input=true` 时会真的注入（本探针未开启 sink，只证明解码/回调；注入为同路径必然结果）。此外该 PDU 还能让第一个解码事件（示例中的 scancode 0）先取得租约。

反向残留：合法 fast-path PDU 若字节 2..3 恰为 0x17/0x00 且 byte14 落在白名单内，仍会被当作 share data 吞掉（现有回归测试特意用了白名单外的 0x17 才没触发，`tests/test_server.cpp:2040-2045`）。真实客户端不会发 scancode 0，故实际影响低；但白名单只是缩小、没有消除碰撞面。

建议：未定义的 share-data 类型按协议错误计数并**丢弃**（不要回落到 fast-path），或让回落路径要求 `payload[0]` 的 fast-path action/count 与 `total_length` 语义一致；同时保留 `/W4 /WX` 下的回归测试覆盖“未定义 type2 + 低 2 位为 0”这一分支。

## 6. `scancode==0` — PASS（附 F3 说明）

`src/server/desktop_input_map.cpp:30-58`：

- `kKey` 分支只在 `ev.scancode == 0` 时返回空（`:34-38`），不触碰 extended/release 之外任何语义；
- `kUnicode` 分支独立检查 `ev.unicode_code == 0`（`:49-51`），与 scancode 零码处理一致（都是“零码不产生平台事件”）；
- 鼠标/滚轮分支不受影响（`:59-92`），`kMouseRel`/`kSync` 仍为空（`:93-101`）。

测试 `desktop_input_zero_scancode_is_not_injected`（`tests/test_desktop_input.cpp:74-88`）覆盖 down/up/extended 三种零码：

```
[BASH] RTSC_TEST_FILTER=desktop_input_zero_scancode rtsc_desktop_input_tests.exe
1 tests, 3 checks, 0 failing tests, 0 failed checks          (exit=0)
```

注意（与 F3 同一机制）：过滤发生在 sink 层，服务器仍在 `Inject` 之前调用 `AcquireInputLease()`，并且仍把该事件交给 `input_callback_`（`src/server/server.cpp:1863-1866`、`:1991-1994`）。即“scancode 0 事件”不会注入，但仍能取得租约并出现在观察回调里。若租约语义是“控制权”，应把零码/空翻译事件排除在仲裁之外。

## 7. 独立变异测试 — PASS（先红后绿 + 哈希双证）

变异源与构建目录严格按要求：`git archive 3f30939` → `%TEMP%\rtsc-mut-a9-src`；构建 `C:\Users\liulilte\rtsc-mutbuild-a9`（不在 %TEMP%）。变异：把租约上限判定 `holders.size() < max_sessions` 改为 `<=`（`max_sessions=1` 时等效“恒收纳”，第二个会话也获准）。

### 7.1 基线（未变异）

```
[BASH] RTSC_TEST_FILTER=server_input_lease_one_session_then_handoff rtsc_server_tests.exe
[ RUN  ] server_input_lease_one_session_then_handoff
[  OK  ] server_input_lease_one_session_then_handoff
1 tests, 28 checks, 0 failing tests, 0 failed checks          (exit=0)
```

### 7.2 变异后必红（原始失败行）

```
[BASH] rtsc_server_tests.exe (mutated: holders.size() <= max_sessions)
  FAIL ...tests/test_server.cpp:3482  WaitUntil( [&server]() { return server.input_lease_denied_count() >= 5; })
  FAIL ...tests/test_server.cpp:3483  server.input_lease_denied_count() == static_cast<size_t>(5) (got 0, want 5)
  FAIL ...tests/test_server.cpp:3484  id == holder (got 2, want 1)
  FAIL ...tests/test_server.cpp:3484  id == holder (got 2, want 1)
  FAIL ...tests/test_server.cpp:3484  id == holder (got 2, want 1)
  FAIL ...tests/test_server.cpp:3484  id == holder (got 2, want 1)
  FAIL ...tests/test_server.cpp:3484  id == holder (got 2, want 1)
[ FAIL ] server_input_lease_one_session_then_handoff
1 tests, 33 checks, 1 failing tests, 7 failed checks          (exit=1)
```

变异文件 SHA256：`DFA3D4BEC9E3D098F1D18804C527CA61D324CEE6E844B0A10E6B56643FE40268`（与基线不同）。

### 7.3 恢复后必绿 + 哈希双证

用 `git show 3f30939:src/server/server.cpp > <temp>` 逐字节还原（cmd 重定向，避免 PowerShell 文本重编码），然后：

```
[BASH] git hash-object %TEMP%\rtsc-mut-a9-src\src\server\server.cpp
       8de773e2a02539c06476f8eae86258ce6a0924e3
[BASH] git rev-parse 3f30939:src/server/server.cpp
       8de773e2a02539c06476f8eae86258ce6a0924e3      <- 与提交 blob 完全一致
[BASH] git hash-object F:\rtsc\src\server\server.cpp
       8de773e2a02539c06476f8eae86258ce6a0924e3      <- 与仓库工作树一致
[恢复文件 SHA256] 4966F2434A942AA2A5292F7B97A376C3B46914AB16E938AEBE2A8ACF0544035E
[仓库文件 SHA256] DE4C23085E8029ECFE5802FDBE9E32CD83BC5E2DF2CAD3CBC0E85DE004DBB535
```

（两份 SHA256 的差异只是 `%TEMP%` 副本为 LF、仓库检出为 CRLF；`git hash-object` 三者相同才是内容证据。）

恢复后重建并重跑：

```
[BASH] cmake --build C:\Users\liulilte\rtsc-mutbuild-a9 --target rtsc_server_tests
[1/3] Building CXX object CMakeFiles\rtsc_server.dir\src\server\server.cpp.obj
[2/3] Linking CXX static library rtsc_server.lib
[3/3] Linking CXX executable rtsc_server_tests.exe
[BASH] RTSC_TEST_FILTER=server_input_lease_one_session_then_handoff rtsc_server_tests.exe
[  OK  ] server_input_lease_one_session_then_handoff
1 tests, 28 checks, 0 failing tests, 0 failed checks          (exit=0)
```

审计探针 `tests/test_server.cpp` 改动也已还原并以 `git hash-object` 验证：`ea15ff16a804303524124598672b500531d252ed` == `git rev-parse 3f30939:tests/test_server.cpp`。

## 8. 其他交付项（4eb3344）旁证

| 项 | 证据 | 结论 |
|----|------|------|
| 慢路径 MOUSEREL | `src/server/server.cpp:1826-1853`（有符号 i16、X1/X2 回退、kind=kMouseRel）与快路径 `:1936-1968` 语义一致；测试 `server_decodes_slowpath_mouse_relative`（`tests/test_server.cpp:1787`）绿：`1 tests, 9 checks` | PASS |
| `malformed_input_pdu_count` | 短头/截断事件/计数越过 PDU：`src/server/server.cpp:1751-1775`；计数器 `:2451-2453`；测试 `server_slowpath_event_count_mismatch_is_counted` 绿（`1 tests, 7 checks`） | PASS；小注：payload 比 count 长的“尾部多余”不算 malformed（`:1763` 循环只按 count 走） |
| `Stats()` | 接口 `include/rtsc/server/desktop_input.h:36-47`；实现 `src/server/desktop_input_win32.cpp:145-154`；计数点 `:428-441`（成功/失败）与 `:199-205`（丢弃/驱逐） | PASS；`dropped_queue_full` 同时统计“被驱逐的 move”，名字略宽 |
| `ReleaseSession` 清 `last_move_sent_` | 请求入 `forget_moves_`（`:133`），worker 在派发前于锁内 erase（`:244`、`:271-275`） | PASS；注释 `:488` “never touched under mu_” 已过时（`ForgetReleasedMovesLocked` 在 mu_ 下删 `last_move_sent_`），仅文档问题 |
| `SetInputSink` 时序注释 | `include/rtsc/server/server.h:302-313` 明确 must-before-Start + borrowed pointer；实现只存指针 `src/server/server.cpp:2171`，会话启动时快照传入（`:2257`、`:2385`） | PASS |

## 9. 未验证 / 限制（W5）

- F1（硬限丢 keyup 卡键）、F2（交接误释放）、4.2 的“worker 阻塞 + 连续会话”越界均为**静态推断**：Win32 sink 会真实调用 `SendInput`，审计不向本机桌面注入，故未做运行时复现。Win32 跟踪/入队交互目前也无任何自动化测试（F4）。
- “白名单外类型 → 幻影输入”已用临时探针在真实服务器路径上实测（回调收到 0x1E）；“会真的注入”依赖 `enable_desktop_input=true` + sink，走的是同一 `Acquire/Inject` 代码，未开启真实 sink 验证。
- 未跑全量 ctest（审查未改仓库代码；按影响范围只跑了租约、队列策略、零码、慢路径/白名单相关用例）。若执行 AI 采纳 F1/F2 的修复，受影响套件至少应包括：`rtsc_server_tests`、`rtsc_desktop_input_tests`，并新增 Win32 入队/跟踪的可测试单元（F4）。

## 10. 给执行 AI 的最小修复建议（按优先级）

1. **F1（必修）**：让按键账本只在事件真正进入队列后更新；或让 keyup 永不因硬限被丢弃（并重新设计上限语义）。补“队列满 + keyup”的单元测试（把 Win32 跟踪逻辑抽成平台无关可测层）。
2. **F1/4.2（必修或明确文档）**：`AppendReleasesLocked` 的越界如果保留，必须把“绝对上界”改成“硬限 + 每 teardown 会话 ≤515 的软越界”，并限制在途 teardown 数量；否则把释放事件也纳入上限（但要同时保证 keyup 不丢）。
3. **GAP④（建议）**：未定义 pduType2 的 share-data PDU 不应回落到 fast-path；按协议错误计数并丢弃。补“未定义 type2 + 低 2 位为 0”的回归测试。
4. **F2（建议）**：`ReleaseInput` 先释放 sink 再 erase 租约（或引入“释放中”状态），避免交接误释放。
5. **F3（建议）**：只有会产生平台事件的事件才参与租约仲裁，或将租约获取延后到 `TranslateInput` 非空之后。
6. **F5（可选）**：更新 `src/server/desktop_input_win32.cpp:488` 的过时注释。