# 滚轮修复 `042687f` 独立复核（审计 A）

范围：`git show 042687f`（HEAD 即该提交）。只读复核 + `%TEMP%` 沙箱变异；**未改仓库 src/include/tests**。
沙箱：`C:\Users\liulilte\AppData\Local\Temp\opencode\wheelA`（`git archive` 不可用→逐文件 `git show 042687f:<path>` 写入，SHA 校验）。
构建：`cmake --build build --config Release --target rtsc_server_tests`，0 error C / 0 warning C。

## 1. 客户端编码 `src/client/client.cpp:239-262` — **PASS**

实现：`scaled = wheel_delta(notch) * 120` → clamp ±255（保号）→ `flags = (horizontal?0x0400:0x0200) | (units & 0x01FF)`，
**未单独 OR `kPtrWheelNegative`**（该位是 9 位字段的符号位）。

纸面核算（自算，非抄实现）：
```
[BASH: notches=-1  -> units=-120 -> flags=0x0388]   (-120 & 0x1FF = 0x188)
[BASH: notches= 1  -> units= 120 -> flags=0x0278]
[BASH: notches= 2  -> units= 240 -> flags=0x02F0]
[BASH: notches=-120-> units=-255 -> flags=0x0301]   (-255 & 0x1FF = 0x101)
[BASH: notches=120 -> units= 255 -> flags=0x02FF]
[BASH: notches= 1  -> hwheel     -> flags=0x0478]
```
六锚点与题目要求**逐位一致**。`int` 中间量：`int16_t(-32768)*120 = -3,932,160`，不溢出（无 UB）。

## 2. 服务端解码 `src/server/server.cpp:1571-1586` — **PASS**

`WHEEL|HWHEEL` 均进 kWheel 分支；`vertical = (pf & kPtrWheel)`，`horizontal = !vertical`（双置位时 WHEEL 优先，
符合 [MS-RDPBCGR] "PTRFLAGS_WHEEL takes precedence"）；`raw = pf & 0x01FF`；
`delta = (raw & 0x0100) ? raw - 0x0200 : raw`（9 位符号扩展）；**不再二次取负、不再乘除 120**。
纸面解码：`0x188→-120, 0x078→120, 0x0F0→240, 0x101→-255, 0x0FF→255, 0x000→0`；`0x0600`（双置位）→ vertical=true, raw=0 → delta 0 ✓。

## 3. 断言是否"测试固化" — **PASS（附保留）**

- `tests/test_client.cpp:149-212`：期望字节取自规范位布局（注释给出 `0x0200 | (0xFF88 & 0x01FF) = 0x0388` 的推导），
  与我独立核算一致 → **非固化**。
- `tests/test_server.cpp:709-772`：喂入 `0x0388/0x0478/0x0301/0x02FF/0x0600`，断言 `-120/120/-255/255/0` 与
  `horizontal` 布尔，是**语义断言**而非实现自证；14 checks。
- 保留：两侧同源（同一作者同一约定）无法独立证明"9 位二补码"是真实对端约定；唯一外部证据是提交注释引用的
  FreeRDP PR #6806（136 vs 120 的故障描述与 9 位二补码一致）。**建议**补一次抓包/mstsc 对照（UNVERIFIED）。

## 4. M2 变异独立复现 — **PASS（转红成功）**

沙箱内把 `server.cpp:1585` 的 `raw - 0x0200 : raw` 改为 `raw : raw`（等价 `(int16_t)raw`）：
```
mutant_sha=3AB8FAE62D8E2E12CDB4FC75DCA0EEEA922921C4731E23482E92649604C06DDC
sha_before_build == sha_after_build（防旧 exe 假绿）
  FAIL ...tests/test_server.cpp:761  wheels[0].wheel_delta == static_cast<int16_t>(-120) (got 392, want -120)
  FAIL ...tests/test_server.cpp:765  wheels[2].wheel_delta == static_cast<int16_t>(-255) (got 257, want -255)
[ FAIL ] server_decodes_wheel_rotation_in_wire_units
1 tests, 14 checks, 1 failing tests, 2 failed checks   (exit=1)
```
与主代理报告"server 1 failing/2 checks"**一致**。还原后：
```
restored_sha=F60ABC3BC8DE3209EF61B8E1A9524E5CB723BC294465C719BDEF389296146DBE
expected_baseline_sha=F60ABC…146DBE  (相等)
[ OK  ] server_decodes_wheel_rotation_in_wire_units
1 tests, 14 checks, 0 failing tests, 0 failed checks   (exit=0)
```
（首次尝试因替换串拼成 `raw :: M2` 编译失败、测试跑的是旧 exe 而假绿——**已作废**，不采信；上面是修正后的证据。）

## 5. 边界漏洞（新发现）

| # | 级别 | 问题 | 证据 |
|---|---|---|---|
| N1 | **中** | 单事件幅度被**静默截断**：clamp ±255 units = ±2.125 notch；3 格滚轮（360 units）只滚 2.125 格。应改为**拆分为多个 ≤255 的 wheel 事件**或跨事件累计余量 | 纸面：`3*120=360 → 255`；`src/client/client.cpp:248-255` |
| N2 | 低 | 注释称"9 位二补码对称范围 -255..+255"，实际 9 位范围是 **-256..+255**（`0x100` = -256），clamp 少用 1 个码位 | `src/client/client.cpp:26-28`；解码 `0x100→-256` |
| N3 | 低 | HWHEEL 被执行 gating（服务器未广告即 `return {}`）时**无计数/无日志**，上层 `SendPdu` 对空 PDU 返回 true → 观测不到丢事件 | `src/client/client.cpp:230`、`SendPdu` 空返回 true |
| N4 | **中** | 服务端对 wheel 事件**仍继续处理 `PTRFLAGS_DOWN`/按钮位**：畸形 `WHEEL|DOWN|BUTTON1` 会产出 `kind=kWheel` 且 `button=1,button_down=true`；规范要求 wheel 事件"all other pointer flags are ignored" | `src/server/server.cpp:1587-1603` |
| N5 | 低 | wheel 事件仍解析 xPos/yPos 到 `ev.x/ev.y`（规范 SHOULD ignore）；注入层必须忽略，否则横向滚轮会带陈旧坐标 | `src/server/server.cpp:1567-1569` |
| N6 | 低 | 测试缺口：无**负向 HWHEEL**（`0x0588`）、无 `0x0300`(-256)、无 `INT16_MIN` 输入、无 3 格截断用例 | `tests/test_server.cpp:748-771`；`tests/test_client.cpp:149-212` |

## 结论

第 1/2/3/4 项 **PASS**（M2 已独立转红并还原哈希一致）；第 5 项发现 **6 个边界问题**，其中
**N1（幅度截断）与 N4（wheel 仍解析按钮位）建议本批或下一批修复**；N2/N3/N5/N6 为文档/观测/覆盖补强。
真机/对端对照（mstsc 抓包验证 9 位二补码）仍为 **UNVERIFIED**。

---

# 返工复核（批 1 + A/B/C/D）

坐标系：**沙箱** `C:\Users\liulilte\AppData\Local\Temp\opencode\wheelA`（工作树文件的逐字节副本，`Get-FileHash` 双证相等后才构建）。
仓库 `src/include/tests` **本次未改**。

## R0 方法与一个必须记下的坑（增量构建假绿/假红）

- `Copy-Item` **保留源文件 mtime**，MSBuild 因 `obj(旧) > src(旧)` 跳过重编 → 跑的是**旧 exe**。
  实测症状：新用例名返回 `0 tests, 0 checks`（测试列表根本没有新用例），旧用例返回莫名 FAIL。
- 处置：复制后强制 `(Get-Item $p).LastWriteTime = Get-Date`，并（首次）删除 `server.obj`/`test_server.obj`。
  之后每次变异均校验 `sha_before_build == sha_after_build` 且 `obj_mtime > src_mtime`。
- 这条对甲/乙/执行 AI 同样适用：`git show` 或 `Copy-Item` 落盘后不 touch 文件，任何"变绿"都不可信。

## R1 三个关键判定的变异测试（全部转红，恢复后转绿）

基线（批 1 未含 A/B 返工时的快照）：
```
server.cpp sha256 = 7BA3C8C134052CD4B50DCD2829D00C938B9B6FBD4EC8CC633CBEF11B94A631D2
rtsc_server_tests.exe  34 tests, 330 checks, 0 failing tests, 0 failed checks   (exit=0)
```

| # | 变异（改坏被测的关键判定） | 变异体 sha256 | 失败原文（沙箱行号） | 结果 |
|---|---|---|---|---|
| M-A1 | 按钮身份解码退回 `PTRFLAGS_DOWN` 分支内（释放丢失按钮号） | `E167266D…15653C` | `test_server.cpp:712 seen.x1_up` / `:713 seen.x2_up` / `:714 !seen.release_lost_button` | 1 failing / 3 failed checks，exit=1 |
| M-A2 | QoE 分支 `continue` → `break`（幻影 kKey 事件） | `F5ED7558…944D190` | `:767 got.size()==1 (got 2, want 1)`；连带 `:872 got.size()==2 (got 3)` | 两用例各 1 failing，exit=1 |
| M-A3 | `kMouseRel` 退回旧行为（只 `pos += 6; break;`，不设 kind） | `0D9048E5…091448` | `:818 kind==kMouseRel` / `:819 rel_x (got 0)` / `:820 rel_y (got 0)` / `:821 is_move`；连带 `:874/:875/:876` | 1 failing / 4 failed checks + 3 failed checks，exit=1 |

每次变异均 `sha_before_build == sha_after_build`（防旧 exe），且**非目标用例保持绿**（M-A1 下 wheel/QoE/rel 三例全绿，证明不是全局崩坏导致的假红）。
恢复后：`restored_sha = 7BA3C8C1…A631D2`（与原基线相等），套件回到 `34 tests, 330 checks, 0 failing`。

结论：三条用例**真会咬人**，不是固化式假测试。

## R2 A/B/C/D 返工状态：**未完成，当前快照是红的**（阻断）

返工进行中，工作树 `server.cpp` 在 3 分钟内出现 4 个不同 sha256（`2E4AEEFD…76ABCC` → `27CF4F3E…AD846A`
→ `19309376…D146F`），说明执行 AI 正在连续改写。已抓到的两个**不可交付**快照：

- `2E4AEEFD…`（1:14:35）：`if (wheel) { … ev.x = 0; ev.y = 0; }` 后紧跟无条件 `ev.x = x_pos; ev.y = y_pos;`
  → **D 死存储**；且 `DecodePointerButtons` 在分支外无条件调用 → **C 未生效**。
  实测 `34 tests, 350 checks, 1 failing, 14 failed checks`（`:1174/:1175` 各 6 条 + `:1179/:1180`）。
- `19309376…`（1:16 同步）：坐标已修（`ev.x=0; ev.y=0;` 后 `break;` 收口，D 生效），
  但 wheel 分支内**仍有** `[READ:src/server/server.cpp:1623] DecodePointerButtons(pf, false, ev);` → **违反裁决 C**。
  实测：``FAIL :1179 wheels[5].button==0 (got 1, want 0)`` / ``FAIL :1180 !wheels[5].button_down``，
  `34 tests, 350 checks, 1 failing, 2 failed checks`（exit=1）。

```diff
@@ 19309376…  wheel 分支
                         ev.x = 0;
                         ev.y = 0;
+                        DecodePointerButtons(pf, false, ev);   ← 裁决 C 要求删除
                         break;
```

这组红同时就是 **C 的反向变异红证**：把解码调用放回 wheel 分支 → `:1179/:1180` 立即转红；
同理 `2E4AEEFD…` 的 `:1174/:1175` 是 **D 的反向变异红证**（去掉清零 → 坐标 1/2/3/4/5/123/456 原样透出）。
但**红基线不能作为验收**，需等执行 AI 把 C 收口后复测到 `0 failing`。

A 已落地：`[READ:src/server/server.cpp:1643-1662]` 无 `ev.is_move = true`，只 `DecodePointerButtons(pf, false, ev)`；
对应断言 `[READ:tests/test_server.cpp:834]`（`!is_move`）、`[READ:tests/test_server.cpp:835-836]`（`x==y==0`）。
B（PTRXFLAGS 回退）**不该删**——见 R4，规范原文推翻该裁决。

## R2b A/B/C/D 反向变异（最终基线 `27CF4F3E…EAD846A`，全部转红）

沙箱基线：`27CF4F3E24B50140CFC10E9A82DFBCCB1C1A5ACF4A2A423994E24EBC9EAD846A`
→ `34 tests, 350 checks, 0 failing tests, 0 failed checks`（exit=0）。

| # | 反向变异（恢复旧行为） | 变异体 sha256 | 失败原文 |
|---|---|---|---|
| A | kMouseRel 内加回 `ev.is_move = true;` | `F8328B1E…7D11A21` | `:834 !got[0].is_move` / `:844 !got[1].is_move`，1 failing/2 failed |
| B | 加回 PTRXFLAGS 回退（`0x0002 → X2`） | `3210FAB0…31C52134` | `:842 got[1].button==0 (got 5, want 0)`，1 failing/1 failed —— **这是"假红"：转红只因测试本身写错了期望**，见 R4 |
| C | wheel 分支内加回 `DecodePointerButtons(pf, false, ev);` | `19309376…A07D146F` | `:1179 button==0 (got 1)` / `:1180 !button_down`，1 failing/2 failed |
| D | 删掉 wheel 分支的早退 `break;`（保留清零 = 死存储） | `2E4AEEFD…ADF76ABCC` | `:1174`×6 / `:1175`×6（1,2,3,4,5,123 / 1,2,3,4,5,456）+ `:1179/:1180`，14 failed |

**等价变异（必须记下）**：只删 `ev.x = 0; ev.y = 0;`、保留 `break;` → sha `2D0A0842…38E9E59`
→ **仍然全绿**（`1 tests, 28 checks, 0 failing`）。因为 `break` 已把事件截在赋值之前，清零本身是冗余防御；
**C 与 D 的真正承重行是 wheel 分支里的那一句早退 `break;`**。将来任何人把它改成 fallthrough，
C/D 两个缺陷会同时复活（本次 D 变异 14 条红即证据）。清零保留作为"改动 break 也能兜住一半"的纵深防御，可接受。

每条均 `sha_before_build == sha_after_build`，恢复后回到 `27CF4F3E…` 并复跑全绿。

> **但 B 这一行不能算"变异被咬住"**：它转红是因为测试把 `0x0002 → button==0` 当成期望，而这个期望本身违反规范
> （R4）。这正是第 16 条要防的镜像情况——**实现正确、测试错误**时，"变异"同样会红，却毫无保护价值。

## R3 结论与残留风险

1. **A/C/D 三项已落地并被反向变异咬住**（R2b 的 A/C/D 三条红 + 一条等价变异），基线 `27CF4F3E…` 在沙箱为
   `34 tests, 350 checks, 0 failing tests, 0 failed checks`（exit=0）。裁决 C/D 的实现方式与主代理要求一致：
   wheel 分支 `if (wheel) { …; ev.x = 0; ev.y = 0; break; }`，其后才是不带 wheel 门控的普通鼠标解码。
   **B 为反向结论**：回退必须恢复，见 R4（本批若按原裁决提交，相对模式侧键会静默失效）。
2. **工作树在返工期间被原地变异过（2026-11-01 01:26:59，现已还原）**：该时刻 `F:\rtsc\src\server\server.cpp`
   sha256 = `E58C1E46…A4404F5`，与沙箱基线 `27CF4F3E…` 的差异**只有一行**
   （`[BASH: git diff --no-index <sandbox>/src/server/server.cpp F:\rtsc\src\server\server.cpp]` →
   `+ ev.is_move = true;`，插在 `ev.kind = kMouseRel;` 之后）；01:28:32 复读已回到 `27CF4F3E…`，属验证中间态。
3. 方法学：任何在仓库工作树内做变异（哪怕计划还原）都会与多代理共享工作树冲突——该中间态与我早前误留的
   `// M2` 是同一类事故。变异必须在 `%TEMP%` 副本内做，且 `Copy-Item` 后要 touch。

## R4 **裁决 B 被规范原文推翻：PTRXFLAGS 回退必须恢复**（我上一轮判断有误，纠正）

我在批 1 复核里把 B 报为"疑似与 2.2.8.1.2.2.7 的 PTRFLAGS 命名空间矛盾"，主代理据此裁决"删除回退"。
**这条判断是错的**，现在用规范原文推翻：

- `[WEB:https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/9af47964-8bfc-4f43-8a15-4339a89833fa]`
  （2.2.8.1.1.3.1.1.7 `TS_RELPOINTER_EVENT`）pointerFlags 表**明确列出**：
  > `PTRXFLAGS_BUTTON1 0x0001` Extended mouse button 1 (also referred to as button 4) was pressed or released…
  > `PTRXFLAGS_BUTTON2 0x0002` Extended mouse button 2 (also referred to as button 5) was pressed or released…
- `[WEB:https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/3b4ee59e-6049-45a9-9fcb-2e308defa3eb]`
  （2.2.8.1.2.2.7 `TS_FP_RELPOINTER_EVENT`）：
  > pointerFlags … **The possible flags are identical to those found in the pointerFlags field of the TS_RELPOINTER_EVENT structure.**

即 fast-path 相对事件的 pointerFlags **就是**慢路径 `TS_RELPOINTER_EVENT` 的那一套，含 `0x0001/0x0002` 的 X1/X2。
`PTRXFLAGS_DOWN` 是 `0x8000`（与 `PTRFLAGS_DOWN` 同值），所以 `button_down` 解码不受影响；
`0x0001/0x0002` 在 PTRFLAGS 命名空间里未定义，不存在二义性。

**后果**：删除回退是**功能回归**——相对模式下的 X1/X2 按下/释放会被解码成 `button == 0`（seam 侧丢掉侧键）。
更严重的是本批把错误行为**固化成断言**：`[READ:tests/test_server.cpp:820-823]`
`EncodeRelativeMouseEvent(0x0002, 0, 0)` → 期望 `button == 0`，注释还写着"0x0002 is an undefined PTRFLAGS bit"——
按规范应为 `button == 5`。这是本轮唯一的**固化式错误测试**（第 16 条意义上的反向：改坏实现它反而绿）。

**返工要求（阻断交付）**：
1. `src/server/server.cpp` 的 `kMouseRel` 分支恢复 X1/X2 解码：
   `DecodePointerButtons(pf, false, ev);` 之后，若 `ev.button == 0`：
   `if (pf & kPtrXButton2) ev.button = 5; else if (pf & kPtrXButton1) ev.button = 4;`
   （`kPtrXButton1/2` = 0x0001/0x0002，两者互斥且与 wheel 位不重叠）。
2. 测试改为：`0x0001 → button==4`、`0x0002 → button==5`；补 `0x8002 → button==5 && button_down`、
   `0x0002` 单独 → `button==5 && !button_down`（释放语义）。
3. 注释与 `docs/spec/share-data.md:805` 对齐（该本地笔记本来就是对的，无需改文档）。

**我的方法论失误**：我拿"TS_FP_POINTERX_EVENT 用 PTRXFLAGS、TS_FP_POINTER_EVENT 用 PTRFLAGS"的类比去推断相对事件，
没有查 2.2.8.1.2.2.7 的 cross-reference 原文。后续凡涉及"命名空间/可用取值"的论断，一律先抓原文再下结论。
（同时确认 A 仍成立：`PTRFLAGS_MOVE` 在相对事件里语义是"按 delta 移动"，与绝对 `(x,y)` 无关，
保持 `is_move == false` + `rel_x/rel_y` 是对的。）

## R5 修复方案的沙箱预验证（先绿→变异红→复绿，可直接复制）

仓库 `e0bee4b` 已含错误 B，工作树 `server.cpp` sha = `27CF4F3E…EAD846A`（= 该提交内容）。
我在 `%TEMP%` 副本上把修复**完整实现并验证**，供修复提交直接采用（未改仓库任何 src/include/tests）：

**实现（`kMouseRel` 分支，副本 `src/server/server.cpp:1660-1664`）**
```cpp
DecodePointerButtons(pf, false, ev);
if (ev.button == 0) {
    if ((pf & proto::kPtrXButton2) != 0) ev.button = 5;
    else if ((pf & proto::kPtrXButton1) != 0) ev.button = 4;
}
pos += 6;
```
`if (ev.button == 0)` 保证不与 PTRFLAGS 的 BUTTON1/2/3（0x1000/0x2000/0x4000）抢优先级；
0x0001/0x0002 与 wheel 的 `WheelRotationMask (0x01FF)` 位重叠，但相对事件不带 WHEEL/HWHEEL 位，
畸形 `0x0201` 会被当成 X1（风险低，已在 N6 类覆盖缺口内，可后续补一条）。

**测试（副本 `tests/test_server.cpp`，用例扩展为 5 个相对事件）**
- `kPtrMove,10,-5` → `rel_x=10/rel_y=-5`、`!is_move`、`x==y==0`、`button==0`
- `0x0001` → `button==4 && !button_down`
- `0x0002` → `button==5 && !button_down`
- `0x8002` → `button==5 && button_down`
- `0x8001` → `button==4 && button_down`
- 四个相对事件均断言 `!is_move`

**验证链（全部 `sha_before_build == sha_after_build`）**
```
修复版 sha=3210FAB08739E72701881FF95DCCC0661FA45D549AF40C9C7EC7E00431C52134
34 tests, 358 checks, 0 failing tests, 0 failed checks   (exit=0)

反向变异 = 再次删除该回退（等价于仓库 e0bee4b 现状）
  变异体 sha=27CF4F3E24B50140CFC10E9A82DFBCCB1C1A5ACF4A2A423994E24EBC9EAD846A  ← 与 HEAD 内容完全相同
  FAIL tests/test_server.cpp:848  got[1].button == 4 (got 0, want 4)
  FAIL tests/test_server.cpp:850  got[2].button == 5 (got 0, want 5)
  FAIL tests/test_server.cpp:852  got[3].button == 5 (got 0, want 5)
  FAIL tests/test_server.cpp:854  got[4].button == 4 (got 0, want 4)
  1 tests, 24 checks, 1 failing tests, 4 failed checks   (exit=1)

恢复修复版 → sha 回到 3210FAB0…，34 tests, 358 checks, 0 failing   (exit=0)
```
**这条变异体 sha 恰好等于仓库 HEAD 的 `server.cpp`**，即"现在的提交代码"就是"被变异体"，缺陷被证实为真。

**同一变异体下其余用例仍全绿**（只有该用例 4 条红），说明断言定位精确、不是全局崩坏的假红。
A/C/D 的断言（`!is_move`、wheel 的 `button==0`、wheel 坐标 `x==y==0`）在该修复版里同时为绿，
即 R5 修复与 A/C/D 裁决**互不冲突**，可一并落地。

## R6 执行 AI 落地版复核（`src=67A4ABAD…B92456`，A/B/C/D 四条变异全部复咬）

工作树已由修复执行 AI 改写。我用 `Get-FileHash` 双证后同步到沙箱复跑：

```
src/server/server.cpp  sha256 = 67A4ABADA61C1689A5D9CABAD9D720D0D2CC3A8CF72E71A2E8C971AA1DB92456
（= 工作树；沙箱副本同值）build: warning C = 0, error C = 0
快照 A（tests 2B53BDCE…）：34 tests, 364 checks, 0 failing tests, 0 failed checks
```
实现（`[READ:src/server/server.cpp:1660-1664]`）与 R5 提议一致：`DecodePointerButtons` 后
`if (ev.button == 0) { X2→5 / X1→4 }`。测试（`[READ:tests/test_server.cpp:873-876]`）四条相对事件
`0x0001 / 0x0002 / 0x8002 / 0x8001`，断言 `4/5/5&&down/4&&down` 且均 `!is_move`、`x==y==0`。

**四条反向变异（同一 src `67A4ABAD…`，全部转红、恢复后转绿）**

| # | 变异 | 变异体 sha256 | 失败原文 |
|---|---|---|---|
| A | 相对分支加回 `ev.is_move = true;` | `74BAE7C5…CC3B28C` | `:848/:859/:867/:875 !got[i].is_move`（4 failed） |
| B | 删除 X1/X2 回退 | `7907A949…F074CC42` | `:852/:857/:865/:873 button (got 0, want 4/5/5/4)`（4 failed） |
| C | wheel 分支内加回 `DecodePointerButtons` | `0FE1A320…31450E19` | `:1212 wheels[5].button==0 (got 1)` / `:1213 !button_down` |
| D | 删除 wheel 分支早退 `break;` | `00C9BD9A…24B35BE4` | `:1207`×6 / `:1208`×6（1..5,123 / 1..5,456）= 14 failed |

每条均 `sha_before_build == sha_after_build`；B 的变异体等价于上一提交 `e0bee4b` 的代码，红证成立。

**遗留覆盖缺口（低优先）**：相对事件用例里**没有**"纯移动、无按钮位 → `button == 0`"的断言
（第一个事件 `0x0001` 已带按钮位，`[READ:tests/test_server.cpp:873]`）。建议补一条
`EncodeRelativeMouseEvent(kPtrMove, 3, -4)` → `button==0 && !button_down`，否则"回退把 0 误判成按钮"这类
新缺陷不会被发现（当前回退只在 `button == 0` 时生效，逻辑上安全，但缺回归护栏）。

**同时观察（非本单范围，仅报告）**：2:00:52 的工作树 `tests/test_server.cpp` 已扩到 40 tests，新增
slow-path 解码用例（`server_decodes_slowpath_*`、`server_slowpath_malformed_input_is_survivable`、
`server_advertises_fastpath_input_capability`）当前为 **6 failing / 8 failed checks**（401 checks 总计），
其中 `server_input_relative_mouse_keeps_signed_deltas` 等 5 个滚轮/输入用例仍全绿。
该 6 条红属"实现未跟上"的中间态，**不可作为提交基线**；与本复核结论无关。

## §10b3b20 复核（只读；提交内容以 `git show 10b3b20:<path>` 为准）

1. **PASS** 能力集：`[BASH: git show 10b3b20:include/rtsc/proto/capabilities.h]` `:245` 0x0008、`:253` 0x0020、
   `:262-264` 默认 `input_flags = 0x0001|0x0008|0x0020|0x0004|0x0010|0x0100 = 0x013D`；`:240` 仅保留 `kInputFlagMouse=0x0002`
   且注明"不得广告"（被 `tests/test_capabilities.cpp:356-358` 引用，不能删）。
2. **PASS** 慢路径取值：`[BASH: git show 10b3b20:include/rtsc/proto/share.h]` `:176-182` = `0x0000/0x0002/0x0004/0x0005/0x8001/0x8002/0x8004`；
   `:190` `kSlowPathInputEventSize = 12`（头 6 + 体 6）。与 [WEB:ms-rdpbcgr/a9a26b3d] 表逐值一致 → 旧任务书的 0..4/4B 作废，实现正确。
3. **PASS** 无第二套语义：`[BASH: git show 10b3b20:src/server/server.cpp]` 慢路径 wheel 在 `:1667` 调 `DecodePointerEvent`，
   其 9 位符号扩展在 `:573-582`（`0x0100` 为符号位、`raw-0x0200`）；fast-path 同函数（`:1755`），`is_move/horizontal` 同结构体。
4. **PASS（实测）** 基线：`C:\Users\liulilte\rtsc-mutbuild-a2`（源 `...\rtsc-mutsrc-a2`，`git archive 10b3b20`）构建 `0 warning C / 0 error C`；
   server `40 tests/433 checks/0 failing`、capabilities `42/315/0`、client `21/127/0`、gui_send `2/38/0`。
5. **PASS（变异）** M1 去 `0x0020` → `FAIL tests/test_server.cpp:643 (r.input_flags & 0x0020) != 0`（1 failing/1 check）；
   恢复（touch 后重编）→ `1 tests/9 checks/0 failing`。M2 `kWheelStep 255→120` → `FAIL test_client.cpp:235/237/251/252`
   （`got 3, want 2`）；恢复 → `21 tests/127 checks/0 failing`。
6. **GAP-1（低）** 客户端切块上限 `8*255=2040 units`，对 >17 格的 delta 会**静默丢弃**余量，但 `[READ:src/client/client.cpp:269]`
   注释称"nothing silently clamped away"——注释与行为不符，且无丢弃计数器（对比 HWHEEL 有 `dropped_hwheel_count_`）。
7. **GAP-2（低）** 慢路径 `numberEvents` 与实际长度不符时直接 `return`（`[READ:src/server/server.cpp:1621-1626]`），
   **不计数**；而未知 messageType 会计数。建议截断路径也 `fetch_add`，否则捕获侧看不到畸形 slow-path。
8. **GAP-3（低）** 慢路径 MOUSEREL 被记入 `unknown_input_event_count`（`:1682-1686`）——它是**已知**类型，
   语义上污染"未知 eventCode"指标；建议单列 `undecoded_slowpath_relative_count` 或直接解码。
9. **GAP-4（低）** `was_share_data` 依赖 `ShareDataHeader::parse` 的 version/type 校验；畸形 fast-path PDU 若
   byte2=0x17、byte3=0x00 且长度≥18，会被误判为 share data 而**吞掉 fast-path 事件**（概率低，需畸形包）。建议只对
   已知 `pdu_type2`（refresh/suppress/input）置 handled。
10. **UNVERIFIED** `0x0080 MOUSE_RELATIVE` 未广告时真实 mstsc 的慢路径/相对模式行为（无真机抓包）。
