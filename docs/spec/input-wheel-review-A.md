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

A/B 已落地：`[READ:src/server/server.cpp:1643-1662]` 无 `ev.is_move = true`、无 PTRXFLAGS 回退，
只 `DecodePointerButtons(pf, false, ev)`；对应断言 `[READ:tests/test_server.cpp:834]`（`!is_move`）、
`[READ:tests/test_server.cpp:841-844]`（`0x0002 → button==0`、`!is_move`）。

## R2b A/B/C/D 反向变异（最终基线 `27CF4F3E…EAD846A`，全部转红）

沙箱基线：`27CF4F3E24B50140CFC10E9A82DFBCCB1C1A5ACF4A2A423994E24EBC9EAD846A`
→ `34 tests, 350 checks, 0 failing tests, 0 failed checks`（exit=0）。

| # | 反向变异（恢复旧行为） | 变异体 sha256 | 失败原文 |
|---|---|---|---|
| A | kMouseRel 内加回 `ev.is_move = true;` | `F8328B1E…7D11A21` | `:834 !got[0].is_move` / `:844 !got[1].is_move`，1 failing/2 failed |
| B | 加回 PTRXFLAGS 回退（`0x0002 → X2`） | `3210FAB0…31C52134` | `:842 got[1].button==0 (got 5, want 0)`，1 failing/1 failed |
| C | wheel 分支内加回 `DecodePointerButtons(pf, false, ev);` | `19309376…A07D146F` | `:1179 button==0 (got 1)` / `:1180 !button_down`，1 failing/2 failed |
| D | 删掉 wheel 分支的早退 `break;`（保留清零 = 死存储） | `2E4AEEFD…ADF76ABCC` | `:1174`×6 / `:1175`×6（1,2,3,4,5,123 / 1,2,3,4,5,456）+ `:1179/:1180`，14 failed |

**等价变异（必须记下）**：只删 `ev.x = 0; ev.y = 0;`、保留 `break;` → sha `2D0A0842…38E9E59`
→ **仍然全绿**（`1 tests, 28 checks, 0 failing`）。因为 `break` 已把事件截在赋值之前，清零本身是冗余防御；
**C 与 D 的真正承重行是 wheel 分支里的那一句早退 `break;`**。将来任何人把它改成 fallthrough，
C/D 两个缺陷会同时复活（本次 D 变异 14 条红即证据）。清零保留作为"改动 break 也能兜住一半"的纵深防御，可接受。

每条均 `sha_before_build == sha_after_build`，恢复后回到 `27CF4F3E…` 并复跑全绿。

## R3 结论与残留风险

1. **A/B/C/D 四项均已落地并被反向变异咬住**（R2b 四条红 + 一条等价变异），基线 `27CF4F3E…` 在沙箱为
   `34 tests, 350 checks, 0 failing tests, 0 failed checks`（exit=0）。裁决 C/D 的实现方式与主代理要求一致：
   wheel 分支 `if (wheel) { …; ev.x = 0; ev.y = 0; break; }`，其后才是不带 wheel 门控的普通鼠标解码。
2. **工作树在返工期间仍被原地变异过（2026-11-01 01:26:59）**：`F:\rtsc\src\server\server.cpp`
   sha256 = `E58C1E46…A4404F5`，与沙箱基线 `27CF4F3E…` 的差异**只有一行**
   （`[BASH: git diff --no-index <sandbox>/src/server/server.cpp F:\rtsc\src\server\server.cpp]` →
   `+ ev.is_move = true;`，插在 `ev.kind = kMouseRel;` 之后）。这正是变异 A，属反工单验证的中间态；
   **交付前必须还原回 `27CF4F3E…` 并复跑全绿**，否则等于把缺陷 A 提交进仓库。
3. 方法学：任何在仓库工作树内做变异（哪怕计划还原）都会与多代理共享工作树冲突——本轮的 A 残留在沙箱外复现，
   与我这轮早前误留的 `// M2` 是同一类事故。变异必须在 `%TEMP%` 副本内做，且 `Copy-Item` 后要 touch。
