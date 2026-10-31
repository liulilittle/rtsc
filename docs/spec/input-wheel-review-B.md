# 滚轮修复独立复核（审计乙 · 复核 B）

对象 `042687f`。复核时 `src/server/server.cpp` 有另一执行 AI 的在途改动（P-11 未知事件计数），
但 `git diff -- src/server/server.cpp` 只落在 `:549-561`/`:1630-1633`/`:1737-1743`，**未触碰 1571-1586**，故解码复核有效。
本轮仅新增本文件；`client.cpp` 的 M1 变异已还原（哈希见 §3）。

## 1. 编码（PASS）— `src/client/client.cpp:240-257`

`scaled = wheel_delta * kWheelUnitsPerNotch(120)`（`:247-248`）→ 保号 clamp ±255（`:249-253`，`kMaxWheelRotation=255` at `:27`）
→ `flags = (horizontal?0x0400:0x0200) | (units & 0x01FF)`（`:254-257`，mask 直写，不再 OR 负号位）。
纸面核算 6 锚点：`-1→0x0388`、`+1→0x0278`、`2→0x02F0`、`-120→0x0301`、`+120→0x02FF`、`hwheel+1→0x0478`，全部相符。

## 2. 解码（PASS）— `src/server/server.cpp:1571-1586`

`:1571-1572` WHEEL|HWHEEL 双识别；`:1579/:1581` WHEEL 优先（`horizontal=!vertical`）；
`:1582-1585` `raw=pf&0x01FF`、`(raw&0x0100)?raw-0x0200:raw` 9 位符号扩展；直接赋 `wheel_delta`，**无 ×120**
（`Select-String src\server\server.cpp -Pattern "\b120\b|\* 120"` 仅命中 `:1577` 注释与 `:1584` 类型转换）。
探针实测：`decode(0x0301)=-255`、`decode(0x02FF)=+255`、`-255..255` 全 511 值往返一致。

## 3. 单位契约与残留（PASS）

编码 ×120 / 解码不缩放 / `server.h:217` 注释 "wire units: WHEEL_DELTA (120) per notch" → 契约落地。
`Select-String src\client\client.cpp,src\server\server.cpp -Pattern "kPtrWheelNegative|magnitude"` → **0 命中**（旧语义已清除）。

## 4. 变异 M1（去 ×120）：红 → 绿（PASS）

- 备份：`C:\Users\liulilte\AppData\Local\Temp\opencode\client.cpp.wheelM1.bak`；`PRE_MUTATION_HASH=B7C204D063986D10CA37B8CAEFD62565A244D196552F03FA93F4C66DDCA65B3C`
- 改坏 `client.cpp:247-248` 为 `static_cast<int>(ev.wheel_delta)` → **touch** → 绝对路径
  `cmake --build build --config Release --target rtsc_client_tests`（`build_exit=0`）→ `RTSC_TEST_FILTER=wheel` 跑：
  ```
  FAIL tests/test_client.cpp:175  pdu[3] == 0x78 (got 1, want 120)
  FAIL tests/test_client.cpp:187  pdu[3] == 0xF0 (got 2, want 240)
  FAIL tests/test_client.cpp:199  pdu_down[3] == 0x01 (got 136, want 1)
  FAIL tests/test_client.cpp:208  pdu_up[3] == 0xFF (got 120, want 255)
  5 tests, 17 checks, 4 failing tests, 5 failed checks        MUTANT_exit=1
  ```
- 还原（Copy-Item）→ **touch** → 重编 → `POST_RESTORE_HASH=B7C204D063986D10CA37B8CAEFD62565A244D196552F03FA93F4C66DDCA65B3C`（与 PRE 逐字节相同）；
  `git diff --stat -- src/client/client.cpp` 空；`5 tests, 17 checks, 0 failing tests`，`RESTORED_exit=0`。
- 基线（未变异）两套件：client `5 tests/17 checks/0 fail`、server `1 test/14 checks/0 fail`，均 `exit=0`；
  构建筛选 `error C|warning C` 无命中（C0）。

## 5. 边界漏洞

| 边界 | 裁定 | 证据 |
|---|---|---|
| `INT16_MIN×120` | PASS（无 UB） | int 提升后 `-32768*120=-3932160` 仍在 int32；clamp → `0x0301`；`INT16_MAX` → `0x02FF` |
| `0x0600` 双置位 | PASS（但有后续义务） | `:1579-1581` WHEEL 优先 → `delta=0, horizontal=false`；**注入侧须丢弃 delta==0**（已入接缝文档 T10） |
| `horizontal` gating | PASS | `client.cpp:239` 未广告即 `return {}`；用例 `tests/test_client.cpp:161` OK；解码 `:1581` 置位，`0x0478→+120/horizontal` 有覆盖 |
| 截断包 | PARTIAL（不崩、静默） | `share.cpp:277-278` 校验长度/`size`，不足 `NeedMoreData` 丢弃；事件级 `:1546/1554/1564/1611/1615` 越界即 return；但无计数、`numEvents` 不交叉校验、未知 `eventCode` 只 return（`:1618-1619`）。既有低危，建议计数 + `remaining==0` |

UNVERIFIED：注入侧 `mouseData` 恒等搬运（注入器尚未实现，无代码可验）；真机滚动方向与 mstsc 一致；fuzz 鲁棒性。

## 6. 裁定

项1 PASS / 项2 PASS / 项3 PASS / 项4 PASS / 项5 PASS（截断包 PARTIAL 非阻断）。
