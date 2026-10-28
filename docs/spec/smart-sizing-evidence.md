# EnableSmartSizing 对齐证据（smart-sizing-evidence.md）

状态：初版锚点归档。A6=取证 mstsc EnableSmartSizing 的真实语义并对照仓内 fit 实现。

## 目标二进制
mstscax.dll sha256 d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05

## 已定位锚点（REA/Ghidra 12.1.4）
- FUN_18003444c = 缩放主路径（HALFTONE：SetStretchBltMode(4) + SetBrushOrgEx + StretchBlt）——证据见 scaling-evidence.md。
- FUN_180036ba0（644B，初判尺寸匹配检测）：
  （读缩略）
        FUN_18002f084();
        if ( (region_w == param_2 && region_h == param_3 && 0x50==0) &&
             (0x58==param_2 && 0x54==0 && 0x5c==param_3) ) uVar2 = 1;
        FUN_18002e2bc(&local_res8);
  解释候选：判断"当前窗口尺寸==目标尺寸（无需缩放）"门；或"启用 smart sizing 时窗口未被拉伸"标志。**未验证**。

## 仓内现状（对照）
- src/client/view.cpp：kCmdToggleSmartSizing = 切换 fit 状态（**fit=缩放到窗口**）；zoom presets kMinZoom=0.50/kMaxZoom=5.00；kWheelStep=0.10。
- 差异假设（需取证裁决）：mstsc 的 EnableSmartSizing 可能仅对"窗口尺寸变化时保持桌面 1:1 但滚动窗格"（非缩放到窗口），或与之不同。

## 待取证
1. EnableSmartSizing 方法定位（COM vtable 难直接搜字符串；候选：FUN_180036ba0 的调用者）。
2. 语义裁定：启用后窗口 resize → 桌面是否缩放？还是保持 1:1 + 出现/隐藏滚动条（scrollbars）？
3. 对照仓内 fit 语义 → 偏差清单 → 证据后先红测试。
- [ ] 定位 EnableSmartSizing 方法/调用链
- [ ] 语义裁定与对照
## 取证批次 2（2026-10-28 轮次 102）：EnableSmartSizing 语义裁定 [证据]

### 裁定（FUN_18003444c 缩放主路径，mstscax!FUN_18003444c@0x18003444c）
伪代码（行号基于当前 REA dump）：
- @主要 79/81：`(*pcVar3)(obj+0xa0, "EnableSmartSizing", &local_e0)` —— 属性读取。
- 88：`(*pcVar3)(obj+0xa0, "ZoomLevel", &local_108)` —— 缩放百分比读取。
- 90 起分派：
  - `local_108 == 100`（ZoomLevel=100%）分支（101-118）：
    - `local_e0 == 0`（未启用 SmartSizing）→ 走 102-117：比较并重设窗口尺寸记录后 `BitBlt` 直拷（`FUN_1804d4e10` 路径）；
    - `local_e0 != 0`（启用）→ 走 119+：进入缩放绘制。
  - 153-156：StretchBlt 前置——`local_108==100 && (local_e0==0 || FUN_180036ba0(尺寸相同))` → 不缩放（BitBlt），否则 StretchBlt。

**结论**：
1. `EnableSmartSizing=0` → 恒 1:1 BitBlt 直拷，即使窗口≠桌面（不做窗口缩放）。
2. `EnableSmartSizing=1` → 窗口≠桌面时 StretchBlt + HALFTONE（SetStretchBltMode(hdc,4) + SetBrushOrgEx(0,0)）缩放到窗口。
3. `FUN_180036ba0`（0x180036ba0）= 尺寸相等检测（窗口宽/高==桌面宽/高 → 无需缩放）。
4. ZoomLevel 独立控制缩放比例；100% 且未启用 smart sizing 时不缩放。

### 仓内现状（对照）
- `src/client/view.cpp`：`kCmdToggleSmartSizing` = 切换 `fit`（无条件缩放到窗口）。fetch：ToggleSmartSizing 与 kCmdFit 同语义。
- **偏差（待先红测试定案）**：仓内"fit=缩放到窗口"无条件；mstsc 的 EnableSmartSizing 是**门控**（未启用→保持 1:1 即使窗口变）。二者默认语义不同。

### 待办
- [x] EnableSmartSizing 精确语义裁定
- [ ] 对照仓内 fit 语义 → 偏差清单（先红测试：窗口≠桌面且未启用 smart sizing → 期望 1:1）
- [ ] 最小实现对齐（保留 kCmdFit 但引入 EnableSmartSizing 门控语义）
## 取证批次 3（2026-10-28 轮次 103）：A6 对齐实施盖章 3414ece
- (a) 三处默认 fit true→false（view.h ZoomState/graphics.h GraphicsPipeline/window.h ViewMenuState）+注释"默认未启用=1:1"=EnableSmartSizing=0。
- (b) 翻转 3 断言 + graphics_defaults_to_1to1 改名；红证留存 tests/checks/failing/（入库）。
- (c) SetViewMenuState 接线（启动+consumed），D5 菜单失同步修复。
- (d) R1/R2/R3 先绿证明（1:1 裁剪/居中字邮箱契约、resize 不改语义）。
- 测试 view 56/7203、graphics 15/347、ui 40/226、multimon 24/94、orders 103/5793、client 14/63；全量 build 0err/0warn。双审盖章（甲乙一致）。
- 遗留非阻塞：N1 全屏菜单 no-op（kCmdToggleFullscreen 无消费、SetFullscreen 零调用）、N2 view_transform 级 resize 链覆盖建议；UNVERIFIED：EnableSmartSizing 构造默认、ZoomLevel≠100 行为、窗口>桌面放置位。
- [x] EnableSmartSizing 精确语义裁定
- [x] 对照仓内 fit 语义 → 偏差清单（默认态/菜单态；运行时行为已一致）
- [x] 最小实现（默认翻转+菜单接线+测试锁定）
