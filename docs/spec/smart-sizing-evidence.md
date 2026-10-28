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
