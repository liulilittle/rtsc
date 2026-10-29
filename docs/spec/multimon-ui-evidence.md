# 多屏/窗口 UI 对齐证据（multimon-ui-evidence.md）

状态：A7 初证。目标=mstsc 窗口/多显示器 UI 行为对齐。

## 取证结论（轮次 110）
- mstsc.exe（sha256 04a03d92…）是**薄壳**：窗口类 `MstscRemoteSessionsMgrWndClass`@0x1400dfdc0，仅加载 mstscax.dll（0x1400e1668）并宿主。全部窗口/多屏行为在 mstscax.dll。
- mstscax.dll 侧已有的窗口类锚点：`RdpClipRdrWindowClass`@0x1807f82d0（cliprdr-evidence.md）。
- **window shell 行为（窗口菜单/全屏/后台窗口）**在本工程落地形态=rtsc_gui edit 自绘 Surface + Win32 窗口后端（SetFullscreen/multi_window 已实现，A6/N1 批次双审盖章 + multimon 测试 24/94）。
- 已覆盖：全屏 borderless+监视器定位（window_win32.cpp SetFullscreen）、多屏 union 渲染（graphics RenderMonitorTo + multimon 套件）、缩放/自动伸缩（A6 smart sizing）。
- 待取证（真机）：mstsc.exe 原生"最大化/置顶/后台窗口"交互细节、会话栏窗口类行为（MstscRemoteSessionsMgrWndClass）——影响小，排期低优先。
- [x] mstsc.exe 薄壳确认 + 窗口类定位
- [ ] （低）mstscax.dll 会话栏/多会话窗口行为深挖
