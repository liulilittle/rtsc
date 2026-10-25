import io

proc = """

## 第246轮：整树破损（并发写者冲突）→ 转交两处修复（不自行编辑）

- **破损 1（view.cpp）**：`src/client/view.cpp`（`rtsc::client`）用 `kCmdZoomPresetFirst/Last/Fit/ToggleSmartSizing`（`rtsc::ui`，`window.h:61-67`）**未限定** → `error C2065`（:33/:36/:37/:164/:171）。
  - 修法：加 `using rtsc::ui::kCmdXxx;` 或每处限定。
- **破损 2（audio_win32.cpp）**：`src/audio/audio_win32.cpp:90` `std::lock_guard<std::mutex>` **重载错误**（成员名/类型或锁类别）。
- **根因**：**同一工作树多代理并发写**（甲预警第 3 次）：服务端（`transport.h` 加 `Listener`）、mstsc 菜单（`view.cpp`/`window.h`）、音频（`audio_win32.cpp`）同时编辑 → 不一致态。
- **处置**：**不自行编辑**（避免覆盖），转交两并发写者修复；均提醒勿回退他人改动。
- **长期建议（甲）**：共享工作树应**串行化**或**分工作树/分支**（`using-git-worktrees`），否则并发覆盖反复破坏成果。
- 在途：两处修复；服务端基础层；性能/连续性。
"""
io.open('.opencode/process.md', 'a', encoding='utf-8').write(proc)
print('ok')
