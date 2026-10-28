# mstsc 键盘输入与快捷键：二进制取证

目标：`C:\Windows\System32\mstscax.dll`（SHA-256 前缀 `d73c76d65721043c`）。工具：REA 6.7 + Ghidra 12.1.4。

## 1. 观察（反编译原文，未加解释）

### E1 远程键事件发送：`FUN_1801185e0`（0x1801185e0）

```c
UVar3 = MapVirtualKeyW(0x10, 0);              /* 0x10 = VK_SHIFT, MAPVK_VK_TO_VSC */
FUN_1800e8dfc(param_1, 0x100, 0x10, UVar3);   /* 0x100 = WM_KEYDOWN */
UVar3 = MapVirtualKeyW(0x10, 0);
FUN_1800e8dfc(param_1, 0x101, 0x10, UVar3);   /* 0x101 = WM_KEYUP   */
UVar3 = MapVirtualKeyW(0x5b, 0);              /* 0x5b = VK_LWIN      */
FUN_1800e8dfc(param_1, 0x101, 0x5b, (ushort)UVar3 | 0x8100);
```

同函数另有 `VK_RWIN`(0x5c) 分支，同样 `MapVirtualKeyW(0x5c, 0) | 0x8100`，并清位 `param_1 + 0x36c` 的 `0x100`/`0x200`、清零 `+0x414`/`+0x418`。

### E2 本地键注入：`keybd_event` 的固定标记

`FUN_1801185e0`：

```c
keybd_event('[', '[', 1, 0x4321dcba);   /* VK_LWIN down  */
keybd_event('L', '&', 0, 0x4321dcba);   /* 'L' scan 0x26 */
keybd_event('L', '&', 2, 0x4321dcba);   /* 'L' up        */
keybd_event('[', '[', 3, 0x4321dcba);   /* VK_LWIN up    */
```

`FUN_180096858`：

```c
keybd_event(0xff, '\0', 0, 0x4321dcba);
keybd_event(0xff, '\0', 2, 0x4321dcba);
```

`FUN_18011602c`（修饰键状态同步）：

```c
keybd_event(param_4, '\0', 1, 0x4321dcba);   /* down */
keybd_event(param_4, '\0', 3, 0x4321dcba);   /* up   */
```

所有 `keybd_event` 调用的 dwExtraInfo 均为常量 **0x4321DCBA**。

### E3 焦点/修饰键状态处理：`FUN_180118940`（0x180118940，LRESULT 形态，消息处理）

```c
if (*(int *)(param_1 + 0x4e0) != 0) {
    if (*param_4 == 0x5b) {                       /* VK_LWIN */
        *(uint *)(param_1 + 0x414) = (uint)(param_3 == 0x100);
    }
    if (*param_4 == 0x5c) {                       /* VK_RWIN */
        *(uint *)(param_1 + 0x418) = (uint)(param_3 == 0x100);
    }
}
```

### E4 调用点分布（REA xrefs + resolve_containing_procedure）

- `keybd_event`：10 处 → `FUN_180096858`(2)、`FUN_18011602c`(2)、`FUN_1801185e0`(4)、`FUN_180118940`(1)，1 处不属任何函数。
- `SendInput`：4 处 → `FUN_18011dc30`、`FUN_1801e3670`、`FUN_18021ae1c`，1 处不属任何函数。
- `SetCursorPos`：7 处 → `FUN_180115030`(2)、`FUN_18011dc30`(1)、`FUN_1801e3670`(2)、`FUN_1804c4038`(1)，1 处不属任何函数。
- `MapVirtualKeyW`：126 处（未逐个定位）。

## 2. 推断（明确标注为推断，尚需独立验证）

1. `FUN_1800e8dfc(instance, 0x100/0x101, vk, scancode)` 是「合成一个键盘消息」的内部入口，其 `0x100/0x101` 与 Win32 `WM_KEYDOWN/WM_KEYUP` 数值一致。
2. 扫描码来自 `MapVirtualKeyW(vk, 0)`（`MAPVK_VK_TO_VSC`，即 set-1 扫描码），与 [MS-RDPBCGR] 2.2.8.1.2.2 要求的 keyboard event `keyCode` 语义一致。
3. `| 0x8100` 中的 `0x0100` 与「extended key」标志位一致（右 Win 属 extended）；`0x8000` 为内部标记。**未验证**。
4. `0x4321DCBA` 是 mstsc 给自己注入的本地事件打的标识，用于区分「用户真实按键」与「mstsc 合成按键」（避免回环）。**未验证**。
5. `VK 0xFF` 不是合法虚拟键，配 `flags 0/2`（down/up）应是「冲刷/清除修饰键状态」的技巧。**未验证**。
6. 焦点变化时 mstsc 会主动发送 Shift down/up 与 Win down/up 来让远端修饰键状态归位（`FUN_1801185e0` 的整体行为），并在发送后清零本地记录的 Win 状态（`+0x414`/`+0x418`）。**未验证**。

## 3. 与当前实现的待比对点（`src/ui/window_win32.cpp`、`src/proto/input.cpp`）

| 项 | mstsc（依据 E1/E3） | 本仓现状 | 待核 |
|---|---|---|---|
| 扫描码来源 | `MapVirtualKeyW(vk, MAPVK_VK_TO_VSC)` | 取 lParam bits16..23，0 时回退 `MapVirtualKeyW(VK_TO_VSC)` | 一致（已改） |
| extended 标志 | 右 Win 等置 `0x0100` | `key_extended = lParam bit24` | 需确认 Win 键路径 |
| Win 键转发 | 有（含 down/up 与状态清零） | 待核 | **需核** |
| 修饰键归位 | 焦点变化时重放 Shift/Win | 待核 | **需核** |
| 本地注入标记 | `0x4321DCBA` | 无（无本地注入） | 不适用 |

## 4. 验收要求

- 任何「mstsc 如何处理 X 快捷键」的实现，必须引用本文 E1-E4 的具体地址与语句；无证据者不得写入。
- 若决定对齐 Win 键/修饰键归位行为，先补**确定性单测**（`TranslateWin32KeyMessage` 纯函数层面），期望值来自本文观察，不得用生产输出反推。