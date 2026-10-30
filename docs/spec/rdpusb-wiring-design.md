# USB 重定向接线 — 定案（双审盖章，2026-10-28）

> 审计：甲 ses_e72e0868affeaUw6uYD0cKBzFr（终稿作者）/ 乙 ses_e72e08406ffejMHLs9htdw5G3J（交叉复核 + 4 项红证）。

## 1. 现状（主代理逐条核实）

| 项 | 状态 | 证据 |
|---|---|---|
| drdynvc 未请求 | 确认 | `tools/rtsc_gui/main.cpp:165-168` channel_names 无 "drdynvc" |
| 未链接 | 确认 | `CMakeLists.txt:238-253` 两库仅测试链；`rtsc_gui` 只链 rdpsnd/cliprdr/rdpdr |
| **OUT 载荷全丢（P0）** | 确认 | `rdpusb_client.cpp:475-478`（Control 传 `{}`）、`:492-495`（Bulk/Interrupt 传 `{}`） |
| 读长度纪律缺失 | 确认 | `:350` `(void)output_buffer_size`；`usb_win32.cpp:247` 固定 65536 |
| **未知设备不补全（P0）** | 确认 | `:516-517` `if (d == nullptr) return;` → 服务器永久等待 |
| **接口号改写（P0）** | 确认 | `:302-307` MakeHeaderInterfaceId 强制 `kProxy` 重贴 stream 位；`:518-520` 用改写值 |
| drdynvc 多 PDU 捆绑丢弃 | 确认 | `drdynvc_client.cpp:63-96` 只解析第一个 |
| drdynvc CREATE_RSP 失败悬挂 | 确认 | `:103-112` status!=0 不清 pending_ |
| QI/IFACE_RELEASE / 复合设备 | 确认 | `usb_win32.cpp:158` 只绑 interface 0 |
| kIoControl 无 case | 确认 | `rdpusb_client.cpp:200-251` default break |
| hresult 恒 0 | 确认（次要） | `:528,:538` |

## 2. 定案：路线 A（最小接线 + P0/P1 修复）

### 必须修（P0）
1. **OUT 载荷**：`ExecuteUrb` 的 Control/Bulk/Interrupt 分支把 `req.output_buffer` 传给后端（Control→setup 的 data 阶段；Bulk/Interrupt→`BulkOrInterruptTransfer` 的 data 参数）。
2. **未知设备补全**：`CompleteUrb` 在 `FindDevice == nullptr` 时仍发 URB_COMPLETION（interface_id 用请求里的原始值，status=`kInvalidHandle`），不静默丢弃。
3. **接口号原样回显**：`CompleteUrb` 的 `interface_id` 来自**请求帧的 header.interface_id**原样回显（不重贴 stream 位）；删除 `MakeHeaderInterfaceId` 的 `kProxy` 改写（或仅用于显式代理场景）。

### 必须修（P1）
4. **读长度纪律**：IN 传输后按 `output_buffer_size` 截断再回 `output_buffer`；后端读缓冲不超过请求长度。
5. **drdynvc 多 PDU 捆绑**：`drdynvc_client.cpp:63-96` 改为循环消费同一静态消息内的全部 DVC PDU。
6. **drdynvc CREATE_RSP 失败**：status!=0 时清 `pending_` 并记录，不悬挂。
7. **GUI 接线**：`main.cpp` 请求 "drdynvc" 静态通道 → `ChannelIdForName` 解析 → `RegisterChannel` → `DrdynvcClient(send=SendChannelPdu)`；`CreateWin32Enumerator` → `RdpUsbClient`；Connect 后 `drdynvc.Start()` → `rdpusb.Start()` → 枚举逐个 AddDevice。
8. **CMake**：`rtsc_gui` 链 `rtsc_urbrdc`（+ WIN32 链 `rtsc_usb_win32`）。
9. **后端 Open 失败不宣布**：`AddDevice` 前确认 `device->ready()`（在 usb_win32 里 Open 成功才算 ready），失败跳过 + 日志。
10. **安全门控**：`RTSC_REDIRECT_USB` 环境变量（默认空=不重定向；值=白名单 VID/PID 或 "ALL"），与 `RTSC_REDIRECT_DRIVES` 同风格。

### 不修（记录，后续 P 项）
- 复合设备 `WinUsb_GetAssociatedInterface`
- kIoControl/kInternalIoControl（文档化降级）
- SelectInterface alt-setting 全表
- 控制类 URB 合成 setup packet（Descriptor/Feature/GetStatus 等）
- 热插拔 RemoveDevice
- 同步 WinUSB 阻塞消息泵（可接受，文档化）
- Isoch 传输
- hresult 精确映射
- NoAck 抑制

## 3. 验收
- 新/扩测试（FakeUsbBackend + FakeSendFn）：
  - OUT 载荷到达后端（Control + Bulk/Interrupt，逐字节）
  - IN 按 output_buffer_size 截断
  - 未知设备仍发 completion（不静默）
  - completion 接口号 == 请求接口号（原样回显）
  - drdynvc 一消息多 PDU 全部消费
  - CREATE_RSP 失败不悬挂
- e2e/接线：`test_gui_send` 风格喂 MCS 帧验证 drdynvc→rdpusb 状态机就绪；或自研 server test-only 桩。
- 变异：①删 OUT 传参 → R1/R2 红；②恢复 `kProxy` 改写 → R4 红；③删未知设备补全 → R3 红；④恢复单 PDU 解析 → 多 PDU 红。
- C0：build 0err/0warn；影响面 rdpusb/drdynvc/channel/gui_send/server_* 全绿。
- 真机（W5 未验证）：Windows RDS + USB 设备插拔验证双向 I/O。
