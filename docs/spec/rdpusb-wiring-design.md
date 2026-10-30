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

## 4. 第⑤步验证发现（甲，2026-10-28）

### FAIL-1（P1-5 回归，阻断）：`ConsumeBundlePdu` 的 kCreate 定界错误

**症状**：同一静态通道消息内捆绑两条 `DYNVC_CREATE_RSP` 时，第二条永不交付 → 该设备通道永久 pending、永不宣布。

**证据**
- 实现 `src/channel/drdynvc_client.cpp:74-90` 按 "Status(4) + NUL-terminated ChannelName" 定界（NUL 扫描）。
- 规范 `[MS-RDPEDYC] 2.2.2.2`（已 web 核验，https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpedyc/8f284ea3-54f3-4c24-8168-8a001c63b581）：
  `DYNVC_CREATE_RSP` = `cbId|Sp|Cmd` + `ChannelId (variable)` + `CreationStatus (4 bytes)`。
  **无 ChannelName 字段**；ChannelName 仅存在于 `DYNVC_CREATE_REQ`（2.2.2.1）。
- 我方自家模型亦只读 4 字节 Status：`src/channel/drdynvc_client.cpp:173-174`。
- 轨迹（两 status-only bundle `{0x10,0x01,0,0,0,0, 0x10,0x02,0,0,0,0}`）：NUL 扫描在字节 8 误终止 → 首条消费吞掉第 2 条头 → 余 3 字节解析成垃圾 → 第 2 条丢失。
- 新增单测 `drdynvc_bundled_pdus_in_one_static_message_all_consumed` 用错误布局构造，故假绿（负向漏网）。

**修复指令**
1. `src/channel/drdynvc_client.cpp:74-90` kCreate 分支改为定长消费：`offset = pdu_off + 4`（header + id 已在 `pdu_off` 前扣除，实际 `offset = pdu_off + 4`），删除 NUL 扫描。
2. 重写该单测：两条 status-only `CREATE_RSP` 捆绑，断言 `create_response_count == 2` 且 `pending_.empty()`。
3. 补测：CAPS + CREATE 混合捆绑（Caps 定长 4 字节需同法核对：`DYNVC_CAPS_RSP` = header + Version(2) + PriorityCharge0..3(2 each)，VERSION1 时仅 Version → 按版本定长）。
4. 复核 kData/kDataFirst 的"消费剩余"在多 PDU 场景是否安全（规范：Data PDU 是捆绑中最后一条）。

### 补测盲区（甲）
- `RTSC_REDIRECT_USB` 的 `UsbSpecAllows` 白名单解析无单测。
- `Open()` 成功但 `CreateChannel` 失败路径无用例。
- 跨静态块边界的 DVC 大帧无用例。

### PASS 项（甲逐条核实）
P0-1 OUT 载荷（后端按 `transfer_flags&1` 分 IN/OUT，`usb_win32.cpp:234-247`，Bulk OUT 走 `WinUsb_WritePipe`）、P0-2、P0-3、P1-4、P1-6、P1-9、P1-10、GUI 接线（`main.cpp:224-228,557,731-747`）、CMake（`:568-572`）、测试质量、偏离 1/2（`kInvalidHandle` 不存在；devpkey GUID+pid 2 与 SDK 26100/18362 一致）。

## 5. 第⑤步验证：P0-1 判定更正（甲更正，乙同证）

### FAIL-2（P0-1 残留，阻断）：WinUSB 后端控制 OUT 载荷被清零

**症状**：控制传输 OUT 方向发出的是 N 个零字节，而非 `req.output_buffer` 的真实载荷。

**证据**
- `src/usb/usb_win32.cpp:235-236`：`std::vector<uint8_t> buffer(in ? pkt.Length : input.size());` —— 只按长度零初始化。
- `:238-240`：`WinUsb_ControlTransfer(..., buffer.data(), buffer.size(), ...)` 直接发送。
- **`input` 参数从未拷入 `buffer`**（`std::copy(input.begin(), input.end(), buffer.begin())` 缺失）。
- 对照 `:278-287` Bulk OUT 分支正确：`std::vector<uint8_t> copy = input;` → `WinUsb_WritePipe`。
- 为何此前后端层被掩盖：修复前客户端传 `{}`（空），`input.size()==0`，buffer 为空，看起来"无数据可发"；客户端修好后传真实载荷，`input.size()>0`，buffer 被分配但全零 → 缺陷显形。

**修复指令**
1. `src/usb/usb_win32.cpp` ControlTransfer：OUT 分支 `buffer` 分配后立即 `buffer.assign(input.begin(), input.end())`；IN 分支不变（长度取 `pkt.Length` 后由 `transferred` 重设）。
2. 补测：这是纯 WinUSB 后端实现，无 seam 可注入 → **代码审层门**（静态断言测试难以覆盖）；或将 SetupApi/WinUsb 抽象为 seam 以支持单测（较大改动，记为 P 项）。至少加一条注释与 CI 静态检查（grep `WinUsb_ControlTransfer` 前必须有 `buffer.assign`）。
3. 一并修复：P1-5 kCreate 定长消费、CAPS 版本相关消费（P2）、env 门控 channel_names（P2）。

### 更正后的 P0-1 状态
| 层 | 状态 |
|---|---|
| 客户端传递层（`req.output_buffer` → `ControlTransfer` 的 input 参数） | PASS |
| **WinUSB 后端落地（input → buffer → WinUsb_ControlTransfer）** | **FAIL** |
| Bulk OUT（客户端 + 后端） | PASS |

### 补测缺口（甲补充）
- 后端级控制 OUT 数据断言（需 WinUSB seam；当前无）
- V2 caps + 捆绑
- `UsbSpecAllows` 白名单单测
