# 服务器侧 rdpdr 设备 I/O 设计（docs/spec/rdpdr-server-io-design.md）

> 取证于 2026-10-28。W11 双审计批次前置门。

## 1. 方向澄清（第一性原理）

rdpdr 有两个相反方向，此前双审把两者混为一谈：

| 方向 | 语义 | 同步性 | 当前状态 |
|---|---|---|---|
| **A. 客户端盘给服务器用** | 客户端公告 `C:` → 服务器发 IOREQUEST 读写客户端盘 | **必须异步**（服务器要在等 IOCMPLETION 时继续跑 ActiveLoop，否则死锁） | 未实现（P 项，350-600 行） |
| **B. 服务器盘给客户端用** | 服务器公告自己的目录 → 客户端发 IOREQUEST → 服务器读写本地盘 → 回 IOCMPLETION | **天然同步**（请求到达时立即处理完并回包，无等待） | 未实现（**本批**） |

**B 方向才是"服务器模式"的核心价值**：Windows 家庭版不能做 RDP 宿主，我们用自研服务器；客户端连上来应能看到服务器上的文件夹（mstsc 的"驱动器"在服务器侧的表现）。

**B 不需要异步**：`OnDeviceIoRequest` 在 ActiveLoop 线程内同步处理完（本地 fstream 操作），立即 `SendRaw(completion)`。不存在"等对端回复"的挂起。风险是**慢磁盘阻塞 ActiveLoop**（与 cliprdr/rdpsnd 的 send 阻塞同级别），可接受并文档化。

## 2. proto 层现状（齐备，无需新增）

- 请求解析：`RdpdrCreateReq/ReadReq/WriteReq/CloseReq/QueryDirectoryReq/ControlReq::parse` 全有。
- 响应编码：`RdpdrCreateRsp/ReadRsp/WriteRsp/CloseRsp::encode` + `RdpdrDeviceIoCompletion::encode` 全有。
- 设备公告：`RdpdrDeviceAnnounce::encode` + `RdpdrDeviceListAnnounce::encode` 全有。
- 文件系统：`rtsc::rdpdr::IFileSystem`/`HostFileSystem` 完整（客户端已用，含 `kMaxReadLength` 1 MiB、路径安全由调用方负责）。

## 3. 缺口（本批要补）

1. **服务器公告设备**：`RdpdrServer` 需在 ClientId Confirm 后（或 User LoggedOn 后）发 `DR_CORE_DEVICELIST_ANNOUNCE_REQ`（服务器→客户端方向，[MS-RDPEFS] 2.2.2.9 同样用于服务器公告）。当前 `RdpdrServer` 只收不发。
2. **能力集声明 I/O**：`BuildServerCapabilities` 的 `io_code1 = 0` → 需置 `kRdpdrIrpMjCreate|Read|Write|Close|DirectoryControl` 位（[MS-RDPEFS] 2.2.2.7 GENERAL_CAPS_SET.ioCode1）。
3. **I/O 分发**：`OnDeviceIoRequest` 当前只 `++device_io_request_count_` → 需按 `major_function` 分发到 create/read/write/close/querydir，调 `IFileSystem`，回 `DR_DEVICE_IOCOMPLETION` 派生响应。
4. **路径安全**：服务器公告的目录 root 由配置指定；客户端路径必须经 `ResolvePathUnderRoot`（已在 `rdpdr_client.cpp`，需提取为共享工具或复制）。
5. **file_id 表**：服务器侧独立 `open_files_`（与客户端同构），Create 分配、Close 释放、Read/Write/QueryDirectory 校验。
6. **配置**：`ServerConfig.enable_rdpdr_io`（默认 false）+ `rdpdr_share_root`（目录路径）；`rtsc_server --share-dir <path>`。

## 4. 失败路径（优先分析）

- 共享目录不存在/无权限 → 不公告设备，日志警告，会话照常。
- 路径穿越（`..`/绝对/UNC/保留名）→ `ResolvePathUnderRoot` 拒绝 → `STATUS_ACCESS_DENIED`。
- 读超 1 MiB → `STATUS_INVALID_PARAMETER`。
- 写超 1 MiB → `STATUS_INVALID_PARAMETER`。
- 未知 file_id → `STATUS_INVALID_FILE_ID`（0xC0000008）。
- 未知 major_function → `STATUS_NOT_SUPPORTED`（0xC00000BB）。
- 磁盘满/文件被占用 → `STATUS_UNSUCCESSFUL`（v1 不细分）。
- 客户端中途断开 → 会话析构释放 file 表（fstream 自动关闭）。
- 慢磁盘阻塞 ActiveLoop → 文档化（与 cliprdr send 同级）。

## 5. 验收

- 新套件 `test_rdpdr_server_io.cpp`：Create/Read/Write/Close/QueryDirectory 全往返（FakeFileSystem 注入）、路径穿越拒绝、超限拒绝、未知句柄、未知 major_function、设备公告字节。
- e2e：自研 server（带 share-dir）+ 自研 client（RdpdrClient + HostFileSystem 访问临时目录）→ 客户端能列出并读取服务器共享的文件。
- 变异：①删路径校验 → 穿越用例红；②删读上限 → 超限用例红；③删设备公告 → e2e 客户端看不到盘。
- C0：build 0err/0warn；影响面 rdpdr/rdpdr_server/server/server_rdpdr_e2e/server_rdpsnd_e2e 全绿。

## 6. 【重要修正】双审裁定：方向 B 违反规范（2026-10-28）

主代理独立 web 核实确认：
- [MS-RDPEFS] 2.2.2.9 原文："**The client** announces the list of devices to redirect **on the server**"——**只有客户端→服务器方向**。
- [MS-RDPEFS] 2.2.1.4：I/O 请求（IOREQUEST）是**服务器→客户端**，IOCOMPLETION 是**客户端→服务器**。
- 2.2.2.1 Server Device Announce Response 是"server responds to a Client Device List Announce Request"。

→ **本文件 §1-§5 的"方向 B"不是 RDPEFS 规范内的用法**，而是角色反转的私有扩展：我们的服务器扮演协议上的 RDPEFS-client（公告设备、收 IOREQUEST、发 completion），我们的客户端扮演 RDPEFS-server（发 IOREQUEST、收 completion、回 DeviceReply）。

**后果**：
1. 对 mstsc 开启 B = 服务器发出乱序 DeviceListAnnounce，规范允许 mstsc 直接终止 rdpdr 通道 → 必须 `enable_rdpdr_io` 默认 false 门控 + 文档声明"仅自研闭合对"。
2. 本批需要**两端都补腿**：服务器腿（公告/分发/IO） + 客户端腿（识别服务器公告、发 IOREQUEST、收 completion）——设计 §3 只列服务器腿是作用域缺口。
3. 规范内的方向是 A（客户端盘给服务器用），需要异步 completion 表（服务器发 IREQUEST 后不能阻塞等回复）——350-600 行，风险高。

## 7. 待用户裁定（G1）

两条路线的产品价值与成本差异大，必须与用户对齐：
- **路线 B**（双审推荐 R1）：自研 client⇄server 闭合对可见服务器文件；违反规范、需门控默认关、两端补腿、mstsc 不可用。
- **路线 A**（规范方向）：mstsc 可把自己的盘共享给我们的服务器；需异步引擎 350-600 行，死锁风险需仔细设计。

## 8. 用户裁定（2026-10-28，G1）：走路线 A（规范方向）

用户选择：**路线 A = 客户端把本地盘共享给服务器（规范唯一方向）**，需异步 completion 引擎。

### 为什么 A 需要异步（第一性原理）
服务器发 `DR_DEVICE_IOREQUEST` 给客户端后，必须继续跑 ActiveLoop（收其它通道帧、发桌面、泵音频），**不能阻塞等待 `DR_DEVICE_IOCOMPLETION`**。因为：
- completion 由客户端跨网络回来，需要服务器继续读 socket；
- 若同步等待 → 服务器不再读 → 客户端发不出 completion → 死锁。

### 架构（A 方向）
1. **服务器发 IOREQUEST**：新增"服务器侧 I/O 客户端"角色 —— `RdpdrServer` 增加主动 API（`OpenFile/ReadFile/WriteFile/CloseFile/QueryDirectory`），每次分配 `completion_id` 并登记到 `outstanding_` 表（`completion_id → 回调/结果槽`）。
2. **completion 到达**：`OnDeviceIoRequest` 改为 `OnDeviceIoCompletion`（收 0x4943）→ 查 `outstanding_` 按 `completion_id` 匹配 → 填结果 + 唤醒等待者。
3. **等待语义**：调用方（未来的"服务器访问客户端盘"功能，如把 \\tsclient\C 暴露给服务器上的应用）用**异步回调**而非阻塞等待。v1 可先只提供"异步 API + 测试验证往返"，不接入具体消费方。
4. **超时**：`outstanding_` 每项有 deadline（默认 30s），超时清理并回调失败；会话断开时全部回调失败并清空。
5. **completion_id 单调递增**，`outstanding_` 有上限（如 256），满则拒绝新请求。
6. **客户端侧已具备**：`rdpdr_client.cpp` 的 `OnDeviceIoRequest` 就是应答方（服务端发来的 IRP 它已经会处理并回 completion）——**A 方向客户端腿已完整**，只需服务器补腿。

### 与双审报告的关系
双审报告的 S1/S2/S4/S5/S6 缺陷与建议**全部仍适用**（路径守卫、句柄上限、root 自检、device_id 回查），只是作用对象从"服务器腿 B"变为"服务器发 IRP 的 A 腿 + 客户端应答腿的加固"。

### 范围（本批）
- 服务器：IOREQUEST 发送 API + outstanding 表 + completion 分派 + 超时清理。
- 客户端：device_id 回查加固（S6，双审实证）、句柄上限（S2，双审实证 300 无界）。
- 路径守卫提取（path_guard.h，双审共识）。
- 不做：把客户端盘接入具体服务器消费方（如文件浏览 UI）——留后续。

### 验收
- 新套件 `test_rdpdr_server_io.cpp`：服务器发 IOREQUEST → 客户端应答 → 服务器收到 completion（Pair harness 真编码回环）；completion_id 匹配/未知拒/重复拒；outstanding 上限；超时清理；会话断开清理。
- 变异：①删 outstanding 匹配 → 错配用例红；②删超时 → 超时用例红；③删上限 → 上限用例红。
- C0：build 0err/0warn；影响面全绿。
