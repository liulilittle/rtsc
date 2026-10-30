# 客户端 rdpdr 驱动器重定向接线 — 设计证据（docs/spec/rdpdr-client-wiring-design.md）

> 生成于 2026-10-28 W11 双审计批次。审计：乙 ses_e74bf57acffesehvpW2Elvpj2N（终报已交）；甲 ses_e74bf690bffeBStQzxMoHAlWDd（在途）。

## 1. 现状与缺口（主代理独立核实）

| 项 | 事实 | 证据 |
|---|---|---|
| 客户端协议实现 | 完整：握手/Device List/I-O 服务 | `include/rtsc/channel/rdpdr_client.h` |
| 路径安全 | `ResolvePathUnderRoot` 拒 `..`/绝对/UNC/保留名 | `src/channel/rdpdr_client.cpp` |
| 读上限 | `kMaxReadLength = 1 MiB` | `include/rtsc/rdpdr/file_system.h`；`src/rdpdr/file_system.cpp:186` |
| **GUI 接线** | **仅计数 `++vc_rdpdr`，真实 handler 未接** | `tools/rtsc_gui/main.cpp:390-391` |
| CMake | `rtsc_gui` 未链 `rtsc_rdpdr` | `CMakeLists.txt`（乙核：:554 只链 rdpsnd+cliprdr） |

## 2. 审计发现（乙一审，主代理已逐条核实）

- **F1（中）**：`ChannelReassembler` 无消息长度上限（`include/rtsc/proto/channel.h`：只有 `expected_length_`/`buffer_`，无 cap）→ 对端可声明 4GiB 触发 OOM。drdynvc 已有 16MiB 先例可循。
- **F2（中）**：`HostFileSystem::QueryDirectory` 的 `fs::last_write_time(entry.path())`（`src/rdpdr/file_system.cpp:79`）无 `error_code` 重载 → 枚举期并发删除抛 `filesystem_error`，未捕获则崩会话。乙已探针实证。
- **F3（中）**：`RdpdrClient::OnDeviceIoRequest`（`src/channel/rdpdr_client.cpp:359-376`）**无 phase 门控** → 握手完成前收到 I/O 请求仍执行（乙实证 opens=1/phase=0）。
- **F8（低）**：根目录 junction-swap 残余 TOCTOU（同权限级，接受并记录）。
- **协议**：Device Reply 对初始设备列表**非必需**（[MS-RDPEFS] 1.3.2 原文 optional）→ 我们服务器不回不违规、客户端不依赖、无死锁（**推翻甲初稿的"必须 Device Reply"担忧**）。
- 其它：缺失文件 `FILE_SUPERSEDE` 应创建而报 NOT_FOUND（[MS-SMB2] 2.2.13）；读路径不校验 file_id（关闭句柄返回 UNSUCCESSFUL 而非 INVALID_HANDLE）；写路径无上限；宣告 DeviceRemovePdus 但不处理 DeviceListRemove。

## 3. 服务器侧缺口评估（乙）

真正可用"客户端重定向盘"需服务器发起 I/O 引擎（completion_id 关联 + 异步泵）；因 `server.cpp` 在同一读路径内联喂 `OnChannelData`，同步等待必死锁 → 约 350-600 行 + e2e + 能力集改动，风险高。**定案：不并入接线批**，单列 P 项；批内只补每设备 `ANNOUNCE_RSP`（约 15 行）提互通。

## 4. 定案（主代理）

**本批范围（客户端接线 + 三个中危安全修复）**：
1. GUI 接线：`RdpdrClient` + `HostFileSystem` + 驱动器枚举（`GetLogicalDriveStringsW` + `GetDriveTypeW` 过滤 DRIVE_FIXED/DRIVE_REMOVABLE，默认仅本地固定盘；`--rdpdr=off|local|all` 可选）。
2. **F3**：`OnDeviceIoRequest` 加 `if (phase_ != Phase::kReady) { SendIoCompletion(request, kStatusUnsuccessful); return; }`。
3. **F1**：`ChannelReassembler` 加 `kMaxChannelMessageBytes = 16 MiB`，超限 `Reset()` + 返回 `Status::InvalidField`（与 drdynvc 口径一致）。
4. **F2**：`QueryDirectory` 的 `last_write_time` 改用 `error_code` 重载，失败则跳过该条目。
5. 附带：`FILE_SUPERSEDE` 缺失时创建；读路径校验 file_id；写路径加 `kMaxWriteLength`（1 MiB 对称）。
6. 服务器侧：补每设备 `ANNOUNCE_RSP`（低成本互通项）。

**不在本批**：服务器 I/O 引擎（350-600 行，单列）；DeviceListRemove；F8 TOCTOU（记录）。

## 5. 验收

- 新套件/扩展：`rdpdr_client` 加 F1/F2/F3/SUPERSEDE/file_id/写上限用例；GUI 接线用 e2e（自研 server 对打，验证 Device List Announce 到达服务器 + ANNOUNCE_RSP 回包）。
- 变异红证：F3 删门控→红；F1 删上限→红；F2 还原无 error_code→红。
- C0：build 0err/0warn；影响面 rdpdr/rdpdr_client/rdpdr_server/gui_send/server 全绿。
