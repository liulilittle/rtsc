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

## 6. 定案修订（双审收敛，2026-10-28，取代 §4）

主代理核实：**F4 撤回**（`src/channel/rdpdr_client.cpp:410` 的 `create` 已含 `kFileSupersede`，乙误读）；**F2 升级为确定性触发**（目录含悬空 symlink 枚举即抛未捕获 `filesystem_error`，乙 V2 探针实证）；**F5/F6 确认**（`OnRead:448` 失败返 UNSUCCESSFUL 而非 INVALID_HANDLE；`OnQueryDirectory:517` 同；`OnWrite` 无长度上限）。

### 本批范围（收敛后）
1. **GUI 接线**：`RdpdrClient` + `HostFileSystem` + 驱动器枚举（`GetLogicalDriveStringsW` + `GetDriveTypeW`，默认 DRIVE_FIXED；`--rdpdr=off|local|all`）。
2. **F2**：`QueryDirectory` 的 `last_write_time` 改 `error_code` 重载；整个枚举循环包 try/catch 或逐条 error_code，悬空 symlink 跳过不崩。
3. **F3**：`OnDeviceIoRequest` 加 `phase_ != kReady` 门控 → `SendIoCompletion(kStatusUnsuccessful)`。
4. **F5**：`OnRead`/`OnQueryDirectory` 先校验 `file_id` 存在（用 `file_writable_`/或独立 handle 集合）→ 不存在返 `kStatusInvalidHandle`。
5. **F6**：`OnWrite` 加 `kMaxWriteLength = 1 MiB`（对称 `kMaxReadLength`），超限 `kStatusInvalidParameter`。

### 批外（单列）
- **F1**：`ChannelReassembler` 消息上限 16 MiB（P 项，对齐 drdynvc 口径）。
- **F7**（可选）、**F8**（残余 TOCTOU，记录）。
- **服务器 ANNOUNCE_RSP**：独立小批次（约 15 行）。
- **服务器 I/O 引擎**：P 项（350-600 行，须异步防死锁）。

## 7. 终版定案（甲乙双章，2026-10-28）— 主代理采纳

### 路线
**路线 B**：`rtsc_rdpdr` 库内新增 `include/rtsc/rdpdr/drive_enum.h` + `src/rdpdr/drive_enum_win32.cpp`（`if(WIN32)`），纯过滤函数跨平台可测；`main.cpp` 只调 `EnumerateLocalDrives()`。理由：满足"枚举过滤可单测"验收、与 `rtsc_usb_win32` 先例一致（CMakeLists:244-248）。

### 枚举设计
`GetLogicalDrives()` 位掩码 + `GetDriveTypeW` 过滤 + 空格校验；`Device{dos_name="C:", local_root="C:\\"}`，按盘符升序 `device_id=1..n`（0 不用）。
默认仅 `DRIVE_FIXED`（排除 REMOTE=双重跳/环路、CDROM=媒体未就绪阻塞、REMOVABLE=拔出即失败+隐私）。
配置：env `RTSC_REDIRECT_DRIVES`（`"C,E"` 白名单或 `"ALL"`，空=默认固定盘），与 `RTSC_DUMP_SURFACE` 同风格（main.cpp:768）。

### 接线（main.cpp:390-391 替换）
include `rdpdr_client.h`/`file_system.h`/`drive_enum.h`；`std::unique_ptr<HostFileSystem>` 长于 render loop；`devices=EnumerateLocalDrives(getenv(...))`；`send_rdpdr = [&](msg){ send_channel(kChannelRdpdr, msg); }`（与 cliprdr 同构，main.cpp:380-382）；`RdpdrClient rdpdr(fs.get(), move(devices), "RTSC", send_rdpdr)`；`RegisterChannel(kChannelRdpdr, [&](d,s){ ++vc_rdpdr; rdpdr.OnChannelData(d,s); })`。
**对象序红线**：`rdpdr` 必须先于 `RegisterChannel` 声明（lambda 捕获 `&rdpdr`）。
CMake：`rtsc_gui += rtsc_rdpdr`；`rtsc_rdpdr` 源加 `drive_enum_win32.cpp`；测试加 `test_drive_enum.cpp`。

### 批内缺陷修复
- **F3**：`OnDeviceIoRequest` 入口 `phase_ != kReady` → `SendIoCompletion(kStatusUnsuccessful)`（约 3 行 + 1 测试）。
- **F2**：`file_system.cpp` 的 `file_size()`(:77) 与 `last_write_time()`(:79) 改 `error_code` 重载或 try/catch；悬空 symlink 跳过不崩（约 5 行 + 悬空链接红用例）。
- **F5**：`OnRead`/`OnQueryDirectory` 查 `open_files_`，未知 `file_id` → `kStatusInvalidHandle`（现有 test_rdpdr_client.cpp:679 用未建句柄 0x100 需改为先建句柄，红→绿）。
- **F6**：`OnWrite` 加 `kMaxWriteLength = 1 MiB` 对称上限 → 超限 `kStatusInvalidParameter`。

### 批外（P 项，本批不碰）
D2 服务器 ANNOUNCE_RSP（独立小批 15-30 行）；服务器 I/O 引擎（350-600 行，须异步 completion 表，因 server.cpp:1452 内联喂数同步等待必死锁）；F1 重组上限 16MiB（对齐 drdynvc.h:106）；D3 DeviceReply 门控；F7 Remove；D4 拔盘通知；磁盘满映射。F8 junction TOCTOU 记录不修。

### 验收
C0：`cmake --build build --target rtsc_gui rtsc_rdpdr_tests rtsc_rdpdr_server_tests rtsc_server_rdpdr_e2e_tests --config Release` 零错零警（/W4 /WX）。
ctest：rdpdr + rdpdr_server + server_rdpdr_e2e 全绿 + 新增用例全绿。
变异反证：移除 lambda 内 `rdpdr.OnChannelData` 只留 `++vc_rdpdr` → e2e 握手永不就绪 → 测试失败。
真机（人工，W5 标注）：`rtsc_gui 192.168.1.7` → 服务器资源管理器 `\\tsclient\C` 可见可读写，`device_reply_count == 盘数`。

## 8. 审计红证附录（甲本机探针，2026-10-28）

探针编译链接 Release 库（/MD /O2），temp 目录，无 rtsc* 残留。

| 缺陷 | 红证输出 | 根因（路径:行） |
|---|---|---|
| F3 | `pre-handshake CREATE: phase=0 file_created=yes io_status=0x00000000` | OnDeviceIoRequest/OnCreate 无 phase==kReady 门控（rdpdr_client.cpp:264-376） |
| F5 | `unknown-handle READ io_status=0xC0000001`（期望 0xC0000008） | OnRead(435-459)/OnQueryDirectory(507-528) 跳过 open_files_ 检查；与头注释 :46-47 自声明矛盾 |
| F2 | `QueryDirectory over dangling symlink threw=YES what=directory_entry::file_size: The system cannot find the file specified` | file_system.cpp:77 entry.file_size() / :79 fs::last_write_time() 无 error_code 重载，异常冒泡 |
| F6 | `write 2MiB accepted=YES (no write cap) on_disk=2097152` | OnWrite(461-489) 无长度上限，与 OnRead 的 kMaxReadLength 不对称 |
| F4(撤销) | `missing-file SUPERSEDE created io_status=0x00000000` | rdpdr_client.cpp:410 create 名单已含 kFileSupersede，无缺陷 |

修复方案合计约 19 行 + 6 个新测试，已并入 §7 批内范围。
