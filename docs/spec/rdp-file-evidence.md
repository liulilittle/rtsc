# RDP 连接文件（.rdp）证据与实现（rdp-file-evidence.md）

## 依据
- Microsoft Learn《Supported RDP properties》（rdp-files）：
  https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/rdp-files
- 格式：每行 `key:type:value`，type 为 `s`（字符串）或 `i`（整数/布尔）；
  键名可含空格（`full address`、`screen mode id`、`use multimon`、
  `smart sizing`、`authentication level`）。

## 已实现（批163，2026-11-07）
`include/rtsc/config/rdp_file.h` + `src/config/rdp_file.cpp`（rtsc_config）：
- `ParseRdpFile(text) -> RdpFileSettings`：
  - 键名大小写不敏感；重复键后者覆盖前者（mstsc 行为）；
  - 未知键、缺分隔符、类型非 s/i、整数非法 → 忽略该行；
  - 整数字段按文档范围校验，越界忽略（保留默认值，不做意外钳制）：
    screen mode id 1..2、desktopwidth/height 200..8192、use multimon/
    smart sizing/redirectclipboard/enablecredsspsupport/redirectsmartcards
    0..1、audiomode 0..2、authentication level 0..3、keyboardhook 0..3；
  - 值可含 ':'（`full address:s:[::1]:3389`、`gatewayhostname:s:gw:443`）。
- `WriteRdpFile(settings) -> text`：
  - CRLF 行尾、固定键序；desktopwidth/height 为 0 时不写；
    drivestoredirect 为空时不写；
  - 字符串值含 CR/LF/NUL 时返回空串（防止注入额外键行）。

## 测试（tests/test_rdp_file.cpp，9 tests / 54 checks）
- 真实样例解析（全部字段 + 空行）；
- 未知键/畸形行/非法整数忽略，且后续合法行仍生效；
- 重复键后者胜；键名大小写不敏感；值含冒号；
- 越界整数忽略（默认值保留）；
- 写读往返全字段一致；未设置几何不写键；
- 写拒绝 CR/LF/NUL 注入。
- 变异 M77（接受换行）→ 1 test / 3 checks 红；恢复后全绿。

## 验收
C0 零错误零警告；`ctest -R "^(rdp_file|client|cliprdr|rdpdr)$"` 4/4；
`rtsc_rdp_file_tests` 9/54。

## 未完成 / 未验证
- rtsc_gui 尚未接线（`--rdp-file` 导入、导出菜单）。
- 未与真实 mstsc 生成的 .rdp 文件做逐字节对照（未验证）。
## 2. GUI 接线（批164，2026-11-07）

**用法**：`rtsc_gui --rdp-file <path>`（也接受 `--rdp-file=<path>`）。

**优先级（mstsc 语义）**：显式主机/端口（位置参数或 `/v:`）> .rdp
`full address` > 无。显式端口为 0 表示未给出，回落 3389；显式主机存在时
端口默认 3389，不继承文件端口。
- 用户名/域：位置参数 > .rdp `username`/`domain`。
- 桌面尺寸：`/w:`、`/h:` > 位置参数 > .rdp `desktopwidth/height` > 默认。
- 多显示器：`/multimon` > `/span` > 位置参数 > .rdp `use multimon`。
- 智能缩放：位置参数 fit > .rdp `smart sizing`（0 → 1:1，其余 → fit）。
- 全屏：`/f` 或 .rdp `screen mode id:i:2`。

**实现**：
- `tools/rtsc_gui/mstsc_args.{h,cpp}` 新增纯函数
  `ResolveEndpoint(explicit_host, explicit_port, rdp_full_address, out)`：
  显式主机优先；否则解析 .rdp 地址；两者都无/非法返回 false。
- `tools/rtsc_gui/main.cpp`：预扫描 `--rdp-file` 读取并解析文件（打不开 →
  退出 2），主参数循环跳过该选项；端点、用户名/域、尺寸、多屏、smart
  sizing、全屏按上述优先级合并。
- `rtsc_gui` 链接 `rtsc_config`；usage 文本补充说明。

**测试**：
- `test_mstsc_args.cpp` 新增 3 个用例（显式优先、文件回落、缺失/非法拒绝），
  10 tests / 61 checks。
- 变异 M78（忽略 .rdp 地址）→ 1 test / 5 checks 红；恢复后全绿。

**手工验证**（本机，无需服务器）：
- 非法 `full address`（含空格）→ 打印 `invalid 'full address' in the RDP
  file`，退出码 2。
- 合法 .rdp + `--help` → 正常打印 usage，退出码 0。

**验收**：C0 零错误零警告；`ctest -R "^(rdp_file|mstsc_args|client|gui_send)$"`
4/4；rdp_file 9/54、mstsc_args 10/61。

**未完成 / 未验证**：
- 导出（写出 .rdp）未接线。
- `redirectclipboard`/`audiomode` 等重定向属性尚未映射到会话配置。
- 未与真实 mstsc 生成的 .rdp 逐字节对照；未真机连接验证。
## 3. GUI 导出（批165，2026-11-07）

**用法**：`rtsc_gui <host> [port] ... --save-rdp <path>`（也接受
`--save-rdp=<path>`）。写出当前生效的连接设置后退出 0，不建立连接。

**写出的字段**：
- `full address`：由 `FormatFullAddress(host, port)` 生成——裸 IPv6 加方括号，
  默认端口 3389 省略；
- `username`、`domain`；
- `desktopwidth`/`desktopheight`（当前生效值）；
- `use multimon`（生效的多屏模式）；
- `smart sizing`（fit 生效为 1；显式 zoom 会关闭 fit，与 GUI 语义一致）；
- `screen mode id`（`/f` 或 .rdp 的 2 → 全屏）；
- `redirectclipboard:i:1`（GUI 当前始终启用剪贴板）。

**实现**：
- `mstsc_args` 新增纯函数 `FormatFullAddress`（IPv6 方括号、默认端口省略）。
- `main.cpp` 在合并完所有设置后、创建窗口前处理 `--save-rdp`：
  `WriteRdpFile` 编码失败或文件写入失败 → 退出 2；成功打印路径并退出 0。
- usage 文本补充 `--save-rdp`。

**测试 / 验证**：
- `test_mstsc_args.cpp` 新增 2 个用例（默认端口省略、IPv6 方括号），
  12 tests / 66 checks。
- 变异 M79（总是写端口）→ 2 tests / 3 checks 红；恢复后全绿。
- 手工验证：
  - `rtsc_gui server.example 3390 CONTOSO alice pw 1920 1080 headless 1.0 1 0 0 0 --save-rdp out.rdp`
    → 退出 0，文件含 `full address:s:server.example:3390`、1920x1080、
    `smart sizing:i:0`（显式 zoom 关闭 fit）。
  - `rtsc_gui --rdp-file good.rdp --save-rdp out.rdp` → 退出 0，
    `full address:s:127.0.0.1:1`、800x600、`smart sizing:i:0`。

**验收**：C0 零错误零警告；`ctest -R "^(rdp_file|mstsc_args|client|gui_send)$"`
4/4；rdp_file 9/54、mstsc_args 12/66。

**未完成 / 未验证**：
- 未做 GUI 菜单项（当前为命令行导出）。
- `redirectclipboard`/`audiomode` 等重定向属性仍未映射到会话配置。
- 未与真实 mstsc 生成的 .rdp 逐字节对照。
## 4. 重定向属性映射（批166，2026-11-07）

**映射**（[MS-RDPBCGR] 2.2.1.11 静态虚拟通道）：
- `redirectclipboard:i:0` → 不广播 `cliprdr`；缺省/1 → 广播。
- `audiomode:i:0`（本地播放）→ 广播 `rdpsnd`；`1`（远程播放）/`2`（无声音）
  → 不广播。
- 无 .rdp 文件时保持既有默认：`rdpdr`、`cliprdr`、`rdpsnd` 全部广播。
- `rail` 仍只在 `--rail`；`drdynvc` 仍只在 USB 或 `--disp`。

**实现**：
- `mstsc_args` 新增纯函数
  `BuildStaticChannelNames(rail_mode, dynamic_channels, clipboard_redirect,
  audio_redirect)`，顺序稳定：rdpdr、cliprdr、rdpsnd、rail、drdynvc。
- `main.cpp` 的 `MakeDriver` 增加两个参数并改用该函数；调用点按
  `!have_rdp_file || rdp_file.redirect_clipboard != 0` 与
  `!have_rdp_file || rdp_file.audiomode == 0` 计算。
- `--save-rdp` 导出写出生效值：`redirectclipboard` 按生效状态，
  `audiomode` 保留文件值（无文件写 0）。

**测试 / 验证**：
- `test_mstsc_args.cpp` 新增 1 个用例（5 种组合 + rail/drdynvc 顺序），
  13 tests / 81 checks。
- 变异 M80（剪贴板通道跟随音频标志）→ 1 test / 4 checks 红；恢复后全绿。
- 手工验证：`--rdp-file`（`redirectclipboard:i:0`、`audiomode:i:1`）
  `--save-rdp` 导出保留 `redirectclipboard:i:0`、`audiomode:i:1`。

**验收**：C0 零错误零警告；`ctest -R "^(rdp_file|mstsc_args|client|gui_send|connect_machine)$"`
5/5；rdp_file 9/54、mstsc_args 13/81。

**未验证**：未真机连接验证“服务器侧看不到 cliprdr/rdpsnd 通道”；
`redirectprinters`/`redirectcomports`/`drivestoredirect` 未映射到 rdpdr 设备。
## 5. drivestoredirect → rdpdr 设备（批167，2026-11-07）

**映射**（[MS-RDPEFS] 2.2.1.3 / 2.2.2.9）：
- `drivestoredirect:s:` 空 → 不重定向任何驱动器；
- `*` 或任一 `DynamicDrives` 记号 → 全部本地驱动器（ALL）；
- `C:\;E:\;` → 仅 C、E（大小写不敏感）；
- 未知记号忽略；非驱动器根记号不会扩大选择范围（fail-closed）。
- 优先级：显式 `RTSC_REDIRECT_DRIVES` 环境变量 > .rdp 属性。

**实现**：
- `rtsc::rdpdr::DriveRedirectToSpec(value)`（drive_enum）把 .rdp 值转换为
  既有的 `SelectDrives` 规格（"" / "ALL" / "C,E"）。
- `main.cpp` 的驱动器枚举：环境变量未设置且 .rdp 有 `drivestoredirect` 时
  使用转换结果；日志提示补充 .rdp 来源。

**测试 / 验证**：
- `test_drive_enum.cpp` 新增 1 个用例（8 组输入），6 tests / 26 checks。
- 变异 M81（忽略 `*`）→ 1 test / 1 check 红；恢复后全绿。
- 端到端（本机 `rtsc_server_host --port 3402 --no-enhanced --any-user`，
  `rtsc_gui --rdp-file ... --rdp`）：
  - `drivestoredirect:s:C:\;` → `rdpdr: redirecting 1 drive(s): C:`，
    会话 active；
  - `drivestoredirect:s:` → `rdpdr: no drives redirected`，会话 active。

**验收**：C0 零错误零警告；`ctest -R "^(drive_enum|rdp_file|mstsc_args|rdpdr|client|gui_send)$"`
6/6；drive_enum 6/26。

**未验证**：未对真实 Windows 服务器验证；`DynamicDrives` 按 ALL 处理
（本客户端只在启动时枚举，不跟踪后续接入的驱动器）。
## 6. GUI 菜单“保存连接文件”（批168，2026-11-07）

**行为**：查看(Z) 菜单新增“保存连接文件(C)...”，弹出标准保存对话框
（过滤器 `*.rdp`），把当前会话实际使用的设置写成 .rdp（与 `--save-rdp`
一致的字段来源）。

**实现**：
- `rtsc::config::BuildSessionRdpFile(full_address, username, domain, width,
  height, multimon, fit, fullscreen, clipboard, audiomode)`：纯函数，把会话
  值映射到 .rdp 字段（multimon→use multimon，fit→smart sizing，
  fullscreen→screen mode id 2/1，clipboard→redirectclipboard）。
- `main.cpp`：`--save-rdp` 与菜单处理器共用该函数；新增 Win32
  `ShowSaveConnectionFileDialog`（GetSaveFileNameW，`*.rdp`）。
- `include/rtsc/ui/window.h` 新增 `kCmdSaveConnectionFile`（并入唯一性
  static_assert）；`window_win32.cpp` 新增菜单项与命令映射。

**测试 / 验证**：
- `test_rdp_file.cpp` 新增 `rdp_file_builds_session_settings`：全字段映射、
  multimon/fit 独立用例（防掩蔽）、写读往返，10 tests / 76 checks。
- 变异 M82（multimon 与 fit 交换）→ 1 test / 2 checks 红；恢复后全绿。
- `--save-rdp` 命令路径手工复验：位置参数导出字段正确。

**验收**：C0 零错误零警告；`ctest -R "^(rdp_file|mstsc_args|ui|client|gui_send)$"`
5/5；rdp_file 10/76、mstsc_args 13/81。

**未验证**：菜单项本身未做交互点击验证（无头环境）；未与真实 mstsc
生成的 .rdp 逐字节对照。
## 7. 保存凭据（批169，2026-11-07）

**约定**：mstsc 把保存的密码放在 Windows 凭据管理器，泛型目标名为
`TERMSRV/<host>`，用户名 + UTF-16 密码 blob。

**实现**：
- `include/rtsc/config/credential_store.h`：
  - `CredentialTargetName(host)` = `"TERMSRV/" + host`；
  - `CredentialStore` 接口（Save/Load/Delete）；
  - `CreatePlatformCredentialStore()`：Windows 返回 CredWrite/Read/Delete
    后端，其他平台返回 nullptr。
- `src/config/credential_store_win32.cpp`：CredWriteW（CRED_TYPE_GENERIC、
  CRED_PERSIST_LOCAL_MACHINE、密码为无终止符 UTF-16 blob）、CredReadW、
  CredDeleteW；UTF-8 ↔ UTF-16 用 MultiByteToWideChar/WideCharToMultiByte。
- `main.cpp`：
  - `--save-credential`：保存 host/user/password 后退出 0（失败退出 2）；
  - `--use-credential`：用户/密码缺失时从凭据管理器补全（不覆盖显式值），
    只打印“loaded”，从不打印密码。
- `rtsc_config` 链接 advapi32。

**测试 / 验证**：
- `test_rdp_file.cpp` 新增 `credential_target_name_matches_mstsc`
  （11 tests / 79 checks）。
- 变异 M83（去掉 `TERMSRV/` 的分隔符）→ 1 test / 3 checks 红；恢复后全绿。
- 手工端到端（本机）：
  - `rtsc_gui rtsc-cred-test.example 3389 TEST alice secret --save-credential`
    → 退出 0；`cmdkey /list` 出现
    `LegacyGeneric:target=TERMSRV/rtsc-cred-test.example`；
  - `rtsc_gui --rdp-file cred.rdp --use-credential --save-rdp out.rdp`
    → 退出 0，导出文件含 `username:s:alice`（来自凭据管理器）；
  - `cmdkey /delete:TERMSRV/rtsc-cred-test.example` 清理成功。

**验收**：C0 零错误零警告；`ctest -R "^(rdp_file|mstsc_args|client|gui_send)$"`
4/4；rdp_file 11/79。

**未验证**：Win32 凭据后端没有单元测试（依赖真实用户配置）；未对真实
Windows 服务器验证保存凭据后的自动登录；密码未做内存擦除（进程生命周期内
驻留，既有行为）。
## redirectcomports 与串口接线（批179，2026-11-07）

**实现**：
- `RdpFileSettings.redirect_comports`（int，0/1）：解析 `redirectcomports`
  （越界保留默认）、写回；`BuildSessionRdpFile` 增加 `comports` 参数
  （默认 false）并写入。
- GUI：
  - `--redirect-com` 开关；`RTSC_REDIRECT_COM` 环境变量；`.rdp`
    `redirectcomports:i:1`。显式开关/环境变量优先于文件。
  - 启用时用 `EnumerateSerialPorts()` 枚举本机 COM 口，追加为
    `DeviceType::kSerial` 设备（id 接在驱动器之后），创建
    `Win32SerialBackend` 并 `EnableSerial`；无端口时打印提示。
  - `--save-rdp` 与菜单导出都会写 `redirectcomports`（反映生效状态）。

**测试**：`rdp_file_redirect_comports_round_trip`（解析 0/1、越界默认、
写回、BuildSessionRdpFile 开/关）→ rdp_file 12/85。
变异 M93（导出丢弃串口状态）→ 1 test / 1 check 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdp_file|mstsc_args|rdpdr|client|gui_send)$"`
5/5。

**未验证**：真实 COM 口端到端；GUI 菜单交互未点击验证；mstsc 对
`redirectcomports` 的完整语义（按端口选择）未实现（仅全开/全关）。
## redirectprinters 与打印机接线（批181，2026-11-07）

**实现**：
- `RdpFileSettings.redirect_printers`（int 0/1）：解析 `redirectprinters`
  （越界保留默认）、写回；`BuildSessionRdpFile` 新增 `printers` 末参
  （默认 false）。
- GUI：`--redirect-printers`、`RTSC_REDIRECT_PRINTERS`、`.rdp
  redirectprinters` 三选一启用；显式开关/环境变量优先于文件；用
  `EnumeratePrinters()`（EnumPrintersW level 2）把每个本地/连接打印机追加为
  `DeviceType::kPrinter` 设备（PreferredDosName 为 "PRN<digits>"，携带
  printer_name/driver），创建 `Win32PrinterBackend` 并 `EnablePrinter`；
  无打印机时打印提示。
- `--save-rdp` 与菜单导出写入 `redirectprinters`（反映生效状态）。

**证据**：`rdp_file_redirect_printers_round_trip`（0/1、越界默认、写回、
BuildSessionRdpFile 开/关），rdp_file 13/92；M95（解析范围改为 0..0 拒绝
合法值）→ 1 test / 2 checks 红，恢复后全绿。

**未验证**：真实打印机端到端；菜单交互未点击验证；`redirectprinters` 的
mstsc 语义按整数开关实现（不做队列选择）。