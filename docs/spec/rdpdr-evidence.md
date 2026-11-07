# RDPDR 对齐证据（rdpdr-evidence.md）

状态：锚点定位。目标=取证 mstsc 的 rdpdr（驱动器重定向）实现偏差，与 cliprdr-evidence.md 同级。

## 目标二进制
mstscax.dll sha256 d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05

## 已定位锚点（REA/Ghidra 12.1.4, 2026-10-28 轮次 105）
- 0x1806ad7f0 "Software\Microsoft\Terminal Server Client\Default\AddIns\RDPDR"（注册表插件路径）
- 0x1806c71e0 "m_spRdpDrConfig"（配置对象成员）
- 0x1807aa580 "DisableRDPDR"（TS_PROP 禁用开关）
- 0x1807abf18 "CreateInstance of CMsRdpDrive failed"
- 0x1807abfa0 "CMsRdpDrive::Initialize failed"
- 0x1807ec357 "iCRdpDrPlugin"（插件接口）
- 0x1807ecaa0 "rdpdr static channel connected. Connection time = %I64u ms"
- 0x1807ecb18 "ChannelOnConnected for [rdpdr]"
- 0x1807ecb60 "rdpdr static channel connecting..."
- 0x1807eccd0 "rdpdr.dll"（rdpdr 由外部 rdpdr.dll 载体，mstscax 加载）
- 0x1807ede28 "RdpDr"
- 0x18081c300 "Failed to load RDPDR plugin"（插件工厂失败）

## 仓内现状（对照）
- src/channel/rdpdr_client.cpp：DR_OPEN_FILE 等（S3 批已审计，见 plan.md:324-334；rdpdr_client.cpp:44-50 Information 映射已取证）。
- src/rdpdr/file_system.cpp：文件系统后端。
- tests Test #30 rdpdr。
- 已有 S3 完整审计（DesiredAccess/S3-7 越界/S3-8 等）——非如 cliprdr 的"空白区"。

## 待取证（如排期）
1. CMsRdpDrive / iCRdpDrPlugin 的 mstsc 驱动器映射语义（盘符/相对路径）。
2. mstsc rdpdr 默认允许哪些重定向（盘符/剪贴板/串口/打印机）与 TS_PROP/注册表联动。
3. 与仓内 rdpdr_client.cpp 的偏差清单。
- [ ] 驱动器映射语义取证
- [ ] 默认重定向清单 + 注册表联动
## 取证批次 2（2026-10-28 轮次 109）：rdpdr 取证方向与成本判断
- mstscax 侧仅做 rdpdr 插件加载（"rdpdr.dll"@0x1807eccd0、iCRdpDrPlugin@0x1807ec357、CMsRdpDrive）。实际驱动器映射/盘符枚举逻辑**在外部 rdpdr.dll**，mstscax.dll 无 \tsclient 常量。
- `m_spRdpDrConfig`@0x1806c71e0 引用点 FUN_1801865f0（配置对象集成）。\\tsclient 路径由 rdpdr.dll 提供。
- **成本判断**：深排驱动映射语义需另开 rdpdr.dll 目标（REA 重载）+ 较长分析；仓内 rdpdr_client DR_OPEN_FILE 等已有 S3 审计（plan.md:324-334），当前无证据表明仓内实现偏差。
- 决策：rdpdr 深取证**暂缓排期**（记录），优先现有缺失项。若要深挖见 rdpsnd/bitmap 模式=先取 wire/抓包证据。
- [x] mstscax 侧 rdpdr 插件接口定位
- [ ] rdpdr.dll 驱动器映射语义（待排期/独立目标）

## ClientId Confirm 长度缺陷证据（2026-10-28 轮次 121）

- [MS-RDPEFS] 2.2.2.6 DR_CORE_SERVER_CLIENTID_CONFIRM（learn.microsoft.com/openspecs/windows_protocols/ms-rdpefs/bbbb9666-6994-4cf6-8e65-0d46eb319c6e）：
  Header(4B) + VersionMajor(2B, MUST 0x0001) + VersionMinor(2B, 0x000D/0x000C/0x000A/0x0005/0x0002) + ClientId(4B) = **12 字节**。
- 交叉实现 IronRDP（ironrdp-rdpdr VersionAndIdPdu）：FIXED_PART_SIZE = 2+2+4 = 8（body），加 shared header 4 = 12。
- 本仓现状（修复前）：`RdpdrServerClientIdConfirm::encode()` 写 header(4)+client_id(4)=8 字节；parse size>=8。客户端共用该 parse，故内部测试全绿但真实客户端按规范长度校验会拒收。
- 修复方向：encode/parse 到 12 字节；服务器填 version_major=1/version_minor=0x000C。
- 发现路径：rdpdr e2e 执行子报"头文件已声明 12B 但序列化未落地"。

## DR_DEVICELIST_REMOVE 发送路径（批162，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.3.2 Client Drive Device List Remove
（Header 4B + DeviceCount 4B + DeviceIds 4B×N；PacketId 0x444D）。

**实现**：
- proto：`RdpdrDeviceListRemove`（parse/encode）。DeviceCount 与剩余长度
  不匹配时返回 NeedMoreData，不越界读取。
- `RdpdrClient::RemoveDevice(device_id)`：
  - 仅在 `Phase::kReady`（设备列表已发出）后可用；
  - 磁盘设备从 `devices_` 移除；智能卡设备先 `SetAsyncSmartCard(false)`
    再清 `scard_`（worker 在另一线程读 `scard_`，必须先 join）；
  - 关闭该设备的所有打开文件（服务器不会再为看不见的句柄发 DR_CLOSE_REQ），
    清 `file_writable_` 与 `device_replies_`；
  - 发送 DR_DEVICELIST_REMOVE 并计数；未知 id 返回 false 且不发送。
- 移除后该设备的 DR_CREATE 在文件系统被触碰前失败（STATUS_ACCESS_DENIED），
  不再提供服务。

**测试**：
- `rdpdr_devicelist_remove_round_trip`（字节 72 44 4D 44 + 计数/ids）。
- `rdpdr_devicelist_remove_rejects_truncated_ids`。
- `rdpdr_client_remove_device_sends_and_stops_serving`。
- `rdpdr_client_remove_unknown_device_is_rejected`。
- 变异 M76（不移除 devices_）→ 1 test / 3 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；影响面 ctest 6/6；rdpdr 66/923、
smartcard_channel 47/521。

**未验证**：智能卡设备移除分支无独立用例（drive 路径已覆盖）；未真机验证。
## DR_DRIVE_QUERY_VOLUME_INFORMATION（批170，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.3.3.6（请求）/ 2.2.3.4.6（响应）；
[MS-FSCC] 2.5.4 FileFsFullSizeInformation、2.5.10 FileFsSizeInformation。

**请求布局**：DeviceIoRequest（20B，RDPDR_HEADER 之后）+ FsInformationClass
（4B）+ Length（4B）+ Padding（24B）+ QueryVolumeBuffer（Length 字节）。
`RdpdrQueryVolumeReq::kFixedSize` = 20+4+4+24 = 52；Length 超过剩余字节时
返回 NeedMoreData，不越界。

**响应布局**：DeviceIoReply（DeviceId/CompletionId/IoStatus）+ Length +
Buffer（与设备控制完成相同的字段排布，复用 SendControlCompletion）。

**已实现的信息类**（Windows）：
- FileFsSizeInformation (0x03)：TotalAllocationUnits、AvailableAllocationUnits、
  SectorsPerAllocationUnit、BytesPerSector（24B）；
- FileFsFullSizeInformation (0x07)：Total、CallerAvailable、ActualAvailable、
  SectorsPerAllocationUnit、BytesPerSector（32B）。
- 其他类返回 STATUS_NOT_SUPPORTED（0xC00000BB），未知 FileId 返回
  STATUS_INVALID_HANDLE（0xC0000008）。
- 空间数据来自 GetDiskFreeSpaceExW + GetDiskFreeSpaceW（卷根几何）；
  非 Windows 平台返回 false（不支持）。

**测试**：
- proto：请求解析（52B 定长、截断拒绝）。
- 客户端（MockFs）：成功返回 24B 结构（status/Length/payload）、
  不支持类 → NOT_SUPPORTED 且无 Length、未知句柄 → INVALID_HANDLE。
- 变异 M84（失败仍报成功）→ 1 test / 3 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5；rdpdr 70/949。

**未验证**：HostFileSystem 的 Windows 空间查询无单元测试（需真实卷）；
本机 rtsc_server 不发送该 IRP，未做端到端；FileFsVolumeInformation/
AttributeInformation/DeviceInformation 未实现。
## 卷信息补全：Volume/Attribute/Device（批171，2026-11-07）

**依据**：[MS-FSCC] 2.5.9 FileFsVolumeInformation、2.5.1
FileFsAttributeInformation、2.5.10 FileFsDeviceInformation；
[MS-RDPEFS] 2.2.3.3.6（FileFsVolumeInformation 的 Reserved 字节 MUST NOT
be present）。

**实现**：
- 新增纯函数 `rtsc::rdpdr::EncodeVolumeInfo(class, VolumeInfo, out)`：
  - 0x01 FileFsVolumeInformation：CreationTime(8) + Serial(4) +
    VolumeLabelLength(4，含结尾 NUL) + SupportsObjects(1) + UTF-16 标签 +
    NUL；**无 Reserved 字节**；
  - 0x04 FileFsDeviceInformation：DeviceType + Characteristics（8B）；
  - 0x05 FileFsAttributeInformation：Attributes + MaxComponentLength +
    NameLength + UTF-16 名称（无 NUL，长度按字节）。
- HostFileSystem::QueryVolume 用 GetVolumeInformationW 填充标签/序列号/
  属性/文件系统名，用 GetDriveTypeW 映射 DeviceType（CD-ROM 0x02，其余
  0x07）与 Characteristics（可移动 0x1、只读 0x2、远程 0x10、已挂载 0x20）。
- 其余类仍返回 false → 客户端 STATUS_NOT_SUPPORTED。

**测试**：
- `rdpdr_volume_info_encodes_volume_information`（27B，无 Reserved，
  标签长度含 NUL）；
- `rdpdr_volume_info_encodes_device_information`（8B）；
- `rdpdr_volume_info_encodes_attribute_information`（20B，名称无 NUL）；
- `rdpdr_volume_info_rejects_unknown_class`。
- 变异 M85（插入 Reserved 字节）→ 1 test / 4 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5；rdpdr 74/973。

**未验证**：HostFileSystem 的 Win32 取值无单测（需真实卷）；本机服务器不发
该 IRP，未端到端。
## SET_INFORMATION：删除与重命名（批172，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.3.3.5 DR_DRIVE_SET_INFORMATION_REQ /
2.2.3.4.5 DR_DRIVE_SET_INFORMATION_RSP；[MS-FSCC] 2.4.4
FileDispositionInformation、2.4.11 FileRenameInformation。

**实现**：
- `RdpdrSetInformationReq`：与 QUERY_VOLUME 请求同构（DeviceIoRequest +
  FsInformationClass + Length + 24B Padding + SetBuffer），复用其解析。
- `RdpdrClient::OnSetInformation`：
  - 未知句柄/设备不匹配 → STATUS_INVALID_HANDLE；
  - 0x0D FileDispositionInformation：1 字节 DeleteFile；TRUE 记录待删除，
    FALSE 取消；成功 → DeviceIoReply + Length=0；
  - 0x0A FileRenameInformation：ReplaceIfExists(1) + Reserved(7) +
    RootDirectory(8) + FileNameLength(4) + UTF-16 名称；RootDirectory≠0 →
    STATUS_NOT_SUPPORTED；长度非法 → STATUS_INVALID_PARAMETER；目标存在且
    ReplaceIfExists=FALSE → STATUS_OBJECT_NAME_COLLISION；同名 → 无操作成功；
    否则记录待重命名；
  - 其他类 → STATUS_NOT_SUPPORTED。
- 删除/重命名在 `Close` 时应用（`ApplyPendingFileOperation`）：Windows 上
  打开的 std::fstream 无法被删除/改名，延迟到句柄关闭与 Windows
  delete-on-close / rename-on-close 语义一致；`RemoveDevice` 关闭句柄时同样
  应用；`Reset` 丢弃待定操作（传输重置不是成功关闭）。
- IFileSystem 新增 `Rename(local, new, replace)` / `Delete(local)`；
  HostFileSystem 用 std::filesystem（replace 时先删目标，Windows rename 不
  覆盖）。

**测试**：删除延迟应用、删除取消、重命名延迟应用、冲突拒绝、同名无操作、
不支持类、RootDirectory≠0、未知句柄、proto 解析/截断（rdpdr 83/1033）。
变异 M86（删除分支改为丢弃）→ 1 test / 2 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5。

**未验证**：HostFileSystem 的 Rename/Delete 无单测（需真实文件系统）；本机
服务器不发 SET_INFORMATION，未端到端；Windows 服务器对延迟语义的接受度未
真机验证。
## 目录控制 minor 分发与 NotifyChange（批173，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.3.3.11 DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_REQ
（DeviceIoRequest + WatchTree(1) + CompletionFilter(4) + Padding(27)）、
2.2.3.4.11 DR_DRIVE_NOTIFY_CHANGE_DIRECTORY_RSP（DeviceIoReply）；
[MS-ERREF] 2.3 STATUS_INVALID_DEVICE_REQUEST = 0xC0000010。

**缺陷**：`IRP_MJ_DIRECTORY_CONTROL` 此前不检查 MinorFunction，一律按
IRP_MN_QUERY_DIRECTORY 解析。服务器发 IRP_MN_NOTIFY_CHANGE_DIRECTORY 时，
请求会被误解析（通常因长度不足静默丢弃），服务器收不到完成而等待。

**实现**：
- `RdpdrNotifyChangeDirectoryReq`：解析 DeviceIoRequest + WatchTree +
  CompletionFilter + 27B Padding（kFixedSize=52，与查询卷请求同长）。
- `OnDeviceIoRequest` 按 `minor_function` 分发：
  - 0x01 IRP_MN_QUERY_DIRECTORY → OnQueryDirectory；
  - 0x02 IRP_MN_NOTIFY_CHANGE_DIRECTORY → OnNotifyChangeDirectory；
  - 其他 → STATUS_INVALID_DEVICE_REQUEST（12B 完成）。
- `OnNotifyChangeDirectory`：校验句柄（未知 → INVALID_HANDLE），否则以
  STATUS_NOT_SUPPORTED 完成（未实现变更通知，fail-closed，不再静默丢弃）。

**测试**：notify 失败闭合（12B、NOT_SUPPORTED）、notify 未知句柄、
未知 minor、proto 解析/截断（rdpdr 87/1054）。
变异 M87（交换两个 minor 的处理）→ notify 1 test/4 checks 红、query_directory
1 test/8 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5。

**未验证**：未实现真实目录变更通知（服务器需接受 NOT_SUPPORTED）；本机
服务器不发 notify，未端到端。
## QUERY_INFORMATION（批174，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.3.3.8 DR_DRIVE_QUERY_INFORMATION_REQ /
2.2.3.4.8 DR_DRIVE_QUERY_INFORMATION_RSP；[MS-FSCC] 2.4.7
FileBasicInformation、2.4.41 FileStandardInformation、2.4.6
FileAttributeTagInformation。

**实现**：
- `RdpdrQueryInformationReq`：与 QUERY_VOLUME 请求同构（DeviceIoRequest +
  FsInformationClass + Length + 24B Padding + QueryBuffer）。
- `EncodeFileInformation(class, FileInfo, out)` 纯函数：
  - 0x04 FileBasicInformation：4×时间(8B) + FileAttributes(4B) = 36B；
    **Reserved 不出现**（[MS-RDPEFS] 2.2.3.3.8）；
  - 0x05 FileStandardInformation：AllocationSize(8) + EndOfFile(8) +
    NumberOfLinks(4) + DeletePending(1) + Directory(1) = 22B；
    **Reserved 不出现**；
  - 0x23 FileAttributeTagInformation：FileAttributes(4) + ReparseTag(4) = 8B。
- `IFileSystem::QueryInformation`；HostFileSystem 用 std::filesystem 取大小、
  用 GetFileAttributesExW 取时间/属性（change_time 取 last_write_time；
  allocation_size 近似为逻辑大小，簇大小未暴露）。
- `OnQueryInformation`：未知句柄 → INVALID_HANDLE；不支持类 → NOT_SUPPORTED；
  成功 → DeviceIoReply + Length + Buffer（复用 SendControlCompletion）。

**测试**：三类编码精确字节（含 Reserved 缺失）、未知类拒绝、客户端成功/
不支持/未知句柄、proto 解析/截断（rdpdr 95/1101）。
变异 M88（交换 DeletePending/Directory）→ 1 test / 2 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5。

**未验证**：HostFileSystem 的 Win32 取值无单测；本机服务器不发该 IRP，未端到端。
## LOCK_CONTROL（批175，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.3.3.12 DR_DRIVE_LOCK_REQ、2.2.1.6
RDP_LOCK_INFO、2.2.3.4.12 DR_DRIVE_LOCK_RSP；[MS-ERREF] 2.3
STATUS_LOCK_NOT_GRANTED = 0xC0000055、STATUS_RANGE_NOT_LOCKED = 0xC000007E。

**实现**：
- `RdpdrLockReq`：DeviceIoRequest + Operation(4) + Flags(4) + NumLocks(4) +
  Padding2(20) + Locks（每个 Length(8) + Offset(8)）；NumLocks 超过剩余
  字节数即拒绝。
- `rdpdr::LockTable`（平台无关）：共享/独占字节范围锁；
  - 重叠且任一方为独占 → 冲突；共享+共享允许；
  - Length=0 是合法的零长度区域：永不冲突，但记录以支持精确解锁；
  - 解锁必须与已持有范围精确匹配（含句柄）；
  - LockMany/UnlockMany 全有或全无（先校验后提交）。
- `OnLockControl`：未知句柄 → INVALID_HANDLE；Operation 非 2/3/4/5 或
  NumLocks=0 → INVALID_PARAMETER；冲突 → LOCK_NOT_GRANTED；解锁未持有 →
  RANGE_NOT_LOCKED；成功 → DeviceIoReply + 5B Padding（17B）。
- 句柄关闭/设备移除时 `ReleaseFile`；`Reset` 清空锁表。
- F 位（等待）忽略：本地锁表非阻塞，冲突立即失败。

**测试**：锁表 5 个用例（共享/独占冲突、精确解锁、原子多锁/多解锁、
按句柄释放）+ 客户端 6 个用例（成功 17B、冲突、解锁未持有、非法操作、
未知句柄、关闭释放）+ proto 解析/截断（rdpdr 107/1158）。
变异 M89（仅独占对独占冲突）→ 2 tests / 3 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5。

**未验证**：锁仅为客户端内存语义，未做 OS 级强制；未与真实服务器端到端；
F 位等待语义未实现。
## SET_VOLUME_INFORMATION（批176，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.3.3.7 DR_DRIVE_SET_VOLUME_INFORMATION_REQ /
2.2.3.4.7 DR_DRIVE_SET_VOLUME_INFORMATION_RSP；[MS-FSCC] 2.5.5
FileFsLabelInformation。

**实现**：
- `RdpdrSetVolumeReq`：与 QUERY_VOLUME 请求同构（DeviceIoRequest +
  FsInformationClass + Length + 24B Padding + SetVolumeBuffer）。
- `OnSetVolumeInformation`：
  - 未知句柄 → INVALID_HANDLE；
  - 类非 FileFsLabelInformation(0x02) → NOT_SUPPORTED；
  - SetBuffer 不足 4 字节或 VolumeLabelLength 超出缓冲 → INVALID_PARAMETER；
  - 标签按 UTF-16 解码并去掉尾部空格（允许空格填充）；
  - `IFileSystem::SetVolumeName` 失败 → ACCESS_DENIED；成功 → 成功。
- 响应恒为 DeviceIoReply + Length（16B），**Length 必须回显请求的 Length**；
  失败也用同一布局。
- HostFileSystem 用 SetVolumeLabelW（需要管理员权限）；卷根由
  `VolumeRootOf` 统一计算（与 QueryVolume 共用）。

**测试**：设置标签成功（16B、Length 回显、标签记录）、类不支持、标签长度
越界、未知句柄、ACCESS_DENIED、proto 解析/截断（rdpdr 113/1191）。
变异 M90（响应 Length 改为 0）→ 2 tests / 2 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5。

**里程碑**：客户端已通告的全部 drive IRP（CREATE/CLOSE/READ/WRITE/
DEVICE_CONTROL/QUERY_VOLUME/SET_VOLUME/QUERY_INFORMATION/SET_INFORMATION/
DIRECTORY_CONTROL/LOCK_CONTROL）均有处理路径。

**未验证**：SetVolumeLabelW 需管理员权限且无单测；本机服务器不发该 IRP，
未端到端。
## 串口重定向第一层（批177，2026-11-07）

**依据**：[MS-RDPEFS] 2.2.2.7.3 PORT_CAPS_SET、2.2.1.3 DEVICE_ANNOUNCE
（RDPDR_DTYP_SERIAL = 0x00000001）、2.2.3.3.1 DR_CREATE_REQ、2.2.1.4.3/4
DR_READ/WRITE_REQ、2.2.1.5.5 DR_CONTROL_RSP。

**实现**：
- 新增 `rdpdr::ISerialBackend`（Open/Read/Write/Close/Control），平台中立，
  由 Win32 COM 层或测试替身实现。
- `RdpdrClient::Device` 增加 `type`（kDrive/kSerial）；`EnableSerial(backend)`
  必须在首个入站消息前调用（与 EnableSmartCard 同）。
- 能力：存在串口设备时通告 PORT_CAPS_SET（类型 0x0003、版本 1、仅头 8B）。
- 设备列表：串口设备以 RDPDR_DTYP_SERIAL 通告，DosName 为端口名（COM1）。
- CREATE：串口设备直接调用 backend->Open(dos_name)，句柄 id 从 0x40000000
  起分配（避免与文件系统 id 冲突）；失败/未启用后端 → ACCESS_DENIED。
- READ/WRITE/DEVICE_CONTROL：按句柄路由到串口后端；READ 忽略 offset；
  CONTROL 成功 → DeviceIoReply + Length + OutputBuffer。
- CLOSE/RemoveDevice/Reset：关闭串口句柄并清理映射。

**测试**：5 个用例（通告类型+PORT caps、create/read/write/close、无后端
fail-closed、control 路由、RemoveDevice 关闭句柄，rdpdr 118/1234）。
变异 M91（IsSerialDevice 把串口当磁盘）→ 3 tests / 22 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5。

**未验证**：Win32 COM 后端未实现；GUI/`.rdp` redirectcomports 未接线；
串口 IOCTL 语义由后端决定，未真机验证。
## Win32 串口后端（批178，2026-11-07）

**实现**：
- `rdpdr::Win32SerialBackend`（include/rtsc/rdpdr/serial_win32.h +
  src/rdpdr/serial_win32.cpp，加入 rtsc_rdpdr）：
  - Open：CreateFileW("\\\\.\\COMx")，9600 8N1、无流控，SetCommState +
    SetCommTimeouts（读 100ms 短超时，写同步）；
  - Read/Write：ReadFile/WriteFile（短超时短读）；
  - Close：CloseHandle 并移除句柄；
  - Control：DeviceIoControl 透传，输出缓冲上限 4096B；
  - 析构关闭全部端口。
- `EnumerateSerialPorts()`：QueryDosDeviceW 枚举 COM+数字设备名，排序返回。

**测试**：缺失端口 Open 返回 0；未知句柄的 Read/Write/Close/Control 全部
拒绝（rdpdr 120/1239）。变异 M92（失败仍返回句柄 id）→ 1 test / 1 check 红；
恢复后全绿。

**验收**：C0 零错误零警告；`ctest -R "^(rdpdr|smartcard_channel|drive_enum|client|server)$"`
5/5。

**未验证**：真实 COM 端口的读写/IOCTL 未验证（无硬件）；GUI/`.rdp`
redirectcomports 尚未接线；串口 IOCTL 语义依赖服务器发送的
IOCTL_SERIAL_*。
## 打印机设备重定向（批180，2026-11-07）

**事实来源**：[MS-RDPEFS] 2.2.1.3 / 2.2.2.7.2（PRINTER_CAPS_SET）、
[MS-RDPEPC] 2.2.2.3（RDPDR_PRINTER_ANNOUNCE）。

**实现**：
- `rdpdr::IPrinterBackend`（include/rtsc/rdpdr/printer_backend.h）：
  OpenJob(printer_name)→job id（0=失败）、Write(job, data)、CloseJob(job)。
- `EncodePrinterAnnounce(flags, driver, printer, pnp={})`：
  Flags(4)+CodePage(4，固定 0)+PnPNameLen(4)+DriverNameLen(4)+
  PrintNameLen(4)+CachedFieldsLen(4)=24B 头；Driver/Printer 名 UTF-16LE
  含结尾 NUL；PnPNameLen 为 0 表示无 PnP 名。
- 客户端：`DeviceType::kPrinter` + `EnablePrinter`；create→OpenJob（失败
  ACCESS_DENIED）、write→Write（失败 UNSUCCESSFUL）、close→CloseJob、
  control→NOT_SUPPORTED；打印机文件 id 从 0x50000000 分配。
- caps：存在打印机设备时追加 CAP_PRINTER_TYPE=0x0002、版本 1、长度 8。
- 通告：RDPDR_DTYP_PRINT=0x4，DeviceData 为上述 announce 结构，
  PreferredDosName 用 "PRN<digits>"。

**证据**：`tests/test_rdpdr.cpp` 的 `rdpdr_printer_announce_encodes` 校验
24B 头与名称长度；`tests/test_rdpdr_client.cpp` 的
`rdpdr_printer_device_is_announced` 校验 caps 类型、通告 device_type=4 与
DeviceData 头；`rdpdr_printer_create_write_close` 校验 OpenJob/Write/
CloseJob 路由与计数；`rdpdr_printer_create_without_backend_fails_closed`、
`rdpdr_printer_control_fails_closed` 校验失败路径。rdpdr 125/1285 全绿；
M94（通告 device_type 误用 Filesystem）→ 1 test / 1 check 红，恢复后全绿。

**未验证**：真实打印机端到端（无硬件）；打印 DEVICE_CONTROL（print
IOCTL）未实现；Win32 后端与 GUI 接线在批181。
## Win32 打印机后端（批181，2026-11-07）

**实现**：
- `rdpdr::Win32PrinterBackend`（include/rtsc/rdpdr/printer_win32.h +
  src/rdpdr/printer_win32.cpp，加入 rtsc_rdpdr，链接 winspool）：
  - OpenJob：OpenPrinterW(queue) → StartDocPrinterW(level 1,
    DOC_INFO_1W{pDocName="RTSC Print Job", pDatatype="RAW"}) →
    StartPagePrinter；任一步失败回滚并返回 0。
  - Write：WritePrinter，短写（written != size）视为失败。
  - CloseJob：EndPagePrinter → EndDocPrinter → ClosePrinter。
  - 析构关闭全部未完成作业。
- `EnumeratePrinters()`：EnumPrintersW(PRINTER_ENUM_LOCAL |
  PRINTER_ENUM_CONNECTIONS, level 2) 两段式缓冲，返回 name/driver
  （UTF-8）。
- GUI 在 `--redirect-printers`/`RTSC_REDIRECT_PRINTERS`/`.rdp
  redirectprinters` 时通告全部队列并 `EnablePrinter`。

**证据**：`rdpdr_win32_printer_backend_rejects_unknown_jobs`（空队列名
OpenJob=0、未知 job 的 Write/Close 拒绝、枚举不崩溃），rdpdr 126/1289；
M95 针对 rdp_file 解析（1 test/2 checks 红），恢复后全绿；影响面
`ctest -R "^(rdpdr|rdp_file|mstsc_args|drive_enum|client|gui_send)$"` 6/6。

**未验证**：真实打印机端到端（无硬件/不实际打印）；打印机 DEVICE_CONTROL
仍为 NOT_SUPPORTED；RAW 数据由本地驱动渲染，跨驱动兼容性未验证。
## FileId 复用（批182，2026-11-07）

**事实来源**：[MS-RDPEFS] 2.2.1.5.1 Device Create Response ——
“FileId ... The ID MUST be reused after sending a Device Close Response”。

**实现**：
- `HostFileSystem`：新增空闲 id 栈；`AllocateId()` 优先复用，`Close()` 归还
  （`files_.erase` 成功才归还）。
- `RdpdrClient`：串口/打印机各自维护 `free_serial_file_ids_` /
  `free_printer_file_ids_`；Create 优先复用，Close 与 RemoveDevice 归还，
  Reset 清空（计数器不跨会话回退）。

**证据**：`rdpdr_host_file_system_reuses_closed_file_ids`（打开 A、B→关闭 A
→重开→id 等于 A）；`rdpdr_serial_reuses_closed_file_ids`、
`rdpdr_printer_reuses_closed_file_ids`（两次 Create id 不同，关闭首个后
新建复用其 id）。rdpdr 129/1313 全绿；M96（串口 Create 永不复用）→
1 test / 1 check 红，恢复后全绿；影响面
`ctest -R "^(rdpdr|rdpdr_server|rdpdr_server_io|drive_enum|client|server)$"`
6/6。

**未验证**：无跨会话 id 复用语义验证（Reset 后计数器不回退，符合规范“关闭后
复用”而非“会话重置”）；并发多 Create 的 id 唯一性由单线程通道模型保证。

## 打印机 WRITE 完成长度（批188，2026-11-07）

**事实**：[MS-RDPEPC] 3.2.5.1.10 —— 客户端 MUST 把 DR_WRITE_RSP 的 Length 设为
成功写入打印设备的字节数（并非请求长度），因此部分写入必须以“成功 + 较小
Length”表达，而不是失败。

**缺陷**：`IPrinterBackend::Write` 仅返回 bool，`RdpdrClient::OnWrite` 用
`req.data.size()` 填 Length；`Win32PrinterBackend::Write` 在
`WritePrinter` 短写（pcWritten < size）时返回 false。

**实现**：`Write(job, data, uint32_t& written)`；Win32 后端 `written=pcWritten`，
`WritePrinter` 成功即为成功（允许部分）；客户端 `response.length = written`。

**证据**：`tests/test_rdpdr_client.cpp` 新增
`rdpdr_printer_write_reports_bytes_written`（短写 2/4 → Length=2、
IoStatus=SUCCESS）；rtsc_rdpdr_tests 130 tests / 1321 checks 全绿；影响面 6/6。
变异 M105（回填 req.data.size()）→ 该测试红（got 4, want 2），恢复后绿。

**未验证**：真实服务器在收到短写完成后的续写策略（重发剩余或重发整块）。