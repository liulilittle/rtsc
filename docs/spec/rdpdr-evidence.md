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
