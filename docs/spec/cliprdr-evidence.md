# CLIPRDR 对齐证据（cliprdr-evidence.md）

状态：初始取证。目标=确认 mstsc 在 [MS-RDPECLIP] 之上的实现偏差。

## 目标二进制
mstscax.dll sha256 `d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05`
（C:\Windows\System32\mstscax.dll，9,166,848 B，与立项取证件一致）

## 已定位锚点（REA/Ghidra 12.1.4）
- `0x1807f8150` string "CLIPRDR"
- `0x1807f82d0` string "RdpClipRdrWindowClass"
- `0x1807f8440` "cliprdr static channel connecting..."
- `0x1807f8490` "ChannelOnConnected for [cliprdr]"
- `0x1807f84e0` "cliprdr static channel connected. Connection time = %I64u ms"
- `0x1807f8600` "CClientClipRdrPduDispatcher::CreateInstance failed!"
- `0x18081aab8` string "CClientClipRdrPduDispatcher"
- `0x18081ab28` "Failed to initialize CClientClipRdrPduDispatcher!"
- `0x18081abd0/18081ac70` base dispatcher init/term failure strings

## 构造与虚表
`FUN_180658114` = CClientClipRdrPduDispatcher 构造器：
- 类型标识 `0xdbcaabcd`（@+0x18）
- 类名字符串指针 @+0x10
- vtable 三表：`&PTR_FUN_18066f120`（主表）、`&PTR_FUN_1806991c8`、`&PTR_FUN_1806991a8`
- 引用点：0x18065812a / 0x180658131（工厂 CreateInstance 失败串@0x1807f8600 附近域）

主虚表 `PTR_FUN_18066f120` 首 136B 函数指针（待解码）：
`10e7038001000000 70e7038001000000 80d2028001000000 d03f0f8001000000 ...`
（每项 8B 小端 = 绝对 VA；后续取值待 address_name 解码）

## 待办（A4 取证续）
1. 解码主虚表所有条目名称 → 定位 OnPdu / Format List 处理函数。
2. 取证 mstsc 的 capability set 固定值（Gemini flags、版本），对照 `KBASIC_*`/`K_*` 常量。
3. 格式化名协商默认（长/短）与 `CliprFormatNames` 使用。
4. TempDir（kTempDirectoryUsed）协商路径、文件列表 CF_HDROP 路径格式。
5. 锁定"规范之上偏差"清单，逐条与 `src/channel/cliprdr_client.cpp` 对照。
- [ ] (§1) 虚表解码
- [ ] (§2-§5) 偏差项定位与对照

## 取证批次 2（2026-10-28 轮次 99）：虚表解码 + 事件源架构

### vtable（CClientClipRdrPduDispatcher 三表，构造 FUN_180658114 @0x180658114）
主表 PTR_FUN_1806991a8（8 项首列，RVA+base=VA 已验证）：
- 0x1800e40b0 FUN_1800e40b0（析构/未知）
- 0x1800a2ca0 FUN_1800a2ca0（基类）
- 0x1800a56b0 FUN_1800a56b0（基类）
- 0x180658670 FUN_180658670（dispatcher 同区）
- 0x180658430 FUN_180658430（dispatcher 同区）
- 0x1800f0020 FUN_1800f0020
- 0x180658eb0 FUN_180658eb0 = **Init：创建 event sources**
- 0x180659680 FUN_180659680 = **析构：移除 event sources**

### 事件源架构发现（关键：架构差异点）
`FUN_180658eb0`（9234B）创建并登记事件源（event source），OS event ID：
- 0x9b → FORMAT_LIST event source
- 0x9c → FORMAT_LIST_RESPONSE event source
- …(后续见 0x9d+ FORMAT_DATA_REQUEST / FORMAT_DATA_RESPONSE 等)
`FUN_180659680`（7981B）析构逐源移除；失败日志 "Failed to remove FORMAT_LIST event source!"

推断（待验证）：mstsc 对每个 cliprdr PDU 类别维护独立"事件源"，发送由事件触发而非同步直发——
与 `src/channel/cliprdr_client.cpp` 当前的同步 OnPdu 直发架构不同。
**需对照**：我们的实现是否需引入异步队列以对齐 mstsc 的时序（尤其发送顺序/合并行为）。

### 待办推进
- [x] (§1) 虚表解码（三表已定位 0x1806991a8/1c8/0x18066f120）
- [ ] 取证 PDU 类型分派表（FORMAT_DATA_REQUEST/RESPONSE/锁/临时目录）
- [ ] Capability set 固定值与协商默认
- [ ] 格式名长短默认、CF_HDROP 路径、TempDir
- [ ] 与 cliprdr_client.cpp 对照出"规范之上偏差"清单

## 取证批次 3（2026-10-28 轮次 100）：onPDU dispatch 表完整解码

`FUN_180658670`（11798B）= CClientClipRdrPduDispatcher::OnPDU 主分派（param_2=CLIPRDR_HEADER 指针，uVar1=*param_2 ushort）。

### msgType → handler 完整映射（伪代码分支 uVar1==N）
| uVar1 | handler（失败串） | 规范 [MS-RDPECLIP] 2.2.2 |
|---|---|---|
| 1 | FORMAT_LIST | CB_FORMAT_LIST=0x0001（规范） |
| 2 | FORMAT_LIST_RESPONSE | CB_FORMAT_LIST_RESPONSE=0x0002 |
| 3 | FORMAT_DATA_REQUEST | CB_FORMAT_DATA_REQUEST=0x0003 |
| 4 | FORMAT_DATA_RESPONSE | CB_FORMAT_DATA_RESPONSE=0x0004 |
| 5 | CLIP_CAPS | CB_CLIP_CAPS=0x0007 |
| (无6) | （temp directory 无独立分派） | CB_TEMP_DIRECTORY=0x0006 |
| 7 | FILECONTENTS_REQUEST | CB_FILECONTENTS_REQUEST=0x0008 |
| 8 | FILECONTENTS_RESPONSE | CB_FILECONTENTS_RESPONSE=0x0009 |
| 10 | LOCK_CLIPDATA | CB_LOCK_CLIPDATA=0x000A |
| 11 | UNLOCK_CLIPDATA | CB_UNLOCK_CLIPDATA=0x000B |
| 12 | DATA_CHANNEL_REQUEST | （非基础规范；大剪贴板分片扩展） |
| 13 | DATA_CHANNEL_RESPONSE | （同上） |
| else | UNKNOWN_PDU（有独立 handler，记录未知类） | |

### 对照 `include/rtsc/proto/cliprdr.h` enum（仓内实现）
仓内：kFormatList=2、kFormatDataRequest=3、…=按规范 1 起。

**疑似差异（需抓包/wire 确证，否则只可标 UNVERIFIED）**：
- A) mstsc 的 uVar1 直接用于分支且**无-1 调整**；若 wire 字节 == 规范值（FORMAT_LIST=0x0001），则 mstsc 的 CLIP_CAPS=5 ≠ 规范 7、FILECONTENTS=7≠8 → mstsc 用**自定义 msgType 表**？
- 但更可能：Ghidra 把 CLIPRDR_HEADER.msgType(高字)读作 uVar1 时语义已对齐规范 1-5；则 case5=CLIP_CAPS 意味规范 CLIP_CAPS=7 错位 → 矛盾。
- **裁决路径**：抓真实会话的 cliprdr 字节（FORMAT_LIST PDU 首 4 字节），或查发送函数写入的常量。
- B) mstsc 有 **DATA_CHANNEL_REQUEST/RESPONSE(0xC/0xD)** 扩展，**仓内缺失**。
- C) mstsc **无独立 TEMP_DIRECTORY 分派**（0x6 无 case），TempDir 处理可能并入其他地方。

### 待办
- [x] 分派表（FORMAT_DATA_REQUEST/RESPONSE/锁/FILECONTENTS/CLIP_CAPS/DATA_CHANNEL/UNKNOWN）
- [ ] 发送方向：FORMAT_LIST 发送时 msgType 字段写入值（裁决 A）
- [ ] Capability set 固定值（版本/长度）
- [ ] 与 cliprdr_client.cpp 对照出偏差清单
