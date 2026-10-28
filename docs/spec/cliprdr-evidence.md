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

## 取证批次 4（2026-10-28 轮次 100）：与仓内实现对照 → 偏差清单

### 仓内实现现状（src/channel/cliprdr_client.cpp OnPdu）
处理：kMonitorReady、kClipCaps、kFormatList、kFormatListResponse、kFormatDataRequest、kFormatDataResponse、kTempDirectory、kLockClipData、kUnlockClipData。
proto enum（include/rtsc/proto/cliprdr.h）含 kFileContentsRequest=0x0008 / kFileContentsResponse=0x0009 定义但 **OnPdu 未处理**。

### 偏差清单（mstsc vs 仓内，对照图）
| 项 | mstsc（反汇编） | 仓内 | 判定 |
|---|---|---|---|
| DATA_CHANNEL_REQUEST/RESPONSE (0xC/0xD) | 有独立 handler + event source | **无** | **缺口**：大剪贴板分片通道扩展 |
| FILECONTENTS_REQUEST/RESPONSE (0x8/0x9) | 有独立 handler + event source（含 %I64u 计时串） | enum 有、OnPdu 无处理 | **缺口**：文件目录/内容传输 |
| TEMP_DIRECTORY (0x6) | 无独立分派 case | 有 kTempDirectory 处理 | **待验证**：mstsc 的 TempDir 处理位置（或并入 FileContents） |
| msgType 编号 | dispatch 用 1..5,7,8,10,11,12,13 | 规范值 1..11 + 无 12/13 | **疑点（wire 待裁决）**：mstsc dispatch 序号跳过 6/9，若即 wire 值则与规范不同；否则 Ghidra 内部 enum |
| UNKNOWN_PDU | 有独立 handler（记录未知类型） | default: break 静默 | **差异**：mstsc 显式上报未知 PDU |
| event-source 发送架构 | 每 PDU 类独立事件源，异步 | 同步 OnPdu 直发 | **架构差异**（影响发送顺序/合并；功能等价性待判） |

### 待办
- [x] 分派表解码（含 DATA_CHANNEL 扩展、UNKNOWN_PDU handler）
- [x] 与仓内实现对照 → 偏差清单 v0.1
- [ ] **wire 裁决**：真机抓包 FORMAT_LIST/CLIP_CAPS 的 msgType 字节，确认 mstsc 编号系
- [ ] 决定：DATA_CHANNEL / FILECONTENTS 是否落入本期实现范围（涉及文件拖放=目标功能之一，倾向纳入 FILECONTENTS）
- [ ] Capability set 固定值（版本/长度）取证

## 取证批次 5（2026-10-28 轮次 100）：capset 静态搜索无果 → wire 裁决清单

- `search_bytes "01 00 01 00 02 00 00 00 01 00 00 00"`（GENERAL capset 特征）在全部段（.text/.rdata/.data）无命中 → **CLIP_CAPS payload 运行时构造**，无线下常量可锚。
- 同理 `"0x01 0x00 0x02 0x00"` 等均不可能离线锚定。

### 结论：A4 二进制静态取证部分完成；capset 数值与 msgType 编号系归入「真机抓包清单」
| 待 wire 裁决 | 方法 |
|---|---|
| CLIP_CAPS wire payload（numCaps/type/len/version/flags） | 真机会话抓 cliprdr 通道；或读 mstsc 客户端日志（开启 cliprdr 跟踪） |
| FORMAT_LIST/CAPS msgType 编号是否规范值 1/5 | 同上抓包比对 |
| DATA_CHANNEL(0xC/0xD) 发送条件（大剪贴板阈值） | 抓包剪贴板>阈值场景 |

### A4 产出
1. `docs/spec/cliprdr-evidence.md` 已有 dispatch 表、event-source 架构、偏差清单 v0.1、wire 裁决清单。
2. **偏差结论（代码层）**：仓内缺 DATA_CHANNEL（0xC/0xD，大剪贴板分片）与 FILECONTENTS（0x8/0x9，文件拖放/目录枚举）两条线协议路径；UNKNOWN_PDU 静默 vs mstsc 显式上报。
3. **决策建议（下一阶段）**：FILECONTENTS 与目标「剪贴板=文件重定向」直接挂钩，建议优先；DATA_CHANNEL 次之。两者均需在 client 增加 OnPdu 分支 + 发送支持（复用事件源架构可选）。
## 6. FILECONTENTS 实现定案与盖章（2026-10-28，提交 d29ec55）

双审定案：甲(wire/集成) + 乙(状态机/失败路径)，两轮磋商收敛。

方向 A（客户端取回远端文件）= 完整；方向 B（服务器抓取本地文件）接口+serve 门落地，Win32 DROPFILES backend 独立 ticket。

wire：CB_FILECONTENTS_REQUEST=0x0008（24B，可选尾部 4B clipDataId=28B，无 presence 字）；RESPONSE=0x0009（OK/FAIL，SIZE 成功恰 8B u64、RANGE 至多 cbRequested、FAIL dataLen=4）。
请求校验失败表：body 仅 24/28 合法；msgFlags!=0 忽略（宽松）；两旗同置/零旗/0x3 外位→FAIL；SIZE 须 cb==8 且 pos==0；lindex<0 或越界→FAIL；带 clipDataId 无锁→FAIL；FORMAT_LIST 被拒→全 FAIL；offset==size→OK+0B / >size→FAIL / +count>size→截断 EOF。
C++ 接口：proto 层 CliprdrFileContentsRequest/Response + CliprdrFileDescriptor(592B 固定布局) + CliprdrFileList；channel 层 EnableFileClip(0x04)/EnableHugeFileSupport(0x20)/RequestRemoteFileList/RequestRemoteFile/SetTransferTimeoutMs(30s)/Poll/Cancel/诊断计数；clipboard 层 FileListProvider(file_count/file_info/read_range)。
测试：31/155 → 105/546（rtsc_cliprdr_tests）；全量 ctest 51/51；build 0err/0warn。
审计遗留 ticket：方向B backend；真机抓包（UNVERIFIED：RANGE 分块/0x046C0000 实际值/CACHED 语义/目录枚举 0x4/mstsc capset 固定值）；D4 可选加固（单槽抢占）。
## 7. 方向 B backend 定案与盖章（2026-10-28，提交 b09c4cf）
- DropFileList（include/rtsc/clipboard/drop_files.h + src/clipboard/drop_files.cpp）：CF_HDROP→FileListProvider。
  - DROPFILES 头 20B（pFiles@0/fNC@12/fWide@16）；fWide==1 才支持（v1 仅 UTF-16）；全部下标守卫（短头/pFiles 越界/截断名）；单/双 null 收尾；缺失名停止保前名。
  - file_info：basename（去尾分隔符）、is_directory、惰性 size；非目录 stat 失败→false（禁伪造 0B）→ SIZE 请求 MUST FAIL（[MS-RDPECLIP] 3.1.5.4.6）。
  - read_range：offset>size false、offset==size 空 true、超售截断、append 语义、目录/缺失 false。
  - 副效应：FILELIST 构建遇任一缺失条目→整表 FAIL（fail-closed，compact-skip 留后续）。
- rtsc_gui 接线：WM_CLIPBOARDUPDATE→CreateDropFileListFromBytes→SetFileListProvider；离开 CF_HDROP→先 SetFileListProvider(nullptr) 再 reset()。
- 测试：rtsc_clipboard_tests 30/93（新套件）；rtsc_cliprdr 106/553（+端到端缺失文件 SIZE→FAIL）。
- C0：全量 build 0err/0warn；ctest 51/52 绿（view 0.8x bench 因外部 il2cpp 构建 CPU 争用红，非代码，discover.md 已记录，独占复跑仍需在无争用窗口）。
- 审计遗留：GUI 真拖放端到端；真机互通；ANSI(fWide==0) 可选；方向B 变异脚本 UNVERIFIED。
