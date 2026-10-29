# RDPSND 对齐证据（rdpsnd-evidence.md）

状态：初始锚点定位。A5=取证 mstsc rdpsnd 音频格式协商默认值（wave2 等）与规范之上的差异。

## 目标二进制
mstscax.dll sha256 d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05

## 已定位锚点（REA/Ghidra 12.1.4）
- 0x1807e6fb0 "rdpsnd static channel connecting..."
- 0x1807e6f70 "ChannelOnConnected for [rdpsnd]"
- 0x1807e6ef0 "rdpsnd static channel connected. Connection time = %I64u ms"
- 0x1807e7020 string "CRdpSndPlugin"
- 0x18081c378 "Failed to load RDPSND plugin"
- 0x18081c3e8 "Failed to load Internal RDPSND"
- 0x1807a4a68 "DisableRDPSNDSVC"（TS_PROP_WIN32CORE_DISABLE_RDPSND_SVC）
- 0x1807a4ae0 "Failed to set TS_PROP_WIN32CORE_DISABLE_RDPSND_SVC"
- xrefs "CRdpSndPlugin" -> FUN_1804f5274（CreateInstance/工厂）

## 待取证（A5）
1. 音频格式协商：wave PDU（TSSNDCAPS）的 formatCount / formats[] 默认集（wave2 PcmWaveFormat 44100 16bit stereo 等）。
2. QualityMode 协商与默认值。
3. Volume 设置 PDU（SNDSTREAM 状态机）与 mstsc 默认音量。
4. 仓内 src/proto/rdpsnd* / src/channel/rdpsnd* 现状对照（tests Test #31/32）。
- [ ] TSSNDCAPS 默认格式集取证（wave2）
- [ ] 与 rdpsnd 通道实现对照## 取证批次 2（2026-10-28 轮次 101）：TSSNDCAPS 运行时构造
- CRdpSndPlugin 构造器 FUN_1804f5274（名字段"CRdpSndPlugin"、类型 0xdbcaabcd、主 vtable PTR_FUN_180686268）。vtable 方法（解析已验证）：FUN_180376530/FUN_180376460（插件主方法）、FUN_1800b2b40、FUN_1800ab660、FUN_1800f37f0、FUN_1800a7de0。
- search_bytes "44 AC 00 00 10 00 02 00"（44100 PCM 16bit 2ch）全段无命中 → **TSSNDCAPS 格式数组运行时构造，静态无常量可锚**。
## 结论（A5 → 真机抓包项）
mstsc 的 rdpsnd 默认音频格式（wave2 44100/22050、PCM、块对齐）与 FILECONTENTS capset 一样非静态可锚。A5 需：
1. 真机抓包 rdpsnd 通道 SNDC_CAPS（TSSNDCAPS 数组）字节；
2. 或深层 hook/运行时追踪（成本高）。
仓内 rdpsnd 实现已有 2 个测试套件（Test #31/#32）且实现完整；优先瞄准"差异对齐"则抓包裁决。
- [x] CRdpSndPlugin 工厂/主 vtable 定位
- [x] TSSNDCAPS 静态不可锚（→真机抓包）
## 取证批次 3（2026-10-28 轮次 109）：rdpsnd server_formats=0 根因
- 真机会话 A：audio server_formats=0、server version 0、rdpsnd chunks=0。
- 排查一：rdpsnd client 纯被动（无 Start()），规范确认 MS-RDPEA 3.1.5 初始化=**服务器先发 Server Audio Formats and Version PDU**（"Event: connected from client. Action: server sends..."）→ 被动等待正确，非协议缺口。
- 排查二：channel join 完整（connect_machine.cpp:388-396 将 channel_names 全部加 join_queue，含 "rdpsnd"）→ join 侧正常。
- **根因结论**：rdpsnd chunks=0 + server_formats=0 = **服务器未发起音频重定向**（会话策略：默认"在远程计算机播放"不向客户端发流；或远程会话禁用音频）。非本仓代码缺陷。
- **验证手段**（需服务器端配置）：在 192.168.1.7 的会话设置把音频播放改为"在此计算机播放"/"不播放"，或预期场景（有音频播放）再看 server_formats。本机无服务器配置权限，标记"待服务器侧配合"。
- 关联：rdpsnd client 的 SelectFormat/send ClientAudioFormats/QualityMode 路径在测试网套件（31/32）全绿；缺失的是真机服务器主动发流场景。
