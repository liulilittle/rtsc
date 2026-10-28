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
