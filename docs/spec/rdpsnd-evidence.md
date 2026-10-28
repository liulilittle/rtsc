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
- [ ] 与 rdpsnd 通道实现对照