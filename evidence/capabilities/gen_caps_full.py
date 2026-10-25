# -*- coding: utf-8 -*-
# Generate the per-capability byte-layout sections for docs/spec/capabilities.md.
# Field widths and section numbers are taken verbatim from the official DOCX text
# ([MS-RDPBCGR] v62.0 / [MS-RDPEGDI] / [MS-RDPERP] / [MS-RDPRFX]); offsets are
# computed by summation so they cannot drift. Verified against official dumps
# 4.1.12 / 4.1.13 by F:\rtsc\.tmp\verify_caps.py.

OUT = r'F:\rtsc\.tmp\caps_full.md'

# (type, name, section, sent_by, note, [ (offset, width, field, desc) ... ])
CAPS = []

def cap(t, name, section, sent_by, note, fields):
    CAPS.append((t, name, section, sent_by, note, fields))

cap(0x0001, 'General Capability Set（`TS_GENERAL_CAPABILITYSET`）', '2.2.7.1.1（S13）',
    'client ⇄ server', '基于 [T128] §8.2.3。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_GENERAL (1)`'),
     (2, 2, 'lengthCapability', 'MUST = 24（含本 4 字节头）'),
     (4, 2, 'osMajorType', '平台类型：0x0000 UNSPECIFIED / 0x0001 WINDOWS / 0x0002 OS2 / 0x0003 MACINTOSH / 0x0004 UNIX / 0x0005 IOS / 0x0006 OSX / 0x0007 ANDROID / 0x0008 CHROME_OS'),
     (6, 2, 'osMinorType', '平台版本：0x0000 UNSPECIFIED / 0x0001 WINDOWS_31X / 0x0002 WINDOWS_95 / 0x0003 WINDOWS_NT / 0x0004 OS2_V21 / 0x0005 POWER_PC / 0x0006 MACINTOSH / 0x0007 NATIVE_XSERVER / 0x0008 PSEUDO_XSERVER / 0x0009 WINDOWS_RT'),
     (8, 2, 'protocolVersion', 'MUST = `TS_CAPS_PROTOCOLVERSION (0x0200)`'),
     (10, 2, 'pad2octetsA', '填充，MUST 忽略'),
     (12, 2, 'compressionTypes', 'MUST = 0'),
     (14, 2, 'extraFlags', '见下方 extraFlags 表'),
     (16, 2, 'updateCapabilityFlag', 'MUST = 0'),
     (18, 2, 'remoteUnshareFlag', 'MUST = 0'),
     (20, 2, 'compressionLevel', 'MUST = 0'),
     (22, 1, 'refreshRectSupport', '**server-only**：0x00 = 不支持 Refresh Rect PDU；0x01 = 支持'),
     (23, 1, 'suppressOutputSupport', '**server-only**：0x00 = 不支持 Suppress Output PDU；0x01 = 支持'),
    ])

cap(0x0002, 'Bitmap Capability Set（`TS_BITMAP_CAPABILITYSET`）', '2.2.7.1.2（S14）',
    'client ⇄ server', '基于 [T128] §8.2.4。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_BITMAP (2)`'),
     (2, 2, 'lengthCapability', 'MUST = 28'),
     (4, 2, 'preferredBitsPerPixel', '服务端 MUST 置为会话色深；客户端 SHOULD 置为 Client Core Data（2.2.1.3.2）中请求的色深'),
     (6, 2, 'receive1BitPerPixel', '**被忽略**，SHOULD = TRUE (0x0001)'),
     (8, 2, 'receive4BitsPerPixel', '**被忽略**，SHOULD = TRUE (0x0001)'),
     (10, 2, 'receive8BitsPerPixel', '**被忽略**，SHOULD = TRUE (0x0001)'),
     (12, 2, 'desktopWidth', '会话桌面宽度（像素）'),
     (14, 2, 'desktopHeight', '会话桌面高度（像素）'),
     (16, 2, 'pad2octets', '填充，MUST 忽略'),
     (18, 2, 'desktopResizeFlag', '0x0000 = 不支持通过 Deactivation-Reactivation 改分辨率；0x0001 = 支持'),
     (20, 2, 'bitmapCompressionFlag', '**MUST = TRUE (0x0001)**——压缩位图是连接继续的必要条件'),
     (22, 1, 'highColorFlags', '**被忽略**，SHOULD = 0'),
     (23, 1, 'drawingFlags', '见下方 drawingFlags 表'),
     (24, 2, 'multipleRectangleSupport', '**MUST = TRUE (0x0001)**——多矩形是连接继续的必要条件'),
     (26, 2, 'pad2octetsB', '填充，MUST 忽略'),
    ])

cap(0x0003, 'Order Capability Set（`TS_ORDER_CAPABILITYSET`）', '2.2.7.1.3（S15）',
    'client ⇄ server', '基于 [T128] §8.2.5。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_ORDER (3)`'),
     (2, 2, 'lengthCapability', 'MUST = 88'),
     (4, 16, 'terminalDescriptor', '**被忽略**，SHOULD 全 0'),
     (20, 4, 'pad4octetsA', '填充，MUST 忽略'),
     (24, 2, 'desktopSaveXGranularity', '**被忽略**，假定为 1'),
     (26, 2, 'desktopSaveYGranularity', '**被忽略**，假定为 20'),
     (28, 2, 'pad2octetsA', '填充，MUST 忽略'),
     (30, 2, 'maximumOrderLevel', '**被忽略**，SHOULD = `ORD_LEVEL_1_ORDERS (1)`'),
     (32, 2, 'numberFonts', '**被忽略**，SHOULD = 0'),
     (34, 2, 'orderFlags', '见下方 orderFlags 表'),
     (36, 32, 'orderSupport', '32 字节数组，下标 = 主绘图订单协商索引；支持则置 0x01。索引表见 §9.4'),
     (68, 2, 'textFlags', '**MUST 被忽略**'),
     (70, 2, 'orderSupportExFlags', '0x0002 `ORDERFLAGS_EX_CACHE_BITMAP_REV3_SUPPORT`；0x0004 `ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT`'),
     (72, 4, 'pad4octetsB', '填充，MUST 忽略'),
     (76, 4, 'desktopSaveSize', '**被客户端忽略**，假定 230400 字节（480×480）'),
     (80, 2, 'pad2octetsC', '填充，MUST 忽略'),
     (82, 2, 'pad2octetsD', '填充，MUST 忽略'),
     (84, 2, 'textANSICodePage', '客户端 ANSI 代码页；**被客户端忽略**，服务端 SHOULD 置 0'),
     (86, 2, 'pad2octetsE', '填充，MUST 忽略'),
    ])

cap(0x0004, 'Bitmap Cache Capability Set, Revision 1（`TS_BITMAPCACHE_CAPABILITYSET`）', '2.2.7.1.4.1（S16）',
    '**仅 client → server**', '客户端还 MUST 支持 MemBlt / Mem3Blt 主绘图订单才能接收 Cache Bitmap (Rev 1) 二级订单。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_BITMAPCACHE (4)`'),
     (2, 2, 'lengthCapability', 'MUST = 40'),
     (4, 4, 'pad1', '填充，MUST 忽略'),
     (8, 4, 'pad2', '填充，MUST 忽略'),
     (12, 4, 'pad3', '填充，MUST 忽略'),
     (16, 4, 'pad4', '填充，MUST 忽略'),
     (20, 4, 'pad5', '填充，MUST 忽略'),
     (24, 4, 'pad6', '填充，MUST 忽略'),
     (28, 2, 'Cache0Entries', 'Bitmap Cache 0 条目数，**上限 200**'),
     (30, 2, 'Cache0MaximumCellSize', 'Bitmap Cache 0 最大单元尺寸'),
     (32, 2, 'Cache1Entries', 'Bitmap Cache 1 条目数，**上限 600**'),
     (34, 2, 'Cache1MaximumCellSize', 'Bitmap Cache 1 最大单元尺寸'),
     (36, 2, 'Cache2Entries', 'Bitmap Cache 2 条目数，**上限 65535**'),
     (38, 2, 'Cache2MaximumCellSize', 'Bitmap Cache 2 最大单元尺寸'),
    ])

cap(0x0005, 'Control Capability Set（`TS_CONTROL_CAPABILITYSET`）', '2.2.7.2.2（S29）',
    '**仅 client → server**（服务端忽略内容）', '完整定义见 [T128] §8.2.10。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_CONTROL (5)`'),
     (2, 2, 'lengthCapability', 'MUST = 12'),
     (4, 2, 'controlFlags', 'SHOULD = 0'),
     (6, 2, 'remoteDetachFlag', 'SHOULD = FALSE (0x0000)'),
     (8, 2, 'controlInterest', 'SHOULD = `CONTROLPRIORITY_NEVER (0x0002)`'),
     (10, 2, 'detachInterest', 'SHOULD = `CONTROLPRIORITY_NEVER (0x0002)`'),
    ])

cap(0x0007, 'Window Activation Capability Set（`TS_WINDOWACTIVATION_CAPABILITYSET`）', '2.2.7.2.3（S30）',
    '**仅 client → server**（服务端忽略内容）', '完整定义见 [T128] §8.2.9。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_ACTIVATION (7)`'),
     (2, 2, 'lengthCapability', 'MUST = 12'),
     (4, 2, 'helpKeyFlag', 'SHOULD = FALSE (0x0000)'),
     (6, 2, 'helpKeyIndexFlag', 'SHOULD = FALSE (0x0000)'),
     (8, 2, 'helpExtendedKeyFlag', 'SHOULD = FALSE (0x0000)'),
     (10, 2, 'windowManagerKeyFlag', 'SHOULD = FALSE (0x0000)'),
    ])

cap(0x0008, 'Pointer Capability Set（`TS_POINTER_CAPABILITYSET`）', '2.2.7.1.5（S19）',
    'client ⇄ server', '基于 [T128] §8.2.11。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_POINTER (8)`'),
     (2, 2, 'lengthCapability', 'MUST = 10'),
     (4, 2, 'colorPointerFlag', '**被忽略**，恒按 TRUE 处理（0x0000 = 仅单色；0x0001 = 彩色）'),
     (6, 2, 'colorPointerCacheSize', '24-bpp 彩色指针缓存槽数（存 Color Pointer Update 数据）'),
     (8, 2, 'pointerCacheSize', '任意色深指针缓存槽数（存 New Pointer Update 数据）。**若为 0 或客户端未含此字段，服务端不会使用 New Pointer Update**'),
    ])

cap(0x0009, 'Share Capability Set（`TS_SHARE_CAPABILITYSET`）', '2.2.7.2.4（S31）',
    'client ⇄ server', '基于 [T128] §8.2.12。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_SHARE (9)`'),
     (2, 2, 'lengthCapability', 'MUST = 8'),
     (4, 2, 'nodeID', '客户端 SHOULD 置 0；服务端置为 server channel ID `0x03EA`'),
     (6, 2, 'pad2octets', '填充，MUST 忽略'),
    ])

cap(0x000A, 'Color Table Cache Capability Set（`TS_COLORTABLE_CAPABILITYSET`）', '[MS-RDPEGDI] 2.2.1.1（S79）',
    'client ⇄ server', '规范称其为"unused capability set"：实际色表缓存存在性由 MemBlt/Mem3Blt 订单支持隐含。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_COLORCACHE (0x000A)`'),
     (2, 2, 'lengthCapability', 'MUST = 8'),
     (4, 2, 'colorTableCacheSize', '**MUST 在能力交换期间忽略**，恒假定为 `0x0006`'),
     (6, 2, 'pad2octets', '任意值，MUST 忽略'),
    ])

cap(0x000C, 'Sound Capability Set（`TS_SOUND_CAPABILITYSET`）', '2.2.7.1.11（S26）',
    '**仅 client → server**', '若客户端声明 beep 支持，则 MUST 支持 Play Sound PDU（2.2.9.1.1.5）。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_SOUND (12)`'),
     (2, 2, 'lengthCapability', 'MUST = 8'),
     (4, 2, 'soundFlags', '0x0001 = `SOUND_FLAG_BEEPS`（支持播放 beep）'),
     (6, 2, 'pad2octetsA', '填充，MUST 忽略'),
    ])

cap(0x000D, 'Input Capability Set（`TS_INPUT_CAPABILITYSET`）', '2.2.7.1.6（S20）',
    'client ⇄ server', '**至少 `INPUT_FLAG_SCANCODES` MUST 置位**。服务端方向的 keyboard*/imeFileName SHOULD 为 0。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_INPUT (13)`'),
     (2, 2, 'lengthCapability', 'MUST = 88'),
     (4, 2, 'inputFlags', '见下方 inputFlags 表。**至少 `INPUT_FLAG_SCANCODES` MUST 置位**'),
     (6, 2, 'pad2octetsA', '填充，MUST 忽略'),
     (8, 4, 'keyboardLayout', '活动输入 locale 标识符（HKL），如 0x00000409 = US。**仅客户端置有效值**，SHOULD 与 Client Core Data 一致'),
     (12, 4, 'keyboardType', '键盘类型：0x1 IBM PC/XT(83) / 0x2 Olivetti ICO(102) / 0x3 IBM PC/AT(84) / 0x4 IBM enhanced(101/102) / 0x5 Nokia 1050 / 0x6 Nokia 9140 / 0x7 Japanese。**仅客户端置有效值**'),
     (16, 4, 'keyboardSubType', '键盘子类型（OEM 相关）。**仅客户端置有效值**'),
     (20, 4, 'keyboardFunctionKey', '功能键数量。**仅客户端置有效值**'),
     (24, 64, 'imeFileName', 'IME 文件名，最多 31 个 Unicode 字符 + NUL。**仅客户端置有效值**'),
    ])

cap(0x000E, 'Font Capability Set（`TS_FONT_CAPABILITYSET`）', '2.2.7.2.5（S32）',
    'client ⇄ server', '⚠ 官方 dump 4.1.12 中服务端发的该 capability **lengthCapability = 4**（缺 `fontSupportFlags`/`pad2octets`），规范注解称这是服务端 bug。**解析器必须容忍 4 字节形态**。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_FONT (14)`'),
     (2, 2, 'lengthCapability', '规范值 8；**实测服务端会发 4**'),
     (4, 2, 'fontSupportFlags', 'SHOULD = `FONTSUPPORT_FONTLIST (0x0001)`；**当 lengthCapability = 4 时此字段缺失**'),
     (6, 2, 'pad2octets', '填充，MUST 忽略；**当 lengthCapability = 4 时此字段缺失**'),
    ])

cap(0x000F, 'Brush Capability Set（`TS_BRUSH_CAPABILITYSET`）', '2.2.7.1.7（S21）',
    '**仅 client → server**', '',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_BRUSH (15)`'),
     (2, 2, 'lengthCapability', 'MUST = 8'),
     (4, 4, 'brushSupportLevel', '0x00000000 `BRUSH_DEFAULT`（RDP 4.0）/ 0x00000001 `BRUSH_COLOR_8x8`（≤8×8 彩色刷 + 缓存）/ 0x00000002 `BRUSH_COLOR_FULL`（任意尺寸）'),
    ])

cap(0x0010, 'Glyph Cache Capability Set（`TS_GLYPHCACHE_CAPABILITYSET`）', '2.2.7.1.8（S22）',
    '**仅 client → server**', '`GlyphCache` 是 10 个 `TS_CACHE_DEFINITION`（2.2.7.1.8.1，S23）的数组，每个 4 字节。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_GLYPHCACHE (16)`'),
     (2, 2, 'lengthCapability', 'MUST = 52'),
     (4, 40, 'GlyphCache[0..9]', '10 × `TS_CACHE_DEFINITION`：`CacheEntries(2) | CacheMaximumCellSize(2)`。Cache ID 0..9'),
     (44, 4, 'FragCache', '`TS_CACHE_DEFINITION`：条目上限 256，单元上限 256 字节'),
     (48, 2, 'GlyphSupportLevel', '0x0000 NONE / 0x0001 PARTIAL / 0x0002 FULL / 0x0003 ENCODE（Rev 2 Cache Glyph 订单）'),
     (50, 2, 'pad2octets', '填充，MUST 忽略'),
    ])

cap(0x0011, 'Offscreen Bitmap Cache Capability Set（`TS_OFFSCREEN_CAPABILITYSET`）', '2.2.7.1.9（S24）',
    '**仅 client → server**', '',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_OFFSCREENCACHE (17)`'),
     (2, 2, 'lengthCapability', 'MUST = 12'),
     (4, 4, 'offscreenSupportLevel', '0x00000000 = 不支持；0x00000001 = 支持'),
     (8, 2, 'offscreenCacheSize', '客户端 offscreen 位图缓存最大尺寸，**单位 KB**'),
     (10, 2, 'offscreenCacheEntries', '客户端 offscreen 位图缓存最大条目数'),
    ])

cap(0x0012, 'Bitmap Cache Host Support Capability Set（`TS_BITMAPCACHE_HOSTSUPPORT_CAPABILITYSET`）', '2.2.7.2.1（S28）',
    '**仅 server → client**', '用于声明持久化位图缓存支持。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_BITMAPCACHE_HOSTSUPPORT (18)`'),
     (2, 2, 'lengthCapability', 'MUST = 8'),
     (4, 1, 'cacheVersion', 'MUST = `TS_BITMAPCACHE_REV2 (0x01)`'),
     (5, 1, 'pad1', '填充，MUST 忽略'),
     (6, 2, 'pad2', '填充，MUST 忽略'),
    ])

cap(0x0013, 'Bitmap Cache Capability Set, Revision 2（`TS_BITMAPCACHE_CAPABILITYSET_REV2`）', '2.2.7.1.4.2（S17）',
    '**仅 client → server**', '客户端还 MUST 支持 MemBlt / Mem3Blt 才能接收 Cache Bitmap (Rev 2) 二级订单。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_BITMAPCACHE_REV2 (19)`'),
     (2, 2, 'lengthCapability', 'MUST = 40'),
     (4, 2, 'CacheFlags', '0x0001 `PERSISTENT_KEYS_EXPECTED_FLAG`（客户端将在 Connection Finalization 发 Persistent Key List PDU）；0x0002 `ALLOW_CACHE_WAITING_LIST_FLAG`（支持 cache waiting list，位图第二次命中才缓存）'),
     (6, 1, 'Pad2', '填充，MUST 忽略'),
     (7, 1, 'NumCellCaches', '位图缓存个数，**上限 5**'),
     (8, 4, 'BitmapCache0CellInfo', '`TS_BITMAPCACHE_CELL_CACHE_INFO`；条目上限 **600**；仅当 NumCellCaches ≥ 1 有效'),
     (12, 4, 'BitmapCache1CellInfo', '同上；条目上限 **600**；仅当 NumCellCaches ≥ 2 有效'),
     (16, 4, 'BitmapCache2CellInfo', '同上；条目上限 **65536**；仅当 NumCellCaches ≥ 3 有效'),
     (20, 4, 'BitmapCache3CellInfo', '同上；条目上限 **4096**；仅当 NumCellCaches ≥ 4 有效'),
     (24, 4, 'BitmapCache4CellInfo', '同上；条目上限 **2048**；仅当 NumCellCaches = 5 有效'),
     (28, 12, 'Pad3', '填充，MUST 忽略'),
    ])

cap(0x0014, 'Virtual Channel Capability Set（`TS_VIRTUALCHANNEL_CAPABILITYSET`）', '2.2.7.1.10（S25）',
    'client ⇄ server', '`VCChunkSize` 在 8 字节形态中**不存在**；仅 12 字节形态含该字段。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_VIRTUALCHANNEL (20)`'),
     (2, 2, 'lengthCapability', '8（无 VCChunkSize）或 12（含 VCChunkSize）'),
     (4, 4, 'flags', '0x00000000 `VCCAPS_NO_COMPR` / 0x00000001 `VCCAPS_COMPR_SC`（客户端支持 server→client 压缩）/ 0x00000002 `VCCAPS_COMPR_CS_8K`（服务端支持 client→server 压缩，限 RDP 4.0 bulk）'),
     (8, 4, 'VCChunkSize（可选）', '服务端发：虚拟通道 chunk 最大尺寸，MUST ∈ [`CHANNEL_CHUNK_LENGTH`, 16256]；客户端发：被服务端忽略'),
    ])

cap(0x0015, 'DrawNineGrid Cache Capability Set（`TS_DRAW_NINEGRID_CAPABILITYSET`）', '[MS-RDPEGDI] 2.2.1.2（S80）',
    '**仅 client → server**', '',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_DRAWNINEGRIDCACHE (0x0015)`'),
     (2, 2, 'lengthCapability', 'MUST = 12'),
     (4, 4, 'drawNineGridSupportLevel', '0x00000000 NO_SUPPORT / 0x00000001 SUPPORTED（Rev 1 stream bitmap 订单）/ 0x00000002 SUPPORTED_REV2（Rev 2 stream bitmap 订单）'),
     (8, 2, 'drawNineGridCacheSize', 'NineGrid 位图缓存最大尺寸（KB），当前服务端上限 **2560**'),
     (10, 2, 'drawNineGridCacheEntries', '缓存最大条目数，当前服务端上限 **256**'),
    ])

cap(0x0016, 'Draw GDI+ Capability Set（`TS_DRAW_GDIPLUS_CAPABILITYSET`）', '[MS-RDPEGDI] 2.2.1.3（S81）',
    'client ⇄ server', '只有客户端初始化 `GdipVersion` / `GdipCacheEntries` / `GdipCacheChunkSize` / `GdipImageCacheProperties`。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSTYPE_DRAWGDIPLUS (0x0016)`'),
     (2, 2, 'lengthCapability', 'MUST = 40'),
     (4, 4, 'drawGDIPlusSupportLevel', '0x00000000 `TS_DRAW_GDIPLUS_DEFAULT`（不支持）/ 0x00000001 `TS_DRAW_GDIPLUS_SUPPORTED`'),
     (8, 4, 'GdipVersion', '底层 GDI+ 1.1 子系统 build 号；**仅 client→server 实例有效**'),
     (12, 4, 'drawGdiplusCacheLevel', '0x00000000 CACHE_LEVEL_DEFAULT / 0x00000001 CACHE_LEVEL_ONE'),
     (16, 10, 'GdipCacheEntries', '`TS_GDIPLUS_CACHE_ENTRIES`（S82）：Graphics(2) Brush(2) Pen(2) Image(2) ImageAttributes(2)；上限 10/5/5/10/2'),
     (26, 8, 'GdipCacheChunkSize', '`TS_GDIPLUS_CACHE_CHUNK_SIZE`（S83）：Graphics(2) Brush(2) Pen(2) ImageAttributes(2)；上限 512/2048/1024/64 字节'),
     (34, 6, 'GdipImageCacheProperties', '`TS_GDIPLUS_IMAGE_CACHE_PROPERTIES`（S84）：ChunkSize(2) TotalSize(2) MaxSize(2)；上限 4096 B / 256 chunks / 128 chunks'),
    ])

cap(0x0017, 'Remote Programs Capability Set（RAIL）', '[MS-RDPERP] 2.2.1.1.1（S85）',
    'client ⇄ server', '声明可通过 RAIL 静态虚拟通道通信。',
    [
     (0, 2, 'CapabilitySetType', 'MUST = `CAPSTYPE_RAIL (0x0017)`'),
     (2, 2, 'LengthCapability', 'MUST = 8'),
     (4, 4, 'RailSupportLevel', '位域（bit0 在左）：bit0 `S` = `TS_RAIL_LEVEL_SUPPORTED`；bit1 `L` = DOCKED_LANGBAR；bit2 `H` = SHELL_INTEGRATION；bit3 `I` = LANGUAGE_IME_SYNC；bit4 `C` = SERVER_TO_CLIENT_IME_SYNC；bit5 `M` = HIDE_MINIMIZED_APPS；bit6 `K` = WINDOW_CLOAKING；bit7 `E` = HANDSHAKE_EX。**S 为 0 时其余位 MUST 为 0**'),
    ])

cap(0x0018, 'Window List Capability Set', '[MS-RDPERP] 2.2.1.1.2（S86）',
    'client ⇄ server', '声明支持 Windowing Alternate Secondary Drawing Orders。',
    [
     (0, 2, 'CapabilitySetType', 'MUST = `CAPSTYPE_WINDOW (0x0018)`'),
     (2, 2, 'LengthCapability', 'MUST = 11'),
     (4, 4, 'WndSupportLevel', '0x00000000 NOT_SUPPORTED / 0x00000001 SUPPORTED / 0x00000002 SUPPORTED_EX（额外支持 CLIENTAREASIZE、RPCONTENT、ROOTPARENT 字段）'),
     (8, 1, 'NumIconCaches', '图标缓存个数（Demand Active 为服务端请求值，Confirm Active 为客户端支持值）'),
     (9, 2, 'NumIconCacheEntries', '每个图标缓存的条目数'),
    ])

cap(0x0019, 'Desktop Composition Capability Set（`TS_COMPDESK_CAPABILITYSET`）', '2.2.7.2.8（S35）',
    'client ⇄ server', '',
    [
     (0, 2, 'capabilitySetType', 'MUST = `0x0019`（`CAPSETTYPE_COMPDESK`）'),
     (2, 2, 'lengthCapability', 'MUST = 6'),
     (4, 2, 'CompDeskSupportLevel', '0x0000 `COMPDESK_NOT_SUPPORTED` / 0x0001 `COMPDESK_SUPPORTED`'),
    ])

cap(0x001A, 'Multifragment Update Capability Set（`TS_MULTIFRAGMENTUPDATE_CAPABILITYSET`）', '2.2.7.2.6（S33）',
    'client ⇄ server', '界定 Fast-Path Update 分片重组的缓冲上限。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSETTYPE_MULTIFRAGMENTUPDATE (26)`'),
     (2, 2, 'lengthCapability', 'MUST = 8'),
     (4, 4, 'MaxRequestSize', '重组 Fast-Path Update 所用缓冲区大小；缓冲区必须足以容纳一个 update 的**全部**片段'),
    ])

cap(0x001B, 'Large Pointer Capability Set（`TS_LARGE_POINTER_CAPABILITYSET`）', '2.2.7.2.7（S34）',
    'client ⇄ server', '启用大指针时双方 MUST 同时交换 Multifragment Update（2.2.7.2.6）。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSETTYPE_LARGE_POINTER (27)`'),
     (2, 2, 'lengthCapability', 'MUST = 6'),
     (4, 2, 'largePointerSupportFlags', '0x0001 `LARGE_POINTER_FLAG_96x96`；0x0002 `LARGE_POINTER_FLAG_384x384`（含 Fast-Path Large Pointer Update）'),
    ])

cap(0x001C, 'Surface Commands Capability Set（`TS_SURFCMDS_CAPABILITYSET`）', '2.2.7.2.9（S36）',
    'client ⇄ server', '若客户端声明支持 surface commands，MUST 同时在 General 的 `extraFlags` 置 `FASTPATH_OUTPUT_SUPPORTED (0x0001)`。',
    [
     (0, 2, 'capabilitySetType', 'MUST = `0x001C`（`CAPSETTYPE_SURFACE_COMMANDS`）'),
     (2, 2, 'lengthCapability', 'MUST = 12'),
     (4, 4, 'cmdFlags', '0x00000002 `SURFCMDS_SETSURFACEBITS` / 0x00000010 `SURFCMDS_FRAMEMARKER` / 0x00000040 `SURFCMDS_STREAMSURFACEBITS`'),
     (8, 4, 'reserved', '保留，**MUST = 0**'),
    ])

cap(0x001E, 'Frame Acknowledge Capability Set（`TS_FRAME_ACKNOWLEDGE_CAPABILITYSET`）', '[MS-RDPRFX] 2.2.1.3（S87）',
    'client ⇄ server', '',
    [
     (0, 2, 'capabilitySetType', 'MUST = `CAPSETTYPE_FRAME_ACKNOWLEDGE (0x001E)`'),
     (2, 2, 'lengthCapability', 'MUST = 8'),
     (4, 4, 'maxUnacknowledgedFrameCount', '服务端可置 0（仅声明能收）；客户端给出可缓冲的 in-flight 帧数提示'),
    ])

ENUMS = r'''
## 9 枚举与位域明细

#### 9.1 General.extraFlags（2.2.7.1.1，S13）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0001 | `FASTPATH_OUTPUT_SUPPORTED` | 声明方支持 fast-path 输出 |
| 0x0004 | `LONG_CREDENTIALS_SUPPORTED` | 支持 Save Session Info PDU 中的长用户名/密码/域（RDP 4.0/5.0 之外） |
| 0x0008 | `AUTORECONNECT_SUPPORTED` | 支持自动重连（5.5） |
| 0x0010 | `ENC_SALTED_CHECKSUM` | 支持 salted MAC 生成（5.3.6.1.1） |
| 0x0400 | `NO_BITMAP_COMPRESSION_HDR` | 支持省略 8 字节 Compressed Data Header |

> 0x0004 在 RDP 4.0/5.0 之外支持；0x0008 / 0x0010 在 RDP 4.0/5.0/5.1 之外支持（S13 原文分档）。

#### 9.2 Bitmap.drawingFlags（2.2.7.1.2，S14）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x02 | `DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY` | 支持 32-bpp 位图逐像素降色保真度的有损压缩 |
| 0x04 | `DRAW_ALLOW_COLOR_SUBSAMPLING` | 支持色度抽样 |
| 0x08 | `DRAW_ALLOW_SKIP_ALPHA` | 支持压缩时去除 alpha 通道（alpha 视为 0xFF，即不透明） |
| 0x10 | `DRAW_UNUSED_FLAG` | 未使用；若出现在 server→client 的 Bitmap Capability Set 中，客户端 MUST 忽略 |

#### 9.3 Order.orderFlags（2.2.7.1.3，S15）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0002 | `NEGOTIATEORDERSUPPORT` | 支持用 `orderSupport` 声明订单；**MUST 置位** |
| 0x0008 | `ZEROBOUNDSDELTASSUPPORT` | 支持 `TS_ZERO_BOUNDS_DELTAS (0x20)` 标志；**客户端 MUST 置位** |
| 0x0020 | `COLORINDEXSUPPORT` | 支持订单中发送颜色索引（而非 RGB 值） |
| 0x0040 | `SOLIDPATTERNBRUSHONLY` | 本端只能接收实心刷与图案刷 |
| 0x0080 | `ORDERFLAGS_EXTRA_FLAGS` | `orderSupportExFlags` 含有效数据 |

#### 9.4 Order.orderSupport 索引表（2.2.7.1.3，S15）

`orderSupport` 是 32 字节数组，下标 = 主绘图订单协商索引；**支持则该字节 MUST 为 0x01**，不支持为 0x00。

| 索引 | 名称 | 对应主绘图订单（[MS-RDPEGDI] 2.2.2.2.1.1.2） |
|---:|---|---|
| 0x00 | `TS_NEG_DSTBLT_INDEX` | DstBlt |
| 0x01 | `TS_NEG_PATBLT_INDEX` | PatBlt + OpaqueRect |
| 0x02 | `TS_NEG_SCRBLT_INDEX` | ScrBlt |
| 0x03 | `TS_NEG_MEMBLT_INDEX` | MemBlt |
| 0x04 | `TS_NEG_MEM3BLT_INDEX` | Mem3Blt |
| 0x05 | `UnusedIndex1` | **MUST 忽略** |
| 0x06 | `UnusedIndex2` | **MUST 忽略** |
| 0x07 | `TS_NEG_DRAWNINEGRID_INDEX` | DrawNineGrid |
| 0x08 | `TS_NEG_LINETO_INDEX` | LineTo |
| 0x09 | `TS_NEG_MULTI_DRAWNINEGRID_INDEX` | MultiDrawNineGrid |
| 0x0A | `UnusedIndex3` | **MUST 忽略** |
| 0x0B | `TS_NEG_SAVEBITMAP_INDEX` | SaveBitmap |
| 0x0C | `UnusedIndex4` | **MUST 忽略** |
| 0x0D | `UnusedIndex5` | **MUST 忽略** |
| 0x0E | `UnusedIndex6` | **MUST 忽略** |
| 0x0F | `TS_NEG_MULTIDSTBLT_INDEX` | MultiDstBlt |
| 0x10 | `TS_NEG_MULTIPATBLT_INDEX` | MultiPatBlt |
| 0x11 | `TS_NEG_MULTISCRBLT_INDEX` | MultiScrBlt |
| 0x12 | `TS_NEG_MULTIOPAQUERECT_INDEX` | MultiOpaqueRect |
| 0x13 | `TS_NEG_FAST_INDEX_INDEX` | FastIndex |
| 0x14 | `TS_NEG_POLYGON_SC_INDEX` | PolygonSC + PolygonCB |
| 0x15 | `TS_NEG_POLYGON_CB_INDEX` | PolygonCB + PolygonSC |
| 0x16 | `TS_NEG_POLYLINE_INDEX` | Polyline |
| 0x17 | `UnusedIndex7` | **MUST 忽略** |
| 0x18 | `TS_NEG_FAST_GLYPH_INDEX` | FastGlyph |
| 0x19 | `TS_NEG_ELLIPSE_SC_INDEX` | EllipseSC + EllipseCB |
| 0x1A | `TS_NEG_ELLIPSE_CB_INDEX` | EllipseCB + EllipseSC |
| 0x1B | `TS_NEG_INDEX_INDEX` | GlyphIndex |
| 0x1C | `UnusedIndex8` | **MUST 忽略** |
| 0x1D | `UnusedIndex9` | **MUST 忽略** |
| 0x1E | `UnusedIndex10` | **MUST 忽略** |
| 0x1F | `UnusedIndex11` | **MUST 忽略** |

> 注意 `0x14` 与 `0x15`、`0x19` 与 `0x1A` 在规范原文中互相引用同一对订单——
> 这是原文写法（PolygonSC/PolygonCB 共用一对索引），不是笔误。

#### 9.5 Input.inputFlags（2.2.7.1.6，S20）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0001 | `INPUT_FLAG_SCANCODES` | 支持 scancode 键盘事件；**至少此位 MUST 置位** |
| 0x0004 | `INPUT_FLAG_MOUSEX` | 支持扩展鼠标事件（button 4/5） |
| 0x0008 | `INPUT_FLAG_FASTPATH_INPUT` | RDP 5.0/5.1 服务端用于声明 fast-path 输入 |
| 0x0010 | `INPUT_FLAG_UNICODE` | 支持 Unicode 键盘事件 |
| 0x0020 | `INPUT_FLAG_FASTPATH_INPUT2` | RDP 4.0/5.0/5.1 之外的服务端声明 fast-path 输入 |
| 0x0040 | `INPUT_FLAG_UNUSED1` | 未使用；server→client 出现时客户端 MUST 忽略 |
| 0x0080 | `INPUT_FLAG_MOUSE_RELATIVE` | 相对鼠标模式；若 Client Core Data 协议版本 < 0x00080011 则服务端 MUST 忽略 |
| 0x0100 | `TS_INPUT_FLAG_MOUSE_HWHEEL` | 支持水平滚轮事件 |
| 0x0200 | `TS_INPUT_FLAG_QOE_TIMESTAMPS` | 支持 QoE 时间戳事件（仅 fast-path） |

> **规范原文缺陷**：官方 dump 4.1.12/4.1.13 的注解把 `0x0010` 标注为 `INPUT_FLAG_VKPACKET`，
> 但 2.2.7.1.6 正文的枚举名是 `INPUT_FLAG_UNICODE`。两者数值相同（0x0010），语义一致
> （均指 Unicode/虚拟键输入）。见 §12 U-04。

#### 9.6 GlyphCache.GlyphSupportLevel（2.2.7.1.8，S22）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0000 | `GLYPH_SUPPORT_NONE` | 不支持字形缓存，文本以 Bitmap Update 发送 |
| 0x0001 | `GLYPH_SUPPORT_PARTIAL` | 支持 Rev 1 Cache Glyph 二级订单 |
| 0x0002 | `GLYPH_SUPPORT_FULL` | 支持 Rev 1 Cache Glyph 二级订单 |
| 0x0003 | `GLYPH_SUPPORT_ENCODE` | 支持 Rev 2 Cache Glyph 二级订单 |

> `PARTIAL` 与 `FULL` 的规范描述文字相同（均指 Rev 1 订单），这是原文表述，见 §12 U-05。

#### 9.7 BitmapCacheRev2.CacheFlags（2.2.7.1.4.2，S17）

| 值 | 名称 | 说明 |
|---:|---|---|
| 0x0001 | `PERSISTENT_KEYS_EXPECTED_FLAG` | 客户端将在 Connection Finalization 发 Persistent Key List PDU |
| 0x0002 | `ALLOW_CACHE_WAITING_LIST_FLAG` | 支持 cache waiting list（位图第二次命中才缓存） |

#### 9.8 `TS_BITMAPCACHE_CELL_CACHE_INFO.CellInfo` 位域（2.2.7.1.4.2.1，S18）

| 位 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0–30 | 31 | `NumEntries` | 该缓存的条目数 |
| 31 | 1 | `k` | 1 = 该缓存跨连接持久，服务端 MUST 为每个插入的位图发送 64-bit key |

**编码等价式**（官方 dump 4.1.13 实测）：`CellInfo = (k << 31) | NumEntries`。
dump 中 `fb 09 00 80` → `0x800009FB` → `NumEntries = 0x9FB = 2555`、`k = TRUE`。
'''

body = []
for idx, (t, name, section, sent_by, note, fields) in enumerate(CAPS, 1):
    total = sum(w for _, w, _, _ in fields)
    body.append('#### 8.%d 0x%04X — %s\n' % (idx, t, name))
    body.append('- 章节：**%s**' % section)
    body.append('- 方向：%s' % sent_by)
    body.append('- 固定总长：**%d 字节**（即 `lengthCapability` 值）\n' % total)
    if note:
        body.append('> %s\n' % note)
    body.append('| 偏移 | 长度 | 字段 | 说明 |')
    body.append('|---:|---:|---|---|')
    off = 0
    for o, w, f, d in fields:
        assert o == off, (name, f, o, off)
        body.append('| %d | %d | `%s` | %s |' % (o, w, f, d))
        off += w
    body.append('')
    body.append('> 偏移校验：末字段结束 = %d = 固定总长 %d ✔\n' % (off, total))

text = '\n'.join(body) + ENUMS
open(OUT, 'w', encoding='utf-8', newline='\n').write(text)
print('caps=%d bytes=%d' % (len(CAPS), len(text)))




