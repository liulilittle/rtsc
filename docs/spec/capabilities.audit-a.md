# `docs/spec/capabilities.md` 独立审计报告（审计 AI 甲）

- 审计对象：`F:\rtsc\docs\spec\capabilities.md`（实测 2497 行 / 149,038 字节；任务书说 2498 行，差 1 行，属末尾换行计法差异，非内容问题）
- 审计方式：**独立复核**，不采信文档自述。全部结论来自官方 DOCX 抽取文本 `F:\rtsc\.tmp\bcgr.txt`（1,141,165 字节，`[MS-RDPBCGR]` v62.0）、`F:\rtsc\.tmp\egdi.txt`（674,864 字节，`[MS-RDPEGDI]`），加两处 webfetch（MS-RDPERP / MS-RDPRFX 网页版），加实际运行仓库脚本。
- 本报告**未修改** `capabilities.md`，未写 C++。
- 所有临时脚本写在 `F:\rtsc\.tmp\a_*.py`，均以 `encoding='utf-8'` 读写。

## 结论速览

| 项 | 判定 | 一句话 |
|---|---|---|
| A capability 字段宽度 | **PASS（27/27 宽度全对，10 个必查项逐字段核对通过）**，但 §8.18 的"固定总长 12"表述有内部矛盾 | 见缺陷 D-04 |
| B 编号表 | **PASS** | 28 行逐条、逐序、逐名与规范原文完全一致；文档对任务提示的订正全部成立 |
| C 共享头 / Fast-Path 位域 | **PASS** | pduType 5 值、fpInputHeader、fpOutputHeader、eventHeader 位序全部与原文一致 |
| D 错误策略 U-01/U-08/U-09 | **PARTIAL（方向同意，三处需修正）** | 三条都缺"长度越界"约束，U-09 未区分 len==4 合法与 len==0 |
| E 官方 dump 真实性 | **PARTIAL（4 组中 3 组逐字节全同，13.4 组自相矛盾）** | §13.4 把解密后的明文标成"完整线上字节"且标成"密文"，见 D-03 |
| F 长度模型反向验证 | **PARTIAL（脚本真实存在、逻辑成立、实际跑通 31/31，但验证力被高估）** | 只验总长不验字段宽度/身份；21/27 类型有覆盖，见 D-06/D-11 |

**缺陷总数：11 条**（1 条中高严重度数值错误，3 条中等，7 条轻微/表述精度）。
**最严重**：§4.1 行 688 把 MCS I/O channel ID 写成 `0x03E3`（= 995），而同文档自己的官方 dump 里是 `0x03EB`（= 1003）——硬编码即连不上。

---

## 0. 证据基线与复现命令

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
# 规范原文抽取文本（已存在，直接复用）
python F:\rtsc\.tmp\a_show.py <start> <end> <label>   # 打印 bcgr.txt 指定字节区间
python F:\rtsc\.tmp\a_specfields.py                    # 从原文逐条抓 Definition-Field 的宽度
python F:\rtsc\.tmp\a_cmpA3.py                         # 文档 §8 宽度 vs 原文宽度 逐字段对比
python F:\rtsc\.tmp\a_cmpB2.py                         # 文档 §6.2 编号表 vs 原文编号表
python F:\rtsc\.tmp\a_dumpcmp.py                       # 文档 §13 dump vs 原文 dump 逐字节
python F:\rtsc\.tmp\a_quote.py                         # 文档引用的 verify_caps.py 输出 vs 实际输出
python F:\rtsc\.tmp\a_schema.py                        # verify_caps.py 的 SCHEMA vs 原文宽度
python F:\rtsc\.tmp\a_redgreen.py                      # 注入错误宽度，观察脚本是否变红
python F:\rtsc\.tmp\a_mutgen.py / a_mutgen3.py         # 注入错误到 gen_caps_full.py，观察 assert 是否拦住
```

`a_show.py` 输出样例（原文 2.2.7.1.1 字段区，位置 326711）：

```
[Heading5] General Capability Set (TS_GENERAL_CAPABILITYSET)
[Definition-Field] capabilitySetType (2 bytes)
[Definition-Field] lengthCapability (2 bytes)
[Definition-Field] osMajorType (2 bytes)
[Definition-Field] osMinorType (2 bytes)
[Definition-Field] protocolVersion (2 bytes)
[Definition-Field] pad2octetsA (2 bytes)
[Definition-Field] compressionTypes (2 bytes)
[Definition-Field] extraFlags (2 bytes)
[Definition-Field] updateCapabilityFlag (2 bytes)
[Definition-Field] remoteUnshareFlag (2 bytes)
[Definition-Field] compressionLevel (2 bytes)
[Definition-Field] refreshRectSupport (1 byte)
[Definition-Field] suppressOutputSupport (1 byte)
```

---

## A. capability 字段宽度逐项复核 —— **PASS**（附 1 条表述缺陷 D-04）

### A.0 方法

1. 用 `a_specfields.py` 从官方原文（bcgr.txt / egdi.txt）**按 `[Definition-Field] <name> (<n> bytes)` 逐条抓取**，得到每个 capability 的宽度序列与总长；不读文档表格。
2. 用 `a_cmpA3.py` 解析文档 §8.1–§8.27 的 Markdown 表格（`| 偏移 | 长度 | 字段 |`），得到文档侧宽度序列与总长。
3. 逐字段比对（字段名 + 宽度 + 顺序），再比对总长。
4. 对 10 个必查项打印逐字段对照表（`a_perfield.py`）。

`a_cmpA3.py` 实际输出（全部 27 个）：

```
type     docTot   specTot  verdict
0x0001  24       24       OK
0x0002  28       28       OK
0x0003  88       88       OK
0x0004  40       40       OK
0x0005  12       12       OK
0x0007  12       12       OK
0x0008  10       10       OK
0x0009  8        8        OK
0x000A  8        8        OK
0x000C  8        8        OK
0x000D  88       88       OK
0x000E  8        8        OK
0x000F  8        8        OK
0x0010  52       52       OK
   name/order diff:
     doc : GlyphCache[0..9]
     spec: GlyphCache          <-- 仅命名详略差异，宽度 40 相同
0x0011  12       12       OK
0x0012  8        8        OK
0x0013  40       40       OK
0x0014  12       12       OK
   name/order diff:
     doc : VCChunkSize（可选）
     spec: VCChunkSize        <-- 仅标注差异，宽度 4 相同
0x0015  12       12       OK
0x0016  40       40       OK
0x0017  8        None     NO-SPEC-TEXT   <-- 见 A.3，已用网页版补证
0x0018  11       None     NO-SPEC-TEXT   <-- 同上
0x0019  6        6        OK
0x001A  8        8        OK
0x001B  6        6        OK
0x001C  12       12       OK
0x001E  8        None     NO-SPEC-TEXT   <-- 同上
```

`NO-SPEC-TEXT` 的三项（RAIL / Window / FrameAck）不在 bcgr/egdi 的 DOCX 里，我用 webfetch 抓了官方网页版逐字段核对（见 A.3），结论同样 PASS。

### A.1 十个必查项的逐字段对照

**① General 0x0001（文档 §8.1，行 1071–1095）**

| # | 文档字段 | 文档宽度 | 原文宽度 | 一致 |
|---|---|---:|---:|---|
| 0 | capabilitySetType | 2 | 2 | ✔ |
| 1 | lengthCapability | 2 | 2 | ✔ |
| 2 | osMajorType | 2 | 2 | ✔ |
| 3 | osMinorType | 2 | 2 | ✔ |
| 4 | protocolVersion | 2 | 2 | ✔ |
| 5 | pad2octetsA | 2 | 2 | ✔ |
| 6 | compressionTypes | 2 | 2 | ✔ |
| 7 | extraFlags | 2 | 2 | ✔ |
| 8 | updateCapabilityFlag | 2 | 2 | ✔ |
| 9 | remoteUnshareFlag | 2 | 2 | ✔ |
| 10 | compressionLevel | 2 | 2 | ✔ |
| 11 | refreshRectSupport | 1 | 1 | ✔ |
| 12 | suppressOutputSupport | 1 | 1 | ✔ |
| | **累加** | **24** | **24** | ✔ |

独立验算：`11 × 2 + 2 × 1 = 22 + 2 = 24`。文档行 1075「固定总长 24」、行 1095「末字段结束 = 24」均成立。
原文侧核对：`a_specfields.py` 抓到 13 个 `[Definition-Field]`，宽度序列 `2,2,2,2,2,2,2,2,2,2,2,1,1`，和上表逐项相同。
**这与文档 §14.1 的自述「11×2+2×1」吻合，且是我独立从原文数出来的，不是抄文档。**

**② Bitmap 0x0002（文档 §8.2，行 1097–1123）**

宽度序列 `2,2,2,2,2,2,2,2,2,2,2,1,1,2,2` → `11×2 + 2×1 + 2×2 = 22+2+4 = 28` ✔
原文 15 个字段名/宽度与文档 15 行**逐项同名同宽同序**。特别注意 `highColorFlags(1)` / `drawingFlags(1)` 这对 1 字节字段夹在两个 2 字节字段之间（偏移 22、23），文档正确（行 1118–1119）。

**③ Order 0x0003（文档 §8.3，行 1125–1155）**

文档宽度序列：`2,2,16,4,2,2,2,2,2,2,32,2,2,4,4,2,2,2,2` = 88
原文 19 个字段：同名、同宽、同序，逐项一致。
关键点：`terminalDescriptor` 16 字节（行 1137）、`orderSupport` 32 字节（行 1145）、`desktopSaveSize` 4 字节（行 1149）、`textANSICodePage` 在 `pad2octetsD` 之后、`pad2octetsE` 之前（行 1152–1153）——顺序与原文表完全一致。

**④ BitmapCache Rev1 0x0004（文档 §8.4，行 1157–1182）**

宽度序列：`2,2,4,4,4,4,4,4,2,2,2,2,2,2` = `4 + 24 + 12` = 40 ✔
原文 14 个字段：`pad1..pad6` 各 4 字节，随后 6 个 2 字节（Cache0/1/2 的 Entries+MaximumCellSize）。文档行 1169–1180 逐项一致。条目上限 200/600/65535 与原文一致。

**⑤ Pointer 0x0008（文档 §8.7，行 1222–1238）**

宽度序列：`2,2,2,2,2` = 10 ✔
原文 5 字段：`colorPointerFlag(2) / colorPointerCacheSize(2) / pointerCacheSize(2)`。文档行 1234–1236 一致。
文档行 1236「若为 0 或客户端未含此字段，服务端不会使用 New Pointer Update」对应原文 `[Definition-Field2] If the value contained in this field is zero or the Pointer Capability Set sent from the client does not include this field, the server will not use the New Pointer Update.` ✔（注意原文这段是 `Definition-Field2` 而非 `Definition-Field`，我的抓取脚本会漏掉它，但文档把语义写对了。）

**⑥ Input 0x000D（文档 §8.11，行 1291–1311）**

宽度序列：`2,2,2,2,4,4,4,4,64` = `8 + 16 + 64` = 88 ✔
原文 9 字段同名同宽同序。文档行 1309 `imeFileName 64` 字节、「最多 31 个 Unicode 字符 + NUL」与原文 `contains up to 31 Unicode characters plus a null terminator` 一致。

**⑦ VirtualChannel 0x0014（文档 §8.18，行 1421–1436）**

宽度序列：`2,2,4,4` = 12（含可选字段）；8 字节形态为 `2,2,4`。
原文表：`capabilitySetType(2) | lengthCapability(2) | flags(4) | VCChunkSize (optional)(4)`，原文明确标注 `VCChunkSize (optional)`。
文档行 1427「`VCChunkSize` 在 8 字节形态中不存在；仅 12 字节形态含该字段」——**正确且与原文一致**。
但文档行 1425「固定总长：**12 字节**」+ 行 1436「末字段结束 = 12 = 固定总长 12」与行 1432「8 或 12」自相矛盾，且两个官方 dump 都是 8。见缺陷 **D-04**。

**⑧ Share 0x0009（文档 §8.8，行 1240–1255）**

宽度序列：`2,2,2,2` = 8 ✔ 原文 4 字段同名同宽同序。`nodeID` 客户端 SHOULD 0、服务端 0x03EA 与原文一致。

**⑨ Font 0x000E（文档 §8.12，行 1313–1328）**

宽度序列：`2,2,2,2` = 8 ✔ 原文 4 字段一致。
文档行 1319 关于「dump 4.1.12 服务端发 4 字节、规范注解称 bug」的说明，我在原文 890998 处逐字核对：
`Due to a bug, the TS_FONT_CAPABILITYSET capability set size is incorrectly set to 4 bytes (it has to be 8 bytes). As a result of this bug, the fontSupportFlags and pad2octets fields are missing.` ✔ 文档转述准确。

**⑩ GlyphCache 0x0010（文档 §8.14，行 1344–1361）**

宽度序列：`2,2,40,4,2,2` = 52 ✔
原文：`GlyphCache (40 bytes)` = 10 × `TS_CACHE_DEFINITION`；`FragCache (4 bytes)`；`GlyphSupportLevel (2 bytes)`；`pad2octets (2 bytes)`。
文档行 1356 把 40 字节展开为「10 × `TS_CACHE_DEFINITION`：`CacheEntries(2)` + `CacheMaximumCellSize(2)`」，与原文 2.2.7.1.8.1 一致。
文档行 1357 `FragCache` 上限 256 条目 / 256 字节，与原文 `maximum number of entries allowed in the cache is 256, and the largest allowed maximum size of an element is 256 bytes` 一致。

### A.2 其余 17 个（同样逐字段比对，全部 PASS）

`0x0005 Control 12`、`0x0007 Activation 12`、`0x000A ColorCache 8`、`0x000C Sound 8`、`0x000F Brush 8`、`0x0011 Offscreen 12`、`0x0012 BmpCacheHost 8`、`0x0013 Rev2 40`、`0x0015 DrawNineGrid 12`、`0x0016 DrawGdiPlus 40`、`0x0019 CompDesk 6`、`0x001A Multifrag 8`、`0x001B LargePointer 6`、`0x001C SurfaceCommands 12`、`0x0017 Rail 8`、`0x0018 Window 11`、`0x001E FrameAck 8`。
EGDI 三项原文宽度（`a_cmpA2.py` 输出）：

```
EGDI 0x000A capabilitySetType:2 | lengthCapability:2 | colorTableCacheSize:2 | pad2octets:2  total= 8
EGDI 0x0015 capabilitySetType:2 | lengthCapability:2 | drawNineGridSupportLevel:4 | drawNineGridCacheSize:2 | drawNineGridCacheEntries:2  total= 12
EGDI 0x0016 capabilitySetType:2 | lengthCapability:2 | drawGDIPlusSupportLevel:4 | GdipVersion:4 | drawGdiplusCacheLevel:4 | GdipCacheEntries:10 | GdipCacheChunkSize:8 | GdipImageCacheProperties:6  total= 40
```

三个子结构（S82/S83/S84）的细分宽度我也核了原文：
- `TS_GDIPLUS_CACHE_ENTRIES` = 5 × 2 = 10 ✔（Graphics/Brush/Pen/Image/ImageAttributes）
- `TS_GDIPLUS_CACHE_CHUNK_SIZE` = 4 × 2 = 8 ✔（Graphics/Brush/Pen/ImageAttributes）
- `TS_GDIPLUS_IMAGE_CACHE_PROPERTIES` = 3 × 2 = 6 ✔（ChunkSize/TotalSize/MaxSize）
文档行 1469–1471 的字段顺序与上限（10/5/5/10/2、512/2048/1024/64、4096/256/128）与原文逐条一致。

### A.3 三个 DOCX 缺失项的补证（webfetch 官方网页版）

- **RAIL 0x0017**：`CapabilitySetType(2) | LengthCapability(2) | RailSupportLevel(4)` = 8 ✔；位图行为 `S | L | H | I | C | M | K | E | 0…`，即 bit0=S…bit7=E，与文档行 1487 的位名序列完全一致；「S 为 0 时其余位 MUST 为 0」原文对 L/H/I/C/M/K/E 每一位都写了该约束 ✔。
- **Window 0x0018**：`CapabilitySetType(2) | LengthCapability(2) | WndSupportLevel(4) | NumIconCaches(1) | NumIconCacheEntries(2)` = 11 ✔；文档行 1503 的 0/1/2 三个 level 语义与原文一致。
- **FrameAck 0x001E**：`capabilitySetType(2) | lengthCapability(2) | maxUnacknowledgedFrameCount(4)` = 8 ✔；文档行 1582「服务端可置 0（仅声明能收）」对应原文 `MAY be set to 0, in which case it simply advertises the server's ability to receive` ✔。

### A.4 位域字段的位序（文档 §1.2 的提取公式）

原文位域图首行是 `0 | 1 | 2 | … | 31`，且**列号即位号、位 0 在最左**（图左端 = LSB）。文档 §1.2 行 150–185 的表述与此一致。我用原文自带的注解做了三重反证：

1. `fpInputHeader = 0xC4`，原文注解 `Binary of 0xc4 = 11 0001 00`、`action = FASTPATH_INPUT_ACTION_FASTPATH (0)`、`numEvents = 1`、`flags = 0x3`。
   文档公式 `action=h&3; numEvents=(h>>2)&0xF; flags=(h>>6)&3` 代入得 `0 / 1 / 3` ✔。
   反证：若按"图左=MSB"，`action` 会取 bit7–6 = `0b11` = 3 = X.224 慢路径，与注解矛盾 ✔。
2. `eventHeader = 0x20`，原文注解 `Binary of 0x20 = 001 00000`、`eventFlags = 0`、`eventCode = 1 (MOUSE)`。
   原文位域行顺序是 `eventFlags | eventCode`（eventFlags 5 bit 在前 = bit0–4），故 `eventCode=(h>>5)&7=1`、`eventFlags=h&0x1F=0` ✔。
   文档 §3.7 行 638–639 的公式正确，且 §14.4 行 2344–2346 用"若把 eventCode 当低 3 位会得到 0（SCANCODE，只有 1 字节），与后续 6 字节 pointerFlags/xPos/yPos 长度不匹配"做了长度反证 ✔。
3. `pduType = 0x0011`，原文注解 `= 0x0010 | 0x0001 = TS_PROTOCOL_VERSION | PDUTYPE_DEMANDACTIVEPDU`，文档公式 `type = pduType & 0x000F; PDUVersion = pduType >> 4` 得 `1 / 0x1` ✔。

**A 结论：PASS。** 27 个定长 capability 的宽度与总长全部与规范原文一致；10 个必查项逐字段核对通过；General 的 24 = 11×2+2×1 是我独立从原文数出的。唯一问题是 §8.18 的"固定总长 12"表述（D-04）。

---

## B. 编号表核对 —— **PASS**

### B.1 方法

`a_cmpB2.py`：从 bcgr.txt 的 `[Heading7] Capability Set (TS_CAPS_SET)` 之后的 `Value | Meaning` 表逐行正则抓 `ROW: <NAME>0x<HHHH> | <meaning>`，与文档 §6.2 表格（`| 0x0001 | `CAPSTYPE_GENERAL` |`）逐行比对。

### B.2 结果

```
spec rows: 28
doc rows: 28
identical sequence? True
set diff spec-doc set()  doc-spec set()
```

28 行**编号、名称、顺序完全一致**。逐条抄出的原文表（关键 6 行加粗）：

```
0x0001 CAPSTYPE_GENERAL                General Capability Set (2.2.7.1.1)
0x0002 CAPSTYPE_BITMAP                 Bitmap Capability Set (2.2.7.1.2)      <-- 是 0x0002
0x0003 CAPSTYPE_ORDER                  Order Capability Set (2.2.7.1.3)       <-- 是 0x0003
0x0004 CAPSTYPE_BITMAPCACHE            Revision 1 Bitmap Cache (2.2.7.1.4.1)
0x0005 CAPSTYPE_CONTROL
0x0007 CAPSTYPE_ACTIVATION
0x0008 CAPSTYPE_POINTER
0x0009 CAPSTYPE_SHARE                  Share Capability Set (2.2.7.2.4)       <-- 是 0x0009
0x000A CAPSTYPE_COLORCACHE
0x000C CAPSTYPE_SOUND
0x000D CAPSTYPE_INPUT
0x000E CAPSTYPE_FONT                   Font Capability Set (2.2.7.2.5)        <-- 是 0x000E
0x000F CAPSTYPE_BRUSH
0x0010 CAPSTYPE_GLYPHCACHE
0x0011 CAPSTYPE_OFFSCREENCACHE
0x0012 CAPSTYPE_BITMAPCACHE_HOSTSUPPORT
0x0013 CAPSTYPE_BITMAPCACHE_REV2       Revision 2 Bitmap Cache (2.2.7.1.4.2)  <-- 是 0x0013
0x0014 CAPSTYPE_VIRTUALCHANNEL         Virtual Channel (2.2.7.1.10)           <-- 是 0x0014
0x0015 CAPSTYPE_DRAWNINEGRIDCACHE
0x0016 CAPSTYPE_DRAWGDIPLUS
0x0017 CAPSTYPE_RAIL
0x0018 CAPSTYPE_WINDOW
0x0019 CAPSETTYPE_COMPDESK
0x001A CAPSETTYPE_MULTIFRAGMENTUPDATE
0x001B CAPSETTYPE_LARGE_POINTER
0x001C CAPSETTYPE_SURFACE_COMMANDS
0x001D CAPSETTYPE_BITMAP_CODECS
0x001E CAPSSETTYPE_FRAME_ACKNOWLEDGE
```

文档 §6.2 行 864–891 与上表逐行对应，连 `CAPSETTYPE_*` 与 `CAPSTYPE_*` 的前缀差异（原文本身就是混用的）都保留了，没有"统一美化"成错。`CAPSSETTYPE_FRAME_ACKNOWLEDGE` 原文就是双 S 拼写，文档也照抄，正确。

### B.3 对任务提示的订正是否成立

任务提示要求"特别验证 Bitmap=0x0003、Order=0x0002、VirtualChannel=0x0014、Font=0x000E、BitmapCache Rev2=0x0013、Share=0x0009"。**这里必须指出：任务提示自身有两处写反了。** 原文事实是：

| 项 | 任务提示 | 规范原文 | 文档 §1.4/§6.2 写的 | 判定 |
|---|---|---|---|---|
| Bitmap | 0x0003 | **0x0002** | 0x0002（行 208、865） | 文档正确，提示错误 |
| Order | 0x0002 | **0x0003** | 0x0003（行 209、866） | 文档正确，提示错误 |
| VirtualChannel | 0x0014 | 0x0014 | 0x0014（行 211、881） | 双方一致 |
| Font | 0x000E | 0x000E | 0x000E（行 875） | 双方一致 |
| BitmapCache Rev2 | 0x0013 | 0x0013 | 0x0013（行 880） | 双方一致 |
| Share | 0x0009 | 0x0009 | 0x0009（行 871） | 双方一致 |

证据：原文 229457 处表体 `ROW: CAPSTYPE_BITMAP0x0002 | Bitmap Capability Set`、`ROW: CAPSTYPE_ORDER0x0003 | Order Capability Set`。文档 §1.4 行 208–209 的订正表述「Bitmap 编号「3」→ CAPSTYPE_BITMAP = 0x0002」「Order 编号「5」→ CAPSTYPE_ORDER = 0x0003」是**正确的**。

### B.4 未分配编号

文档行 893–895 说 `0x0001–0x001E` 区间跳过 `0x0006` 与 `0x000B`，`0x0000`、`0x001F` 及以后未出现。我核对了 28 行编号集合：确实缺 `0x0000`、`0x0006`、`0x000B`、`0x001F+` ✔。

**B 结论：PASS。** 文档对任务提示 9 处订正的编号部分全部成立；反过来说明任务提示的 Bitmap/Order 两项编号本身是错的。

---

## C. 共享头 / Fast-Path 位域 —— **PASS**

### C.1 TS_SHARECONTROLHEADER.pduType（文档 §2.1，行 239–266）

原文（390626 起）：
```
ROW: totalLength | pduType
ROW: pduSource
[Definition-Field] type (4 bits)
ROW: PDUTYPE_DEMANDACTIVEPDU0x1
ROW: PDUTYPE_CONFIRMACTIVEPDU0x3
ROW: PDUTYPE_DEACTIVATEALLPDU0x6
ROW: PDUTYPE_DATAPDU0x7
ROW: PDUTYPE_SERVER_REDIR_PKT0xA
[Definition-Field] PDUVersion (12 bits)
```
文档行 243–252 列出 `type=4bit / PDUVersion=12bit` 与 **恰好 5 个值**（0x1/0x3/0x6/0x7/0xA），与原文逐条一致。位序「位 0 在左 ⇒ type 占 bit0–3」与原文位图行 `type | PDUVersion` 一致；文档行 264 的 `type = pduType & 0x000F` 正确。
`totalLength == 0x8000 ⇒ FlowPDU 且 MUST 忽略`（文档行 236–237）与原文一致 ✔。

### C.2 fpInputHeader（文档 §3.2，行 471–481）

原文（424274 起）位域行：`action | numEvents | flags`；`action (2 bits)`、`numEvents (4 bits)`、`flags (2 bits)`。
文档行 475–477 给 `bit0–1 action / bit2–5 numEvents / bit6–7 flags`，提取公式 `action=h&3; numEvents=(h>>2)&0xF; flags=(h>>6)&3`。
与原文一致，并用 `0xC4` 反证通过（见 A.4 第 1 条）。
`numEvents > 15 ⇒ 位域置 0 且外挂 1 字节插在 dataSignature 之后`（文档行 476）与原文 `MUST be set to zero, and the numEvents optional field inserted after the dataSignature field. This allows up to 255 input events` 一致 ✔。

### C.3 fpOutputHeader（文档 §3.3，行 494–514）

原文（493297 起）位域行：`action | reserved | flags`；原文正文明确写 `Two pieces of information are collapsed into this byte: Security flags / Action code`（**只有两项**，没有事件数）。
文档行 498–500 给 `bit0–1 action / bit2–5 reserved(MUST 0) / bit6–7 flags`，且文档 §16 第 5 条（行 2417）明确"`length1`/`length2` 是独立字段，不在位域内"。
原文结构行是 `fpOutputHeader | length1 | length2 (optional) | fipsInformation (optional)` —— `length1`/`length2` 与 `fpOutputHeader` 是并列字段，确实不在位域内 ✔。
文档行 511–514 的推论「未加密单条输出 PDU 首字节 0x00；加密 0x80；加密+salted 0xC0」由位域定义直接得出，正确 ✔。

### C.4 TS_FP_INPUT_EVENT.eventHeader（文档 §3.7，行 627–672）

原文（428400 起）位域行 `eventFlags | eventCode`；`eventFlags (5 bits)`、`eventCode (3 bits)`。
文档行 638–639 `eventCode=(h>>5)&7; eventFlags=h&0x1F` ✔，与 `0x20` 注解一致。
`eventCode` 7 个已分配值（0x0–0x6，0x7 未分配）与原文表一致 ✔；`eventFlags` 的 5 个键盘标志 + 4 个同步标志（数值重叠、语义不同）与原文一致，文档行 671–672 明确说明这是原文写法而非笔误 ✔。

**C 结论：PASS。** 三处位域（含被任务书点名的"位序写反后改正"）全部与规范原文一致，且用官方 dump 做了独立反证。

---

## D. 错误策略建议 U-01 / U-08 / U-09 —— **PARTIAL（方向同意，三处需修正）**

### D.1 规范接收侧到底怎么要求的（先取证）

我在 bcgr.txt 全文搜索，**没有**任何关于"未分配 capabilitySetType / 未分配 updateCode"的处置条款：

```
grep 'unrecognized|unrecognised|not recognized|unknown'  -> 仅命中 ERRINFO_* 错误码表（300053），
                                                            与 capability/updateCode 无关
grep 'updateCode.{0,120}ignore' / 'capabilitySetType.{0,120}ignore' -> 0 命中
grep 'unassigned' -> 0 命中
```

规范对 `lengthCapability` 的唯一定义是（原文 231917 等 23 处）：
`A 16-bit, unsigned integer. The length in bytes of the capability data, including the size of the capabilitySetType and lengthCapability fields.`
**没有** "MUST be set to N" 字样（见缺陷 D-09）。所以文档 §15 把这三项标为"规范未规定"是**正确的定性**。

### D.2 U-01（未分配 capabilitySetType → 按长度跳过，不断链）

- **定性正确**：规范确实没写。跳过（skip-by-length）是唯一可行的前向兼容做法；若断链，未来新增 capability（如 `0x001F` 之后）会直接打死连接。
- **需要修正**：文档 §6.1 行 845–852 的遍历伪码只写了 `if len < 4: error`，**没有把 `len` 限制在剩余区间内**。一个 `len = 0xFFF0` 的畸形 set 会让 `p` 冲出 `caps_start + lcc - 4`，随后 `p += len` 使后续所有 set 全部错位，最终 `assert` 失败——但那时已经"读过"越界内存。建议改为：
  ```
  end = caps_start + lengthCombinedCapabilities - 4
  if len < 4 or p + len > end: reject PDU   # 不是 skip，是整包拒绝
  ```
- **是否"静默接受畸形数据"**：会。跳过一个未知 type 意味着客户端**忽略**了服务端认为已协商的能力，服务端可能据此启用客户端解析不了的特性。建议文档补一句"跳过时必须记入告警并禁止把该 type 视为已协商"，否则"跳过"和"接受"在实现里容易被混为一谈。

**结论：同意方向，需补越界约束 + 补"不得视为已协商"。**

### D.3 U-08（未分配 updateCode → 按 size 跳过，不断链）

- **定性正确**：原文 2.2.9.1.2.1 只列 12 个值（0x0–0x6、0x8–0xC），0x7 与 0xD–0xF 未分配，且无处置条款。
- **按 `size` 跳过在技术上成立**：原文 `size (2 bytes): The size in bytes of the data in the updateData field.` —— 是线上字节数，跳过 `size` 字节即可对齐下一条 update（无论是否压缩，`size` 描述的都是 updateData 的实际线上长度）。
- **需要修正（两点）**：
  1. 同样缺越界检查：`if size > remaining: reject`。否则一个畸形 size 会让后续 update 全错位，而 `TS_FP_UPDATE` 是数组，没有总长校验可兜底。
  2. **分片场景**：若未知 updateCode 出现在 `fragmentation != 0` 的序列里，跳过单个片段会破坏重组状态（后续 FIRST/LAST 无法配对）。文档应说明"遇到未知 code 且处于分片序列时，丢弃整个重组缓冲"，而不是继续拼。
- **是否"静默接受畸形数据"**：比 U-01 风险低（update 之间是平铺数组，跳过不会改变已解析内容的语义），但仍需告警。

**结论：同意方向，需补越界检查 + 分片处置。**

### D.4 U-09（lengthCapability < 4 → 必须拒绝）

- **核心判断正确**：`lengthCapability` 的定义**含** 4 字节头，所以 `len < 4` 在定义上就是畸形的；`p += len` 时 `len = 0` 完全不前进，`len = 1..3` 会前移但把指针插进字段中间，两种都必须拒绝。文档"否则死循环"的说法对 `len == 0` 精确，对 `len = 1..3` 是"错位"而非死循环——建议措辞区分。
- **`lengthCapability == 0` 与 `< 4` 是否该区分**：**不该区分，但要说清**。`0` 是 `< 4` 的子集，处理动作相同（拒绝）。真正需要单独强调的是**`len == 4` 是合法的**：官方 dump 4.1.12 的 Font 就是 4 字节（原文注解明说是服务端 bug 但线上确实如此），文档 §8.12 已经容忍了 4 字节形态。若把判定写成 `len <= 4` 就会把官方 dump 判成畸形——这是最容易被写错的地方，文档 §6.1 行 849 写的是 `if len < 4`，**正确**，但 §15 U-09 的表述"`< 4` 则遍历指针不前进"没有点出 `len == 4` 必须放行，建议补一句。
- **"断链或跳过剩余 caps"这个二选一不合适**：capability 区是结构化数据，一旦某个 set 的长度不可信，后续所有 set 的边界都不可信。此时"跳过剩余 caps"等于保留一半不可信状态。建议明确为"整包拒绝（SHOULD 断链）"，与 §4.4 第 5 条"长度不符 → 断链"保持一致。

**结论：需修正（方向对，措辞与动作需精确化）。**

### D.5 小结

| 项 | 规范是否规定 | 文档建议 | 我的判定 |
|---|---|---|---|
| U-01 | 未规定（已取证） | 按长度跳过、不断链 | 同意，需补 `p+len<=end` 与"不得视为已协商" |
| U-08 | 未规定（已取证） | 按 size 跳过、不断链 | 同意，需补 `size<=remaining` 与分片丢弃 |
| U-09 | 未规定（已取证） | 必须拒绝 | 需修正：区分 `len==0`（死循环）与 `len=1..3`（错位）；明确 `len==4` 合法；动作统一为整包拒绝 |

**D 结论：PARTIAL。**

---

## E. 官方 dump 真实性 —— **PARTIAL（4 组中 3 组逐字节全同，13.4 组自相矛盾）**

### E.1 方法

`a_dumpcmp.py`：从 bcgr.txt 按 `[Code] 0000000X …` 行抓官方 dump 的十六进制流（`Decrypted TS_XXX_PDU:` 之后），从文档 §13 的 fenced block 抓十六进制流，逐字节比对 + 比总长。

### E.2 结果

```
== demand    spec_len=359 doc_len=359
  first32 spec: 67 01 11 00 ea 03 ea 03 01 00 04 00 51 01 52 44 50 00 0d 00 00 00 09 00 08 00 ea 03 dc e2 01 00
  first32 doc : 67 01 11 00 ea 03 ea 03 01 00 04 00 51 01 52 44 50 00 0d 00 00 00 09 00 08 00 ea 03 dc e2 01 00
  diff count 0

== confirm   spec_len=492 doc_len=492
  first32 spec: ec 01 13 00 ef 03 ea 03 01 00 ea 03 06 00 d6 01 4d 53 54 53 43 00 12 00 00 00 01 00 18 00 01 00
  first32 doc : ec 01 13 00 ef 03 ea 03 01 00 ea 03 06 00 d6 01 4d 53 54 53 43 00 12 00 00 00 01 00 18 00 01 00
  diff count 0

== fontlist  spec_len=26 doc_len=26
  diff count 0

== fontmap   spec_len=26 doc_len=26
  diff count 0

== fpinput   spec_len=17 doc_len=17
  first32 spec: c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28
  first32 doc : c4 11 30 35 6b 5b b5 34 c8 47 20 00 08 ab 02 6f 01
  diff count 7  (偏移 10..16 全不同)
```

### E.3 逐字节比对细节（抽查 4 组，超过任务要求的 2 组）

**dump #1 Demand Active（文档 §13.1，行 1969–2028）**：359 字节全同。capabilitySets 从 `0x16` 起，13 个 set 长度
`8,24,8,40,4,28,88,8,8,10,88,8,11`，和 `333`；`0x16 + 333 = 0x163`，`+4` 字节 sessionId = `0x167` = 359 = `totalLength` ✔。
我用独立解码器（`a_decode.py`）逐字段解出：Share nodeID=0x03EA、General extraFlags=0x041D rr=1 so=1、VirtualChannel flags=2、
DrawGdiPlus len=40、Font len=4、Bitmap bpp=24 1280×1024 comp=1 multi=1、Order orderFlags=0x0022 saveSize=1000000、
ColorCache 6、BmpCacheHost ver=1、Pointer 25/25、Input flags=0x0035、Rail 0、Window 0 —— **与文档行 2012–2024 的注解逐项一致**。

**dump #2 Confirm Active（文档 §13.2，行 2030–2101）**：492 字节全同。18 个 set 和 `466`，`0x1A + 466 = 0x1EC` = 492，
**无尾部字段**，证明 Confirm Active 无 sessionId ✔。逐字段解出 extraFlags=0x041D rr=0 so=0、Order orderFlags=0x002A cp=1252、
Rev2 CacheFlags=3 NumCellCaches=3 cell2=0x800009FB、Pointer 20/21、Input 0x0015 layout=0x409 type=4 fn=12、Sound 1、Font 1、
GlyphCache entries=[254×9,64] frag=256/256 level=3、Brush 1、Offscreen 7680KB/100、VirtualChannel 1、DrawNineGrid level=2 2560/256、
DrawGdiPlus 全 0 —— 与文档行 2080–2097 逐项一致。

**dump #3 Font List / Font Map（文档 §13.3，行 2103–2155）**：各 26 字节全同。`pad1` 在 Font List 是 `00`、在 Font Map 是 `45`，
`streamID` 分别是 `01`(LOW) / `02`(MED)，与原文注解 `pad1` 未初始化、`streamID` 不参与语义一致 ✔。

**dump #4 Fast-Path Input（文档 §13.4，行 2157–2186）**：**不一致**。
- 原文（webfetch 官方页 `d8f1be0e-…` + bcgr.txt 1020179）：
  `c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28`（17 字节）
  注解：`26 18 5e 76 0e de 28 -> Encrypted TS_FP_INPUT_PDU::fpInputEvents`
- 文档行 2162 给的"**完整线上字节**"：
  `c4 11 30 35 6b 5b b5 34 c8 47 20 00 08 ab 02 6f 01`
  即把最后 7 字节换成了**解密后**的 `20 00 08 ab 02 6f 01`。
- 而文档行 2171 又把 `20 00 08 ab 02 6f 01` 标注为 `fpInputEvents（密文）`、说明"7 字节加密载荷"。

**这是自相矛盾**：同一段字节既被称作"完整线上字节"（行 2159），又被称作"密文"（行 2171），而实际是明文。
第 10–16 字节的 7 个差异是**可执行复现的红证**（`a_dumpcmp.py` 输出 `diff count 7`）。
注意：长度自洽 `1+1+8+7=17` 仍然成立，所以这条缺陷不影响 §3.4 的结论，只影响 §13.4 的"真实性"。

**E 结论：PARTIAL。** 4 组 dump 中 3 组（359 / 492 / 26+26）与规范原文逐字节完全一致、遍历精确收尾；
第 4 组（Fast-Path 17 字节）混入了明文且标注自相矛盾，见缺陷 **D-03**。

---

## F. 长度模型反向验证 —— **PARTIAL（脚本真实、逻辑成立、跑通，但验证力被高估）**

### F.1 脚本确实存在且真做了这件事（读代码，不只看自述）

`F:\rtsc\evidence\capabilities\verify_caps.py`（91 行）：

```python
SCHEMA = [
    ('General',        1,  [2,2,2,2,2,2,2,2,2,1,1],                'BCGR 2.2.7.1.1'),
    ('Bitmap',         2,  [2,2,2,2,2,2,2,2,2,1,1,2,2],            'BCGR 2.2.7.1.2'),
    ('Order',          3,  [16,4,2,2,2,2,2,2,32,2,2,4,4,2,2,2,2],  'BCGR 2.2.7.1.3'),
    ('BitmapCacheRev1',4,  [4,4,4,4,4,4,2,2,2,2,2,2],              'BCGR 2.2.7.1.4.1'),
    ...
    ('VirtualChannel',20,  [4],                                    'BCGR 2.2.7.1.10'),
    ...
]
LEN = {c[1]: (c[0], 4 + sum(c[2]), c[3]) for c in SCHEMA}
```

- 它是**独立的长度模型**：只声明 payload 字段宽度，总长 `4 + sum(widths)` 由代码算出，不是抄 dump 的 `lengthCapability`。
- 它做**反向遍历**：从 dump 里读 `numberCapabilities`，逐个读 `capabilitySetType`/`lengthCapability`，与模型预测比，`PASS/FAIL`。
- 它做**收尾校验**：`end = p + tail_bytes; good = (end == total)`，`tail_bytes` 分别传 4（Demand Active 的 sessionId）和 0（Confirm Active）。
- 退出码：`sys.exit(0 if (a and b) else 1)`，任一 FAIL 即非零。

**逻辑成立。** 这是真的"先红后绿"结构（模型错 → expect ≠ len → FAIL）。

### F.2 实际运行结果

```
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
python F:\rtsc\evidence\capabilities\verify_caps.py
```
实际输出与文档 §14.1 行 2258–2295 引用的 38 行**逐行完全一致**（`a_quote.py`：`quoted lines 38 actual lines 38 / identical? True`），
尾部 `RESULT demand=True confirm=True`，退出码 0。

```
--- Demand Active [BCGR 4.1.12]  totalLength=359  numberCapabilities=13  capStart=0x16  tail=4
  cap[ 4] @0x066 type=0x000e Font              len=4   expect=8   PASS* DOCUMENTED-DEVIATION(server bug, len 4 not 8)
  ...
  caps end=0x163  + tail 4 = 0x167  totalLength=359  PASS
--- Confirm Active [BCGR 4.1.13]  totalLength=492  numberCapabilities=18  capStart=0x1a  tail=0
  ...
  caps end=0x1ec  + tail 0 = 0x1ec  totalLength=492  PASS
RESULT demand=True confirm=True
```

31 个实例（13+18）确实全部匹配；Font 那 1 个以 `PASS*` 走 documented-deviation 分支，这是**有意的、有原文依据的**放行（原文 890998 处明说是 bug），不算作弊。

### F.3 但"31/31 通过"的验证力被高估（三点实测）

**(a) 只验总长，不验字段宽度与字段身份。** 我做了两组注入（`a_mutgen.py` / `a_mutgen3.py`）：

- MUT1：把 General 的 `osMajorType` 与 `osMinorType` **名字互换**（宽度不变）→ `gen_caps_full.py` 的 `assert o == off` **全部通过**，`caps=27 bytes=25034`，正常产出文件。说明 assert 只校验"偏移 == 累加值"，**不校验字段名/语义**。
- MUT3：把 Bitmap 的 `highColorFlags` 改成 2 字节、`drawingFlags` 移到偏移 24 且改 2 字节、删掉 `pad2octetsB`、`multipleRectangleSupport` 挪到 26 → **总长仍是 28，assert 全部通过**，正常产出：
  ```
  | 22 | 2 | `highColorFlags` |
  | 24 | 2 | `drawingFlags` |
  | 26 | 2 | `multipleRectangleSupport` |
  > 偏移校验：末字段结束 = 28 = 固定总长 28 ✔
  ```
  这是一张**完全错误但对内自洽**的表。`verify_caps.py` 也拦不住它（它只比总长 28 == 28）。
- 所以文档 §14.2 行 2315「因此 §8 的偏移不存在手抄错误」——**这句本身成立**（偏移确实由累加得出），但 §15.1 行 2394「27 个定长 capability 的总长 … 脚本累加校验」把它读成"宽度也被机器校验过"就**不成立**：宽度是人工转录的，脚本只保证"人工转录的宽度之和 == 人工声明的总长"。
- 补一句正面证据：我实际做了宽度核对（A 项，27/27 全对），所以**结论没错**，只是**证据强度被高估**。

**(b) 覆盖 21/27 个类型，不是 27。** `a_cov.py` 统计两个 dump 里出现的 type 集合：

```
instances 31
distinct covered 21
NOT covered ['0x0004','0x0019','0x001A','0x001B','0x001C','0x001E']  (6 个)
```

未被任何 dump 覆盖的 6 个：BitmapCache Rev1、CompDesk、MultifragUpdate、LargePointer、SurfaceCommands、FrameAck。
其中 `0x0004`（Rev1，40 字节）和 `0x001A`（Multifrag，8 字节）是**很常用的**，它们的长度模型从未被 dump 反证过。
文档 §15.1 行 2393 说"全部 28 个 capabilitySetType 的编号与名称 … §14.1 脚本对 31 个实例逐个匹配"——**编号与名称的匹配来自 §6.2 的人工转录，脚本只匹配长度，而且只碰到 21 个类型**。

**(c) Fast-Path 的 2 字节长度形式完全没有向量。** 脚本只处理慢路径 dump，`length1 & 0x80` 分支（文档 §3.4）无任何机器验证，文档 §14.5 已诚实声明（U-07），这点是**加分**而非缺陷。

**(d) VirtualChannel 的模型编码的是 8 字节形态。** `SCHEMA` 里 `('VirtualChannel', 20, [4])` → `LEN = 4+4 = 8`，与文档 §8.18 声称的"固定总长 12"矛盾（两个 dump 都是 8）。这反证了 §8.18 的表述问题（D-04），也说明脚本与文档 §8 在这一点上不同源。

**F 结论：PARTIAL。** 脚本真实存在、逻辑正确、实际跑通 31/31 且输出与文档引用逐字相同（这部分 PASS）；
但"独立长度模型"只能证明长度自洽，不能证明宽度正确（已用注入实验证伪其"万能"假设），且类型覆盖 21/27。

---

## 缺陷清单（11 条）

### D-01（中）§4.3 的 totalLength 闭式等式多算 4 字节
- **文档位置**：行 727–728
- **文档声称**：
  ```
  totalLength = (14 + lengthSourceDescriptor + 4) + Σ lengthCapability[i] + 4
              = 18 + lengthSourceDescriptor + lengthCombinedCapabilities + 4
  ```
- **规范原文**：2.2.1.13.1.1 —— `lengthCombinedCapabilities (2 bytes): The combined size in bytes of the numberCapabilities, pad2Octets, and capabilitySets fields.`（原文 227893）；`sessionId (4 bytes)` 紧随 `capabilitySets`。
- **差异**：第一行代入 L=4、Σ=333 得 359 ✔（正确）；但化简到第二行多了一个 `+4`。因为 `lcc = 4 + Σ`，正确闭式是 `18 + L + lcc` = 18+4+337 = **359**，文档写 `+4` 得 **363**，与它自己行 740 的 `355+4=359` 矛盾。
- **建议修正**：删掉第二行末尾的 `+ 4`，改为 `= 18 + lengthSourceDescriptor + lengthCombinedCapabilities`。

### D-02（高，最严重）§4.1 把 MCS I/O Channel ID 写成 0x03E3，且 hex≠dec
- **文档位置**：行 688
- **文档声称**：`mcsSDin.channelId` MUST = MCS I/O Channel ID（`0x03E3` = 1003）
- **规范原文**：3.3.5.3.13.1（原文 793566）只说 `the embedded channelId field MUST be set to the MCS I/O channel ID held in the I/O Channel ID store`，**不给字面值**（该值由 Server Network Data 分配）。官方 dump 4.1.12 的实际字节是 `68 00 01 03 eb 70 81 73` → channelId = `0x03EB` = **1003**（原文 880397 + 注解 `channelId = 1003 (0x03eb)`）。
- **差异**：`0x03E3` = **995**，不是 1003；且正确值应为 `0x03EB`。同文档行 2202 自己写的是 `channelId = 1003 (0x03EB)`，**前后矛盾**。
- **影响**：按行 688 硬编码 `0x03E3` 会让 MCS SendDataIndication 的 channelId 错误，服务端直接丢弃该 PDU → 握手卡在 Demand Active。
- **建议修正**：改为 `channelId` MUST = I/O Channel ID store 中的值（本 dump 为 `0x03EB` = 1003；不可硬编码，必须从 Server Network Data 取）。

### D-03（中）§13.4 把解密后的明文当作"完整线上字节"，且标注为"密文"
- **文档位置**：行 2159、2162–2163、2171
- **文档声称**：行 2159「这是**完整线上字节**（17 字节）」；行 2162 给出 `… c8 47 20 00 08 ab 02 6f 01`；行 2171 把 `20 00 08 ab 02 6f 01` 标为 `fpInputEvents（密文）`「7 字节加密载荷」。
- **规范原文**（bcgr.txt 1020179，及官方页 `ms-rdpbcgr/d8f1be0e-…`）：`c4 11 30 35 6b 5b b5 34 c8 47 26 18 5e 76 0e de 28`，注解 `26 18 5e 76 0e de 28 -> Encrypted TS_FP_INPUT_PDU::fpInputEvents`。
- **差异**：偏移 10–16 共 7 字节不同（`26 18 5e 76 0e de 28` vs `20 00 08 ab 02 6f 01`）。文档把"解密后明文"填进了"线上字节"代码块，同时保留"密文"标签，二者不可能同真。
- **建议修正**：代码块改回原文 `26 18 5e 76 0e de 28`，并在表里明确「偏移 10 的 7 字节是密文，解密后为 `20 00 08 ab 02 6f 01`（见下方解密块）」。长度自洽 `1+1+8+7=17` 不变。

### D-04（中）§8.18 VirtualChannel"固定总长 12"与自身表格/官方 dump 矛盾
- **文档位置**：行 1425、1432、1436
- **文档声称**：行 1425「固定总长：**12 字节**」；行 1432「`lengthCapability` | 8（无 VCChunkSize）或 12（含 VCChunkSize）」；行 1436「偏移校验：末字段结束 = 12 = 固定总长 12 ✔」
- **规范原文**：2.2.7.1.10 —— 结构行 `VCChunkSize (optional)`；官方 dump 4.1.12 与 4.1.13 的 VirtualChannel 都是 `lengthCapability = 8`（原文注解 `08 00 -> TS_VIRTUALCHANNEL_CAPABILITYSET::lengthCapability = 8 bytes`，两处）。
- **差异**：这不是"定长 12"的 capability。行 1425/1436 的"固定总长 12"与行 1432 的"8 或 12"直接冲突；`verify_caps.py` 的 `SCHEMA` 也按 8 编码（`[4]` → 8），说明模型与文档不同源。
- **建议修正**：行 1425 改为「总长：**8**（无 `VCChunkSize`，官方 dump 形态）或 **12**（含 `VCChunkSize`）」；行 1436 改为「两种形态分别结束于 8 / 12」。

### D-05（中）§14.1 的"先红后绿"红证算错：多一个 2 字节字段是 26 不是 28
- **文档位置**：行 2304–2309
- **文档声称**：「模型第一版把 General 的字段宽度写成 13 项（**多算了一个 `pad2octets`**），导致 `expect=28` 而 dump 是 `24`」
- **规范/脚本事实**：`verify_caps.py` 的 `LEN` 是 `4 + sum(payload widths)`，**已自动加 4 字节头**。所以 payload 里多加**一个** 2 字节字段 → `4+22+2 = 28`? 不对：正确 payload 是 11×2+2×1 = 24，`4+24 = 28`? 也不对——正确总长是 24，即 payload 应为 20（`4+20=24`）。
- **我实测两种注入**（`a_redgreen.py`）：
  ```
  == red_doublecount.py  (payload 里把 capabilitySetType/lengthCapability 也算进去)
        cap[ 1] General  len=24  expect=28  FAIL     <-- 与文档声称的 28 一致
  == red_onepad.py       (payload 里只多加一个 2 字节 pad2octets，即文档所述原因)
        cap[ 1] General  len=24  expect=26  FAIL     <-- 是 26，不是 28
  == green_orig.py
        cap[ 1] General  len=24  expect=24  PASS
  ```
- **差异**：文档描述的"多算一个 `pad2octets`"只能得到 `expect=26`。要得到文档声称的 `expect=28`，必须是**把两个头字段（capabilitySetType + lengthCapability）也当 payload 又加了一遍**（double-count，`4 + 24 = 28`）。红证的方向（错模型必被 dump 打回）成立，但**归因写错了**。
- **建议修正**：改为「模型第一版把 `capabilitySetType` 与 `lengthCapability` 也写进了 payload 宽度表，被 `LEN` 的 `4 +` 二次计入，`expect=28`；实测 `payload 多一个 2 字节字段` 只会得到 `expect=26`」。

### D-06（中）§14.2/§15.1 把"偏移自洽"说成"宽度已被机器校验"
- **文档位置**：行 2313–2315、行 2394
- **文档声称**：行 2315「因此 §8 的偏移**不存在手抄错误**」（这句本身成立）；行 2394「27 个定长 capability 的总长 | §14.2 脚本累加校验 + §14.1 dump 反向匹配（31/31 通过）」——被读成"宽度也过了机器校验"。
- **实测**：`gen_caps_full.py` 只有 `assert o == off`（行 461），**不比对宽度、不比对字段名**。注入实验：
  - 交换 `osMajorType`/`osMinorType` 名字 → assert 全通过，产出 25034 字节文件；
  - Bitmap 改成 `highColorFlags(2) @22 / drawingFlags(2) @24 / 删 pad2octetsB / multipleRectangleSupport @26` → **总长仍 28，assert 全通过**，产出一张错误但自洽的表。
- **差异**：脚本保证的是"人工宽度之和 == 人工总长"，**不是**"宽度 == 规范"。§14.1 的 dump 反向匹配也只比总长（28==28 对上述错误表同样 PASS）。
- **建议修正**：把行 2394 的证据列改为「总长由累加保证；**字段宽度为人工转录，已由审计逐字段比对规范原文（27/27 一致）**」，并把 §14.2 的结论限定为"偏移无手抄错误，宽度正确性由逐字段人工核对保证"。

### D-07（轻）§0.2/§14.3 的"85 个 URL / 85/85"与实际 87 个、脚本覆盖 83 个不符
- **文档位置**：行 129、行 2323–2332
- **文档声称**：行 129「上述 **85 个** `learn.microsoft.com` 页面 … 85/85 返回 HTTP 200」；行 2331「脚本对 **§0.2 表中每个** `learn.microsoft.com` URL 发 HEAD」。
- **实测**（`a_urls.py` / `a_urls3.py`）：§0.2 表共 89 行，其中 `ms-*` learn 页面 **87 个**，DOCX 直链 2 个（S88/S89）。`check_urls.ps1` 内列表 **85 个**，与文档 87 个的交集 **83**：
  - 文档有、脚本无：S01 `2.2 Message Syntax`、S05 `2.2.1.13`、S67 `5.3.6.1`、S69 `5.3.6.2`
  - 脚本有、文档无：`ms-rdpbcgr/5073f4ed…`（协议首页）、`ms-rdpegdi/745f2eee…`
- **补充取证**：我自己对那 4 个缺失 URL 逐个 HEAD，全部 200：
  ```
  ms-rdpbcgr/b61e1c76-… -> 200
  ms-rdpbcgr/8be0074f-… -> 200
  ms-rdpbcgr/7c61b54e-… -> 200
  ms-rdpbcgr/e0d4b29b-… -> 200
  ```
  并实际运行脚本：`checked=85 ok=85 bad=0`（与文档输出一致）。
- **差异**：结论"所有引用页面可达"**成立**（87/87 可达），但"85 个"计数与"对 §0.2 每个 URL"的说法**不准确**（应为 87 个，脚本覆盖 83/87）。
- **建议修正**：行 129 改为「87 个 learn 页面（另 2 个 DOCX 直链）」；行 2331 改为「脚本覆盖其中 85 个（含 2 个未在 §0.2 表内的协议首页/EGDI 页），其余 4 个已单独 HEAD 验证 200」。

### D-08（轻）"pduSource MUST = User Channel ID"的出处引错
- **文档位置**：行 265–266、行 792
- **文档声称**：行 266「这符合 3.2.5.3.13.2 "`pduSource` MUST be set to the User Channel ID"（S61）」；行 792 在 `TS_CONFIRM_ACTIVE_PDU` 字段表里同样标 MUST。
- **规范原文**：该句在 **3.2.5.1 Constructing a Client-to-Server Slow-Path PDU**（原文 682180）：
  `The pduSource field of the embedded Share Control Header (section 2.2.8.1.1.1.1) MUST be set to the User Channel ID held in the User Channel ID store (section 3.2.1.5).`
  3.2.5.3.13.2（S61）全文 **不含 `pduSource`**（我截取 S61 段落实测 `pduSource in S61? False`）。
- **差异**：要求真实存在，但章节号错（S61 → 3.2.5.1）。另外 2.2.1.13.2.1 本身对 `pduSource` 无 MUST（它只在 Share Control Header 定义里说"transmission source"）。
- **建议修正**：行 266 改为「3.2.5.1（Constructing a Client-to-Server Slow-Path PDU）对通用客户端 PDU 规定 `pduSource` MUST = User Channel ID」；行 792 的"依据"补 3.2.5.1。

### D-09（轻）U-20 的前提"各 capability 节都写 MUST be set to N"不成立
- **文档位置**：行 2385
- **文档声称**：「各 capability 节都写 "MUST be set to N"，但未规定接收方校验义务」
- **规范原文**：全文搜索 `lengthCapability` + `MUST` → **bcgr 0 处、egdi 0 处**。23 处 `lengthCapability (2 bytes)` 定义全部只有 `The length in bytes of the capability data, including the size of the capabilitySetType and lengthCapability fields.` 无任何字面长度要求。全文 `MUST be set to <n> bytes` 仅 1 处，且是 Monitor Layout 的 `monitorAttributeSize`（原文 2.2.1.3.10），与 capability 无关。
- **差异**：固定总长是**由字段表隐含**的，不是用 MUST 写出的。文档的结论（接收侧无校验义务、应按实际 `lengthCapability` 定界）**依然正确**，但前提表述失实。
- **建议修正**：改为「各 capability 节的字段表隐含固定总长（原文未用 MUST 表述长度），但未规定接收方校验义务」。

### D-10（轻）两处交叉引用错章节：§12 → §15
- **文档位置**：行 1677、行 1688
- **文档声称**：行 1677「见 §12 U-04」；行 1688「见 §12 U-05」
- **实际**：U-04 / U-05 在 **§15 不确定项清单**（行 2369 / 2370）。§12 是"客户端能力交换状态机"，不含 U 编号。
- **建议修正**：均改为「见 §15 U-04」「见 §15 U-05」。

### D-11（轻）§15.1 把"31 个实例"说成"28 个类型已核实"
- **文档位置**：行 2393、行 2394
- **文档声称**：行 2393「全部 28 个 `capabilitySetType` 的编号与名称 | 规范原文表（S08）+ §14.1 脚本对 31 个实例逐个匹配」
- **实测**（`a_cov.py`）：31 个实例只覆盖 **21 个不同类型**；`0x0004 / 0x0019 / 0x001A / 0x001B / 0x001C / 0x001E` 这 6 个类型**从未出现在任何 dump 中**，其长度模型未被反证。脚本匹配的是"长度"，不是"名称"。
- **建议修正**：拆成两行——「28 个编号与名称：规范原文表逐行比对（本审计 §B）」+「21 个类型 × 31 个实例的长度：dump 反向匹配通过；其余 6 个类型无 dump 佐证」。

---

## 未覆盖的部分（显式声明，未审计）

以下内容**我没有独立核实**，不得据此认为它们正确：

1. **§12 状态机的时序正确性**：只核了 §4.4/§5.4/§10.4 引用的三段原文存在且转述无误；§12.2 迁移表逐行是否与 1.3.1.1 的完整序列一致，未逐条核对。
2. **§2.3–§2.5 安全头与 MAC 算法**：只核了 4/12/16 字节结构与 `SEC_*` 标志位（与原文一致），`Pad1/Pad2/SHA/MD5/HMAC` 的算法描述只做了"原文存在且公式文本一致"的比对，未做密码学正确性验证（无测试向量）。
3. **§3.5 `TS_FP_UPDATE` 各 subtype 的 `updateData` 内部结构**：只核了 `updateCode`/`fragmentation`/`compression` 三个位域与 12 个 code 的映射，未逐 subtype 核 `TS_FP_UPDATE_BITMAP`/`PALETTE`/`SURFCMDS` 的载荷布局。
4. **§9.4 `orderSupport` 的"对应主绘图订单"语义**：32 行索引与名称已逐行比对一致，但"某索引对应哪几个订单"（如 0x01 = PatBlt + OpaqueRect）只读了原文表格，未到 [MS-RDPEGDI] 2.2.2.2.1.1.2 逐节确认。
5. **§10 Deactivate All**：结构（6+4+2+var）与 `pduType=0x0016` 已核；但**无官方 dump**（文档 §14.5 也承认），`totalLength=13` 的推导未做向量验证。
6. **§11 Font List / Font Map 的处理规则**：26 字节结构与 dump 已逐字节核对；"业务字段 MUST 忽略"已核（原文 722687 / 799873），但"服务端收到 Font List 后 MUST 发 Font Map、失败 SHOULD 断链"的原文我核到了，**未核** U-06 关于 `FONTSUPPORT_FONTLIST` 是否为前置条件的完整论证。
7. **§7.2/§7.3 的 capability 集合建议**：18 个 set 的顺序与长度已与 dump 逐项核对通过；但"最小集合"是工程判断（文档自己标 B 级），我未做实测（无实机/无抓包）。
8. **§6.4 Bitmap Codecs 的 GUID 字节序**：GUID 表已与原文比对；`B9 1B 8D CA …` 的线上字节序只按 [MS-DTYP] 规则手算，未与实包比对。
9. **`check_urls.ps1` 的 HTTP 语义**：我实际运行得到 `checked=85 ok=85 bad=0`，但未审该脚本是否对 3xx/403 做了正确的失败判定（只看了它发 HEAD、失败回退 GET）。
10. **现代 mstsc（10.x）行为**：无抓包，未核（文档 U-02 已声明）。

---

## 附：本次审计用到的独立计算汇总

| 计算 | 输入 | 结果 | 与文档一致 |
|---|---|---|---|
| General 总长 | 11×2 + 2×1 | 24 | ✔ |
| Bitmap 总长 | 11×2 + 2×1 + 2×2 | 28 | ✔ |
| Order 总长 | 2+2+16+4+2+2+2+2+2+2+32+2+2+4+4+2+2+2+2 | 88 | ✔ |
| Input 总长 | 2+2+2+2+4+4+4+4+64 | 88 | ✔ |
| GlyphCache 总长 | 2+2+40+4+2+2 | 52 | ✔ |
| DrawGdiPlus 总长 | 2+2+4+4+4+10+8+6 | 40 | ✔ |
| Window 总长 | 2+2+4+1+2 | 11 | ✔ |
| Demand Active 遍历 | 0x16 + 333 + 4 | 0x167 = 359 | ✔ |
| Confirm Active 遍历 | 0x1A + 466 + 0 | 0x1EC = 492 | ✔ |
| lcc 口径 | 4 + 333 | 337 = 0x151 | ✔ |
| Confirm lcc | 4 + 466 | 470 = 0x1D6 | ✔ |
| totalLength 闭式（正确） | 18 + 4 + 337 | 359 | 文档写 +4 得 363 ✘（D-01） |
| Fast-Path 长度 | 1+1+8+7 | 17 = 0x11 | ✔ |
| `0x03E3` | hex→dec | 995 ≠ 1003 | ✘（D-02） |
| `0x03EB` | hex→dec | 1003 | 正确值 |
| 红证（一个多余 2B 字段） | 4+20+2 | 26 | 文档说 28 ✘（D-05） |
| 红证（双计头字段） | 4+24 | 28 | 与文档数字吻合 |

*报告结束。审计 AI 甲。*
