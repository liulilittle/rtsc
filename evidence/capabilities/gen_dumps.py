import re, io

lines = io.open(r'F:\rtsc\.tmp\bcgr.txt', encoding='utf-8').read().splitlines()

def grab(marker):
    idx = next(i for i, l in enumerate(lines) if marker in l)
    out = bytearray()
    i = idx + 1
    while i < len(lines):
        m = re.match(r'^\[Code\] [0-9a-f]{8} ((?:[0-9a-f]{2} ?)+)', lines[i])
        if not m:
            break
        out.extend(int(x, 16) for x in m.group(1).split())
        i += 1
    return bytes(out)

def hexdump(b, per=16):
    out = []
    for off in range(0, len(b), per):
        chunk = b[off:off+per]
        hx = ' '.join('%02x' % x for x in chunk)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
        out.append('%08x  %-47s  %s' % (off, hx, asc))
    return '\n'.join(out)

def emit(title, marker, fields, note=''):
    b = grab(marker)
    print('### ' + title)
    print()
    if note:
        print(note)
        print()
    print('```')
    print(hexdump(b))
    print('```')
    print()
    print('| 偏移 | 字节 | 字段 | 值 / 说明 |')
    print('|---:|---|---|---|')
    for off, ln, f, desc in fields:
        hx = ' '.join('%02x' % x for x in b[off:off+ln])
        print('| %d (0x%03x) | %d | `%s` | `%s` — %s |' % (off, off, ln, f, hx, desc))
    print()
    print('总长 **%d 字节**。' % len(b))
    print()
    return b

# ---------------- Demand Active (4.1.12) ----------------
b = grab('Decrypted TS_DEMAND_ACTIVE_PDU:')
assert len(b) == 359
caps = [
 (0x016, 8, 0x0009, 'Share', 'nodeID=0x03EA, pad2octets=0xE2DC'),
 (0x01e, 24, 0x0001, 'General', 'osMajor=1(WINDOWS) osMinor=3(WINDOWS_NT) protocolVersion=0x0200 extraFlags=0x041D refreshRect=1 suppressOutput=1'),
 (0x036, 8, 0x0014, 'VirtualChannel', 'flags=0x00000002 (VCCAPS_COMPR_CS_8K)'),
 (0x03e, 40, 0x0016, 'DrawGdiPlus', 'drawGDIPlusSupportLevel=0, GdipVersion/drawGdiplusCacheLevel=1, 其余字段服务端未初始化'),
 (0x066, 4, 0x000e, 'Font', '**lengthCapability=4（服务端 bug，规范值 8）**，fontSupportFlags 与 pad2octets 缺失'),
 (0x06a, 28, 0x0002, 'Bitmap', 'preferredBitsPerPixel=24, desktop=1280x1024, bitmapCompressionFlag=TRUE, multipleRectangleSupport=TRUE'),
 (0x086, 88, 0x0003, 'Order', 'orderFlags=0x0022 (COLORINDEXSUPPORT OR NEGOTIATEORDERSUPPORT), desktopSaveSize=1000000'),
 (0x0de, 8, 0x000a, 'ColorCache', 'colorTableCacheSize=6'),
 (0x0e6, 8, 0x0012, 'BmpCacheHostSupport', 'cacheVersion=1 (Rev2)'),
 (0x0ee, 10, 0x0008, 'Pointer', 'colorPointerFlag=TRUE, colorPointerCacheSize=25, pointerCacheSize=25'),
 (0x0f8, 88, 0x000d, 'Input', 'inputFlags=0x0035 (FASTPATH_INPUT2 OR UNICODE OR MOUSEX OR SCANCODES), keyboardLayout/Type/SubType/FunctionKey/imeFileName 服务端未初始化'),
 (0x150, 8, 0x0017, 'Rail', 'railSupportLevel=0'),
 (0x158, 11, 0x0018, 'Window', 'wndSupportLevel=0, nIconCaches=0, nIconCacheEntries=0'),
]
fields = [
 (0, 2, 'TS_SHARECONTROLHEADER.totalLength', '0x0167 = 359'),
 (2, 2, 'TS_SHARECONTROLHEADER.pduType', '0x0011 = TS_PROTOCOL_VERSION(0x10) OR PDUTYPE_DEMANDACTIVEPDU(1)'),
 (4, 2, 'TS_SHARECONTROLHEADER.pduSource', '0x03EA = 1002（MCS server channel）'),
 (6, 4, 'TS_DEMAND_ACTIVE_PDU.shareID', '0x000103EA'),
 (10, 2, 'lengthSourceDescriptor', '4'),
 (12, 2, 'lengthCombinedCapabilities', '0x0151 = 337 = 4 + Σ lengthCapability(333)'),
 (14, 4, 'sourceDescriptor', '"RDP" + NUL'),
 (18, 2, 'numberCapabilities', '13'),
 (20, 2, 'pad2Octets', '0'),
]
for off, ln, t, nm, d in caps:
    fields.append((off, ln, 'capability[%d] type=0x%04x %s' % (caps.index((off, ln, t, nm, d)), t, nm), 'lengthCapability=%d；%s' % (ln, d)))
fields.append((355, 4, 'TS_DEMAND_ACTIVE_PDU.sessionId', '0（被客户端忽略）'))

print('### 13.1 dump #1 — Server Demand Active PDU（[MS-RDPBCGR] 4.1.12，S70）')
print()
print('> 来源：官方规范 §4.1.12 注解 dump（Microsoft RDP 5.1 client ↔ RDP 5.1 server）。')
print('> 下表的十六进制是 dump 中 **解密后的 `TS_DEMAND_ACTIVE_PDU` 明文**（359 字节），')
print('> 不含 TPKT / X.224 / MCS / securityHeader。外层封装见 §13.5。')
print()
print('```')
print(hexdump(b))
print('```')
print()
print('| 偏移 | 字节 | 字段 | 值 / 说明 |')
print('|---:|---|---|---|')
for off, ln, f, desc in fields:
    hx = ' '.join('%02x' % x for x in b[off:off+ln])
    if ln > 16:
        hx = ' '.join('%02x' % x for x in b[off:off+8]) + ' ... ' + ' '.join('%02x' % x for x in b[off+ln-4:off+ln])
    print('| %d (0x%03x) | %d | `%s` | `%s` — %s |' % (off, off, ln, f, hx, desc))
print()
print('**长度自洽**：`totalLength = 22 + 333 + 4 = 359` ✔（capabilitySets 起于 0x16，13 个 capability 合计 333 字节，')
print('末尾 4 字节 `sessionId`）。`lengthCombinedCapabilities = 4 + 333 = 337 = 0x0151` ✔。')
print()

# ---------------- Confirm Active (4.1.13) ----------------
b2 = grab('Decrypted TS_CONFIRM_ACTIVE_PDU:')
assert len(b2) == 492
caps2 = [
 (0x01a, 24, 0x0001, 'General', 'extraFlags=0x041D；**refreshRectSupport=0、suppressOutputSupport=0**（客户端置 0，与 Demand Active 的 1 形成对比）'),
 (0x032, 28, 0x0002, 'Bitmap', 'preferredBitsPerPixel=24, desktop=1280x1024'),
 (0x04e, 88, 0x0003, 'Order', 'orderFlags=0x002A（含 ZEROBOUNDSDELTASSUPPORT，客户端 MUST 置位）, textANSICodePage=0x04E4(1252)'),
 (0x0a6, 40, 0x0013, 'BitmapCacheRev2', 'CacheFlags=0x0003, NumCellCaches=3, Cache2CellInfo=0x800009FB（k=TRUE, NumEntries=2555）'),
 (0x0ce, 8, 0x000a, 'ColorCache', 'colorTableCacheSize=6'),
 (0x0d6, 12, 0x0007, 'Activation', '全部 0'),
 (0x0e2, 12, 0x0005, 'Control', 'controlInterest=2, detachInterest=2'),
 (0x0ee, 10, 0x0008, 'Pointer', 'colorPointerCacheSize=20, pointerCacheSize=21'),
 (0x0f8, 8, 0x0009, 'Share', 'nodeID=0（客户端置 0）'),
 (0x100, 88, 0x000d, 'Input', 'inputFlags=0x0015 (UNICODE OR MOUSEX OR SCANCODES), keyboardLayout=0x00000409, keyboardType=4, keyboardFunctionKey=12'),
 (0x158, 8, 0x000c, 'Sound', 'soundFlags=0x0001 (SOUND_FLAG_BEEPS)'),
 (0x160, 8, 0x000e, 'Font', 'fontSupportFlags=0x0001 (FONTSUPPORT_FONTLIST)'),
 (0x168, 52, 0x0010, 'GlyphCache', 'GlyphCache[0..8]: 254 条目；[9]: 64 条目；FragCache: 256/256；GlyphSupportLevel=3 (ENCODE)'),
 (0x19c, 8, 0x000f, 'Brush', 'brushSupportLevel=1 (BRUSH_COLOR_8x8)'),
 (0x1a4, 12, 0x0011, 'Offscreen', 'offscreenSupportLevel=1, cacheSize=7680 KB, cacheEntries=100'),
 (0x1b0, 8, 0x0014, 'VirtualChannel', 'flags=0x00000001 (VCCAPS_COMPR_SC)'),
 (0x1b8, 12, 0x0015, 'DrawNineGrid', 'supportLevel=2 (SUPPORTED_REV2), cacheSize=2560 KB, entries=256'),
 (0x1c4, 40, 0x0016, 'DrawGdiPlus', '全部 0（客户端不支持 GDI+ 1.1）'),
]
fields2 = [
 (0, 2, 'TS_SHARECONTROLHEADER.totalLength', '0x01EC = 492'),
 (2, 2, 'TS_SHARECONTROLHEADER.pduType', '0x0013 = TS_PROTOCOL_VERSION OR PDUTYPE_CONFIRMACTIVEPDU(3)'),
 (4, 2, 'TS_SHARECONTROLHEADER.pduSource', '0x03EF = 1007（**User Channel ID**）'),
 (6, 4, 'shareID', '0x000103EA（回填 Demand Active 的 shareID）'),
 (10, 2, 'originatorID', '0x03EA（MUST = server channel ID）'),
 (12, 2, 'lengthSourceDescriptor', '6'),
 (14, 2, 'lengthCombinedCapabilities', '0x01D6 = 470 = 4 + Σ lengthCapability(466)'),
 (16, 6, 'sourceDescriptor', '"MSTSC" + NUL'),
 (22, 2, 'numberCapabilities', '18'),
 (24, 2, 'pad2Octets', '0'),
]
for i, (off, ln, t, nm, d) in enumerate(caps2):
    fields2.append((off, ln, 'capability[%d] type=0x%04x %s' % (i, t, nm), 'lengthCapability=%d；%s' % (ln, d)))

print('### 13.2 dump #2 — Client Confirm Active PDU（[MS-RDPBCGR] 4.1.13，S71）')
print()
print('> 来源：官方规范 §4.1.13 注解 dump。下表是 dump 中 **解密后的 `TS_CONFIRM_ACTIVE_PDU` 明文**（492 字节）。')
print()
print('```')
print(hexdump(b2))
print('```')
print()
print('| 偏移 | 字节 | 字段 | 值 / 说明 |')
print('|---:|---|---|---|')
for off, ln, f, desc in fields2:
    hx = ' '.join('%02x' % x for x in b2[off:off+ln])
    if ln > 16:
        hx = ' '.join('%02x' % x for x in b2[off:off+8]) + ' ... ' + ' '.join('%02x' % x for x in b2[off+ln-4:off+ln])
    print('| %d (0x%03x) | %d | `%s` | `%s` — %s |' % (off, off, ln, f, hx, desc))
print()
print('**长度自洽**：`totalLength = 26 + 466 = 492` ✔（capabilitySets 起于 0x1A = 26，18 个 capability 合计 466 字节，')
print('恰好到文件末尾，**无尾部字段**——Confirm Active 没有 `sessionId`）。')
print('`lengthCombinedCapabilities = 4 + 466 = 470 = 0x01D6` ✔。')
print()

# ---------------- Font List / Font Map ----------------
b3 = grab('Decrypted TS_FONT_LIST_PDU:')
b4 = grab('Decrypted TS_FONT_MAP_PDU:')
assert len(b3) == 26 and len(b4) == 26

print('### 13.3 dump #3 — Client Font List PDU 与 Server Font Map PDU（[MS-RDPBCGR] 4.1.18 / 4.1.22，S72 / S73）')
print()
print('**Font List（客户端 → 服务端，26 字节明文）**')
print()
print('```')
print(hexdump(b3))
print('```')
print()
print('| 偏移 | 字节 | 字段 | 值 / 说明 |')
print('|---:|---|---|---|')
fl = [
 (0, 2, 'totalLength', '0x001A = 26'),
 (2, 2, 'pduType', '0x0017 = TS_PROTOCOL_VERSION OR PDUTYPE_DATAPDU(7)'),
 (4, 2, 'pduSource', '0x03EF = 1007（User Channel ID）'),
 (6, 4, 'shareID', '0x000103EA'),
 (10, 1, 'pad1', '0'),
 (11, 1, 'streamID', '0x01 = STREAM_LOW'),
 (12, 2, 'uncompressedLength', '0xDA3B（**服务端 bug，未初始化**）'),
 (14, 1, 'pduType2', '0x27 = PDUTYPE2_FONTLIST(39)'),
 (15, 1, 'compressedType', '0'),
 (16, 2, 'compressedLength', '0'),
 (18, 2, 'numberFonts', '0（SHOULD）'),
 (20, 2, 'totalNumFonts', '0（SHOULD）'),
 (22, 2, 'listFlags', '0x0003 = FONTLIST_FIRST OR FONTLIST_LAST'),
 (24, 2, 'entrySize', '0x0032 = 50（SHOULD）'),
]
for off, ln, f, desc in fl:
    hx = ' '.join('%02x' % x for x in b3[off:off+ln])
    print('| %d | %d | `%s` | `%s` — %s |' % (off, ln, f, hx, desc))
print()
print('**Font Map（服务端 → 客户端，26 字节明文）**')
print()
print('```')
print(hexdump(b4))
print('```')
print()
print('| 偏移 | 字节 | 字段 | 值 / 说明 |')
print('|---:|---|---|---|')
fm = [
 (0, 2, 'totalLength', '0x001A = 26'),
 (2, 2, 'pduType', '0x0017 = TS_PROTOCOL_VERSION OR PDUTYPE_DATAPDU(7)'),
 (4, 2, 'pduSource', '0x03EA = 1002（server channel ID）'),
 (6, 4, 'shareID', '0x000103EA'),
 (10, 1, 'pad1', '0x45（**未初始化，MUST 忽略**）'),
 (11, 1, 'streamID', '0x02 = STREAM_MED'),
 (12, 2, 'uncompressedLength', '0x001A = 26'),
 (14, 1, 'pduType2', '0x28 = PDUTYPE2_FONTMAP(40)'),
 (15, 1, 'compressedType', '0'),
 (16, 2, 'compressedLength', '0'),
 (18, 2, 'numberEntries', '0（SHOULD）'),
 (20, 2, 'totalNumEntries', '0（SHOULD）'),
 (22, 2, 'mapFlags', '0x0003 = FONTMAP_FIRST OR FONTMAP_LAST'),
 (24, 2, 'entrySize', '0x0004 = 4（SHOULD）'),
]
for off, ln, f, desc in fm:
    hx = ' '.join('%02x' % x for x in b4[off:off+ln])
    print('| %d | %d | `%s` | `%s` — %s |' % (off, ln, f, hx, desc))
print()
print('> **两个 dump 的关键差异**：`pad1` 在 Font List 中是 0，在 Font Map 中是 0x45。')
print('> 这直接印证 §2.2 的"`pad1` MUST 被忽略"——它不是保留位，任何值都合法。')
print('> `streamID` 也不同（LOW vs MED），说明 streamID 不参与语义判断。')
print()

# ---------------- Fast-Path input ----------------
b5 = grab('Decrypted TS_FP_INPUT_PDU::fpInputEvents:')
full = bytes([0xC4, 0x11, 0x30, 0x35, 0x6b, 0x5b, 0xb5, 0x34, 0xc8, 0x47]) + b5
assert len(full) == 17
print('### 13.4 dump #4 — Fast-Path Input Event PDU（[MS-RDPBCGR] 4.7，S74）')
print()
print('> 来源：官方规范 §4.7 注解 dump。这是**完整线上字节**（17 字节，无 TPKT/X.224/MCS 封装）。')
print()
print('```')
print(hexdump(full))
print('```')
print()
print('| 偏移 | 字节 | 字段 | 值 / 说明 |')
print('|---:|---|---|---|')
fp = [
 (0, 1, 'TS_FP_INPUT_PDU.fpInputHeader', '0xC4 = 0b1100_0100；位 0–1 `action`=0（FASTPATH_INPUT_ACTION_FASTPATH）；位 2–5 `numEvents`=1；位 6–7 `flags`=3（SECURE_CHECKSUM OR ENCRYPTED）'),
 (1, 1, 'length1', '0x11 = 17；MSB=0 ⇒ **无 length2**，总长即 17'),
 (2, 8, 'dataSignature', '8 字节 MAC（salted，因 flags 含 SECURE_CHECKSUM）'),
 (10, 7, 'fpInputEvents（密文）', '7 字节加密载荷'),
]
for off, ln, f, desc in fp:
    hx = ' '.join('%02x' % x for x in full[off:off+ln])
    print('| %d | %d | `%s` | `%s` — %s |' % (off, ln, f, hx, desc))
print()
print('解密后的 `fpInputEvents`（7 字节）：')
print()
print('```')
print(hexdump(b5))
print('```')
print()
print('| 偏移 | 字节 | 字段 | 值 / 说明 |')
print('|---:|---|---|---|')
fpe = [
 (0, 1, 'TS_FP_INPUT_EVENT.eventHeader', '0x20 = 0b0010_0000；位 0–2 `eventCode`=1（FASTPATH_INPUT_EVENT_MOUSE）；位 3–7 `eventFlags`=0（鼠标事件 MUST 为 0）'),
 (1, 2, 'TS_FP_POINTER_EVENT.pointerFlags', '0x0800 = PTRFLAGS_MOVE'),
 (3, 2, 'xPos', '0x02AB = 683'),
 (5, 2, 'yPos', '0x016F = 367'),
]
for off, ln, f, desc in fpe:
    hx = ' '.join('%02x' % x for x in b5[off:off+ln])
    print('| %d | %d | `%s` | `%s` — %s |' % (off, ln, f, hx, desc))
print()
print('**长度自洽**：`1 (fpInputHeader) + 1 (length1) + 8 (MAC) + 7 (events) = 17 = 0x11 = length1` ✔。')
print()
