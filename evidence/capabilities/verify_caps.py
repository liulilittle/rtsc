import re, sys

lines = open(r'F:\rtsc\.tmp\bcgr.txt', encoding='utf-8').read().splitlines()

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

SCHEMA = [
    ('General',        1,  [2,2,2,2,2,2,2,2,2,1,1],                'BCGR 2.2.7.1.1'),
    ('Bitmap',         2,  [2,2,2,2,2,2,2,2,2,1,1,2,2],            'BCGR 2.2.7.1.2'),
    ('Order',          3,  [16,4,2,2,2,2,2,2,32,2,2,4,4,2,2,2,2],  'BCGR 2.2.7.1.3'),
    ('BitmapCacheRev1',4,  [4,4,4,4,4,4,2,2,2,2,2,2],              'BCGR 2.2.7.1.4.1'),
    ('Control',        5,  [2,2,2,2],                              'BCGR 2.2.7.2.2'),
    ('Activation',     7,  [2,2,2,2],                              'BCGR 2.2.7.2.3'),
    ('Pointer',        8,  [2,2,2],                                'BCGR 2.2.7.1.5'),
    ('Share',          9,  [2,2],                                  'BCGR 2.2.7.2.4'),
    ('ColorCache',    10,  [2,2],                                  'EGDI 2.2.1.1'),
    ('Sound',         12,  [2,2],                                  'BCGR 2.2.7.1.11'),
    ('Input',         13,  [2,2,4,4,4,4,64],                       'BCGR 2.2.7.1.6'),
    ('Font',          14,  [2,2],                                  'BCGR 2.2.7.2.5'),
    ('Brush',         15,  [4],                                    'BCGR 2.2.7.1.7'),
    ('GlyphCache',    16,  [40,4,2,2],                             'BCGR 2.2.7.1.8'),
    ('Offscreen',     17,  [4,2,2],                                'BCGR 2.2.7.1.9'),
    ('BmpCacheHost',  18,  [1,1,2],                                'BCGR 2.2.7.2.1'),
    ('BitmapCacheRev2',19, [2,1,1,4,4,4,4,4,12],                   'BCGR 2.2.7.1.4.2'),
    ('VirtualChannel',20,  [4],                                    'BCGR 2.2.7.1.10'),
    ('DrawNineGrid',  21,  [4,2,2],                                'EGDI 2.2.1.2'),
    ('DrawGdiPlus',   22,  [4,4,4,10,8,6],                         'EGDI 2.2.1.3'),
    ('Rail',          23,  [4],                                    'RDPERP 2.2.1.1.1'),
    ('Window',        24,  [4,1,2],                                'RDPERP 2.2.1.1.2'),
    ('CompDesk',      25,  [2],                                    'BCGR 2.2.7.2.8'),
    ('MultifragUpdate',26, [4],                                    'BCGR 2.2.7.2.6'),
    ('LargePointer',  27,  [2],                                    'BCGR 2.2.7.2.7'),
    ('SurfaceCommands',28,[4,4],                                   'BCGR 2.2.7.2.9'),
    ('FrameAck',      30,  [4],                                    'RDPRFX 2.2.1.3'),
]
LEN = {c[1]: (c[0], 4 + sum(c[2]), c[3]) for c in SCHEMA}

def scan(name, marker, cap_start, tail_bytes=0, known_deviations=None):
    known_deviations = known_deviations or {}
    b = grab(marker)
    total = int.from_bytes(b[0:2], 'little')
    ncap = int.from_bytes(b[cap_start-4:cap_start-2], 'little')
    print('\n--- %s  totalLength=%d  numberCapabilities=%d  capStart=0x%x  tail=%d'
          % (name, total, ncap, cap_start, tail_bytes))
    p = cap_start
    ok = True
    for k in range(ncap):
        ctype = int.from_bytes(b[p:p+2], 'little')
        clen = int.from_bytes(b[p+2:p+4], 'little')
        cname, expect, src = LEN.get(ctype, ('UNKNOWN', None, '?'))
        if ctype in known_deviations:
            note = 'DOCUMENTED-DEVIATION(%s)' % known_deviations[ctype]
            verdict = 'PASS*'
        elif expect is None:
            note = 'variable-length, not length-checked'
            verdict = 'n/a'
        else:
            verdict = 'PASS' if expect == clen else 'FAIL'
            note = ''
            if verdict == 'FAIL':
                ok = False
        print('  cap[%2d] @0x%03x type=0x%04x %-17s len=%-3d expect=%-3s %-5s %s %s'
              % (k, p, ctype, cname, clen, str(expect), verdict, src, note))
        p += clen
    end = p + tail_bytes
    good = (end == total)
    if not good:
        ok = False
    print('  caps end=0x%x  + tail %d = 0x%x  totalLength=%d  %s'
          % (p, tail_bytes, end, total, 'PASS' if good else 'FAIL'))
    return ok

# 4.1.12 Demand Active: caps end 0x163 = 355, then 4-byte sessionId -> 359.
# Font capability in this dump is 4 bytes: documented server bug (see BCGR 4.1.12 note).
a = scan('Demand Active [BCGR 4.1.12]', 'Decrypted TS_DEMAND_ACTIVE_PDU:',
         cap_start=22, tail_bytes=4, known_deviations={14: 'server bug, len 4 not 8'})
b = scan('Confirm Active [BCGR 4.1.13]', 'Decrypted TS_CONFIRM_ACTIVE_PDU:',
         cap_start=26, tail_bytes=0)

print('\nRESULT demand=%s confirm=%s' % (a, b))
sys.exit(0 if (a and b) else 1)
