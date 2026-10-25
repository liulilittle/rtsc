import io, re, sys, urllib.request, concurrent.futures

p = r'F:\rtsc\docs\spec\capabilities.md'
L = io.open(p, encoding='utf-8').read().split('\n')

# Collect S-table rows from section 0.2.
rows = []
for i in range(35, len(L)):
    l = L[i]
    if l.startswith('## ') or l.startswith('### '):
        break
    m = re.match(r'^\| \*?\*?(S\d+)\*?\*? \|', l)
    if m:
        rows.append((i + 1, m.group(1), l))

print(f'S rows = {len(rows)}')

base = 'https://learn.microsoft.com/en-us/openspecs/windows_protocols/'
learn, docx = [], []
for ln, sid, l in rows:
    m = re.search(r'`(ms-rdp[a-z]+/[0-9a-f-]+)`', l)
    if m:
        learn.append((sid, m.group(1)))
    elif '.docx' in l:
        docx.append((sid, l))
print(f'learn = {len(learn)}  docx = {len(docx)}')

def head(item):
    sid, path = item
    url = base + path
    try:
        req = urllib.request.Request(url, method='HEAD',
                                     headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=20) as r:
            return (sid, r.status, url)
    except Exception as e:
        code = getattr(e, 'code', None)
        return (sid, code if code else 'ERR', url)

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    results = list(ex.map(head, learn))

bad = [r for r in results if r[1] != 200]
print(f'\nHEAD checked = {len(results)}  ok = {len(results)-len(bad)}  bad = {len(bad)}')
for sid, st, url in bad:
    print(f'  BAD {sid} -> {st}  {url}')

# Report specifically the 14 the document claims were verified separately.
claimed = ['S01', 'S05', 'S67', 'S69'] + [f'S{n:02d}' for n in range(90, 100)]
print('\n--- the 14 claimed as "verified separately, 14/14 = 200" ---')
for sid, st, url in results:
    if sid in claimed:
        print(f'  {sid}: {st}')
missing = [c for c in claimed if c not in [r[0] for r in results]]
print('claimed-but-not-found-in-table:', missing)
