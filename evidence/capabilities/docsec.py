"""章节定位工具（锚定标题编号，避免 2.2.7.2 误配 7.2）。供 check_acceptance.py 复用。"""
import io
import re

HEAD = re.compile(r'^(#{1,6})\s+(\d+(?:\.\d+)*)[.、]?\s+(.*)$')


def load(path=r'F:\rtsc\docs\spec\capabilities.md'):
    L = io.open(path, encoding='utf-8').read().splitlines()
    H = []
    for i, l in enumerate(L, 1):
        m = HEAD.match(l)
        if m:
            H.append((i, len(m.group(1)), m.group(2), m.group(3).strip()))
    return L, H


def section(L, H, num):
    """按章节编号精确定位，返回 (start, end_exclusive, text)。num 如 '7.2'。"""
    for idx, (ln, lvl, n, txt) in enumerate(H):
        if n == num:
            end = len(L) + 1
            for ln2, lvl2, _, _ in H[idx + 1:]:
                if lvl2 <= lvl:
                    end = ln2
                    break
            return ln, end, '\n'.join(L[ln - 1:end - 1])
    return None, None, ''


if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    L, H = load()
    for num in ['0.2', '1.2', '2.4', '4.3', '5.5', '6.1', '7.2', '7.3', '8.18',
                '11.1', '12.2', '12.3', '13.4', '14.1', '14.2', '15.1', '16']:
        s, e, t = section(L, H, num)
        print('%-6s -> %s..%s (%s 行)' % (num, s, (e - 1) if e else None, (e - s) if s else 0))
