import sys, zipfile, re
from xml.etree import ElementTree as ET

W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'

def text_of(el):
    out = []
    for node in el.iter():
        tag = node.tag
        if tag == W + 't':
            out.append(node.text or '')
        elif tag == W + 'tab':
            out.append('\t')
        elif tag == W + 'br':
            out.append('\n')
    return ''.join(out)

def main(path, out):
    z = zipfile.ZipFile(path)
    data = z.read('word/document.xml')
    root = ET.fromstring(data)
    body = root.find(W + 'body')
    lines = []
    for child in body:
        if child.tag == W + 'p':
            style = ''
            ppr = child.find(W + 'pPr')
            if ppr is not None:
                ps = ppr.find(W + 'pStyle')
                if ps is not None:
                    style = ps.get(W + 'val') or ''
            t = text_of(child).strip()
            if t:
                lines.append(('P', style, t))
        elif child.tag == W + 'tbl':
            lines.append(('TBL_START', '', ''))
            for tr in child.findall(W + 'tr'):
                cells = []
                for tc in tr.findall(W + 'tc'):
                    cells.append(text_of(tc).strip().replace('\n', ' / '))
                lines.append(('ROW', '', ' | '.join(cells)))
            lines.append(('TBL_END', '', ''))
    with open(out, 'w', encoding='utf-8') as f:
        for kind, style, t in lines:
            if kind == 'P':
                f.write('[%s] %s\n' % (style or 'Normal', t))
            elif kind == 'ROW':
                f.write('  ROW: %s\n' % t)
            else:
                f.write('%s\n' % kind)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
