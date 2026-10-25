# bcgr.txt 的来源与提取方法

## 文件

`F:\rtsc\.tmp\bcgr.txt`（1154865 B）

能力交换阶段 `evidence/capabilities/verify_caps.py` 的输入。
`verify_caps.py:3` 硬编码读取该路径。

## 来源

[MS-RDPBCGR]（Remote Desktop Protocol: Basic Connectivity and Graphics Remoting）
官方 Open Specifications 文档的 Word 版本。

`F:\rtsc\.tmp\bcgr.docx`（3674631 B）

## 提取方法（已实测可逐字节重现）

```
python F:\rtsc\.tmp\docx2txt.py F:\rtsc\.tmp\bcgr.docx F:\rtsc\.tmp\bcgr.regen.txt
```

`docx2txt.py` 的做法：
- 用 `zipfile` 读 `word/document.xml`
- `ElementTree` 解析，`w:t` 取文本、`w:tab` 转 `\t`、`w:br` 转 `\n`
- 按 `w:p` / `w:tbl` 逐块输出，段落带样式前缀 `[Normal]` / `[ListParagraph]` 等，
  表格输出 `TBL_START` / `ROW: a | b | c` / `TBL_END`
- 以 UTF-8 写出

## 可重现性验证（2026-10-23 实测）

```
orig   1154865  ca703a9f3395801c
regen  1154865  ca703a9f3395801c
IDENTICAL True
```

sha256 前 16 位两次一致。**「可从官方文档重新获取」已由假设变为事实。**

## 若 `.tmp` 被清理

按上面的命令重跑即可。需要两个输入：
1. `bcgr.docx`（官方下载，3674631 B）
2. `docx2txt.py`（提取脚本，约 2 KB，内容见下）

### docx2txt.py 的来源（consult-b 第⑲步：可重现的边界）

**这是本项目自写的脚本，不是 pip 包、不是第三方工具。** 依据：

- 文件位于 `F:\rtsc\.tmp\docx2txt.py`（本仓库的临时目录），不是 site-packages
- 只依赖标准库 `sys` / `zipfile` / `re` / `xml.etree.ElementTree`，无第三方 import
- 全文见下，**约 2 KB，可直接复制重建**

**边界（诚实说明）**：本次重现用的是**同一个** `docx2txt.py`。
若该脚本也丢失，需按下面全文重建——**所以全文必须在这里留档**，
这是「可重现」的最后一环，缺了它前面的 sha 一致就只是「用同一个工具跑了两次」。

### docx2txt.py 全文

**位置：本文件第 62–116 行**（`python` 代码块，代码本体在第 63–115 行）。

```python
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
```

## 为什么不移到 evidence/

- `verify_caps.py` **不在 `verify.ps1` 调用链上**（已核实），不影响任何门禁。
- 该阶段已收口（能力交换 41 条缺陷 + §18.5 完成声明）。
- 文件 1.1 MB，纳入版本控制收益低。
- **关键：可重现性已证明**，所以「不可恢复」的风险不存在。

（consult-b 第⑱步 Q4 的裁定：接受不移走，但须补来源说明。）
