"""统计 design-a.md 中 §3.4.2 / §3.4.3 的交叉引用次数。

**为什么需要这个脚本**（consult-b 第⑩步 Q5）：
这个数字已经人工维护错过两次（父会话写 15/20、consult-b 写 12+15，实测都是错的），
说明人工维护必然失败。它完全可机械判定，因此固化为脚本 + `--check` 门禁。

**口径定义**（必须同时声明三个维度，否则数字无法复现）：
  1. 计数单位：按"次"（同一行出现 2 次算 2）vs 按"行"
  2. 范围：全文 vs 截断到 `### 8.6` 之前（§8.6 会自指，含它数字随本节文字变化）
  3. 是否含代码块

**唯一稳定口径 = B**：截断 §8.6 之前、按次、含代码块。
文档中引用的数字必须等于口径 B。

用法：
    python count_sec_refs.py                 # 打印六口径
    python count_sec_refs.py --check         # 校验文档数字 == 口径 B，不符 exit=1
    python count_sec_refs.py --file X.md
"""
import argparse
import io
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

DEFAULT_DOC = r'F:\rtsc\docs\spec\tls-backend.design-a.md'
CUT = '### 8.6'


def load(path):
    return io.open(path, encoding='utf-8').read()


def count_occurrences(t):
    h = re.findall(r'\u00a73\.4\.[23]', t)
    return h.count('\u00a73.4.2'), h.count('\u00a73.4.3')


def count_lines(t):
    a = sum(1 for l in t.split('\n') if '\u00a73.4.2' in l)
    b = sum(1 for l in t.split('\n') if '\u00a73.4.3' in l)
    return a, b


def strip_fences(t):
    out, infence = [], False
    for l in t.split('\n'):
        if l.strip().startswith('```'):
            infence = not infence
            continue
        if not infence:
            out.append(l)
    return '\n'.join(out)


def caliber_b(doc):
    """唯一稳定口径：截断 §8.6 之前、按次、含代码块。"""
    i = doc.find(CUT)
    head = doc[:i] if i > 0 else doc
    return count_occurrences(head)


def parse_doc_claim(doc):
    """从文档「唯一稳定口径」那一行提取断言值。

    锚点：包含「唯一稳定口径」的表行，格式 `| 正文（§8.6 之前，**唯一稳定口径**） | **8** | **13** |`
    """
    for l in doc.split('\n'):
        if '唯一稳定口径' in l and l.lstrip().startswith('|'):
            nums = re.findall(r'\*\*(\d+)\*\*', l)
            if len(nums) >= 2:
                return int(nums[0]), int(nums[1])
    return None


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', default=DEFAULT_DOC)
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args(argv)

    doc = load(a.file)
    i86 = doc.find(CUT)
    head = doc[:i86] if i86 > 0 else doc

    if not a.check:
        print('A 全文·按次·含码块      :', count_occurrences(doc))
        print('B 截断8.6前·按次·含码块  :', count_occurrences(head), '  <- 唯一稳定口径')
        print('C 全文·按次·排码块      :', count_occurrences(strip_fences(doc)))
        print('D 截断8.6前·按次·排码块  :', count_occurrences(strip_fences(head)))
        print('E 全文·按行·含码块      :', count_lines(doc))
        print('F 截断8.6前·按行·含码块  :', count_lines(head))
        print()
        print('（历史留痕里提到的 15/20 是自指污染值，当前文档不再使用；以口径 B 为准。）')
        return 0

    b = caliber_b(doc)
    claim = parse_doc_claim(doc)
    if claim is None:
        print('FAIL: 文档中未找到「唯一稳定口径」断言行')
        return 1
    if claim != b:
        print('FAIL: 文档写 %s，口径 B 实测 %s' % (claim, b))
        return 1
    print('OK: 文档断言 %s == 口径 B %s' % (claim, b))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
