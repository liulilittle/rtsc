"""生成改动前后的结构化状态快照（consult-b 第⑰步 Q3 / 规则 F）。

存在理由：手写的 BEFORE 段是「回忆性描述」，证明力弱于「机器生成的客观记录」。
本脚本读取文件系统与脚本源码，输出 JSON；两份 JSON 一 diff 即为证据。

**定位（consult-b 第⑱步 Q1）**：本脚本只记录**结构指纹 + 文本模式计数**，
**不验证行为**。行为验证由 verify.ps1 的各道门禁负责（跑脚本看 exit 码）。
两者互补，不可替代：`anchor_triple_count=8` 只说明「有 8 处写了这个正则」，
不说明「这 8 处都正确工作」——后者靠 verify_sideeffect_leaf.py 的 20 个用例。

用法：
    python state_snapshot.py --step 17 --phase before
    python state_snapshot.py --step 17 --phase after
    python state_snapshot.py --step gate --phase after --exit-codes "S1=0,S2=0"

输出：
    evidence/tls/state-<phase>-step<NN>.json   全量状态（覆盖写，只留最新）
    evidence/tls/state-history.jsonl           摘要追加（永不覆盖 = 轨迹）
"""
import argparse
import ast
import hashlib
import io
import json
import os
import re
import sys
import tokenize
import warnings
from datetime import datetime, timezone

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = r'F:\rtsc'
EVID = os.path.join(ROOT, 'evidence', 'tls')
SNAPDIR = os.path.join(EVID, 'snapshots')
HISTORY = os.path.join(EVID, 'state-history.jsonl')

# 纳入状态观测的文件
WATCH = [
    os.path.join(ROOT, 'verify.ps1'),
    os.path.join(EVID, 'pseudo_lint.py'),
    os.path.join(EVID, 'pseudo_lint_redtest.py'),
    os.path.join(EVID, 'verify_elif_semantics.py'),
    os.path.join(EVID, 'verify_sideeffect_leaf.py'),
    os.path.join(EVID, 'count_sec_refs.py'),
    os.path.join(EVID, 'state_snapshot.py'),
    os.path.join(ROOT, 'docs', 'spec', 'tls-backend.design-a.md'),
]

SNAP_EXPECT = [
    'design-a.bak.md',
    'design-a.step7.snapshot.md',
    'design-a.step7.v2.md',
    'design-a.step8.base.md',
]


def sha(path):
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    if not os.path.exists(path):
        return None
    return io.open(path, encoding='utf-8', errors='replace').read()


def count(text, pattern, multiline=True):
    """在已给定的文本上计数（调用方决定是原文还是屏蔽后的代码）。"""
    if text is None:
        return None
    flags = re.M if multiline else 0
    return len(re.findall(pattern, text, flags))


def _line_offsets(src):
    lines = src.splitlines(keepends=True)
    off = [0]
    for l in lines:
        off.append(off[-1] + len(l))
    return lines, off


def _byte_col_to_char_col(line, byte_col):
    """ast 的 col_offset 是 UTF-8 字节偏移，tokenize 是字符偏移，必须换算。"""
    return len(line.encode('utf-8')[:byte_col].decode('utf-8', errors='replace'))


def mask_noncode(src):
    """把 docstring 与 `#` 注释替换成空格，返回 (code_only, docstring_only)。

    G13（consult-b 第⑱步）：原实现直接在全文上正则计数，
    把 verify_elif_semantics.py 里 docstring 提到的那一处也算了进去（报 9，实际代码 8）。
    后果：只改 docstring 措辞，指标就变，看起来像「少了一个锚点」——状态轨迹失真。
    修法：按 tokenize/ast 给出的精确字符区间屏蔽，而不是整行屏蔽
    （正则字面量本身是字符串 token，整行或全部字符串屏蔽都会把代码也屏蔽掉）。
    """
    lines, off = _line_offsets(src)

    def pos(row, col):
        return off[row - 1] + col

    code = list(src)
    doc = list(src)

    def blank(buf, a, b):
        for i in range(a, min(b, len(buf))):
            if buf[i] != '\n':
                buf[i] = ' '

    # 1) `#` 注释：两个缓冲都屏蔽（注释不是代码也不是文档）
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                a, b = pos(*tok.start), pos(*tok.end)
                blank(code, a, b)
                blank(doc, a, b)
    except (tokenize.TokenError, IndentationError):
        pass

    # 2) docstring：只在 code 缓冲屏蔽（doc 缓冲保留，用于对照指标）
    try:
        with warnings.catch_warnings():
            # The modelled script's docstring contains `\s`; ast.parse emits a
            # SyntaxWarning about it. Unrelated to this measurement.
            warnings.simplefilter('ignore', SyntaxWarning)
            tree = ast.parse(src)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Module, ast.ClassDef,
                                     ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = getattr(node, 'body', None) or []
            if not body:
                continue
            first = body[0]
            if not (isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                continue
            v = first.value
            r0, c0 = v.lineno, _byte_col_to_char_col(lines[v.lineno - 1], v.col_offset)
            r1, c1 = v.end_lineno, _byte_col_to_char_col(lines[v.end_lineno - 1], v.end_col_offset)
            blank(code, pos(r0, c0), pos(r1, c1))

    code_s = ''.join(code)
    doc_s = ''.join(doc)
    return code_s, doc_s


def parse_exit_codes(arg):
    if not arg:
        return {}
    out = {}
    for part in arg.split(','):
        part = part.strip()
        if not part:
            continue
        k, _, v = part.partition('=')
        try:
            out[k.strip()] = int(v.strip())
        except ValueError:
            out[k.strip()] = v.strip()
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('--step', required=True)
    ap.add_argument('--phase', required=True, choices=['before', 'after'])
    ap.add_argument('--exit-codes', default='',
                    help='形如 "S1=0,S2=0"：由 verify.ps1 汇总传入，避免再落临时文件')
    a = ap.parse_args(argv)

    plint = os.path.join(EVID, 'pseudo_lint.py')
    sem = os.path.join(EVID, 'verify_elif_semantics.py')
    vps = os.path.join(ROOT, 'verify.ps1')

    state = {
        'step': a.step,
        'phase': a.phase,
        'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'files': {},
        'snapshots': {},
        'metrics': {},
        'gate_exits': parse_exit_codes(a.exit_codes),
    }

    for p in WATCH:
        rel = os.path.relpath(p, ROOT).replace('\\', '/')
        state['files'][rel] = {
            'exists': os.path.exists(p),
            'bytes': os.path.getsize(p) if os.path.exists(p) else None,
            'sha256': sha(p),
        }

    for n in SNAP_EXPECT:
        p = os.path.join(SNAPDIR, n)
        state['snapshots'][n] = {
            'exists': os.path.exists(p),
            'bytes': os.path.getsize(p) if os.path.exists(p) else None,
            'sha256': sha(p),
        }

    sem_src = read(sem) or ''
    sem_code, sem_doc = mask_noncode(sem_src)
    vps_src = read(vps) or ''
    vps_code, _ = mask_noncode(vps_src)

    tmpdir = os.path.join(ROOT, '.tmp')
    tmp_dupes = len([f for f in os.listdir(tmpdir)
                     if f.startswith('design-a.') and f.endswith('.md')]) \
        if os.path.isdir(tmpdir) else None

    # 门禁调用点计数：唯一能反映「门禁是否被删减」的可观测信号。
    # 必须限定在 -PseudoLint 块内：doc lint 块里也有一处 `& $py $lint`，
    # 全文件统计会把它算进来（实测报 8，实际 pseudo 门禁 7 道）。
    m = re.search(r'if \(\$PseudoLint\)\s*\{(.*?)\n\}\n', vps_code, re.S)
    pseudo_block = m.group(1) if m else ''
    gate_lines = [l for l in pseudo_block.splitlines()
                  if re.search(r'&\s+\$py\s+\$', l)]
    state_invocations = len([l for l in gate_lines if '$state' in l])
    py_invocations = len(gate_lines) - state_invocations

    state['metrics'] = {
        # 代码行统计（G13：docstring 已屏蔽）
        'anchor_triple_count': count(sem_code, r'\(\?:\^\|;\|:\\s\)'),
        'anchor_semicolon_only_residual': count(sem_code, r'\(\?:\^\|;\)\\s'),
        # 对照：docstring 里的同一模式（证明屏蔽生效，不是碰巧为 0）
        'anchor_triple_in_docstring': count(sem_doc, r'\(\?:\^\|;\|:\\s\)')
                                      - count(sem_code, r'\(\?:\^\|;\|:\\s\)'),
        # 门禁完整性
        'py_gate_invocations': py_invocations,
        'py_state_invocations': state_invocations,
        # 开关与旁路
        'allow_no_snapshots_mentions': count(vps_code, r'AllowNoSnapshots'),
        'skip_bracket_mentions': count(vps_code, r'\[skip\]'),
        'write_warning_mentions': count(vps_code, r'Write-Warning'),
        # 回归基线
        'known_table_entries': count(read(plint) or '', r"^    'design-a\.[^']+':"),
        'snapshot_dir_referenced': count(vps_code, r'evidence\\tls\\snapshots'),
        # 临时目录残留（G12）
        'tmp_design_a_copies': tmp_dupes,
    }

    # Provenance: which generator produced this record. Schema changes must be
    # visible in the record itself, otherwise two records cannot be diffed
    # safely (consult-b step 18: step17 lacked generated_at / gate_exits).
    state['schema'] = 2

    out = os.path.join(EVID, 'state-%s-step%s.json' % (a.phase, a.step))
    io.open(out, 'w', encoding='utf-8', newline='').write(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + '\n')

    # 追加式轨迹（consult-b 第⑱步放行条件 1）：
    # 全量 JSON 覆盖写只留最新；这里追加一行摘要，永不覆盖。
    digest = {k: (v['sha256'] or '')[:16] for k, v in sorted(state['files'].items())}
    record = {
        'step': a.step,
        'phase': a.phase,
        'generated_at': state['generated_at'],
        'sha16': digest,
        'metrics': state['metrics'],
        'gate_exits': state['gate_exits'],
    }
    with io.open(HISTORY, 'a', encoding='utf-8', newline='') as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + '\n')

    print('wrote', out)
    print('appended', HISTORY)
    print(json.dumps(state['metrics'], ensure_ascii=False, indent=2, sort_keys=True))
    if state['gate_exits']:
        print('gate_exits:', json.dumps(state['gate_exits'], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
