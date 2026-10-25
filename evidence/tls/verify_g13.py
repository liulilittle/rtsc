"""G13 acceptance: structural counters must exclude non-code text.

consult-b step 20 放行条件 3: the previous "independent implementation" was
NOT independent - it used ast.walk with the same isinstance chain as
mask_noncode, so an error in that reasoning would break both identically.

The added evidence here is a DIFFERENT INFORMATION SOURCE, not a different
way of writing the same ast code:

  source 1: ast (byte offsets from the parser)
  source 2: raw text scan of the triple-quote delimiters (no ast at all)

Both must agree on where the docstring region is. Only agreement between
different information sources is real evidence.

Known limitation (documented, not hidden): if an anchor pattern occurred inside
a `#` comment it would be masked from BOTH buckets, so
`total == code + docstring` would fail. That assertion therefore encodes the
assumption "anchors live only in code or docstrings", which holds for the
current document (0 anchors in comments).
"""
import ast
import io
import os
import re
import sys
import warnings

sys.path.insert(0, r'F:\rtsc\evidence\tls')
import state_snapshot as ss  # noqa: E402

SRC = r'F:\rtsc\evidence\tls\verify_elif_semantics.py'
TMP = r'F:\rtsc\.tmp\g13_docstring_variant.py'
PAT = r'\(\?:\^\|;\|:\\s\)'

ok = True


def chk(name, cond, detail=''):
    global ok
    print('%-62s %s %s' % (name, 'PASS' if cond else 'FAIL', detail))
    if not cond:
        ok = False


# ---------------------------------------------------------------- source 1: ast
def spans_from_ast(src):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', SyntaxWarning)
        tree = ast.parse(src)
    lines = src.splitlines(keepends=True)
    offs = [0]
    for l in lines:
        offs.append(offs[-1] + len(l.encode('utf-8')))
    raw = src.encode('utf-8')
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, 'body', []) or []
        if not body:
            continue
        first = body[0]
        if not (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            continue
        v = first.value
        # offs[] holds BYTE offsets per line start; col_offset is also bytes.
        c0 = len(raw[:offs[v.lineno - 1] + v.col_offset].decode('utf-8'))
        c1 = len(raw[:offs[v.end_lineno - 1] + v.end_col_offset].decode('utf-8'))
        out.append((c0, c1, v.lineno, v.end_lineno))
    return out


# ------------------------------------------------- source 2: pure text scanning
def spans_from_text(src):
    """Find docstring regions by scanning triple quotes, with no ast at all.

    A triple-quoted string is treated as a docstring candidate if the only
    thing before it on its line is indentation (i.e. it starts a statement).
    This is a deliberately different rule set from ast's body[0] check; where
    the two disagree, the disagreement is reported rather than smoothed over.
    """
    spans = []
    i = 0
    n = len(src)
    while i < n:
        # only consider positions at the start of a statement
        line_start = src.rfind('\n', 0, i) + 1
        prefix = src[line_start:i]
        if prefix.strip() != '':
            i += 1
            continue
        for q in ('"""', "'''"):
            if src.startswith(q, i):
                j = src.find(q, i + 3)
                if j < 0:
                    i += 1
                    break
                spans.append((i, j + 3))
                i = j + 3
                break
        else:
            i += 1
    return spans


def count_outside(src, spans, pattern):
    keep = list(src)
    for a, b, *_ in spans:
        for k in range(a, min(b, len(keep))):
            if keep[k] != '\n':
                keep[k] = ' '
    return len(re.findall(pattern, ''.join(keep), re.M))


def strip_hash_comments(src):
    out = list(src)
    i, n, quote, triple = 0, len(src), None, False
    while i < n:
        c = src[i]
        if quote:
            if triple:
                if src.startswith(quote * 3, i):
                    i += 3
                    quote, triple = None, False
                    continue
                i += 1
                continue
            if c == '\\':
                i += 2
                continue
            if src.startswith(quote, i):
                i += 1
                quote = None
                continue
            i += 1
            continue
        if src.startswith('"""', i) or src.startswith("'''", i):
            quote, triple = src[i], True
            i += 3
            continue
        if c in ('"', "'"):
            quote = c
            i += 1
            continue
        if c == '#':
            j = src.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = ' '
            i = j
            continue
        i += 1
    return ''.join(out)


orig = io.open(SRC, encoding='utf-8').read()

# --- agreement between two information sources -------------------------------
ast_spans = spans_from_ast(orig)
txt_spans = spans_from_text(orig)
ast_ranges = sorted((a, b) for a, b, *_ in ast_spans)
txt_ranges = sorted(txt_spans)

chk('ast and text scan agree on the docstring region set',
    ast_ranges == txt_ranges,
    'ast=%d text=%d' % (len(ast_ranges), len(txt_ranges)))

# --- line-number anchoring: no ast involved ----------------------------------
# The docstring that contains the pattern is the module docstring; assert its
# delimiters are at the expected physical lines, judged by plain text.
lines = orig.splitlines()
open_lines = [i + 1 for i, l in enumerate(lines) if l.strip().startswith('"""')]
chk('module docstring delimiters found by text scan',
    len(open_lines) >= 2, 'lines=%s' % open_lines[:6])

# A single-line docstring ("""text""") both opens and closes on the same
# physical line. The first version toggled the state once per line that merely
# STARTED with """, so it drifted out of phase after the first one-liner and
# reported line 196 as "not in a docstring" - a false negative produced by the
# checker, not by the file. Counting the delimiters per line fixes that.
docstring_lines = set()
open_count = 0
for i, l in enumerate(lines, 1):
    n_delim = l.count('"""')
    if n_delim == 0:
        if open_count % 2 == 1:
            docstring_lines.add(i)
        continue
    docstring_lines.add(i)
    open_count += n_delim
chk('triple-quote delimiters are balanced (text only)',
    open_count % 2 == 0, 'count=%d' % open_count)
chk('the pattern line is inside a triple-quoted block (text only)',
    196 in docstring_lines, 'line196_in_docstring=%s' % (196 in docstring_lines))

# --- masking behaviour -------------------------------------------------------
code_ss, doc_ss = ss.mask_noncode(orig)
n_ss = len(re.findall(PAT, code_ss, re.M))
n_doc = len(re.findall(PAT, doc_ss, re.M)) - n_ss

n_txt = count_outside(strip_hash_comments(orig), txt_spans, PAT)
chk('code count agrees across sources (ast-mask vs text-mask)',
    n_ss == n_txt, 'mask_noncode=%d text=%d' % (n_ss, n_txt))
chk('docstring-only count is 1 (mask actually masks something)',
    n_doc == 1, 'got=%d' % n_doc)
chk('total == code + docstring (no third bucket)',
    n_ss + n_doc == len(re.findall(PAT, orig, re.M)),
    '%d + %d == %d' % (n_ss, n_doc, len(re.findall(PAT, orig, re.M))))

# --- docstring-only edit must not move the code count ------------------------
variant = orig.replace('`(?:^|;|:\\s)`', '`行首-分号-冒号空格`')
chk('docstring edit actually changed the file', variant != orig)
if variant != orig:
    io.open(TMP, 'w', encoding='utf-8', newline='').write(variant)
    v_code, v_doc = ss.mask_noncode(variant)
    n_v_code = len(re.findall(PAT, v_code, re.M))
    n_v_doc = len(re.findall(PAT, v_doc, re.M)) - n_v_code
    v_txt = count_outside(strip_hash_comments(variant), spans_from_text(variant), PAT)
    chk('code count unchanged after docstring-only edit', n_v_code == n_ss,
        '%d -> %d' % (n_ss, n_v_code))
    chk('text-source count also unchanged', v_txt == n_txt, '%d -> %d' % (n_txt, v_txt))
    chk('docstring-only count DID change (edit was effective)', n_v_doc != n_doc,
        '%d -> %d' % (n_doc, n_v_doc))
    os.remove(TMP)

# --- documented limitation is actually true right now ------------------------
comments = [l for l in lines if l.lstrip().startswith('#')]
anchors_in_comments = len([l for l in comments if re.search(PAT, l)])
chk('assumption holds: no anchor inside a # comment (else total breaks)',
    anchors_in_comments == 0, 'found=%d' % anchors_in_comments)

print('RESULT=%s' % ('PASS' if ok else 'FAIL'))
sys.exit(0 if ok else 1)
