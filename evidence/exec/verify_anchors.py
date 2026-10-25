"""Anchor gate v9 -- closes the two blind spots both auditors found in v8.

A's finding (round 8): 15 stale citations, 6 of them RANGE citations
(`:489-507`, `:369-382`, `:66-73`, `:568-575`). v8's `locates()` joined the
whole range into one span, so an anchor sitting anywhere inside passed -- even
when the range START was a blank line and the END was not the function's closing
brace. "Anchor is inside the range" cannot prove the boundaries are right.

B's finding (round 8): WEAK ANCHORS. `locates()` asked "does the anchor appear in
the span", never "does the anchor appear ONLY at the cited line". So:
    doc:2876 cites :432 with anchor `closed_ = true;`   (hits 304 and 432)
    change the citation to :304, anchor untouched -> gate still green.
Both lines contain the anchor, so the number is unverifiable.

v9 adds two invariants:

  I1  RANGE START: for `t:A-B`, the first anchor fragment must appear at cur[A].
      (A range citation names the construct that STARTS the range.)

  I2  UNIQUENESS: the set of lines in the file that contain the anchor must be a
      subset of the cited range. If the anchor also matches elsewhere, it cannot
      tell those lines apart, so it cannot certify this one.

Both are hard failures. An anchor that cannot discriminate is not an anchor.
"""
import io
import re
import sys

DOC = r'F:\rtsc\docs\spec\security-integration.audit-a.md'

FILES = {
    'tls_schannel.cpp': r'F:\rtsc\src\net\tls_schannel.cpp',
    'tls.h': r'F:\rtsc\include\rtsc\net\tls.h',
    'credssp.h': r'F:\rtsc\include\rtsc\credssp\credssp.h',
    'credssp.cpp': r'F:\rtsc\src\credssp\credssp.cpp',
    'ts_request.cpp': r'F:\rtsc\src\credssp\ts_request.cpp',
    'connect_machine.cpp': r'F:\rtsc\src\proto\connect_machine.cpp',
    'test_tls.cpp': r'F:\rtsc\tests\test_tls.cpp',
    'test_credssp_sm.cpp': r'F:\rtsc\tests\test_credssp_sm.cpp',
}
SRC = {}
for k, v in FILES.items():
    try:
        # Whitespace-normalized ON PURPOSE: the anchor text in the doc is
        # whitespace-insensitive, so comparing normalized-to-normalized is what
        # makes an anchor match regardless of how the source is indented.
        # The side effect is that every pattern in this file sees column 0.
        # Auditor A's R-1 exposed that the `^\s{0,8}` bound in INNER_BLOCK /
        # CLOSING_PREFIX was consequently vacuous AND fragile (it would have
        # missed t:315/t:320 at indent 12 if normalization were removed).
        # Those patterns now use `^\s*`. Do not "restore" a small indent bound
        # here without re-checking that it is not silently load-bearing.
        SRC[k] = [' '.join(x.split()) for x in io.open(v, encoding='utf-8').read().splitlines()]
    except OSError:
        pass

L = io.open(DOC, encoding='utf-8').read().splitlines()

H = re.compile(r'^##\s+(\d+)\.')
starts = [(int(m.group(1)), i) for i, l in enumerate(L) if (m := H.match(l))]
SEC = {}
for k, (n, a) in enumerate(starts):
    e = starts[k + 1][1] - 1 if k + 1 < len(starts) else len(L) - 1
    SEC[n] = (a, e)

TARGET_SECTIONS = (5, 6, 13, 15, 17, 18, 19)
EXECUTOR_SECTIONS = (19,)

NAME = re.compile(r'(tls_schannel\.cpp|tls\.h|credssp\.h|credssp\.cpp|ts_request\.cpp|'
                  r'connect_machine\.cpp|test_tls\.cpp|test_credssp_sm\.cpp)')
CITE = re.compile(r'`(?:src/net/|src/credssp/|src/proto/|tests/)?'
                  r'(?:(tls_schannel\.cpp|tls\.h|credssp\.h|credssp\.cpp|ts_request\.cpp|'
                  r'connect_machine\.cpp|test_tls\.cpp|test_credssp_sm\.cpp)|t)?'
                  r':(\d+)(?:-(\d+))?`')

WHITELIST_MARKERS = ('行号基线', '现在指向', '旧行号')


def norm(s):
    return ' '.join(s.split())


def resolve_file(dl, pos):
    line = L[dl - 1]
    best = None
    for m in NAME.finditer(line, 0, pos):
        best = m.group(1)
    if not best and dl >= 2:
        for m in NAME.finditer(L[dl - 2]):
            best = m.group(1)
    return best or 'tls_schannel.cpp'


def cite_file(m, dl):
    """Which source file does this citation point at?

    ``t:NNN`` is an explicit alias for tls_schannel.cpp and must NOT be resolved
    by scanning leftwards: doc:2443 cites ``tls.h:148-150`` and then ``t:246``,
    and the leftward scan attributed the second one to tls.h.
    """
    if m.group(1):
        return m.group(1)
    if m.group(0).startswith('`t:') or m.group(0).startswith('`t:'):
        return 'tls_schannel.cpp'
    return resolve_file(dl, m.start())


def extract_clause(tail):
    i = 0
    n = len(tail)
    while i < n and tail[i] in '）) \t':
        i += 1
    if i >= n or tail[i] not in '（(':
        return None
    j = i + 1
    in_bt = False
    while j < n:
        c = tail[j]
        if c == '`':
            in_bt = not in_bt
        elif not in_bt and c in '）)':
            return tail[i + 1:j]
        j += 1
    return None


def split_anchor(text):
    """Return (fragments, disambiguator, claimed_multi).

    A trailing ``(in Func)`` / ``(inside Func)`` is not source text: it says WHICH
    of several byte-identical lines is meant. Stripping it here and returning it
    separately lets the caller verify the function actually encloses the cited
    line, which is a stronger check than text uniqueness.

    ``claimed_multi`` is True when the author wrote ``A .. B``. That is a claim
    about BOTH boundaries, so the caller must not silently accept the anchor if
    one of the fragments is too short to survive the ``len >= 6`` filter --
    otherwise ``sig .. }`` degrades to a single-fragment anchor and the range
    start constraint disappears (auditor B, round 9, measured BLIND).
    """
    f = norm(text)
    if f.startswith('锚点 '):
        f = f[3:]
    m = re.search(r'\((?:in|inside)\s+([A-Za-z_]+)\)\s*$', f)
    dis = m.group(1) if m else None
    if m:
        f = f[:m.start()]
    raw = [p.strip() for p in re.split(r'\s\.\.\s', f) if p.strip()]
    parts = [p for p in raw if len(p) >= 6]
    return parts, raw, dis, len(raw) > 1


def anchor_candidates(line, m):
    clause = extract_clause(line[m.end():m.end() + 260])
    if clause is None or '锚点' not in clause:
        return False, [], None, False, []
    parts = []
    raw_all = []
    dis = None
    claimed_multi = False
    for frag in re.findall(r'`([^`]+)`', clause):
        p, raw, d, multi = split_anchor(frag)
        parts.extend(p)
        raw_all.extend(raw)
        if d:
            dis = d
        if multi:
            claimed_multi = True
    # The author may write the separator OUTSIDE the backticks: `sig` .. `}`.
    # That is still a two-boundary claim, so treat a clause-level `..` the same
    # way (auditor B, round 9: `sig` .. `}` degraded to one fragment and the
    # range-start constraint disappeared, measured BLIND on doc:1798).
    if re.search(r'\.\.', clause):
        claimed_multi = True
    return True, parts, dis, claimed_multi, raw_all


def enclosing_function(src, line_no):
    """Name of the function whose body contains `line_no`, by scanning back for a
    signature line of the form `<Type> Name(` at the outermost indent."""
    pat = re.compile(r'^\s{0,8}(?:Error|bool|void|DWORD|std::\w+|Status|int|size_t)\s+'
                     r'([A-Za-z_]\w*)\s*\(')
    for i in range(min(line_no, len(src)) - 1, -1, -1):
        m = pat.match(src[i])
        if m:
            return m.group(1)
    return None


def hits_of(src, parts):
    """Lines (1-based) containing every fragment -- used for SINGLE-line anchors."""
    return [i + 1 for i, s in enumerate(src) if all(p in s for p in parts)]


def brace_balanced(src, ca, cb):
    """True when [ca, cb] opens exactly one block and cb closes it.

    A ``.. `}`` anchor claims the range ENDS on a closing brace. Text alone
    cannot certify that (``}`` occurs everywhere), so verify the block structure
    instead: the depth over ca..cb-1 must be exactly 1 (the block opened at ca),
    and cur[cb] must bring it back to 0.

    ``depth == 0`` is NOT acceptable: that means the range never opened a block
    at all, so cur[cb] closes some OUTER scope. Auditor B's P3 -- with depth 0,
    ``t:103-116`` (a run of statements ending on a line that merely contains
    ``}``) passes as if it were a function body.
    """
    depth = 0
    for i in range(ca, cb):
        s = src[i - 1]
        depth += s.count('{') - s.count('}')
        if depth < 0:
            return False
    if depth != 1:
        return False
    s = src[cb - 1]
    return '}' in s and depth + s.count('{') - s.count('}') == 0


SIG = re.compile(r'^\s{0,8}(?:Error|bool|void|DWORD|std::\w+|Status|int|size_t)\s+'
                 r'([A-Za-z_]\w*)\s*\(')

# A block that starts with one of these is an INNER block or an aggregate, never
# a function body. Blacklist, not whitelist: a whitelist of return types can
# never be complete (auditor A's R-2 -- it rejected 5 real functions:
#   t:89  ~SchannelTransport()          (no return type)
#   t:517 uint32_t ExpectedActualOverhead()
#   t:561 static uint16_t WireVersionFromProtocolMask()
#   t:671 PCCERT_CONTEXT PeerCert()
#   t:690 static Error ConstError()     (return type listed, killed by `static`)
# ). Missing a return type makes the gate cry wolf on a CORRECT citation, which
# is worse than the hole I6 was added to close.
# NOTE on the indent bound: SRC is whitespace-normalized at load time
# (`' '.join(x.split())`, line 45), so every line these patterns see starts at
# column 0. A `^\s{0,8}` bound is therefore a VACUOUS condition today -- it can
# never reject anything. Worse, it is a trap: auditor A's R-1 found that if the
# normalization were ever removed, `t:315` / `t:320` (indent 12) would slip
# past `CLOSING_PREFIX` and be judged functions again, and the bound would look
# like it was doing work the whole time. Use `\s*` so the pattern states what
# it means, and rely on normalization explicitly rather than accidentally.
INNER_BLOCK = re.compile(
    r'^\s*(?:namespace|struct|class|enum|union|typedef|using|'
    r'if|else|for|while|do|switch|case|default|try|catch|return)\b')

# A continuation of the previous statement, e.g.
#   t:315  `} else if (st == SEC_I_CONTINUE_NEEDED) {`
# The `}` prefix hides `else` from INNER_BLOCK, and the line has `(`, so the two
# rules above let it through as a "function". Caught while attacking the v12
# blacklist: starts_a_function(315) returned True. brace_balanced happened to
# reject it (depth != 1), but relying on two rules accidentally covering for each
# other is not a design -- each rule must be correct on its own.
CLOSING_PREFIX = re.compile(r'^\s*\}')

# A lambda's capture list is followed directly by its parameter list, which makes
# the opener look exactly like a signature:
#   ntlm.cpp:239  `auto emit = [&](const Bytes& v, size_t field) {`
# Auditor B's round-12 P2 found this as the only block-opening non-function in
# the whole tree (src/ + include/ + tools/, 44 files). ntlm.cpp is not in FILES
# today, so it is not reachable yet -- but it becomes reachable the moment batch
# 2/3 widens the whitelist, and the fix is one line now versus a silent false
# accept later.
#
# `operator[]` is a REAL function and has the same `[...](` shape, so the
# keyword must short-circuit the lambda test. Measured: without this guard,
# `int operator[](int i) {` was rejected as if it were a lambda.
LAMBDA_HEAD = re.compile(r'\[[^\]]*\]\s*\(')
OPERATOR_KW = re.compile(r'\boperator\b')


def statement_head(src, ca):
    """Line number where the statement containing src[ca-1] starts.

    Auditor A's round-12 veto (cur:362): a WRAPPED `if` condition has the same
    shape as a wrapped function signature --

        t:360 `if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,`
        t:361 `&cert->pCertInfo->SubjectPublicKeyInfo, 0, nullptr,`
        t:362 `out.data(), &size)) {`          <- brace@20 > paren@18, head='out.data'

    `{` is after the last `)`, an identifier precedes a paren, so v14 accepted
    it; brace_balanced(362,366) is also True, so BOTH layers passed. The only
    thing that separates it from `PeerSubjectPublicKey` (t:371) is that the
    statement began two lines earlier with `if`.

    Walk back accumulating paren balance until a line opens an unclosed paren
    group. That line is the head.

    Comments are stripped before counting: a `//` note containing a stray `(`
    or `)` otherwise shifts the walk-back and makes a legitimate wrapped
    signature look like it starts at the comment. Measured on the synthetic
    case

        Error Foo(int x,
          // note ( unbalanced open
          int y) {

    without stripping, statement_head(3) returned 2 (the comment), and the real
    signature at line 3 was rejected. Block comments are stripped too, though
    this codebase does not use them in wrapped signatures.
    """
    for i in range(ca, 0, -1):
        line = _strip_comments(src[i - 1])
        opens = line.count('(')
        closes = line.count(')')
        if opens > closes:
            return i
        if i == ca and opens == closes:
            return ca
    return 1


_COMMENT_TAIL = re.compile(r'//.*$')
_COMMENT_BLOCK = re.compile(r'/\*.*?\*/')


def _strip_comments(line):
    """Remove comment text so paren counting sees only code."""
    line = _COMMENT_BLOCK.sub('', line)
    return _COMMENT_TAIL.sub('', line)


def starts_a_function(src, ca):
    """True when cur[ca] begins a function definition (not an inner block).

    A range that ends on ``}`` and is balanced claims to be a whole block. If it
    is a whole block but starts with ``if``/``for``/``switch``/... it is an inner
    block being passed off as a function body -- what the prose almost never
    means. Auditor A's X1 probe: cite ``FinishHandshake`` as ``t:493-496`` (the
    first inner ``if``) with a self-consistent anchor, and the v10 gate said
    nothing.

    Auditor B's round-12 P2: the v12 body accepted ``// comments``, bare
    statements (``out.clear();``) and aggregate initializers
    (``sb[1] = {...}`` / ``SecBuffer ib{...}``) as functions, because
    ``head = line.split('(')[0]`` finds an identifier in all of them. Five
    end-to-end cases were ACCEPTED through the real gate.

    Auditor A's round-12 veto: the fix above still accepted t:362, the third
    line of a wrapped `if` condition -- see statement_head().

    Deliberately permissive about the return type: ctors/dtors, ``static``, and
    any user type are all functions.
    """
    line = src[ca - 1]
    if INNER_BLOCK.match(line):
        return False
    # `} else if (...) {` / `} while (...);` -- a continuation, not a signature.
    if CLOSING_PREFIX.match(line):
        return False
    if line.lstrip().startswith('//'):
        return False
    # A signature puts the parameter list on its opening line. A line that opens
    # a brace but has no `(` is the tail of a WRAPPED condition, e.g.
    #   t:679  `SEC_E_OK) {`      <- the `if (QueryContextAttributesW(...` is above
    #   t:572  `info_.tls_version > config_.max_version) {`
    # Those are inner blocks, so reject them too.
    if '(' not in line:
        return False
    # The statement must START here. A wrapped `if` puts its tail on its own
    # line, and that tail is indistinguishable from a signature line by shape
    # alone -- the head of the statement is what tells them apart.
    head_line = src[statement_head(src, ca) - 1]
    if INNER_BLOCK.match(head_line):
        return False
    if LAMBDA_HEAD.search(line) and not OPERATOR_KW.search(head_line):
        return False
    brace = line.rfind('{')
    if brace >= 0:
        # The body brace must close the parameter list, not open an initializer:
        #   t:371 `Error PeerSubjectPublicKey(std::vector<uint8_t>& out) const override {`
        #         brace@69 > paren@52 -> accept
        #   t:595 `sb[1] = {static_cast<unsigned long>(size), SECBUFFER_DATA,`
        #         brace@8 < paren@40 -> reject
        if brace < line.rfind(')'):
            return False
    else:
        # No brace on the line: legitimate only as a WRAPPED signature whose
        # parameter list continues below (auditor A's R-2 found 8 of these:
        # t:68/101/204/230/589/616/647/740). Those end on a comma and have
        # unbalanced parens. A complete statement such as `out.clear();` has
        # balanced parens and must be rejected.
        if line.count('(') <= line.count(')'):
            return False
    head = line.split('(')[0]
    return bool(re.search(r'[A-Za-z_]\w*', head)) or '~' in head


def range_matches(src, ca, cb, parts, raw):
    """True when a range anchor is placed correctly.

    A range anchor `A .. B` names the FIRST and LAST line of the range, so the
    fragments are not required to co-occur on one line. Instead:
      - the FIRST fragment must sit on cur[ca] -- that is the start constraint;
      - the LAST fragment must sit on cur[cb]. When it is a bare ``}`` the text
        proves nothing, so fall back to brace balance: the range must open a
        block at ca and close it exactly at cb.
    Allowing a single fragment to match anywhere in between made the whole
    check vacuous: shifting a range by -2 while keeping a mid-range anchor still
    passed (auditor B, round 9, measured BLIND on doc:1828 / doc:1796).
    """
    if ca > len(src) or cb > len(src) or ca > cb:
        return False
    first = raw[0] if raw else parts[0]
    last = raw[-1] if len(raw) > 1 else (parts[-1] if len(parts) > 1 else None)

    if first not in src[ca - 1]:
        return False
    if last is None:
        return True
    if last == '}':
        return brace_balanced(src, ca, cb) and starts_a_function(src, ca)
    return last in src[cb - 1]


wrongline = []
noanchor_exec = []
noanchor_other = 0
anchored_ok = 0
total = 0

for num in TARGET_SECTIONS:
    a, e = SEC[num]
    for i in range(a, e + 1):
        line = L[i]
        if any(k in line for k in WHITELIST_MARKERS):
            continue
        for m in CITE.finditer(line):
            total += 1
            fname = cite_file(m, i + 1)
            if fname not in SRC:
                continue
            src = SRC[fname]
            ca = int(m.group(2))
            cb = int(m.group(3)) if m.group(3) else ca
            has_clause, parts, dis, claimed_multi, raw_all = anchor_candidates(line, m)
            if not has_clause:
                if num in EXECUTOR_SECTIONS:
                    noanchor_exec.append((num, i + 1, m.group(0), line.strip()[:110]))
                else:
                    noanchor_other += 1
                continue

            if not parts and not raw_all:
                wrongline.append((num, i + 1, m.group(0), 'clause has no usable text'))
                continue

            # Two shapes, two different obligations.
            #
            # SINGLE-LINE (ca == cb): the anchor must be UNIQUE to that line.
            #   If the same text also occurs elsewhere, the anchor cannot tell
            #   those lines apart, so it cannot certify this citation. Exception:
            #   an explicit `(in Func)` disambiguator, in which case the named
            #   function must really enclose the cited line.
            #
            # RANGE (ca != cb): the anchor names the boundaries. First fragment
            #   must sit on cur[ca], last on cur[cb]. Uniqueness is not required
            #   (function signatures are naturally unique at the start line).
            if ca != cb:
                if not range_matches(src, ca, cb, parts, raw_all):
                    wrongline.append((num, i + 1, m.group(0),
                                      'range anchor misplaced: %r..%r not at '
                                      'cur[%d]=%r / cur[%d]=%r'
                                      % ((raw_all[0] if raw_all else '?')[:30],
                                         (raw_all[-1] if raw_all else '?')[:30], ca,
                                         src[ca - 1][:36] if ca <= len(src) else '?',
                                         cb,
                                         src[cb - 1][:36] if cb <= len(src) else '?')))
                    continue
                anchored_ok += 1
                continue

            hits = hits_of(src, parts)
            if not hits:
                # a bare `:NNN` may have been attributed to the wrong file
                alt = None
                if m.group(1) is None:
                    for f in SRC:
                        if f == fname:
                            continue
                        h2 = hits_of(SRC[f], parts)
                        if h2 == [ca]:
                            alt = f
                            break
                if alt is None:
                    wrongline.append((num, i + 1, m.group(0),
                                      'anchor does not occur at cur[%d]' % ca))
                else:
                    anchored_ok += 1
                continue

            # The anchor text MUST be on the cited line. `(in Func)` never
            # substitutes for this: A1/A2 proved that accepting a bare function
            # check lets an anchor taken from the neighbouring line through.
            if ca not in hits:
                wrongline.append((num, i + 1, m.group(0),
                                  'anchor not at cur[%d] (hits %s)'
                                  % (ca, hits[:6])))
                continue

            if hits == [ca]:
                anchored_ok += 1
                continue

            # the text also occurs elsewhere: the (in Func) disambiguator must
            # name the function that really encloses the cited line
            if dis:
                fn = enclosing_function(src, ca)
                if fn == dis:
                    anchored_ok += 1
                    continue
                wrongline.append((num, i + 1, m.group(0),
                                  'anchor not unique and (in %s) does not enclose '
                                  'cur[%d] (enclosing=%s)' % (dis, ca, fn)))
            else:
                wrongline.append((num, i + 1, m.group(0),
                                  'anchor not unique: hits %s, cited %d'
                                  % (hits[:6], ca)))

print('=== anchor gate v9 (uniqueness + range start) ===')
print('citations examined                     :', total)
print('anchored, unique, start-correct        :', anchored_ok)
print('WRONGLINE                              :', len(wrongline))
print('no clause, section 19 (semantic gate)  :', len(noanchor_exec))
print('no clause, other sections (uncovered)  :', noanchor_other)
print()
for num, dl, cite, text in wrongline:
    print('  [WRONGLINE] [§%d] doc:%-5d %-16s %s' % (num, dl, cite, text))
sys.exit(1 if wrongline else 0)
