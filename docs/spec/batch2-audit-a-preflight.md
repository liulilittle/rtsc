# 批 2 派单前最后提醒（审计甲）

> 严格只读：未改 `src/`/`include/`/`tests/`，未构建，未跑变异。
> **结论：派单前有 2 个门禁缺口必须补，否则执行 AI 漏做也不会被发现。**

## 1. 缺口 1（**高**）：`batch2_gate.py` 未接入 `verify.ps1`

主代理说「全部门禁 exit=0（`verify -DocCite` 16/16、citation 43/0）」。
**这是真的，但它不包含 `batch2_gate.py`。**

实测 `verify.ps1` 的 `-DocCite` 块（`:321-327`）只调用：
```powershell
$pf = Join-Path $root "evidence\exec\batch2_preflight.py"   # :324
```

全文件 grep `batch2_gate` → **零命中**。所以：

| 检查 | 由谁做 | 是否在 verify.ps1 |
|---|---|---|
| 8 条用例名存在 | `batch2_gate.py` | ❌ **未接入** |
| 总数 >= 34 | `batch2_gate.py` | ❌ **未接入** |
| S23 注释契约 | `batch2_gate.py` | ❌ **未接入** |
| 7 条锚点命中数 | `batch2_preflight.py` | ✅ 已接入 |

**后果**：执行 AI 若漏写 S10、或把 `tls.h:42` 注释改回旧文案，
**`verify.ps1 -DocCite` 仍然 exit=0**。这正是我们花两轮防的「S10 被总数掩盖」问题——
**门禁写了，但没接线，等于没写。**

**必须补**（`verify.ps1` 的 `-DocCite` 块内，`batch2_preflight.py` 之后）：
```powershell
# 5c) batch-2 delivery gate: every required test exists by name, and the
#     tls.h kPeerAlert contract still says what SChannel can actually do.
$bg = Join-Path $root "evidence\exec\batch2_gate.py"
if (-not (Test-Path $bg)) { Write-Error "missing $bg"; exit 1 }
& $py $bg
if ($LASTEXITCODE -ne 0) { Write-Error "batch-2 delivery gate failed"; exit 1 }
```

**注意**：`batch2_gate.py` 在**当前树**（修复前）必然 exit=1（8 条用例全缺、注释还是旧文案）。
所以它**不能无条件接入 `-DocCite`**，否则 `-DocCite` 立刻永久红。

**两个选项**：
- **A（推荐）**：接入但用开关 `-PostBatch2`，与 `-PreBatch1` 对称。
  批 2 完成前不跑；执行 AI 完成后用 `-PostBatch2` 验收。
- **B**：接入但让它**只检查 S23 契约**（当前树已红，仍不可行）。

→ **选 A**。这与 `batch1_preflight.py` 用 `-PreBatch1` 门控是同一模式（`verify.ps1:338`）。

## 2. 缺口 2（**中**）：`batch2_preflight.py` 的 S9 仍是旧规则

实测输出：
```
S9     expect 3  got 3  OK        [106, 209, 232]
       Receive at 230 -> first closed_ hit after it: 232
```

**这是「Receive 之后第一处」规则**——正是我们在 §18.7 勘误 1 里**否决**的那条。
我们已确定改用**双边界区间锚点**（`Receive` 签名 `:230` .. `size_t progressed = 0;` `:239`）。

**后果**：门禁验证的是旧规则，而 §19.3.3 的订正 7 写的是新规则。
**两者不一致**——将来若在 `:230-232` 之间插入新守卫，
`batch2_preflight.py` 会**静默选错**（它只打印 "first after"，不做区间计数校验）。

**必须补**：把 S9 检查改为区间计数：
```python
if name == 'S9':
    lo = next((i + 1 for i, s in enumerate(src)
               if 'Error Receive(const uint8_t* ciphertext' in s), None)
    hi = next((i + 1 for i, s in enumerate(src)
               if 'size_t progressed = 0;' in s), None)
    if lo is None or hi is None:
        ok = False
        print('       S9 window bounds not found (lo=%s hi=%s)' % (lo, hi))
    else:
        in_win = [h for h in hits if lo < h < hi]
        print('       window (%d,%d) closed_ hits = %s' % (lo, hi, in_win))
        if len(in_win) != 1:
            ok = False
            print('       FAIL: expected exactly 1 closed_ guard in the window')
```

这样「区间内命中 2 次」会**报错而不是静默选错**——正是区间锚点要保证的性质。

## 3. 其余我核对过，无需再改

| 项 | 状态 |
|---|---|
| `batch2_gate.py` 两个独立函数 | ✅ 实测存在（`check_source` + `check_tls_header_contract`） |
| 三要素判别力 | ✅ 我复现了主代理的表，结论一致 |
| 当前树 exit=1 | ✅ 实测 `GATE_EXIT=1`，8 条全缺 + 契约 3 项 FAIL |
| `verify.ps1 -DocCite` | ✅ 实测 exit=0（因为它没跑 `batch2_gate.py`） |
| `batch2_preflight.py` 的 `SystemExit` | ✅ `:56` 有 `raise SystemExit(0 if ok else 1)`（乙报的坑已修） |

## 4. 派单前必须说的其他事

### 4.1 执行 AI 的「现状观测」要求，建议给出可执行格式

主代理已采纳「每条缺陷先跑现状观测」。**建议在任务书里给出统一格式**，否则执行 AI 会各写各的：
```
// S24-a 现状观测（修复前实测）：
//   Shutdown() -> status=kOk, native_code=0x00090312, out=201
//   out[0] = 0x16 (Handshake record), expected after fix: 0x15 (Alert)
```
**每条用例的注释里必须有这样一段**，且数值来自**实跑**而非文档抄录。

### 4.2 `RawServer::CloseNotify()` 的失败语义要定

`probe_u4e` T4 显示：空 token 的 `ApplyControlToken` 返回 `SEC_E_UNSUPPORTED_FUNCTION`。
**若 `CloseNotify()` 失败，用例应该怎么办？**
建议：`CloseNotify()` 返回 `SECURITY_STATUS`，用例里 `CHECK_EQ(Opaque(sst), Opaque(SEC_E_OK))`，
**不要静默跳过**——否则 S23 用例可能在"发不出 alert"时假绿。

### 4.3 S23 行为用例依赖 `CloseNotify()`，但 S23 缺陷本身是注释

**这是一个容易混淆的点**：S23 的**红证**是文档断言（注释），
但 C 断言（`native_code == 0x00090317`）需要 `CloseNotify()` 才能跑。
**若 `CloseNotify()` 写不出来，C 就落不了地，只剩 A。**
建议任务书明确：**先实现 `CloseNotify()` 并单独验证它能产出 31 字节 type=21**，
再做 S23 的 C 断言。否则执行 AI 会在 S23 上卡住。

## 5. 结论

**派单前补 2 处，可以派**：

| # | 缺口 | 严重度 | 动作 |
|---|---|---|---|
| 1 | `batch2_gate.py` 未接入 `verify.ps1` | **高** | 加 `-PostBatch2` 开关接入 |
| 2 | `batch2_preflight.py` 的 S9 仍是旧规则 | **中** | 改为区间计数校验 |

**另有 3 条执行提示**（非阻断）：现状观测格式、`CloseNotify()` 失败语义、`CloseNotify()` 先行验证。
