import io

proc = """

## 第197轮：定位到矛盾点 → `[SDH] OK` 却 `[SLOWUPD] parse=5`

- **[BASH] dump**：`[SCH] total=22 pdu_type=0017 raw=7 ver=1` → `ShareControlHeader::parse` 成功；
  `[SDH] OK type2=47 complen=0` → **`ShareDataHeader::parse` 返回 Ok**；但 `[SLOWUPD] parse=5`（`InvalidType`）。
- **关键推论**：`SlowPathGraphicsUpdate::parse`（`output.cpp:143`）的非 Ok 分支**只返回 `NeedMoreData`** → 它**不可能**返回 5
  → **`5` 来自另一处**（另一处调用 `SlowPathGraphicsUpdate::parse`，或 `Client::OnSessionPdu` 被以非 `McsSendData` 的缓冲调用）。
- **[task:general] 新开子代理** 精确定位：
  1. `[SLOWUPD] parse=5` 的真正来源（打印调用线索 + 对比缓冲 size）；
  2. `grep -rn "SlowPathGraphicsUpdate::parse"` 找**第二处**调用；
  3. 同时查**服务器重传最终化序列** → dump 客户端 Confirm Active 能力集 vs 服务器 Demand Active 能力集（子代理 `ses_e8f01f12…` 的线索，可能是**根因**）；
  4. 最小修复 + 真机验证 `non-black>0`；移除全部临时 fprintf（`client.cpp`/`share.cpp`/`session_setup.cpp`），保留 surface 统计。
- 在途：精确定位 + 修复。真机表面仍全黑。
"""
io.open('.opencode/process.md', 'a', encoding='utf-8').write(proc)
print('ok')
