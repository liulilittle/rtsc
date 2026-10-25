# design-a 历史快照（回归基线）

本目录是 `evidence/tls/pseudo_lint.py --regress` 的**输入集**，
与 `pseudo_lint.py` 中的 `KNOWN` 表（4 条）**一一对应**。

## 用途

证明检查器能抓到**已知缺陷**。`--regress` 对每个快照跑一遍结构检查，
断言「命中项 ⊇ KNOWN」——即该版本已知的缺陷必须仍被检出。
若某快照的已知缺陷检不出来了，说明检查器退化。

## 文件

| 文件 | 大小 | 说明 |
|---|---|---|
| `design-a.bak.md` | 92381 B | 1139 行版，**B1 未修**（缺回边），B10/B12/B13 未修 |
| `design-a.step7.snapshot.md` | 112779 B | 1392 行版，B1-B9 已修，B10/B12/B13 未修 |
| `design-a.step7.v2.md` | 120397 B | 1464 行版，B10 已修，B12/B13 未修 |
| `design-a.step8.base.md` | 135988 B | 1632 行版，仅剩 S2/S4/S12 |

## 契约

1. **这 4 个文件是冻结基线，禁止修改**。
   它们是历史版本的客观记录，改了就不再是那个版本。
2. **新增基线必须同时更新 `KNOWN` 表**（`pseudo_lint.py`）。
   多一个不在 `KNOWN` 里的文件，会让「本目录文件都该被 regress」这个隐含契约失效。
3. **禁止在 `.tmp` 保留同名副本**。
   同名双份会导致「改哪一份」的歧义——改错那份不会让门禁失败，但改动白费。
   （consult-b 第⑰步 G12 就是这个问题）
4. 本目录**不放** `design-a.step7.v3.md`（与 `v2.md` sha256 完全相同，是重复副本）。

## 为什么放在 evidence/ 而不是 docs/

- `docs/` 是**被审计对象**，`evidence/` 是**审计工具与证据**，边界应保持。
- `docs/` 下的文件通常被认为可编辑；这 4 个必须冻结。
- `pseudo_lint.py --regress` 消费它们，就近原则。

## 状态记录

改动前后的客观状态由 `state_snapshot.py` 机器生成（JSON），
见 `state-before-stepNN.json` / `state-after-stepNN.json`。
两份 diff 即为证据，不依赖人工回忆。
