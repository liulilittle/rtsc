# 订正：「红证不可构造」是我测试方法错了

日期：2026-10-23
触发：用户指出「如果有错误就一定能抓到，抓不到就是测试方法测试错误；如果没有问题也就测不出来问题」。

## 1. 我之前的错误结论

第 24 轮 S25 裁决中，我写下（并写入 memory 规则 48）：

> **「红证不可构造」就不该占独立缺陷编号**
> 甲主张 S24-b 不单列 S25，理由是「修好 token 后没有任何可复现的失败状态」。
> 我实测确认：正确 token 下 `ApplyControlToken` 与 `ISC` 都返回 `SEC_E_OK`，
> `native_code` 必为 0 → 不存在「S24 已修、S25 未修」的状态。

据此我裁决 S24-b **不单列**，作为 S24 的子项，理由是「红证不可构造」。

## 2. 错在哪

我的探针只问了一个问题：**「能不能通过产品的正常路径触达那个分支」**。

`S24-b` 是 `tls_schannel.cpp:431`：

```cpp
if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
    closed_ = true;
    return MakeError(Status::kOk, st, "");
}
```

我构造的 CELL C 用了**正确 token**，于是 `ISC` 返回 `SEC_E_OK`，走的是第一个分支。
`SEC_I_CONTINUE_NEEDED` 那一半没被触及，我就断言「不可达 → 不可测」。

**这是把「我的探针构造不出」当成了「缺陷不可检出」。**

两件事完全不同：
- 缺陷是否可检出，取决于**测试方法**；
- 我的探针构造不出，只说明**我的探针**不行。

## 3. 正确的测试方法（实测）

探针 `F:\rtsc\.tmp\probe_s24b\probe_s24b.cpp`（链接真实产品库 + 映射函数隔离）：

```
--- PART 1: product, handshake complete, Shutdown() ---
  status=0 native=0x00090312 out=201 closed=true
  ASSERTION A: status != kOk ?                    FAIL  <-- RED today
  ASSERTION B: native_code != CONTINUE_NEEDED ?   FAIL  <-- also RED today

--- PART 2: the mapping function, in isolation ---
  MapShutdownStatus(SEC_I_CONTINUE_NEEDED) = 0
  MapShutdownStatus(SEC_E_OK)              = 0
  MapShutdownStatus(SEC_E_UNSUPPORTED_FUNCTION) = 5
  ASSERTION C: MapShutdownStatus(CONTINUE_NEEDED) != kOk ?  FAIL
  ASSERTION D: MapShutdownStatus(SEC_E_OK) == kOk ?         PASS
```

**三条独立红证，全部在今天的代码上失败。**

关键在 **ASSERTION C**：它把映射规则从实现里抽出来单独验证。
- 当前代码失败（`CONTINUE_NEEDED` 被映射成 `kOk`）；
- **只修 `:431` 就通过**，即使 token 仍然是坏的；
- 所以 S24-b **是可独立检出的真实缺陷**。

另外 **ASSERTION A/B 甚至不需要抽取**：产品当前行为就是
`status=kOk` + `native_code=0x00090312` + `out=201`（重协商记录）。
「成功关闭却发了重协商请求」这个矛盾**今天就在产品上可观测**。

## 4. 两种测试方法

| 方法 | 问的问题 | 结果 |
|---|---|---|
| 我的（错） | 产品正常路径能否触达该分支 | 不能 → 误判「不可测」 |
| 正确的 | 该判定规则本身是否正确 | 能 → 三条红证 |

**一般化**：
1. **分支不可达 ≠ 规则正确**。一个 `if` 的某个 arm 走不到，不代表写在那里的映射是对的。
2. **映射规则可以脱离调用路径单独测**。把 `status → Status` 的映射抽成函数，就能直接断言。
3. **「产品当前行为自相矛盾」本身就是红证**。`status=kOk` 同时 `out` 是重协商记录，这两个事实互相矛盾，不需要构造特殊输入。

## 5. 连带订正：这条错误影响了两处

### 5.1 memory 规则 48 必须改写

原文「红证不可构造就不该占独立缺陷编号」是错的。
正确表述见 memory 规则 50（本次新增）。

### 5.2 批 0 的 B1 裁决方向也要改

执行 AI 报告 3 个 Linux 编译错误，问「批准修复还是认定既有问题」。
我原本倾向「既有问题、转其他批次」，理由是「改前就失败」。

**按同一条方法论，这个理由也站不住**：
- 那 3 个错误（`std::terminate` 缺 `<exception>`、两个未使用的 helper）
  在 **Linux 上是真实缺陷**（编译失败）；
- 它们在 Windows 上测不出来，是因为 **MSVC 的 `<string>` 传递引入 `<exception>`**，
  而 libstdc++ 不会 —— **这是 Windows 测试方法的盲区，不是「没有问题」**；
- 批 0 的目标是「Linux 能 `cmake --build` 成功」，不修它们目标就没达成。

**所以应当批准修复**（4 行），而不是转出去。

## 6. 局限

- 只验证了 S24-b 这一条。其他被我按「不可构造」处理过的条目
  （例如乙的 M22「对端主动重协商是否可达」）**没有重新验证**，可能同样存在方法错误。
- ASSERTION C 依赖「把映射抽成函数」这一重构；当前产品代码里它是内联在 `Shutdown` 里的。
  抽取本身是修复的一部分（提高可测性），不是测试技巧。
