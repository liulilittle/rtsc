# S25 实测裁决：S24-b 应归入 S24，不单列

主代理独立探针 `F:\rtsc\.tmp\probe_s25\probe_s25.cpp`：
**A 段链接真实产品库 `build\verify\rtsc_tls.lib`**（测产品行为），
C 段用手写上下文（测 API 语义）。两段目的不同，不能混用。

## 1. 被测命题

审计甲在 §18 主张：S24-b（`tls_schannel.cpp:429` 把 `SEC_I_CONTINUE_NEEDED` 当成功）
**没有独立于 S24-a 的可复现状态**，因此不应单列 S25，而应作为 S24 的子项。

## 2. 实测结果

### CELL A（产品，握手未完成）

```
CELL A (product, handshake_complete=false)
  Shutdown -> status=0 native=0x80090318 out=0 closed=false
```

**逐字复现甲的数字**。这是 **S22 的触发路径**：
`:405` 有 ctx → `:409-411` 空 token → `:429` 不匹配（`0x80090318` 既非 `SEC_E_OK`
也非 `SEC_I_CONTINUE_NEEDED`）→ `:433`「best effort」→ **返回 `kOk`**，`closed_` 保持 `false`。

**S22 从「读代码推断」升级为「有触发路径、有输出」。**

### CELL C（正确 token，握手未完成）

```
CELL C (correct token, handshake NOT complete)
  ApplyControlToken -> 0x00000000
  ISC               -> 0x00000000
  out = 7 bytes, type=21 (Alert)
```

**正确 token 下 `ApplyControlToken` 与 `ISC` 都返回 `SEC_E_OK`**，产出 type=21 (Alert)。

## 3. 与甲预测的一处差异（不影响结论）

甲预测 CELL C 是「31 B, type 21」。我实测是 **7 B, type 21**。

原因：我的 CELL C 在**握手未完成**时关闭，此时 alert 是**明文**（7 字节：
`15 03 03 00 02 <lvl> <desc>`）；甲的 31 字节是**握手完成后**的加密 alert
（13 头 + 2 明文 + 16 trailer）。

**结论不变**：`act == SEC_E_OK && st == SEC_E_OK && type == 21` —— 三个判别量全部成立。
**这正是甲自己总结的规律**：「具体字节数不能跨上下文迁移，只有 record type 这种结构性结论可以」。
我用 7 字节 vs 他的 31 字节，恰好又验证了一遍这条规律。

## 4. 裁决

**S24-b 归入 S24，不单列 S25。** 依据：

1. **根因单一**：2×2 矩阵里只有 token 一个自变量。
2. **修好 token 后无可复现状态**：CELL C 证明正确 token 下 ISC 返回 `SEC_E_OK`，
   `native_code` 必为 0 → 不存在「S24 已修、S25 未修」的状态。
3. **红证不可构造就不该占独立编号**：硬凑会让清单出现永远无法验收的条目。
4. **但必须作为显式子项**：`CHECK_EQ(first[0], 21)` 抓不到 S24-b，
   所以 S24 的修复范围**必须同时包含 `:429`**。

## 5. 甲对我措辞的订正（我接受，且它决定修复位置）

我说过「这个错误连错误码都被丢掉了」。**一半对一半不对**：

| 码 | 是否被丢 | 证据 |
|---|---|---|
| `0x80090302`（`ApplyControlToken` 返回） | **确实完全丢弃** | `:411` 裸调用，无赋值无比较 |
| `0x00090312`（`ISC` 返回） | **没丢**，在 `native_code` 里 | 我自己的输出就是 `native=0x00090312` |

错的是 **`status = kOk`**：调用方按 `Error::ok()`（`tls.h:62`）短路后看不到它。

**为什么这决定修复位置**：若认为「码丢了」→ 去改 `:431` 别丢码 → **改了没用**
（`st` 本来就在 `native_code`）；认清「ctl 的码丢了 + ISC 的码被成功状态包住」
→ 才会改 **`:411`** 与 **`:429`**，那才是根因。

**教训**：「错误码丢失」有两种形态——**值被丢弃** 与 **值存在但被成功状态遮蔽**。
两者修复点完全不同，不能混为一谈。

## 6. 局限

- CELL C 用明文 alert（握手未完成），未测握手完成后的 31 字节加密 alert；
  该数字来自甲的探针（`evidence/u4/probe_u4e.out.txt` T5）。
- 只测 TLS 1.2。
