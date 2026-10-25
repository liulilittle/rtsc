# 批 2 审计甲 · S23 红证形态裁定

> 严格只读：未改 `src/`/`include/`/`tests/`，未构建，未跑变异，未启动 exe。
> 结论：**采纳 A + C 组合（主代理倾向），但两者都不能用现有 C++ 框架单独完成，且我发现了第三个更根本的问题。**

## 1. 先确认主代理这版的事实：全部成立

我独立读了 `evidence/u4/probe_u4.out.txt` 与 `probe_u4e.out.txt`：

| 主代理的断言 | 我的核实 |
|---|---|
| 加密 close_notify → `SEC_I_CONTEXT_EXPIRED` (`0x00090317`) | ✅ `probe_u4e` T2：`client DecryptMessage -> 0x00090317` |
| `c:301-305` 映射为 `kClosed` + `native_code=st` | ✅ 实读 `:301-305`，`MakeError(Status::kClosed, st, ...)` |
| 明文裸 alert → `0x80090318` | ✅ `probe_u4` Q1：`native_code=0x80090318`（`SEC_E_INCOMPLETE_MESSAGE`，我查了 `winerror.h` 确认） |
| T3 的 `level=21 description=3` 是探针误标 | ✅ `0x15,0x03` 是 record 头前两字节（type=21, version 高字节=3） |
| 产品行为本来就对，S23 是纯注释缺陷 | ✅ 成立 |

**额外确认**：`0x80090318` = `SEC_E_INCOMPLETE_MESSAGE`（`winerror.h` 实查），
被 `c:278-283` 捕获 → `Fail(kProtocolError, st)`。主代理没提这一层，但它印证了「明文 alert 走另一条路径」。

## 2. 我发现的第三个问题：**注释修完仍然不准确**

主代理给的 U-N10 新注释：
```cpp
kPeerAlert,  // Backend surfaced a fatal alert. NOTE: SChannel cannot fill native_code
             // with the alert description — ... Kept for backends that can (OpenSSL SSL_AD_*).
```

**问题**：它说 `kPeerAlert` 是「Backend surfaced a fatal alert」，但实测
**`kPeerAlert` 在整个仓库里从未被任何代码产生**：

```
include/rtsc/net/tls.h:42    kPeerAlert,   // 定义
include/rtsc/net/tls.h:68    status == Status::kPeerAlert ||   // terminal() 判断
tests/test_tls.cpp:249       Status::kPeerAlert,               // 枚举列举
```
`src/` 下**零命中**。SChannel 收到 close_notify 返回的是 **`kClosed`**（不是 `kPeerAlert`）；
收到明文 alert 返回 **`kProtocolError`**。

**且 `doc:3127` 已明确批 2 的决定是「保持 `kPeerAlert` 不产出」**（S7 不在批 2 实现）。

→ **修完注释后，读者会以为 `kPeerAlert` 会在某种情况下产生，但它永不产生。**
这与原注释「撒谎」是同一类错误，只是换了个说法。

**建议注释必须同时说两件事**：
1. SChannel 填不了 `native_code` 的 description（主代理已写）
2. **当前没有任何后端产出 `kPeerAlert`**（批 2 决定保持不产出，见 `doc:3127`）

```cpp
kPeerAlert,  // Reserved for backends that can report a peer fatal alert with its
             // description (OpenSSL SSL_AD_*). NO backend produces this today:
             // SChannel reports close_notify as kClosed and encrypted alerts as
             // kProtocolError, and cannot expose level/description at all
             // (measured: evidence/u4/probe_u4e.out.txt). Never interpret
             // native_code as an alert description byte.
```

## 3. 裁定候选：**A + C 组合，但 A 的实现方式要改**

### 候选 A（文档断言）—— 采纳，但**不要**用「不含某字符串」的写法

主代理方案：脚本检查 `kPeerAlert` 行附近**不含** `native_code = alert description`。

**问题**：负向断言（"不含 X"）很脆——只要有人把注释改写成
`native_code != alert description` 或 `native_code is not the alert description`，
字面检查就失效，而语义仍然正确/错误不明。

**更好的写法（正向断言）**：要求 `kPeerAlert` 行块**必须包含**三个关键事实：
```python
must_contain = [
    'kPeerAlert',
    'no backend produces',      # 或等价表述：当前无产出点
    'cannot',                    # SChannel 填不了 description
]
```
加上「不含旧文案」作为辅助。**正向 + 负向双断言**比纯负向稳。

**并且**：这个检查必须能对「把注释改回旧文案」这个变异变红——我实测验证过可行（见 §5）。

### 候选 B（观测型 `native_code != 0x15`）—— **否决**

理由：它锁的是「当前行为」，而 S23 的缺陷是注释。**注释改回旧文案，B 仍然绿**。
主代理自己也说「红证不成立」。**既然不成立，就不该作为 S23 的红证。**
（但它可以作为**防回归**断言留在用例里，防止未来有人真去读 `plain[0]`——这与候选 C 重合。）

### 候选 C（行为型 `native_code == 0x00090317`）—— **采纳**

它锁住「代码不许按错误注释去改」——即防止 `doc:3126` 那个错误变异
（把实现改成读 `plain[0]` → 得到 `0x15` 而非 `0x00090317`）。
**这正是我原稿犯的错，值得用用例钉死。**

## 4. 回答你的三个具体问题

### Q1：`RawServer::CloseNotify()` 该不该加？

**该加，且不算「改产品代码」。** 理由：
- `tests/test_tls.cpp` 的 `RawServer`（`:50`）是**测试夹具**，不是产品
- 它已经有 `Step`（`:73`）、`Encrypt`（`:95`）、`Decrypt`（`:114`）三个 SSPI 封装，
  加 `CloseNotify` 是同一层次的第四个，风格一致
- `probe_u4e` T1 已证明做法可行（`ApplyControlToken(SCHANNEL_SHUTDOWN)` + ISC → `out=31, type=21`）

**但要注意**：`probe_u4e` T1 是在**服务端上下文**做的，且用了 `SECPKG_CRED_INBOUND`。
`RawServer` 正是 inbound（`:68`），**可直接复用**。约 15 行。

**建议实现要点**（写进任务书，避免执行 AI 试错）：
```cpp
// 服务端发 close_notify：ApplyControlToken + ISC，同 probe_u4e T1
DWORD type = SCHANNEL_SHUTDOWN;
SecBuffer tok{sizeof(type), SECBUFFER_TOKEN, &type};
SecBufferDesc td{SECBUFFER_VERSION, 1, &tok};
if (ApplyControlToken(&ctx_, &td) != SEC_E_OK) return SEC_E_UNSUPPORTED_FUNCTION;
// 然后 ISC(空输入) 产出 31 字节 alert record
```

### Q2：文档断言脚本放哪？

**并进 `batch2_gate.py`（你的倾向正确）**，但**分成两个独立检查函数**，不要混在一个逻辑里：
- `check_tests_present()` —— 8 条用例名（现有）
- `check_tls_header_contract()` —— `kPeerAlert` 注释三要素（新增）

理由：一个门禁管一批，但**失败信息必须能区分「缺用例」和「注释回退」**。
合并成一个函数会让输出含糊。

### Q3：S23 是否该降级/挪走？

**不建议挪走，但建议改名定性。**

**不挪走的理由**：
- `doc:3126` 已经把 S23 列为批 2 的变异项，挪走会破坏 §18.3.1 表的完整性
- 它是**唯一一条「注释即缺陷」**的样本，对批 3+ 有方法论价值
  （「文档承诺 ≠ 实现行为」这类缺陷会反复出现）

**建议改名定性**：从「S23 注释缺陷」改为
**「S23 契约缺陷：`tls.h` 对 `kPeerAlert` 的承诺与实际能力不符」**。
理由：它不是"注释写错了字"，是**接口契约撒谎**——后者严重得多。

**若你坚持挪走**：批 2 变 7 条缺陷 / 7 条新用例 / **33 tests**。
但我建议保留，因为它**不增加代码改动量**（零行代码），只增加一个文档断言 + 一条行为用例。

## 5. 我实测验证了「注释变异能否被抓」（只读，未改文件）

用内存中的字符串模拟，验证正向+负向双断言的判别力：

| 注释内容 | 负向（不含旧文案） | 正向（含三要素） | 判定 |
|---|---|---|---|
| 旧文案 `native_code = alert description` | **命中旧文案 → 红** | 缺 "cannot" → 红 | ✅ 红 |
| U-N10 新版（主代理） | 不含旧文案 → 绿 | 含 cannot，但**缺 "no backend produces"** → 红 | ⚠️ 仍红 |
| 我的建议版 | 不含旧文案 → 绿 | 三要素齐 → 绿 | ✅ 绿 |

**这说明主代理的 U-N10 版过不了我的正向断言**——因为它没写「当前无产出点」。
**这不是我故意加严，而是 §2 指出的真实缺陷。**

## 6. 裁定汇总

| 项 | 裁定 |
|---|---|
| **S23 红证形态** | **A（文档断言，正向+负向）+ C（行为型 `native_code==0x00090317`）**；**否决 B 作为红证**（可留作防回归断言） |
| **A 的实现** | 并进 `batch2_gate.py` 的独立函数；正向要求三要素（`kPeerAlert` / `cannot` / `no backend produces`）+ 负向排除旧文案 |
| **Q1 `CloseNotify()`** | **该加**，测试夹具，非产品代码；`probe_u4e` T1 已证可行，约 15 行 |
| **Q2 脚本位置** | 并进 `batch2_gate.py`，但**分两个独立函数**，失败信息可区分 |
| **Q3 降级/挪走** | **不建议挪走**；建议改名「契约缺陷」而非「注释缺陷」 |
| **U-N10 注释** | **需补一句**「当前无任何后端产出 `kPeerAlert`」（`doc:3127` 已定批 2 不实现） |

**门槛不变：8 条缺陷 / 8 条新用例 / 34 tests。**
