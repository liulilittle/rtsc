# 能力交换遍历伪码：红证/绿证 harness

## 用途

复现 `capabilities.md` §6.1（行 844-853）遍历伪码的三条缺陷：

| 缺陷 | 触发 | 后果 |
|---|---|---|
| **F-12** | `numberCapabilities` 大于实际 set 数 | 循环在 `p == caps_end` 处仍读头 → 越界读 |
| **F-03** | `lengthCapability` 大于剩余字节 | 消费超长 → 越界读 |
| **F-13** | `lengthCombinedCapabilities < 4` | `lcc - 4` 在 uint16 下溢为 65534 → assert 失败（**不是**越界） |

## 保真度声明（重要）

文档伪码**没有上界检查**，也**没有 `lcc < 4` 守卫**，但**有**行 849 的 `if len < 4: error`。
harness 不能真的执行越界读（会崩溃），因此每次"读"之前都用 `WouldRead()` 做一次**建模判断**
——它回答"这一读会不会越过末尾"，而**不是**真的去访问越界内存。

除此之外，控制流与文档逐字一致，包括：

- `lcc - 4` 的 **uint16 下溢**（`D` 场景 `end = 65534`）
- 行 849 的 `if len < 4: error`（`F` 场景 → `ERR-len<4`）
- 末尾的 `assert(p == caps_end)`（`E` 场景因此报 `ASSERT-FAIL`）

### 修订史（三处偏离，均由审计甲反向纠错）

| # | 偏离 | 修正 |
|---|---|---|
| 1 | 初版擅自加了文档没有的 `lcc < 4` 前置守卫，D 场景报 `ERR-lcc<4` | 删守卫，改用 `static_cast<uint16_t>` 建模下溢 → `ASSERT-FAIL end=65534` |
| 2 | 初版漏了文档行 852 的 `assert(p == caps_end)`，E 场景报 `OK` | 补上 → `ASSERT-FAIL end=32` |
| 3 | 修正 #1 时**误删了文档行 849 的 `if len < 4: error`**，F 场景报 `ASSERT-FAIL` | 补回 → `ERR-len<4` |

第 3 处的教训：修正"多加了检查"时不能滑到"少加了检查"，两者同样不忠实。
标准必须双向，对批评者自己也成立。

## 实测输出（`redlit_walk.out.txt`）

```
A count>data (F-12)          doc=OOB-READ-HEADER    off=24 len=4 end=24 | fix=ERR-header-oob
B len>remaining (F-03)       doc=OOB-READ-BODY      off=0 len=200 end=8 | fix=ERR-body-oob
C legal (green)              doc=OK                 off=24 len=0 end=24 | fix=OK
D lcc=2 (F-13)               doc=ASSERT-FAIL        off=24 len=0 end=65534 | fix=ERR-lcc<4
E trailing slack             doc=ASSERT-FAIL        off=24 len=0 end=32 | fix=ERR-trailing
F len=0                      doc=ERR-len<4          off=0 len=0 end=24 | fix=ERR-len<4
```

## 结论

1. **A 与 B 是真实越界**（`doc=OOB-READ-*`），修法（`fix=ERR-*`）均能拦住。
   两者触发字段都由**对端**控制，因此按三档定义命中「阻断」的 **(b) 分支**。
2. **C 是绿证**：合法输入下文档伪码正常 → 证明缺陷只在畸形输入下触发，
   即命中 (b) 而非 (a)，这正是「阻断」而非「严重」的判定依据。
3. **D 是 assert 失败而非越界**（`end=65534`）→ F-13 保持「一般」正确。
4. **F 是文档行 849 自己的守卫生效** → 与 F-13 无关，不是缺陷。
5. **E 是末尾 assert 失败**（`end=32`，尾部 slack）→ 与 F-13 同族，不单独升级。

## 复跑

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$vs='C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vs`" >nul 2>&1 && cd /d F:\rtsc\evidence\capabilities && cl /nologo /W4 /WX /EHsc /std:c++20 /utf-8 redlit_walk.cpp /Fe:redlit_walk.exe >rl.log 2>&1 & redlit_walk.exe"
```

## 与实现的关系

本项目实现（`src/proto/capabilities.cpp` 的 `ParseCapabilitySets`）**已含全部四项检查**：
`combined_length < 4` 拒绝、`size < window` 拒绝、`p + 4 > window` 拒绝、
`p + len > window` 拒绝，另有 `len < 4` 拒绝与 `p != window` 的 `trailing_slack` 标记。
**F-03 / F-12 / F-13 是纯文档缺陷，代码未受污染。**
