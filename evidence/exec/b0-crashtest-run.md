# A20-3：`rtsc_crashtest` 的运行验证（主代理补做）

审计甲在 §20 指出：批 0 的 25 个证据文件里**零条** `[crash] dir=` 记录，
`verify.ps1 -CrashCheck` 分支批 0 从未跑过。**该判断属实**（我 grep 确认 `evidence/exec/*.txt` 无 `[crash]` 命中）。

批 0 改了 `tools/rtsc_crashtest/main.cpp:9`（加 `#include <exception>`），
只验证了「编译通过」，没有验证「运行行为不变」。现由主代理补做。

## 实测

```
& F:\rtsc\build\verify\rtsc_crashtest.exe terminate
```

输出：

```
[crash] dir=F:\rtsc\build\verify\crashes mode=terminate
[crash] rtsc_crashtest: std::terminate
dump: F:\rtsc\build\verify\crashes\rtsc_crashtest-20261023-095911-49616.dmp
text: F:\rtsc\build\verify\crashes\rtsc_crashtest-20261023-095911-49616.txt
```

退出码 `3`（非零，符合设计：该程序故意崩溃，ctest 不能收录）。

## 结论

- `std::terminate` 路径**正常触发**，crash guard 捕获成功，dump 与 text 双双落盘。
- `#include <exception>` 是纯增量，**未改变运行行为**。
- 批 0 的 S0.9 第 4 行改动**行为无副作用**（这是补做的证据，不是批 0 交付时的证据）。

## 局限

- 只跑了 `terminate` 模式。`null`（空指针写）与 `abort` 两个模式**未跑**。
- 未验证 `verify.ps1 -CrashCheck` 的完整断言链（它还会检查「无对话框阻塞」）。
