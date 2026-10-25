# SChannel 探针源码（实测证据）

这 50 个 `.cpp` 是 TLS 后端选型阶段的实测探针源码，从 `F:\rtsc\.tmp\tlsprobe\`
复制而来（`.tmp` 是临时目录，可能被清理工具删除）。

## 为什么保留源码

探针的**输出**证明"实测结果是什么"，源码证明"实测是怎么做的"。
两者合起来才构成完整证据链——只留输出无法复核方法是否正确。

## 与 evidence/tls/ 其他文件的关系

| 文件 | 内容 |
|---|---|
| `probe24.out.txt` | probe24 的实测输出（TLS1.2 vs TLS1.3 的 ASC 行为） |
| `probe24.rerun-consult-b.txt` | consult-b 独立复跑同一二进制的输出（逐行一致） |
| `probes/probe24.cpp` | probe24 的源码（证明它调的是 `AcceptSecurityContext` 而非 `DecryptMessage`） |
| `loopback_schannel.cpp` | 进程内 SChannel 回环主证据（RESULT=PASS） |
| `verify_traps.cpp` / `verify_t3.cpp` | 五条陷阱 / TLS1.3 专项验证 |

## 注意

- 这些源码**编译产物（.exe/.obj）未保留**，因为它们可由源码重建，
  且二进制与编译器版本绑定，保留价值低。
- 编译命令见 `docs/spec/tls-backend.design-a.md` 的 §7.5 / §7.5b。
- 源码保持**原样冻结**，不修改。若需修改，应在新的探针文件里做，保留历史。
