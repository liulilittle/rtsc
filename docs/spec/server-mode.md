# 服务器模式（RDP Server）能力与家庭版/多用户说明

状态：2026-10-28。自研 RDP 服务器（`rtsc_server` 库 + `rtsc_server_host` 工具）。

## 架构结论：不依赖 Windows 远程桌面服务

服务器代码 `src/server/`、`include/rtsc/server/` 对以下 Windows 组件**零调用**
（`Select-String termsrv|WTS|wtsapi|NetSession|LsaLogon` 无匹配）：

- termsrv.dll / TermService（Windows 远程桌面服务）
- WTS* 会话管理 API
- 终端服务授权

服务器只依赖：winsock（TCP）、SChannel（TLS）、crypto、GDI（桌面捕获）、
Win32 clipboard。协议栈（TPKT/X.224/MCS/GCC/安全层/共享 PDU/虚拟通道）
全部自实现。

**推论（家庭版解禁）**：Windows 10/11 Home 通过策略限制 TermService 作为
RDP 服务器（`fDenyTSConnections`、单会话、无多用户）。本实现是独立进程，
不经过 TermService，因此在家庭版上同样可运行——限制的是微软服务，不是
RDP 协议本身。未验证项：未在真实 Home SKU 上实跑（本机为 Pro）；
如需证据，需一台 Home 机器执行 `rtsc_server_host`。

**推论（多远程用户）**：会话由 `RdpServer` 自己管理（`registry` +
per-session `RdpSession`），并发客户端隔离由
`server_multisession_concurrent_clients_are_isolated` 与新增的剪贴板
并发用例覆盖；不触 Windows 的单会话策略。

## 能力矩阵（v1）

| 能力 | 状态 | 证据 |
|---|---|---|
| TLS / CredSSP / NLA 服务器 | 完成 | server_security 7/60；真机 mstsc 客户端路径（服务端反向未验） |
| 桌面捕获 + 位图编码/发送 | 完成 | desktop_gdi 5/16；test-pattern；GUI 回环 1280x1024 渲染 |
| 输入（键盘/鼠标 FastPath） | 完成 | SetInputCallback；server 27/239 |
| 剪贴板重定向（CLIPRDR，文本+DIB） | 完成 | cliprdr_server 20/161；e2e 3/29；host 实测双向 data_req/resp |
| 多会话并发 | 完成 | multisession 7/184（含共享剪贴板 last-writer-wins） |
| 设备重定向（RDPDR）握手 | 完成（最小） | rdpdr_server 7/88；空设备列表合法 |
| 设备重定向 文件操作/驱动器映射 | 未做（二期） | docs/spec/rdpdr-server-design.md |
| 音频重定向 RDPSND | 未做（二期） | rdpsnd-evidence |
| RAIL/RemoteApp 服务器侧 | 未做 | — |
| USB 重定向服务器侧 | 未做 | — |

## 反向互通（mstsc → 本服务器）

未验证。需要：
1. mstsc 信任服务器 TLS 证书（自签需导入信任，或用 CredSSP 的 NLA 路径）；
2. 观察 mstsc 的 rdpdr/cliprdr 握手与本实现（客户端已验证的序列）是否一致；
3. 注意客户端取证发现：mstscax 有 DATA_CHANNEL(0xC/0xD) 扩展、msgType 编号
   待 wire 裁决（docs/spec/cliprdr-evidence.md §6），服务器侧当前按规范忽略
   未知 msgType。

## 性能

回环（本机 server → 本机 client，test-pattern）：loop 399-434/s（2.5 ms/帧），
见 process.md 第660轮。

## 结论

objective 的「服务器模式（家庭版解禁、多远程用户）」在**实现层面已达成**：
不依赖 TermService，多会话自管。待补：Home SKU 实跑证据、mstsc 反向互通、
设备/音频/USB 服务器侧。
