# 服务器侧 CLIPRDR 设计定案（cliprdr-server-design.md）

状态：甲乙双审收敛（2026-10-28 轮次 resume 续）。实现依据。

## 核心决策
1. 时序防死锁：**服务器先发**（ClipCaps→MonitorReady）；客户端 Start() 永不发 MonitorReady，只收服务器后跑初始化序列 → 双方互等即死锁。触发=DoFinalization 后/ActiveLoop 首迭代前，恰一次。
2. channel 名映射修复（既有缺陷）：server.cpp 读 TS_UD_CS_NET 只计 count 不解析名字，且 count 用 u16 读 u32 字段 → 改：u32 count + 解析 name[8] 表 → cliprdr id=1004+index（客户端 {"rdpdr","cliprdr","rdpsnd"}→cliprdr=1005）。
3. MCS 集成：ActiveLoop parse 后按 sd.channel_id 三分支（io 原路径 / cliprdr 通道→handler / 其他忽略）；SendRawUserData 泛化 SendMcsUserData(channel_id,ud)；收发加密对称已具备。
4. 状态机（每会话）：kIdle→Start(kInitSent)→kv(kCapsReceived)→首条 FL(kSynced)→kActive。Start=SendClipCaps(0x02)→SendMonitorReady→SendFormatList(空表也发)。Server 收 FormatList 必回 OK(3.1.5.2.2)；未知 msgType SHOULD 忽略。
5. 复用：proto/cliprdr.h+channel.h 平台无关零改动复用；clipboard::Clipboard 后端零改动+扩展 virtual sequence_number()（Win32=GetClipboardSequenceNumber）；CliprdrServer 镜像 CliprdrClient（状态机不可翻转复用）。
6. 并发：全局单剪贴板+进程级 mutex+last-writer-wins（共享桌面语义）；协议状态 per-session；handler 仅会话线程。
7. 变化检测：1s 刷新 tick（server.cpp 读超时分支）轮询 seq 前进→推 FormatList；自回声吞用"应用后 seq"。
8. scope v1：文本+DIB(DIBV5) 双向往返；FILECONTENTS/文件 serve=二期（v1 收 FILECONTENTS 一律 FAIL，不宣告 STREAM_FILECLIP）。
9. 客户端零改动（其 Start 时序严丝合缝）。

## 接口
- include/rtsc/channel/cliprdr_server.h：class CliprdrServer{ SendFn; ctor(Clipboard*,SendFn); Start/OnChannelData/OnLocalClipboardChanged/RequestClientFormat/Poll/EnableFileClip/EnableHugeFileSupport/SetFileListProvider+诊断计数 }。
- server.h 增 SetClipboard(Clipboard*)/SetFileListProvider；RdpSession ctor 增两参。
- clipboard.h 增 virtual uint64_t sequence_number() const{return 0;}。

## TDD（单测 S1-S13 + 集成 S14-S15 + 端到端 E1-E3）
S1 Start 依序 caps→mr→FL 恰一次；S2 client caps→长名协商；S3/S4 长/短名 FL 解析+回 OK；S5 FDR read OK/FAIL；S6 RequestClientFormat 写+吞回声；S7 本地变更→推 FL；S8 分片重组；S9 畸形忽略；S10 TempDir；S11 FILECONTENTS v1→FAIL；S12 EnableFileClip serve；S13 首条 burst。
S14 名解析→cliprdr==1005；S15 ActiveLoop 三分支。
E1 server→client 往返；E2 client→server；E3 握手计数（caps 各1/FLR 成对）。

## mstsc 对照
规范为准；FreeRDP cliprdr server 顺序一致（Capabilities→MonitorReady）。真 Windows TermService 字节级=UNVERIFIED（无逆向后抓包）；DATA_CHANNEL 扩展/msgType 编号已入二期。

## 风险
R1 长短名歧义；R2 OpenClipboard 瞬态失败（v1 同步；预案 worker）；R3 轮询合并最终一致；R4 multisession 争用（后端 mutex）；R5 pre-active 通道数据=自断；R6 FDR 挂起（单槽+超时二期）；R7 未知 msgType=忽略；R8 无延迟渲染同客户端现状。

## 关键既有缺陷一并修
server.cpp CS_NET count u16→u32 + 名字解析（DoConnectResponse）。
