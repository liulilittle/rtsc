# 服务器侧 RDPDR 最小握手设计定案（rdpdr-server-design.md）

状态：W11 执行。v1 范围 = 通道级最小握手，无任何设备操作。

## 核心决策
1. 服务器先发（[MS-RDPEFS] 3.2.5）：Start()=发 **Server Announce**（恰一次）→ 收 Client Announounce
   Reply → 服务器一次发出 **Server Capability（一般能力）→ ClientId Confirm → User LoggedOn**（可选）。
2. **ClientId Confirm 不在收 Client Capability 后才发**（规范读法）。本仓库客户端
   src/channel/rdpdr_client.cpp OnClientIdConfirm 只在收到 Confirm 后才回送自己的 Client
   Capability+DeviceListAnnounce；若服务器等 Client Capability 再发 Confirm 必然互等死锁。
   定案=收到 Client Announce Reply 即同步发出 Capability+Confirm+LoggedOn（FreeRDP rdpdr
   server 同此；S2 测试钉死该顺序，防退化回规范死锁形态）。【偏离源见 §偏离】
3. **v1 不发任何设备**：空设备列表合法（客户端看到 0 个重定向设备）。服务器收到客户端
   DeviceListAnnounce 只计数；DeviceIoRequest（不应出现）忽略+计数，不回 IOCompletion。
4. 复用：include/rtsc/proto/rdpdr.h + src/proto/rdpdr.cpp **零改动**。Server Capability 用
   既有 RdpdrGeneralCapsSet/RdpdrCapabilitySet/ByteWriter 手工组装
   （RdpdrCoreCapability::encode() 写死 ClientCapability 包id，故服务器侧绕开它）+ BuildRdpdrPdu。
5. 集成：server.cpp DoConnectResponse 解析 name[8] 表 → rdpdr id=1004+index（仿 cliprdr）；
   RdpSession 每会话建 RdpdrServer（默认启用，ServerConfig::enable_rdpdr_handshake 可关）；
   ActiveLoop Start（cliprdr 先、rdpdr 后，保既有线序断言）后接 OnChannelData 分发分支。
6. 协议版本：versionMajor=1 / versionMinor=0x000C（与客户端 BuildClientCapabilities 对齐）；
   ClientId 为进程级自增（会话隔离），Announce 与 ClientId Confirm 用同一 id。

## 接口
- include/rtsc/channel/rdpdr_server.h：class RdpdrServer{ SendFn; ctor(SendFn);
  Start/OnChannelData + Phase(kIdle/kAwaitClientAnnounce/kReady) 诊断计数
  （announce/capability/confirm/loggedon/client-announce/client-name/client-capability/
  devicelist-announce/device-iorequest/out-of-order/malformed）}。
- server.h：ServerConfig 增 bool enable_rdpdr_handshake = true。
- server.cpp：RdpSession 增 rdpdr_ + rdpdr_channel_id_；ActiveLoop 增 rdpdr 分支。
- CMake：rdpdr_server.cpp 并入 rtsc_rdpdr；rtsc_server 链 rtsc_rdpdr；新增
  rtsc_rdpdr_server_tests。

## TDD（单测 S1-S6 + 集成 S16）
S1 Start 发 Server Announce（字节断言+幂等）；S2 收 Client Announce→按序
Server Capability/ClientId Confirm/User LoggedOn（分片重组；含能力体解析 ioCode1=0、
extendedPDU=loggedon）；S2b 收 Client Name 只管记录；S3 收 Client Capability→计数+Ready 无新发；
S4 顺序错误/畸形忽略+计数；S5 空设备列表（服务器永不发 DevicelistAnnounce/DeviceReply）；
S6 DeviceIoRequest 忽略+计数。集成 S16：真实 loopback，rdpdr id 1004 路由到 handler
（Announce 到达+回复批回传+client capability/devicelist 无回音）。
变异反证：①Start 不发 Announce→S1 红；②Announce 应答不发 Capability/Confirm→S2 红。

## 影响面（回归）
- DriveToActive(expect_frame=true) 阅读线序须跳过 rdpdr/cliprdr 首帧（server.cpp 服务器现在
  active 即发 Announce）→ test_server.cpp 第 10 步改为跳过非 bitmap 帧。
- 既有 S14/S15（test_server.cpp）selenet 保持绿：Announce 在 cliprdr 初始化之后发，读取循环跳过非
  目标通道帧；1004 垃圾字节被 handler 畸形计数吞掉，不扰会话。
- 客户端 rdpdr 零改动；全量 build 0err/0warn；受影响套件全集回归绿（server/gui_send/
  rdp_standard_security/server_security/multisession/cliprdr_e2e/rdpdr/rdpdr_server/cliprdr_server）。

## v1 明确未做项（留二期，文档记录）
- 服务器侧设备列表/驱动器映射（ServerProvider 方向不发任何 DeviceListAnnounce/DeviceReply）。
- IRP 文件操作全部形态：MJ_CREATE/READ/WRITE/CLOSE/QUERY_DIRECTORY/DEVICE_CONTROL 等（不做、
  不收、不答）。
- 客户端设备消费：收到客户端的 DeviceListAnnounce 后仅计数，不建句柄、不发 DeviceIoRequest。
- 打印机/串口/智能卡重定向；DR_CORE_DEVICELIST_REMOVE；DeviceIoCompletion 发送路径。

## 偏离
1. ClientId Confirm 发出时机 [MS-RDPEFS] 规范文字 vs 本栈客户端行为 → 以客户端为权威
   （任务要点："客户端实现已完整…定义了服务器必须发的序列——反推即可"），
   Confirm 随 Client Capability 应答批同发，不设等待位；S2 断言钉死。
2. S3 任务原文"收 Client Capability→回 ClientId Confirm"实现为：Confirm 已随 Announce 应答发出
   （S2 断言），收 Client Capability 只计数+置 Ready（S3 断言"无任何新发"），保证与在树客户端配对不挂死。
3. ActiveLoop 中 rdpdr Start 排在 cliprdr Start 之后（保持 cliprdr 初始化帧序，既有 S14/S15 线序不变）。

## 风险
R1 规范序客户端（先回 Client Capability 再等 Confirm）与本实现兼容：Capability 到达时计数即可，
Confirm 早已发，客户端照常进 Ready。R2 空设备列表被真实 Windows 客户端视为合法。R3 二期接
ServerProvider 设备时需从 Capability 的 ioCode1=0 改回声明 IRP 集。R4 enable_rdpdr_handshake=false
时客户端 rdpdr 通道回到"静默丢弃"（分发包自决）。