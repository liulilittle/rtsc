# drdynvc 证据（[MS-RDPEDYC]）

## 服务端发起通道创建（批183，2026-11-07）

**事实来源**：
- [MS-RDPEDYC] 2.2.2.1 DVC Create Request PDU (DYNVC_CREATE_REQ)：由 DVC
  server manager 发给 DVC client manager，Cmd MUST be 0x01，ChannelId 由
  服务端生成且连接内唯一，ChannelName 为 null-terminated ANSI 字符串
  （learn.microsoft.com/.../ms-rdpedyc/4448ba4d-...）。
- [MS-RDPEDYC] 2.2.2.2 DVC Create Response PDU (DYNVC_CREATE_RSP)：
  CreationStatus 为 32 位有符号 HRESULT，0 或正数表示成功、负数表示失败；
  失败的 ChannelId MUST NOT 加入活动列表（服务端可不等 CLOSE 直接复用）。

**实现**：
- `IDrdynvcListener::OnChannelCreateRequest(const std::string& name)`：默认
  拒绝（返回 false）。
- `DrdynvcClient` 在 bundle 解析中按 ChannelId 是否在 `pending_` 区分
  CREATE_RSP（4 字节状态）与 CREATE_REQ（NUL 结尾名称）；CREATE_REQ 交给
  首个接受该名称的 listener，回 DYNVC_CREATE_RSP：接受=0，拒绝=
  0xC0000001（STATUS_UNSUCCESSFUL）；仅接受时加入 `open_channels_`。
- `server_create_count()` 诊断计数；Reset 清零。

**证据**：`tests/test_rdpusb.cpp` 的
`drdynvc_server_initiated_create_accepted`（名称解析、状态 0、后续 DATA
送达 listener）与 `drdynvc_server_initiated_create_rejected`（状态
0xC0000001、DATA 被丢弃）；rdpusb 77/444 全绿。M97（始终回失败状态）→
1 test / 1 check 红，恢复后全绿。

**未验证**：真实服务器发起通道（本机 rtsc_server 不发起 DVC）；名称大小写
敏感性按 ANSI 字节精确匹配实现（未与 Windows 行为对照）。
## 客户端主动关闭与本地状态（批184，2026-11-07）

**事实来源**：[MS-RDPEDYC] 2.2.4 Closing a DVC —— DYNVC_CLOSE 由任一端发送，
同一 PDU 兼作关闭请求与关闭响应（learn.microsoft.com/.../ms-rdpedyc/
c02dfd21-...）。

**实现**：
- `CloseChannel(id)`：发送 DYNVC_CLOSE 后立即从 `open_channels_` 移除、
  重置该通道重组器并记入 `closing_`；此后该 id 的入站 DATA 一律丢弃。
- 接收 CLOSE：未知通道为 no-op（不回调）；服务端主动关闭（was_open/
  was_pending）回调 `OnChannelClosed`；对本地已关闭通道的 CLOSE 作为响应，
  回调一次且仅一次（`closing_` 抑制重复）。
- 通知不在 `CloseChannel` 内同步发出，而是在服务端 CLOSE 到达时发出，
  避免调用方在自己的回调里关闭通道时重入（本批实测重入导致堆损坏）。

**证据**：`tests/test_rdpusb.cpp` 的 `drdynvc_client_close_stops_delivery`
（关闭后 DATA 不投递、服务端 CLOSE 只通知一次）与
`drdynvc_close_unknown_channel_is_ignored`；rdpusb 79/448 全绿。M98（关闭
时不移除 open_channels_）→ 1 test / 1 check 红，恢复后全绿；影响面
`ctest -R "^(rdpusb|display_control|client|gui_send)$"` 4/4。

**未验证**：真实服务端关闭时序；多监听器下非发起方监听器在服务端响应前
仍持有旧状态（本仓当前消费者不使用该窗口）。
## 压缩 DATA（批185，2026-11-07）

**事实来源**：[MS-RDPEDYC] 2.2.3.3 / 2.2.3.4（learn.microsoft.com 原文）：
- 0x06 DYNVC_DATA_FIRST_COMPRESSED：cbId(2) + **Len(2)** + Cmd(4) +
  ChannelId + Length（Len 选 1/2/4 字节，Len=3 非法）+ Data；Length 为消息
  未压缩总长。
- 0x07 DYNVC_DATA_COMPRESSED：cbId + Sp + Cmd + ChannelId + Data（无
  Length）；Data 为 RDP_SEGMENTED_DATA/RDP8_BULK_ENCODED_DATA，压缩类型
  RDP8_LITE(0x06)，段上限 8192；仅 DVC v3 + 可靠传输可用。
- 解压需 RDP 8.0 Bulk（[MS-RDPEGFX] 3.1.9.1），每通道独立上下文。

**实现**：
- `src/proto/drdynvc.cpp`：`DynvcHeader::parse` 记录 len_bits；`DynvcPdu::parse`
  对 0x06 按 Len 读取变长 Length 并拒绝 Len=3；新增
  `BuildDynvcDataFirstCompressedPdu(len_bits, ...)`。
- `src/channel/drdynvc_client.cpp`：bundle 解析对 0x06 读变长 Length；
  0x06/0x07 计入 `compressed_data_count_` 并丢弃（无 Bulk 解压器），
  不再落入 default 分支；`Reset` 清零计数。

**证据**：`tests/test_rdpusb.cpp` 新增 5 个测试（Len=1/2/3、builder 往返、
客户端计数丢弃且不污染后续重组）；rdpusb 84/468 全绿；影响面 4/4。
M99（去掉计数）→ 1 test/2 checks 红；M100（Length 固定 4 字节）→ 3 tests
红；恢复后全绿。

**未验证**：真实 v3 服务端压缩流；RDP8 Bulk 解压未实现（PDU 被丢弃，通道
数据不完整时上层无感知）。
## 数据发送的通道校验（批187，2026-11-07）

**事实**：[MS-RDPEDYC] DYNVC_DATA/DYNVC_DATA_FIRST 仅在通道打开后发送才有效；
DYNVC_CLOSE 后 ChannelId 可被服务端复用，向已关闭 id 写数据是协议错误。

**实现**：`DrdynvcClient::SendChannelData` 返回 bool，仅在 `open_channels_` 或
`pending_` 含该 id 时发送；否则 `++refused_data_count_` 并返回 false。新增
`refused_data_count()`，`Reset` 清零。`DisplayControlClient` 只在发送成功后
`++layout_count_`。

**证据**：`tests/test_rdpusb.cpp` 新增
`drdynvc_send_refused_for_unknown_channel`、
`drdynvc_send_refused_after_local_close`、`drdynvc_send_allowed_while_pending`；
rdpusb 87/480 全绿；影响面 5/5。变异 M104（删校验）→ 2 个测试 3/5 checks 红，
恢复后全绿。

**未验证**：真实服务端在 CREATE_RSP 之前收到数据的行为；pending 期间发送保持
允许（既有流水线语义，未针对真实服务端验证）。

## RDP8 bulk 解压器第一阶段（批189，2026-11-08）

**依据**：[MS-RDPEGFX] 3.1.9.1（RDP 8.0 压缩器限制与算法）、2.2.5.1/.2/.3（RDP_SEGMENTED_DATA /
RDP_DATA_SEGMENT / RDP8_BULK_ENCODED_DATA）；[MS-RDPEDYC] 2.2.3.3（RDP 8.0 Lite：类型码 0x06、
历史 8,192、仅 SINGLE）。

**实现**：`include/rtsc/proto/bulk.h`、`src/proto/bulk.cpp` —— `BulkDecompressor` 维护 8,192
字节历史环；解析 SINGLE(0xE0) 段，校验类型码 0x06，未压缩段（无 PACKET_COMPRESSED）
直通写入输出与历史；单段未压缩上限 65,535；MULTIPART(0xE1)、未知描述符、超限、压缩
段（第二阶段前）一律返回 0（失败关闭）。

**证据**：`tests/test_bulk.cpp` 5 用例；[BASH:5 tests, 11 checks, 0 failing]；
红证（实现置空桩）test_bulk.cpp:16 got 0, want 5；变异 M106（0x06→0x04）同样红，恢复后绿；
影响面 ctest 10/10。

**未完成**：令牌表 + 位流解码 + 匹配复制 + 官方样本 4.2.1.1 留出验证；
`drdynvc_client.cpp:213-219` 压缩分支仍为丢弃计数（未接线）。

## RDP8 bulk decompressor phase two (batch 190, 2026-11-08)

**Basis**: [MS-RDPEGFX] 3.1.9.1.2.1 token table, 3.1.9.1.2.4 trailer (low three bits of
the final byte = unused bit count), 3.1.9.1.2.5 bit-stream examples, 4.2.1.1.3 sample ("ABC" x20);
[MS-RDPEDYC] 2.2.3.3 (Lite: 8192-byte history and segment ceiling).

**Implementation**: `src/proto/bulk.cpp` now has an MSB-first BitReader (bounded reads,
leading-ones, byte alignment, raw byte runs) and the 40-entry prefix-free token table; it decodes
literals, null-prefixed literals, distance-0 unencoded runs and matches (including overlap).
Every failure path returns 0: non-SINGLE descriptor, type != 0x06, trailer beyond the
bit stream, reserved token prefix, length prefix above 14 one bits, distance > 8192,
segment output > 8192.

**Evidence**: `tests/test_bulk.cpp` 14 tests / 1139 checks green; red proof: before the type-code fix
the literal case reported got 0, want 1; mutation M107 (token prefix comparison forced true)
turned the assertion red and raised an SEH, and the restored build is fully green; 
impact ctest 11/11.

**Not done**: `drdynvc_client.cpp:213-219` still drops compressed payloads (not wired);
the remaining four 4.2.1.1 official samples are not covered yet.

## DVC compressed data wired (batch 191, 2026-11-08)

**Basis**: [MS-RDPEDYC] 2.2.3.3/2.2.3.4 (Length = total uncompressed message length;
payload is RDP_SEGMENTED_DATA with RDP8 Lite; each channel MUST use a dedicated
compression context) and 3.1.5.3 (reassembly by uncompressed length).

**Implementation**: `DrdynvcClient::OnCompressedData` decompresses with a per-channel
`BulkDecompressor`, then feeds a synthetic DYNVC_DATA_FIRST/DYNVC_DATA PDU through the
normal reassembler. On decompression failure it erases that channel context and resets
the half-assembled message (fail closed) and counts `compressed_failure_count_`. The
context and the failure counter are cleared by `Reset()`; `OnClose` drops the context.

**Evidence**: 4 new tests (single block, cross-PDU history reassembly, corrupt block,
unknown channel) in `tests/test_rdpusb.cpp`; [BASH:90 tests, 491 checks, 0 failing];
impact ctest 9/9; mutation M108 (inverted success test) turned 3 tests red, restored green.

**Not enabled**: the client still sends DYNVC_CAPS_REQ VERSION1, so a conforming server
never sends these PDUs. Enabling requires VERSION3 negotiation plus
DYNVC_SOFT_SYNC_REQUEST/RESPONSE (next batch). Unverified against a real server.

## DVC capabilities response and version 3 (batch 192, 2026-11-08)

**Basis**: [MS-RDPEDYC] 2.2.1 and 3.2.3.1.4 (a client MUST answer DYNVC_CAPS_VERSION1/2/3
with a DYNVC_CAPS_RSP carrying the highest version it supports), 3.2.3.1 (version 3
introduces compressed DVC data), 2.2.1.2 (CAPS_RSP layout: Cmd 0x05, Pad 0, Version).

**Defect**: the client only sent DYNVC_CAPS_REQ and read the server version; it never
answered with a CAPS_RSP, and it never advertised above version 1, so the compressed
path could never legally be used.

**Implementation**: on a server CAPS PDU the client now replies with a CAPS_RSP whose
Version is min(client maximum 3, server-declared). Compressed DATA PDUs are rejected
(counted as failures) while the negotiated version is below 3.

**Evidence**: 4 new tests plus version-3 preconditions added to the batch-191
compression tests; [BASH:94 tests, 508 checks, 0 failing]; impact ctest 9/9;
mutation M109 (always advertise 3) turned 2 tests red; restored build green.

**Scope note**: Soft-Sync ([MS-RDPEDYC] 2.2.5, 3.1.5.3) only defers DVC traffic to
multitransport tunnels; this client does not enable tunnels, so no Soft-Sync PDU is
sent or required. Unverified against a real server.