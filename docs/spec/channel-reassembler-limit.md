# 小批 F1+D2（2026-10-28）

## F1 重组上限（安全，跨全部静态虚拟通道）
- 现状：`src/proto/channel.cpp` `ChannelReassembler::Feed` 的 `expected_length_ = header.length` 完全信任对端 u32，无上限；`buffer_.insert` 持续增长 → 对端声明 4 GiB 即 OOM。
- 修复：新增 `kMaxChannelMessageBytes = 16 MiB`（对齐 `include/rtsc/proto/drdynvc.h:106` 的 `kMaxMessageLength`）。
  - FIRST 分片：`header.length > kMaxChannelMessageBytes` → `Reset()` + 返回 `Status::InvalidLength`。
  - 累积：`buffer_.size() + size > kMaxChannelMessageBytes` → `Reset()` + `Status::InvalidLength`。
- 影响：所有使用 ChannelReassembler 的 handler（cliprdr/rdpdr/rdpsnd/rdpusb）自动获得上限。

## D2 服务器 Device Reply（互通）
- 现状：`src/channel/rdpdr_server.cpp:189-203` `OnDeviceListAnnounce` 只解析计数，不发 `DR_CORE_DEVICE_ANNOUNCE_RSP`；proto 层 `RdpdrDeviceReply::encode()` 已具备。
- 修复：解析成功后对每个 `device_id` 发 `RdpdrDeviceReply{device_id, 0}`（result_code 0 = SUCCESS），计数器 `device_reply_count_`。
- 依据：[MS-RDPEFS] 2.2.2.1；真 mstsc 服务器按设备回复（规范 1.3.2 对初始列表为 optional，但回复提升互通、无副作用）。

## 验收
- F1：新用例（声明 16 MiB+1 → InvalidLength；累积超限 → InvalidLength；正好 16 MiB → 通过）。
- D2：rdpdr_server 用例（1 设备 announce → 收到 1 个 Device Reply，device_id 一致，result_code=0）。
- 变异：F1 删上限 → 红；D2 删回复 → 红。
- C0：build 0err/0warn；影响面 channel/cliprdr/rdpdr/rdpdr_server/rdpsnd/rdpusb/server 全绿。
