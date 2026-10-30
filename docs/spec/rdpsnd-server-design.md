# 服务器侧 rdpsnd 设计证据（docs/spec/rdpsnd-server-design.md）

> 状态：设计取证（实现前门，禁止跳过）。生成于 2026-10-28 W11 双审计批次。
> 审计来源：乙 ses_e7577858cffeF4E1KTM6NePgY0（终报已交）；甲 ses_e7577b947ffe0u079GJhkmmY3y（在途）。

## 1. 目标与第一性原理起点

服务器模式语义：把**服务器本机的系统播放声音**送到远程客户端（等价 mstsc 会话中的"在此计算机上播放"）。
不可再分约束：①rdpsnd 协议只允许服务器推 Wave2、客户端仅回 Confirm（无拉取消息）→ 推送方向唯一；
②客户端 sink 能力边界决定服务器能广告的格式；③多会话共享一台机器的声音源。

## 2. 客户端契约（服务器必须满足，逐条代码证据）

| 项 | 客户端行为 | 证据 |
|---|---|---|
| 谁先说话 | 客户端纯被动，等服务器 SNDC_FORMATS；Client 无 Start | `include/rtsc/channel/rdpsnd_client.h:8-13` |
| SNDC_FORMATS body | 固定 20B：dwFlags(4)+dwVolume(4)+dwPitch(4)+wDGramPort(2)+wNumberOfFormats(2)+cLastBlockConfirmed(1)+wVersion(2)+bPad(1)，后跟 AUDIO_FORMAT[] | `src/proto/rdpsnd.cpp` SndServerFormats::parse；`tests/test_rdpsnd.cpp:129-161` |
| AUDIO_FORMAT | 18B 固定 + cbSize 扩展 | `include/rtsc/proto/rdpsnd.h` SndAudioFormat::kFixedSize=18 |
| wVersion | 必须 ≥6 才触发客户端 QualityMode；=8 才走 Wave2 | `src/channel/rdpsnd_client.cpp:151`；客户端自报 8（`rdpsnd_client.cpp:16`） |
| 格式 | 只认 format_tag=1(PCM)；非 PCM → 客户端不回任何东西 | `src/channel/rdpsnd_client.cpp:198-228` |
| 位深/声道 | sink 拒 bits!=16 或 channels==0/>8 → 线程提前退出但仍标 started_（wedge） | `src/audio/audio_win32.cpp:125-151,89-124` |
| 选择优先序 | 44100/2ch=100, 48000/2ch=90, 44100/1ch=80, 任意2ch=50, 其他=40 | `src/channel/rdpsnd_client.cpp:205-216` |
| 客户端回复 | dwFlags=TSSNDCAPS_ALIVE\|VOLUME(0x3), volume=0xFFFFFFFF, 1 个格式, version=8 | `src/channel/rdpsnd_client.cpp:240-249` |
| Wave2 | formatNo 必须=0（客户端 min(formatNo,size-1)）；每包必回 WaveConfirm | `src/channel/rdpsnd_client.cpp:258-274,262-263` |
| WaveConfirm | sTimeStamp(2)+cConfirmedBlockNo(1)+bPad(1) | `src/proto/rdpsnd.cpp` BuildWaveConfirmBody |
| audioTimeStamp | 客户端解析但忽略 → 可填 0 | `src/proto/rdpsnd.cpp` SndWave2::parse |
| 训练包 | 可选，客户端回 TSSNDCAP_TRAINING 回显 | `src/channel/rdpsnd_client.cpp:168-179` |
| 分片 | 通道消息 = CHANNEL_PDU_HEADER + FragmentChannelMessage（1600） | `include/rtsc/proto/channel.h:71-73` |

## 3. proto 层缺口（实现前必须补）

- [ ] `BuildServerFormatsBody(...)`（服务器侧 SNDC_FORMATS 构造）——现仅有 `BuildClientFormatsBody`。
- [ ] `SndWave2::write()` / `BuildWave2Body(...)`——现仅有 parse。
- [ ] `BuildSndPdu(kSetVolume/kClose)` 复用现有 `BuildSndPdu`（已具备）。

## 4. 服务器状态机（拟）

`idle → (Start, 捕获成功) → await_client_formats --(收 formats 且 ALIVE)--> alive --(WaveConfirm 开窗)--> streaming --(Close/断连)--> closed`
- 捕获失败 → 不发 SNDC_FORMATS，通道静默，会话照常（FP1）。
- 客户端 ALIVE=0 或从不回 formats → 永久静默，不设超时（FP2）。
- 在飞窗口 max_inflight=8，满窗丢弃新音频不入队（FP3 防 DoS）。

## 5. 待双审裁决项（甲乙磋商中）

① formatNo 恒=0 ② 8-bit PCM 客户端 wedge 论证 ③ 自写 float→int16+DSP vs AUTOCONVERTPCM ④ enable_rdpsnd_capture 默认值 ⑤ test_server.cpp:2055 断言迁移。
