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

## 6. 主代理独立核查（对甲乙分歧的事实取证）

1. **客户端无 phase 门**（裁决争议1）：`src/channel/rdpsnd_client.cpp:159-166` OnWave2 直接 parse→PlaySample，**不检查** training/quality 阶段是否完成；`OnPdu` 无状态机（:75-103）。→ 结论：客户端收到 Wave2 就会播，Training 顺序对**本客户端**不构成硬门；但规范 3.3.5.1.1.4 顺序要求应遵守（mstsc 互操作保真）。v1 应发 Training+收 Confirm 再开流（甲口径），但这是"协议正确性"而非"客户端兼容必需"。
2. **D12 客户端 wedge 真缺陷**（核实）：`src/audio/audio_win32.cpp:110` OpenDeviceLocked 失败 → `return` 退出 Worker，但 `:69-70` 已置 `started_=true`；此后 Submit 的 `start_thread=!started_` 恒 false → 永不再起线程 → 永久静默，且 `thread_` 为已结束线程（析构时 join 需检查 joinable）。成立，纳入修复。
3. **Wave2 无 write**（核实）：`include/rtsc/proto/rdpsnd.h` 只有 `SndWave2::parse`，无 write/BuildWave2Body；`SndServerFormats` 只有 parse，无 server 方向 builder → proto 缺口确认。
4. **Training 可由服务器复用**：`BuildSndPdu(kTraining, body)` 已可用（`src/proto/rdpsnd.cpp`），只需 body = wTimeStamp+wPackSize。

## 7. 定案（双审联署，2026-10-28）— 主代理采纳

甲乙三轮互审后完全一致，主代理定案如下（执行依据）：

### 7.1 接口与状态机
- 新 `include/rtsc/channel/rdpsnd_server.h` + `src/channel/rdpsnd_server.cpp`。
- Phase：`kIdle → kAwaitClientFormats → kAwaitTrainingConfirm → kReady → kClosed`。
- `Start()`（幂等，捕获成功才发 SNDC_FORMATS）、`OnChannelData()`（处理 client formats/quality/train-confirm/wave-confirm）、`Poll(now)`（每 tick，`next_audio_due` 20-50ms 排空源）、诊断计数仿 rdpdr_server。
- 在飞窗口 max_inflight=8 块（≈160ms），满窗**丢新块保旧块连续**；流态不设 ACK 超时。
- **协商态超时**：await-formats/await-quality/await-train-confirm 各有 deadline（默认 5s，可注入配置，单测 50ms）；超时 → SNDC_CLOSE + 释放源订阅。

### 7.2 协议契约（byte-exact）
- 服务器 SNDC_FORMATS：v8 + 单格式 PCM16 ≤2ch 原生率 + cLastBlockConfirmed=0，body=BuildClientFormatsBody(0x1,0,0,0,8,{fmt})（布局同构复用）。
- AUDIO_FORMAT 字节：`01 00 02 00 44 AC 00 00 10 B1 02 00 04 00 10 00 00 00`（44100/2ch/16bit, avg=176400, align=4）。
- Wave2：formatNo=0、blockNo 首=1 后续 &0xFF、timeStamp=ms&0xFFFF、audioTimeStamp=0、data≤65535-12、1600B 分片。
- Training：发空 body（wPackSize=0）→ 收 Confirm → kReady（规范 3.3.5.1.1.4 顺序；在库客户端无 phase 门，不构成挂死风险）。
- D13 字节契约：nAvgBytesPerSec=rate*ch*2、nBlockAlign=ch*2。

### 7.3 音频源抽象
- `rtsc::audio::AudioCaptureSource`：Start/Stop/Poll/ok/format（对称 AudioSink）。
- v1：正弦源（平台中立，确定性 CI）+ 每会话独立源实例（工厂注入 seam，仿 SessionThreadLauncher）。
- B2：WASAPI loopback 同 seam 后端；共享广播总线仅 B2 设计约束（多路 loopback 未验证 W5）。

### 7.4 接线
- `server.cpp:974-1014` 加 "rdpsnd" 名解析 + `rdpsnd_channel_id_`；`:985-986` 复位。
- `RdpSession` ctor 仿 `:576-582`（有源工厂才建 handler）；ActiveLoop Start 序 cliprdr→rdpdr→rdpsnd + 分发分支；SendMcsUserData 加密路径复用。
- `ServerConfig.enable_rdpsnd=true` 默认（无源不建 handler → 零可观察默认变化）；`audio_source_factory` 注入 seam；`rtsc_server/main.cpp --audio` 默认关（隐私默认关门）。

### 7.5 缺陷清单（全认）
D1 名表缺 rdpsnd；D2 ActiveLoop 无分支；D3 无 rdpsnd_server + CMake 未链；D4 无 enable/源注入；D5 proto 缺 Wave2 write/Training builder/WaveConfirm·QualityMode·TrainingConfirm parse；D6 cBlockNo 初值+回绕；D7/D11 协商超时；D8 test_server.cpp:2055 注释；D9 音频泵；D10 并发契约；D12 客户端 wedge（独立修复项：started_ 复位+重开）；D13 mstsc 互操作字节契约；D14 main.cpp 开关；D15 rdpsnd-evidence 真机根因闭环。

### 7.6 验收
- 新 `rtsc_rdpsnd_server_tests`（字节契约/窗口/cBlockNo/协商超时/畸形/ALIVE=0）+ 新 `test_server_rdpsnd_e2e`（正弦源+树内 RdpsndClient+MockPlayer：wave_confirm==wave2、多会话双客户端同收）。
- 四变异红证：①S2 提前发 Wave2；②删 cBlockNo 初值规则；③改 formats 字节；④删协商超时。
- 影响面：server/multisession/cliprdr_e2e/rdpdr_e2e/gui_send/rdpsnd/rdpsnd_client/server_security/rdp_standard_security；禁跑 gateway 完整套件；C0 零错零警告。
