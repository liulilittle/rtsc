# RTSC 计划（plan.md）

## 目标
以 REA/Ghidra 对 mstsc.exe / mstscax.dll 的静态取证 + 官方规范 [MS-RDPBCGR] 为双重依据，
用 C++ 跨平台（Windows 优先，Linux 后续）重写 RDP 客户端。

## 依据来源优先级
1. 官方规范（权威）：[MS-RDPBCGR] / [MS-RDPEGDI] / [MS-RDPELE] / [MS-RDPEUDP] /
   [MS-CSSP] / [MS-NLMP] / T.123 / X.224 / T.125(MCS)
2. 二进制取证（REA+Ghidra 12.1.4 @ G:\sre）：mstscax.dll 实际实现与常量表
3. 真实抓包（pktmon + 本地 RDP 服务）：线上字节序验证

## 阶段

### P0 环境与基线 [x]
- [x] 工具链盘点：MSVC 14.44 / CMake 3.31.6 / Ninja 1.12.1 / Python 3.14 / Node 24 /
      Ghidra 12.1.4 + JDK21
- [x] 目标二进制盘点：mstsc.exe 10.0.26100.8875、mstscax.dll 9,166,848 B
- [x] REA provider 绑定 Ghidra（REA 6.7.0 setup + mcp.rea environment；doctor ghidra=healthy）
- [x] 工程骨架 + 四记忆文件（CMake/Ninja + verify.ps1）
- [x] TPKT / X.224 / RDP_NEG 编解码 + 流式切帧
- [x] BER 编解码接入构建并补测试（32 用例）
- [x] MCS/GCC 模板取证（`evidence/mstscax/gcc-ccrq.md`）+ `mcs.cpp` 实现（35 用例）
- 验证方式：`cmake --build` 零错误；`rtsc_probe --version` 可运行；`verify.ps1` 全绿

### P1 连接协商层 [x]
- [x] TPKT（T.123）编解码
- [x] X.224 CRQ/CCF/DR（Class 0）
- [x] RDP_NEG_REQ/RSP/FAILURE（含 requestedProtocols 位图、correlation info）
- 验证方式：单元测试（合法/边界/畸形/超长/截断）+ 与真实服务器交互
  （`evidence/handshake-001.md`）

### P2 MCS 层 [x]
- [x] BER/DER 编码器（GCC 结构）— 32 用例
- [x] Connect Initial / Connect Response + GCC CCRQ/CCRSP — 35 用例，逐字节匹配官方向量
- [x] Erect Domain / Attach User / Channel Join / Send Data / DPU — 39 用例
- [x] Client Info PDU（TS_INFO_PACKET）+ Security Exchange PDU — 30 用例，400B 官方向量往返
- [x] 连接状态机（X.224 → Connect Initial → Erect → Attach → Join → Client Info）— 26 用例
- [x] TPKT 流式分帧（半包/粘包/零长/重同步）— 11 用例
- 验证方式：`docs/spec/mcs-connect.md` + `docs/spec/mcs-domain.md` 的 17 个注解 dump 逐字节回归

### P3 安全层 [~]
- [x] 密码学原语：MD4/MD5/SHA-1/HMAC-MD5/RC4/UTF-16LE — 21 用例，
      RFC 1320/1321/3174/2202 与 [MS-NLMP] 4.2.1/4.2.2 官方向量全对
- [x] 许可阶段结构层（LICENSE_PREAMBLE / 8 消息 / RSA blob / L3 密钥派生与 MAC）
      — 47 用例，含 5 个官方 dump 逐字节回归
- [x] 许可状态机 LicensingMachine（[MS-RDPELE] 1.3）— 4 用例，含 RSA 加密 premaster 的私钥验证
- [~] TLS（PROTOCOL_SSL）— 依赖已解决：Windows 用 SChannel（零依赖，已实测）
      - [x] 方案定案：双后端 + 后端无关接口；Windows=SChannel，Linux=OpenSSL（后续）
      - [x] 真实服务器 TLS 1.2 握手实测（`evidence/schannel-probe.txt`）
      - [x] SPKI 导出实测 294B（`evidence/schannel-spki-probe.txt`）
      - [x] 进程内回环 E 级实测 PASS（`evidence/tls/loopback_schannel.out.txt`）
      - [x] `TlsTransport` 抽象 + SChannel 后端实现 + `tests/test_tls.cpp`
            （26 tests / 139 checks；`verify.ps1 -TlsRedTest` 8 变异全翻红；
              ctest 13/13；`/W4 /WX` 零警告）
      - [ ] TLS1.3 路径实测（回环对端仅 TLS1.2，票据分支未覆盖，见 impl-log I1）
- [~] CredSSP/NTLM（PROTOCOL_HYBRID / HYBRID_EX）— 服务器 192.168.1.7 强制此路径
      - [x] SHA-256（crypto 库新增，FIPS 180-4 向量 + 55/56/64 字节边界）
      - [x] TSRequest DER 编解码（§5.1/§5.2/§5.7，含服务器非规范 errorCode）
      - [x] NTLM 三消息（NEGOTIATE 40B / CHALLENGE 56B / AUTHENTICATE 88B，§6.1-§6.3）
      - [x] NTLMv2 响应 + MIC + SEAL（§6.5/§5.4.3，官方向量 4.2.2/4.2.3.4/4.2.4.4 全对）
      - [x] CredSSP 五步状态机 + pubKeyAuth v5/v6（§5.3/§5.4）
      - [x] TSCredentials（§5.5）
      - [x] 红证：16 变异（15 抓 / 1 编译期拒绝 / 0 漏）
- [x] 接入 ConnectMachine（新增 rtsc_security：SecurityLayer + ConnectionDriver，scripted TLS 驱动全流程测试全绿）
      - [x] 接收方向签名校验：CredSSP OpenReceive 校验 HMAC_MD5 与序列号（测试 tampered_signature_checksum_is_rejected 为证；impl-log C5 已过时）
      - [ ] 数据面签名（TS_SECURITY_HEADER，属 Standard RDP Security 路径，见下）
- [~] Standard RDP Security（RC4 + 密钥交换，PROTOCOL_RDP 兼容路径）
      - [x] 原始 RSA 原语 `RdpRsaEncryptClientRandom`（[MS-RDPBCGR] 5.3.4.1，Windows BCrypt）
            — 2 用例 / 271 检查，含往返验证
      - [x] 会话密钥派生 `DeriveRdpSessionKeys` + `RdpMacSignature`（5.3.5.1）
            — FreeRDP 交叉核对 + 独立 Python 差分
      - [x] 数据面 `RdpSecurityContext`：RC4 双向流 + MAC + 每 4096 包密钥更新（5.3.6/5.3.6.1）
            — 9 用例 / 26 检查，含 9000 包跨 2 次密钥更新边界同步
      - [ ] Security Exchange PDU 接入连接流程（目标服务器用 HYBRID_EX，此路径不触发）
- 验证方式：与 192.168.1.7 完成到 Client Info 的真实连接
  - [x] 实测（无凭据）：X.224 协商 + 真实 TLS 握手（3 轮，846/51 字节）+ CredSSP step 1 发送成功
        （`rtsc_connect 192.168.1.7 3389`；失败点在 NTLMv2 空凭据护栏）
  - [ ] 提供凭据后跑到 Client Info（批 5，需用户提供账号）

### P4 能力交换与核心数据 [x]
- [x] Client/Server Core Data、Security Data、Network Data、Client Info
- [x] 共享 PDU 头（TS_SHARECONTROLHEADER / TS_SHAREDATAHEADER / TS_SECURITY_HEADER 三态）
      — 规范 `docs/spec/share-data.md` 已就绪
- [x] Fast-Path 头与长度编码（action 低 2 位、length1/length2 大端）+ 7 种输入事件尺寸
- [x] Demand Active / Confirm Active（capability sets）— 35 用例，含越界防护
- [x] Deactivate All / Font List / Font Map / Synchronize / Control / PersistentKeyList — 19 用例
- [x] 会话建立状态机 SessionSetupMachine（capabilities.md §12 的 S0-S6）— 7 用例
      官方 4.1.12 Demand Active dump 驱动；Confirm Active + 最终化批 + Font Map 激活 + Deactivate All
- [x] 会话建立状态机 + 许可状态机接入 ConnectionDriver（全链路 scripted TLS 测试到 active）
### P5 图形与输入 [x]
- [x] FastPath 输入事件编码（键盘/Unicode/鼠标/扩展鼠标/相对鼠标/Sync/QoE）
      + `EncodeFastPathInputPdu`（fpInputHeader + length + 事件）— 10 用例 / 35 检查
- [x] Fast-Path 输出解析（TS_FP_UPDATE_PDU + TS_FP_UPDATE + 位图/调色板 payload）
      — 7 用例 / 32 检查
- [ ] SlowPath 输出解析（TS_GRAPHICS_UPDATE）
- [x] 位图解码未压缩路径 `DecodeRawBitmap`（8/15/16/24/32 bpp -> RGBA；自底向上 + 4 字节行补齐）
      + `BitmapCompressedHeader`（TS_CD_HEADER）— 6 用例 / 22 检查
- [x] 位图解码 Interleaved RLE `DecodeRleBitmap`（全部压缩序，8/15/16/24 bpp）— 6 用例
- [x] SlowPath 图形更新 `SlowPathGraphicsUpdate`（TS_GRAPHICS_UPDATE）— 3 用例
- [x] Surface Commands 分帧 `ParseSurfaceCommands`（TS_SURFCMD）— 5 用例
- [x] RDP 6.0 位图压缩分帧（`Rdp6FormatHeader` + `DecodeRdp6RleSegments`）— 8 用例
- [x] RDP 6.0 位图解码 ARGB 路径 `DecodeRdp6Bitmap`（平面组装 + RLE 行差分）— 5 用例
- [x] RDP 6.0 AYCoCg->ARGB 变换（含色度子采样上采样）— 3 用例
- [x] NSCodec 压缩位图流头 + RLE 解码（`NscHeader` + `NscRleDecode`）— 6 用例
- [x] NSCodec 解码 `NscDecodeBitmap`（色彩恢复 + 平面组装 + 子采样）— 4 用例
- [x] Cache Bitmap Rev2 绘制序 + 变长整数编码（`orders.h/.cpp`）— 6 用例
- [x] Cache Bitmap Rev2 绘制序 + 变长整数编码（`orders.h/.cpp`）— 6 用例
- [x] 虚拟通道 PDU 分帧 `ChannelPduHeader` + `ChannelReassembler` + `FragmentChannelMessage`
      — 7 用例 / 47 检查
- [x] cliprdr 剪贴板通道结构层（CLIPRDR_HEADER + Format List + Data Request/Response）— 7 用例
- [x] drdynvc 动态虚拟通道结构层（DYNVC_HEADER + 变长 ChannelId + 9 命令）— 7 用例
- [x] rdpdr 设备重定向通道结构层（RDPDR_HEADER + Server Announce + 11 PAKID）— 5 用例
- [x] rdpsnd 音频通道结构层（SNDPROLOG + 13 SNDC_* + Wave2）— 6 用例
- [x] Cache Bitmap Rev2 绘制序 + 变长整数编码（`orders.h/.cpp`）— 6 用例
- 验证方式：与真实 Windows 会话逐帧比对

### P6 平台抽象与 Linux [x]
- [x] POSIX 阻塞 TCP transport（`src/net/posix_transport.cpp`）+ CMake 平台分支
- [x] Linux 构建门禁通过（`scripts/linux-build-gate.sh`：32/32 测试，零警告）
- [x] Linux TLS 后端 OpenSSL 3.x（`src/net/tls_openssl.cpp`，RTSC_TLS_OPENSSL 选项）— 4 用例
      （Windows 33/33；Linux 默认 32/32；Linux+OpenSSL 33/33）
- [x] UI 表面 + 窗口抽象（`rtsc_ui`：Surface + Window + headless 后端）— 5 用例
- [x] Win32 窗口后端（`src/ui/window_win32.cpp`）— 1 用例
- [x] 图形合成管线 `rtsc_client`（proto 解码 -> ui::Surface，按 flags+bpp 选解码器）— 5 用例
- [x] X11 窗口后端（`src/ui/window_x11.cpp`，RTSC_UI_X11 选项）— WSL 实测真实创建窗口
- [x] Wayland 窗口后端（`src/ui/window_wayland.cpp`，RTSC_UI_WAYLAND 选项）— 四配置全绿
      （Windows 35/35；Linux 默认 34/34；Linux+X11 34/34；Linux+Wayland 34/34）

## 每阶段验收
- 单元/集成测试全绿；C0 编译零错误零警告
- 每条协议字段均标注来源（规范章节 或 REA Evidence ID）
- 真实服务器交互验证（本地 TermService 或外部主机）

- [x] P7 端到端集成：`Client`（driver+graphics+input）、`rtsc_gui` 工具、
      `test_client.cpp`——Windows 36/36，Linux 门禁 35/35
- [ ] 真机联调到 active session（需用户提供凭据；无凭据止于 CredSSP/NTLM）
- [ ] 真实服务器抓包比对 RDP6/NSCodec 解码（当前仅自造流验证）

- [x] 门禁目录累积（甲第7点）：`scripts/linux-build-gate.sh` 唯一化后 `.tmp/linux-gate.<pid>` 无界累积。
      已修：`cleanup()`→`rotate_logs()`（保留最近 5 个、不删目录）+ `trap cleanup EXIT`；`BUILD_DIR` 整体清。
      证据：`linux-build-gate.sh:60 rotate_logs()` / `:79 cleanup()` / `:83 trap cleanup EXIT`。
- [ ] 显式传参分支无 PID 唯一化（甲附加观察，可接受）：并发同传同一显式目录仍竞态；
      属调用方自选路径，文档注明即可。

- [ ] P1：Linux 门禁改在 WSL 原生 ext4 工作副本构建（避开 `/mnt/f` 9p 抖动），使 LINUX GATE PASS 作为绿证可信。
      判定约定：出现 `mkdir ... No such file`/`BUILD_EXIT=1` 但 `FAILED_COUNT=0` → 疑似 9p 抖动，复跑一次区分。
- [ ] 低：`linux-gate-logs.`（空后缀）会被当 PID 目录；同秒 mtime 下 `ls -1dt` 排序不确定（不影响有界性）。

## W11 主绘制 orders + ROP 引擎（进行中，双审计+执行三角色）

依据：[MS-RDPEGDI] 2.2.2.1（drawing orders）/ 2.2.2.2（order encoding）/ 2.2.2.2.1.1.1.7（ROP3 表）。
分层：`rtsc_proto`（纯协议解码，只链 `rtsc_crypto`）→ `rtsc_render`（订单应用，链 proto+ui）→ `rtsc_client`。

- [x] 判据1 B1：`ReadFourByteUnsigned` c=1/c=2 四分支（双审盖章，甲变异 6 处翻红）
- [x] 判据2a ROP2：`rop.h/.cpp` 16 码 RPN 差分（独立 `RpnEval`）+ 未知码恒等契约；6 tests/1188 checks；变异 4/4
- [x] 判据2b ROP3：`kRop3Table[256]`（§2.2.2.2.1.1.1.7 推导）+ `rop3_index_from_code`/`rop3_eval`/`rop3_apply_per_channel`；
      14 tests/22982 checks；变异 5/5
- [x] 判据3a：`OrderHeader` + `ParseOrderHeader`（fieldFlags 动态字段）+ `ui::Surface::SetPixel/Line`（Liang-Barsky+Bresenham）；
      orders 23/147、surface 15/928；变异 7/7
- [x] 判据3b：DstBlt/OpaqueRect/ScrBlt（ScrBlt 先快照源，重叠无拖影）；orders 34→35 tests/633→1113 checks；变异 4/4
      - [x] 分层整改：`Apply*` 从 `rtsc_proto` 迁至新建 `rtsc_render`（proto 恢复零 UI 依赖）；甲乙双审盖章
      - [x] ScrBlt 干净断言 `scrblt_overlap_right_shift_preserves_source_pixels`（96 像素逐像素，去快照变异断言 RED 非崩溃）
- [x] 判据3b2：PatBlt（限 `BS_SOLID`/`BS_NULL`）；`BrushExtra` 7B 仅 `BS_PATTERN` 且 fieldFlags 双向 fail-closed；
      `BS_SOLID` P=ForeColor；HATCHED/PATTERN→`kUnsupported` 不画错；44 tests/1342 checks；甲 4 变异全 RED
- [x] 判据3b3a：PatBlt `BS_HATCHED`(6 种) — `kHatch` 逐字取 FreeRDP `GDI_BS_HATCHED_PATTERNS`；**0=前景/1=背景**、MSB=最左；
      `hatch>0x05`→kUnsupported；49 tests/4179 checks；变异 3/3；甲独立 4 变异 RED
- [x] 判据3b3b：PatBlt `BS_PATTERN` — `pat[i]=brush_extra[6-i]`(顶行→倒数第2行)、`pat[7]=brush_hatch`(底行)、
      `(pat[py]>>(7-px))&1`；官方向量 `{0x02..0x80}`+`0x01` → **完整 8 主对角**；54 tests/4493 checks；变异 4/4；
      甲通过（其手算位映射误读 `>>(7-px)` 为 `>>px` 已更正）；主代理 Python 逐字复算确认 `is_full_diag=True`
- [~] 判据3c：`OrderEngine` + `graphics` 分派（M1/M2/M4/M5/M6）。已交付 63 tests/4569 checks；甲乙交叉核对：
      **D1（高，真缺陷）** PatBlt 的 `kNoOp`(BS_NULL/零负尺寸) 被计入 `unsupported` 且 `unsupported>0` 即 `break`
      → 同 PDU 后续订单全丢（甲乙各自独立红证 `applied=0 unsupported=1`）；修复中（拆 `noop`/`unsupported`/`unknown_order_type`，
      中止条件改 `truncated||failed>0||unknown_order_type`）；D2（applied=订单条数注释）、D3（default 注释与计数一致）、D4（拼写）一并修。
      规范已取：
      `TS_UPDATE_ORDERS_PDU_DATA` = shareDataHeader(18B) + updateType(2B)=0x0000 + pad2OctetsA(2B) + **numberOrders(2B)**
      + pad2OctetsB(2B) + orderData；`DRAWING_ORDER` = controlFlags(1B) + orderType(**仅 TS_TYPE_CHANGE 时存在**)
      + fieldFlags(变长) + bounds(仅 TS_BOUNDS 且非 TS_ZERO_BOUNDS_DELTAS) + primaryOrderData。
      controlFlags：`TS_STANDARD 0x01`(必须)/`TS_BOUNDS 0x04`/`TS_TYPE_CHANGE 0x08`/`TS_DELTA_COORDINATES 0x10`/
      `TS_ZERO_BOUNDS_DELTAS 0x20`/`TS_ZERO_FIELD_BYTE_BIT0 0x40`+`BIT1 0x80`(末尾全零 fieldFlags 字节省略计数)。
      另含 `OrderBodyState` 注释补「字段回写经 helper 引用参数」
- [x] 判据3d-1/2：secondary 头（`orderLength+13`，实际长度）+ 未知 secondary 按长度跳过 + `CACHE_BRUSH_ORDER` 入缓存 +
      `TS_CACHED_BRUSH` 解析（`BrushCacheView`，仅 BMF_1BPP；未命中→kUnsupported 不中止）；84 tests/4697 checks；变异 4/4；
      ALTSEC（仅 TS_SECONDARY，1 字节头）**fail-closed**（`ParseSecondaryOrderHeader` 拒斥；曾是真缺陷，已修）
- [x] 判据3d-3：`COMPRESSED_COLOR_BRUSH`（4 色压缩）——`ClassifyBrushForm`（`BMF_1BPP`→mono；`bytes==16+4*bpp`→4 色压缩；
      `bytes==64*bpp`→未压缩；其它→`InvalidField`）；`P1..P64` 2bit/像素（P1=最高 2 位）+ 行反转；颜色表 0..3→color1..4；
      打包 8BPP→kUnsupported(无调色板)/16BPP R5G6B5/24BPP RGB/32BPP RGB；103 tests/5793 checks；变异 3/3 RED；双审盖章 ✅
- [x] 判据3e：`orderSupport` 对齐 —— 索引是**协商索引**（非 orderType）：`{0x00 DstBlt, 0x01 PatBlt+OpaqueRect, 0x02 ScrBlt}`；
      原 `{0x00,0x01,0x02,0x03,0x04,0x0A,0x0B,0x1C}` 含 MemBlt/Mem3Blt/SaveBitmap **虚假声明**已删；
      `SOLIDPATTERNBRUSHONLY` **裁定不置位**（hatched 已实现、缓存画笔仅 1BPP、unsupported 不中止）；
      capabilities 39 tests/274 checks；变异 M1/M2/M3 + E1/E2/E3 全 RED；双审盖章
- [x] 判据3f：**slow-path orders 分派** —— 新增 `ParseOrdersUpdateBody`（`kBodyHeaderSize=6`、从 `pad2OctetsA` 起，
      fast/slow **共用**同一 body 解析与 4096 上限）；`graphics.cpp:100-114` slow 分支传 `update_data.data()`（**无 +2**）→
      `order_engine_.Apply`；`graphics.h:59` **单一 `order_engine_`** 被 fast/slow 共用（跨 PDU 状态一致）；
      `capabilities.h` 常量补「仅测试防回归」注释。orders **87 tests/4712 checks**、graphics **7 tests/44 checks**；
      变异 M1/M3 经甲在真实套件复现 RED；双审盖章 ✅
- 验收：每判据 = 两审计独立 + 执行 TDD + 变异反证 + C0 双平台 + 指纹；双审一致盖章方为通过


## 真机联调（2026-10-25，凭据由用户提供）

- **凭据**：账号 `MicrosoftAccount\windowsvipcuv@live.cn`，密码 `yy520o!!`（**两个 `!`**；最初少一个 `!` 导致 `0xC000006D`）。
  目标 `192.168.1.7:3389`（Windows 11 22H2，机器名 `DESKTOP-5BFDKO3`）。
- **到达阶段**：X.224 → MCS → TLS → CredSSP（NTLMv2+MIC+CBT）→ **Client Info PDU sent**（`rtsc_connect` exit 0）；
  `rtsc_gui` → `session active` + 数帧渲染。
- **CredSSP 修复（双审盖章）**：`security_layer.cpp:268-283` `complete()` 分支**补发 `BuildStep5` 的 step 5(authInfo)**
  （原直接等 EUAR → 死锁 → 服务器关闭）。
- **BitmapCacheRev2 修复（双审盖章）**：`BitmapCacheRev2CapabilitySet` 固定 **40 字节**（原 19 字节，漏 `Pad2`/`Pad3`）。
- **真机现象**：active 后服务器发 `SetErrorInfo(ERRINFO_NONE=0)` → `SaveSessionInfo` → VC PDU → **关闭**，**从不发位图**（表面全黑）。
  - 审计结论：**post-active 断连在服务器侧**（客户端已正确到达 active；疑 **Windows 11 Home 不支持 RDP 宿主**）。
  - 客户端真实缺口（已修）：**静态 VC（rdpdr/cliprdr/rdpsnd）未按 `channel_id` 分派**（原被图形层吞掉）；
    已加 `SetChannelHandler` + 按 `McsSendData::channel_id` 分派，且 handler **收 `sd.user_data`**（`channelPduHeader` 在其内）。
- **用户可执行验证**：① 服务器 → 设置→系统→关于 → **Edition**（Home 不支持 RDP 宿主）；
  ② 服务器事件查看器 `TerminalServices-LocalSessionManager`；③ 系统自带 mstsc 连同一服务器对照；④ 换 Win11 Pro/Enterprise 复测。
- **证据**：`docs/real-server-investigation.md`（调查报告）、`scripts/real-server-test.ps1`（就绪脚本，凭据从环境变量读入）。
- **当前 C0**：Windows `ctest` 37/37；Linux 门禁 PASS 36/36；`rtsc_orders_tests` 103/5793；`rtsc_security_tests` 16/118；
  `rtsc_capabilities_tests` 41/310。


## 收尾（2026-10-25）

- **目标关闭（complete）**：真机 `192.168.1.7` 端到端到 **active session 并渲染桌面**（`1301681 non-black / 22 colours / 30 frames`）。
- **根因链（5 处客户端缺陷 + D）**：B1 `extra_flags=0x0001`；B2 fast-path 剥离；B3 `kHeaderSize=18`；B4 RLE 线性；B5 输入经 `SendPdu`；D `SPECIAL_FGBG` 隐式 mask —— **双审盖章**。
- **C0**：Windows 37/37；Linux 门禁 PASS 36/36。
- **非阻断盲区**：FGBG run>8 mask 分段 / MEGA_MEGA 变体 / headless 有界退出验收一致性。
- **后续可选**：① 修盲区；② 完整 VC 协议；③ 扩 Android/其它平台。


## 项目愿景（2026-10-25 用户明确）

- **「我们不要急，但我们要做好，保质保量，说白了这个就是开源版本的远程桌面。」**
- → 目标 = **开源版远程桌面**：**客户端模式 + 服务器模式**（服务器模式是核心，因 **Windows 家庭版不能作为 RDP 宿主**，必须自己逆向实现）。
- **节奏**：**不赶进度**（用户预期**一个月**），**保质保量**：维持质量门（两审计独立 + 变异反证 + C0 双平台 + 指纹），做**彻底**的逆向/研究/实现与审计。
- **已达成**：客户端 → 真实 Win11 Pro 服务器 → **active session 并渲染桌面**（最难的第一步）；缩放/自动伸缩已实现。
- **在途**：RDP 服务器基础层；rdpsnd 音频；窗口未响应/输入修复。
- **后续**：完整 VC 协议（cliprdr/rdpdr/rdpsnd/drdynvc）、多显示器、RAIL、RD Gateway、性能基准。


## mstsc 功能/体验对齐清单（逐项推进依据，2026-10-25）

**用户原话**：「我们逐个推进把所有的细节所有点全部做好，夯实把易用性拉曼。我喜欢微软的远程桌面，但我不喜欢微软的态度。」
→ 目标：**体验对齐 mstsc，但开源实现**；**逐点做透、易用性夯实**。

### A. 连接与安全
- [ ] 主机/端口/域/用户；**保存凭据**（等价 cmdkey / RDP 文件）；**RDP 文件导入/导出**
- [ ] NLA（CredSSP/NTLM）、TLS（SChannel/OpenSSL）、Standard RDP Security、许可（自建）
- [ ] **RD Gateway（TS Gateway）**、服务器身份验证级别、证书校验（当前 kInsecure，应可配）
- [ ] 智能卡 / Kerberos（域）

### B. 显示
- [ ] 分辨率、全屏、**智能缩放（smart sizing）**、**多显示器（/multimon、span）**、缩放（连续）
- [ ] 色深（8/15/16/24/32）、字体平滑、桌面合成、视觉样式
- [ ] 帧率/画质（连接质量自适应）、持久位图缓存

### C. 本地资源（虚拟通道）
- [ ] **剪贴板（cliprdr）**：文本/文件/位图
- [ ] **驱动器重定向（rdpdr）**：磁盘/打印机/串口/智能卡
- [ ] **音频（rdpsnd）**：远程播放/本地播放/重定向；麦克风；摄像头；**USB 重定向**
- [ ] 动态虚拟通道（drdynvc）

### D. 输入与快捷键
- [ ] 键盘（含布局）、鼠标、相对鼠标、滚轮、触摸
- [ ] **快捷键**：Ctrl+Alt+End（等价 Ctrl+Alt+Del）、Alt+Tab、Win 键、全屏切换、连接栏
- [ ] 输入坐标**逆映射**（缩放/平移后仍命中正确远程坐标）

### E. 会话
- [ ] **多会话/多用户**（独立或共享桌面）
- [ ] 会话影子（shadow）、管理员模式（/admin）、span 模式
- [ ] **断线重连**、网络自动检测

### F. 命令行与易用性
- [ ] `mstsc` 等价参数：`/v:` `/admin` `/f` `/w` `/h` `/span` `/multimon` `/public` `/edit` `/migrate`
- [ ] **连接栏**（全屏时悬浮）、**截图**、状态显示、错误提示可读
- [ ] 音频/画质/带宽自适应；**性能基准**（吞吐/延迟）

### G. 服务器模式（开源解禁）
- [ ] 独立 RDP 服务器（家庭版可用）；多用户并发；桌面来源（控制台抓取 vs 虚拟桌面）；自建认证/许可


## 方法论（2026-10-25 用户明确）：**全逆向重做**

- **用户原话**：「微软不是想要限制 RDP 吗，开源现在的 XRDP 也是逆向出来的，但是我们偏不，我们要给它全逆向重新做出来。」
- **定位**：不是「用现成开源」（xrdp 也是逆向产物），而是**从二进制全逆向、重新实现** RDP 客户端 + 服务器。
- **绕开微软限制**：Windows **家庭版禁用了 RDP 服务器** → 我们必须**自己实现服务器**（含桌面来源、认证、许可），使**任意 Windows 版本都能作为 RDP 宿主**。

### 服务器逆向目标（REA 取证）
- `termsrv.dll`（Terminal Services 服务）、`rdpdd.dll`（RDP 显示驱动）、`win32k.sys`/`win32kfull.sys`（桌面/窗口）、
  `termsrv` 服务、`TSConnection`/`RDPWD`（监听）、`rdpwsx`、`termdd`、`ntmssvc`；
- 客户端逆向目标：`mstsc.exe` / `mstscax.dll`（已完成大部分）。
- **方法**：REA（Ghidra/反编译/取证）+ 规范（[MS-RDPBCGR]/[MS-RDPE*]）+ 真实抓包（pktmon/Wireshark）三重依据。

## 当前批次 N8（2026-10-28）：客户端通道接线补全 + 服务器模式路线

阶段（状态 [ ]/[~]/[x]；每阶段写明「做了什么」+「怎么验证」）：

### N8-0 已提交改动的补审盖章 [~]
- [~] S4 客户端输入扫描码转发修复（原把 wParam VK 虚拟键码当 set-1 扫描码转发，'A'→F7）——审 src/ui/window_win32.cpp 键盘路径。
- [~] S5 RDP6 planar bottom-up 镜像修复——审 src/proto/rdp6.cpp 行序（RLE/raw 一致性、delta 链语义、重钉 4 个期望是否掩盖缺陷）。
- 验证方式：两审计独立出结论（路径:行）→ 互审磋商 → 双方一致方可盖章；审毕由主代理独立复跑 ctest 51/51 + build 零警告。

### N8-1 客户端虚拟通道接线缺口 [~]
- [~] S1 Gateway（TS Gateway）：src/proto/gateway.cpp + src/net/gateway_transport.cpp **全库零调用点**（死代码）→ 接线 GUI/Client。
- [~] S2 rdpusb：src/channel/rdpusb_client.cpp + src/usb/usb_win32.cpp **全库零调用点** → 接线。
- [~] S3 rdpdr：tools/rtsc_gui/main.cpp:377 仅计数回调，真实 RdpdrClient 未接线 → 接线（设备列表→DeviceAnnounce→DeviceReply→handle 读写）。
- 验证方式：每项先红（补接线前的失败断言/真机统计为 0）后绿；真机统计必须出现对应计数（cliprdr data_req/data_resp>0、rdpdr 设备列表出现、gateway 握手阶段推进）；单测 + ctest 全绿 + Linux 门禁 PASS。

### N8-2 实网交互验证补测 [~]
- [~] P1 剪贴板实际数据往返（远端 notepad 复制 → 本地 Get-Clipboard；反向 Set-Clipboard → 远端粘贴）；当前会话 A 统计 remote_lists=0/data_resp=0 → 仅能力交换。
- [~] P2 扫描码实网验证（远端敲 'a' 必须出字母 a，不得 F7）。
- [~] P3 rdpdr 接线判定；P4 音频播放方向（远端播放 vs 本地回放）；P5 化妆项（test_rdp6.cpp 重复注释块 + 尾换行）。
- 验证方式：证据 = evidence/interaction-batch/v2/*.log 统计行 + 截图；GUI 会话 Alt+F4 收完整统计。

### N8-3 服务器模式（家庭版解禁 + 多远程用户）路线定案 [ ]
- [ ] 审计产出：会话并发模型缺陷、DesktopSource 控制台捕获与并发竞态、可复用资产盘点、≥2 条实施路线对比。
- [ ] 定案后派执行 AI（TDD），验收含：≥2 并发客户端互不干扰（资源所有权/单写者）、断连清理幂等、真机/本地回环验证。
- 验证方式：并发回环测试（2 客户端同时接入）+ 桌面来源真机抓取实证 + ctest/Linux 门禁。

### N8-4 收尾
- [ ] 用户目验 32bpp 画质（rtsc_gui vs mstsc）；性能基准复测（吞吐/延迟/并发度换算）；多显示器实网。

### N8-EXEC-1 定案（2026-10-28，组A 双审终报 v3 盖章后）
组A（甲 ses_e8150e480ffeaYVZn590wi4msC / 乙 ses_e814fe0b5ffeuO6b2N44YXBEL5）3 轮互审收敛，乙章 v3 为最终口径：
- **S6 剪贴板 阻断**：src/channel/cliprdr_client.cpp:309-316 Start() 发送 kMonitorReady（[MS-RDPECLIP] 2.2.2.2 明写 Monitor Ready 是 server→client）→ 方向+时序双反；1.3.2.1 序列应为 ①server CAPS ②server MONITOR_READY ③client CAPS ④client TEMP_DIR ⑤client FORMAT_LIST ⑥server FORMAT_LIST_RESPONSE；OnPdu(:91-117) 缺 kMonitorReady/kFormatListResponse 分支 → 裁决不可观测；客户端从不发 TEMP_DIRECTORY。
- **S3 rdpdr 高危（安全）**：S3-7 路径穿越 src/channel/rdpdr_client.cpp:333-363（无 .. 消解/越界校验）；S3-8 读缓冲无上限 src/rdpdr/file_system.cpp:171（服务器可控 4GiB）；S3-9 覆盖不截断 file_system.cpp:149-156 + rdpdr_client.cpp:214-215；另 S3-7' DR_CREATE 忽略 DesiredAccess（rdpdr_client.cpp:213-215）；S3-2 初始化顺序偏离 MS-RDPEFS（Capability Response 推迟到 :153-167）；S3-4 Device List Remove(0x444D) 未实现。
- **S2 rdpusb 阻断**：drdynvc 未请求(main.cpp:161,163)、rtsc_urbrdc/rtsc_usb_win32 未链接、URB 数据通路双向丢数据(rdpusb_client.cpp:350/468-500)、S2-11 drdynvc 串包(drdynvc_client.cpp:113-119)、S2-10 QI/IFACE_RELEASE 缺失、CompleteUrb 恒 hresult=0 且设备未知不发 URBCOMPLETION(:509-542)。
- **S1 Gateway 阻断**：零接线 + 现有实现是 HTTP CONNECT 代理而非 [MS-TSGU] 3.3.5.1 的 RDGSP(401 挑战/TLS/RDG_OUT_DATA)；Host 头写死路径(gateway.cpp:197)；cookie 硬编码(main.cpp:144)。
- **可盖章**：S4 扫描码本体（window_win32.cpp:321-329）✅（后续项：AltGr 修法=抑制伪 Ctrl+转发右 Alt 0x38 extended；MapVirtualKeyW 返回 0 无守卫；test_ui.cpp:215-220 early-return 空跑）；S5 RDP6 planar 镜像修复 ✅（不改实现，只补奇数高度+2x2 子采样向量测试）。
- **执行顺序硬约束**：①S3 安全三项必须先于/同批于 rdpdr 接线；②S2-11 串包修复必须与 S2 接线同批；③S2-P7(FunctionId 有无)先取证再改；④S6 与 S4-AltGr 进第一批红用例。
- **撤回判据（禁据此改码）**：A1 DR_OPEN_FILE 的 Information 映射（rdpdr_client.cpp:44-50 正确）；A2 RIM_EXCHANGE_CAPABILITY_RESPONSE body=8B（rdpusb.cpp:63-69 正确）；A3 原「FunctionId 必须=0x01」。
- **假绿清单 F1-F8**：gateway 20/106 全绿但 MockGateway 只回 CONNECT 200；session_info 断言硬编码「没有在使用中」；test_ui early-return；rdp6 合成测试自证式；rdpusb/rdpdr 全绿但 GUI 未链接；gateway 测试链接图≠生产图；test_gateway 不断言 Host。

执行分组（互不共享会话，各自 TDD）：
- **EXEC-A（S6 剪贴板）**：src/channel/cliprdr_client.cpp + include/rtsc/channel/cliprdr_client.h + tests/test_cliprdr.cpp。
- **EXEC-B（S3 rdpdr 安全三项+DesiredAccess）**：src/channel/rdpdr_client.cpp + src/rdpdr/file_system.cpp + 对应测试。**待 EXEC-A 或 C 释放配额后派发**。
- **EXEC-C（服务器 H 类崩溃/DoS）**：src/server/server.cpp + include/rtsc/server/server.h + tools/rtsc_server/main.cpp + 服务器测试。H-1 无上限 CS_CORE 宽高(16GB 分配)+线程无 try/catch(bad_alloc→TerminateProcess 杀全进程)；H-2 SendFrame y uint16 回绕(server.cpp:1117，实测 1400x65535 吐 1.07GB 且死循环)；H-3 零宽→chunk_row=0→server.cpp:1111/:1112 除零(0xC0000094)；H-4 会话对象永不回收+明文凭据驻留(:1411/:1450)。
- **EXEC-D（S2-11 drdynvc 串包 + S4-AltGr + S5 向量测试）**：后续批。

### N8-EXEC-2 定案：测试纪律欠账闭合（EXEC-D）
针对「先改实现、后重钉期望」纪律违规（见 .opencode/discover.md 同日条目）与组A乙的 S5-a/S5-b 要求：
- **D1 真机向量方向断言**：以仓库已入库的**真机捕获**字节（rdp6 513B / 1320B tile）构造方向断言——先有捕获向量，再写期望；禁止用与实现同源的假设造流。
- **D2 奇高 + 2x2 色度子采样向量**：钉死亮度/色度两平面行序一致性与 AYCoCg 采样坐标（审计要求，不改实现）。
- **D3 扫描码映射可测化**：把 lParam→set-1 扫描码的映射抽为可单测的纯函数，补确定性红绿用例（不依赖交互桌面），并补 MapVirtualKeyW 返回 0 的守卫（关闭 S4-b）。
- **D4 跳过语义显式化**：tests/test_ui.cpp:212-220 的 early-return 假绿源改为显式可见的跳过/失败判定，不得静默通过（关闭 F3）。
- 验证方式：全部为**先红后绿**的确定性用例（无需 GUI/真机）；ctest -C Release 全绿 + build 零错误零警告；S5/S4 后续项据此复审盖章。

## N9 阶段：按 mstsc 出厂二进制系统性对齐（用户 2026-10-28 指令）

**原则**：规范（[MS-RDPBCGR] 等）只规定"必须怎样"；**微软实际实现的选择**（滤波器、常量、顺序、默认值、降级路径）只能以出厂二进制为准。凡"我认为 mstsc 是 X"而无二进制/抓包证据的断言，一律视为缺陷（已发生 4 次：planar 行序、cliprdr 方向、drdynvc 裸 DATA、缩放插值）。

**工具链**：REA 6.7 + Ghidra 12.1.4，目标 `C:\Windows\System32\mstscax.dll`（sha256 前缀 d73c76d65721043c，PDB mstscax.pdb）与 `mstsc.exe`（1,114,112 B）。证据以 REA evidence_id + 函数地址 + 伪代码片段留档，可复现。

### 对齐队列（按用户可感知影响排序）
- [~] **A1 缩放/插值**（进行中）：二进制事实=1:1 用 BitBlt(SRCCOPY)，其余（含整数倍）一律 StretchBlt + `SetStretchBltMode(4)`(HALFTONE) + `SetBrushOrgEx(0,0)`；状态来自属性 `EnableSmartSizing`/`ZoomLevel`(100)。当前代码 1:1 正确，**整数倍最近邻、非整数倍双线性**与二进制不符。取证：FUN_18003444c / FUN_180191d30 / FUN_1804cfb98。
- [ ] **A2 输入与快捷键**：`keybd_event` 10 个调用点、`SendInput` 4 个、`SetCursorPos` 7 个、`MapVirtualKeyW` 126 个 → 逐个定位 mstsc 的快捷键表（Ctrl+Alt+End / Alt+Tab / Win 键 / 连接栏 / 焦点切换），核对我们的 keymap 与 AltGr 处理。
- [ ] **A3 位图解码与绘制**：32bpp RDP6 planar 已按 FreeRDP 对齐；仍需核对 8/15/16/24bpp、Bitmap Cache Rev2、order 引擎（ROP3/PatBlt/ScrBlt）与 mstsc 实际路径。
- [ ] **A4 剪贴板 cliprdr**：已按 [MS-RDPECLIP] 修正方向/时序；需确认 mstsc 在该规范之外的实际偏差（尤其 TempDir、长名协商、文件剪贴板 CF_HDROP）。
- [ ] **A5 音频 rdpsnd**：格式协商默认值、wave2、训练包、与 mstsc 的差异。
- [ ] **A6 智能缩放/自适应**：`EnableSmartSizing` 的确切语义（窗口缩放时保持纵横比的方式、何时用 HALFTONE 的快速路径 FUN_180036ba0）。
- [ ] **A7 连接栏/全屏/多显示器 UI 行为**：mstsc.exe 侧的窗口管理。
- [ ] **A8 服务器模式**：mstsc 无服务器实现，另以 termsrv.dll/rdpdd.dll 为取证目标（本阶段不做）。

**每项流程（强制）**：①定问题 → ②二进制取证（函数地址 + 伪代码 + 交叉佐证）→ ③写成可复核证据条目 → ④先写失败测试（期望值来自②，禁止用生产输出当期望）→ ⑤最小实现 → ⑥双审独立复验（含变异反证）→ ⑦盖章提交。

## 【纪律升级】工程性质 = 逆向工程（用户 2026-10-28 裁定）

- 一切对齐工作以**反汇编证据为准**；无证据的「我认为 mstsc 是 X」一律视为缺陷。规则全文见 `.opencode/memory.md` 同日条目。
- **流程强制**：取证 → 证据条目（`docs/spec/<area>-evidence.md`）→ 先红测试（期望来自证据）→ 最小实现 → 双审独立复验（含变异反证）→ 盖章提交。
- **禁止**：改实现后重钉期望；用生产输出当期望；在注释写无证据的「mstsc 行为」。
- **当前取证基线**：mstscax.dll d73c76d6…；缩放 = HALFTONE（`FUN_18003444c`）；输入 API 调用点已计数待定位。
