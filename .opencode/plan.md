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
- [x] **A1 缩放/插值**（完成 5b1e00a；双审 + F1 整数除修复 + 性能达标）：二进制事实=1:1 用 BitBlt(SRCCOPY)，其余（含整数倍）一律 StretchBlt + `SetStretchBltMode(4)`(HALFTONE) + `SetBrushOrgEx(0,0)`；状态来自属性 `EnableSmartSizing`/`ZoomLevel`(100)。当前代码 1:1 正确，**整数倍最近邻、非整数倍双线性**与二进制不符。取证：FUN_18003444c / FUN_180191d30 / FUN_1804cfb98。
- [x] **A2 输入与快捷键**（完成 959aaa7/fb20d65；双审驳回后修复：SAS/Pause/X键/NumLock/capture/坐标）：`keybd_event` 10 个调用点、`SendInput` 4 个、`SetCursorPos` 7 个、`MapVirtualKeyW` 126 个 → 逐个定位 mstsc 的快捷键表（Ctrl+Alt+End / Alt+Tab / Win 键 / 连接栏 / 焦点切换），核对我们的 keymap 与 AltGr 处理。
- [~] **A3 位图解码与绘制**（bitmap-evidence 已建；planar 解压器定位；ClearCodec/Progressive 暂缓=无样本可验）：32bpp RDP6 planar 已按 FreeRDP 对齐；仍需核对 8/15/16/24bpp、Bitmap Cache Rev2、order 引擎（ROP3/PatBlt/ScrBlt）与 mstsc 实际路径。
- [x] **A4 剪贴板 cliprdr**（cliprdr-evidence + FILECONTENTS 方向A/B 双审 d29ec55+b09c4cf；服务器侧 ea925c2；DATA_CHANNEL 二期）：已按 [MS-RDPECLIP] 修正方向/时序；需确认 mstsc 在该规范之外的实际偏差（尤其 TempDir、长名协商、文件剪贴板 CF_HDROP）。
- [x] **A5 音频 rdpsnd**（rdpsnd-evidence；真机 server_formats=0=服务器策略非缺陷；TSSNDCAPS 需抓包裁决）：格式协商默认值、wave2、训练包、与 mstsc 的差异。
- [x] **A6 智能缩放/自适应**（裁定 FUN_18003444c=门控缩放；实现 3414ece 双审；EnableSmartSizing=0→1:1）：`EnableSmartSizing` 的确切语义（窗口缩放时保持纵横比的方式、何时用 HALFTONE 的快速路径 FUN_180036ba0）。
- [x] **A7 连接栏/全屏/多显示器 UI**（multimon-ui-evidence；mstsc.exe=薄壳；全屏/多屏已实现双审 296fcfd）：mstsc.exe 侧的窗口管理。
- [~] **A8 服务器模式**（自研 RdpServer：桌面渲染✓ 剪贴板✓ 多会话并发✓ rdpdr 握手实施中；不依赖 termsrv→家庭版天然可用）：mstsc 无服务器实现，另以 termsrv.dll/rdpdd.dll 为取证目标（本阶段不做）。
  - [~] A8-a 输入注入（P0）：滚轮单位/9 位二补码/HWHEEL/clamp 修复执行中（round 793）；
    注入器设计由双审取证（round 793，`docs/spec/input-injection-{evidence,seam}.md`），默认 off + 显式 `--allow-input`。

**每项流程（强制）**：①定问题 → ②二进制取证（函数地址 + 伪代码 + 交叉佐证）→ ③写成可复核证据条目 → ④先写失败测试（期望值来自②，禁止用生产输出当期望）→ ⑤最小实现 → ⑥双审独立复验（含变异反证）→ ⑦盖章提交。

## 【纪律升级】工程性质 = 逆向工程（用户 2026-10-28 裁定）

- 一切对齐工作以**反汇编证据为准**；无证据的「我认为 mstsc 是 X」一律视为缺陷。规则全文见 `.opencode/memory.md` 同日条目。
- **流程强制**：取证 → 证据条目（`docs/spec/<area>-evidence.md`）→ 先红测试（期望来自证据）→ 最小实现 → 双审独立复验（含变异反证）→ 盖章提交。
- **禁止**：改实现后重钉期望；用生产输出当期望；在注释写无证据的「mstsc 行为」。
- **当前取证基线**：mstscax.dll d73c76d6…；缩放 = HALFTONE（`FUN_18003444c`）；输入 API 调用点已计数待定位。

## 【纪律生效】所有后续批次的前置门（用户 2026-10-28）

- 批次开工前必须先在 `docs/spec/<area>-evidence.md` 落证据；**没有证据文档的批次不得进入实现**。
- 交付物必须包含：证据引用（`模块!函数@地址` + 片段）、先红测试（期望来自证据）、变异反证（改回旧行为必须转红）。
- 已建证据文档：`docs/spec/scaling-evidence.md`（A1 缩放）、`docs/spec/input-evidence.md`（A2 输入/快捷键）。
已建证据文档：bitmap-evidence/cliprdr-evidence/rdpsnd-evidence/smart-sizing-evidence/multimon-ui-evidence/rdpdr-evidence/cliprdr-server-design/rdpdr-server-design。待建（需真机抓包）：cliprdr capset/rdpsnd TSSNDCAPS wire 裁决。

## 功能缺口盘点（2026-10-28，主代理取证）

| 功能 | 状态 | 证据 |
|---|---|---|
| 剪贴板 cliprdr | ✅ 客户端+服务器 | 已入库 |
| 音频 rdpsnd | ✅ 客户端+服务器 | 9b1ecbf |
| 驱动器 rdpdr | ✅ 客户端(opt-in)+服务器路线A异步引擎 | bd44d52, 3290402 |
| 多显示器 | ✅ 已接线（`--multimon` + 每显示器窗口 + span） | main.cpp:487-501 |
| RAIL | ✅ 已接线（`--rail` + SetRailSender + StartRailChannel） | main.cpp:460-476 |
| **USB rdpusb** | ❌ **完全未接线** | `src/channel/rdpusb_client.cpp` 仅自身引用；`tools/`、`src/client/` 零引用 |
| Gateway | ⚠️ 是 HTTP CONNECT 代理，非 [MS-TSGU] RDGSP | `src/proto/gateway.cpp:220` "CONNECT ... HTTP/1.1" |

### USB 已知缺陷（N8-EXEC-1 定案 S2 阻断项，待复核）
1. drdynvc 未请求（`main.cpp:161,163` 通道列表无动态通道请求）
2. `rtsc_urbrdc`/`rtsc_usb_win32` 未链接到 GUI
3. URB 数据通路双向丢数据（`rdpusb_client.cpp:350,468-500`）
4. drdynvc 串包（`drdynvc_client.cpp:113-119`）
5. QI/IFACE_RELEASE 缺失（S2-10）
6. `CompleteUrb` 恒 `hresult=0` 且设备未知不发 URBCOMPLETION（`:509-542`）

### USB 批次进展（2026-10-28，第726-729轮）

**已定案并已接线**（未提交，等双章）：drdynvc 静态通道请求 + ChannelIdForName + RegisterChannel + DrdynvcClient + RdpUsbClient + CreateWin32Enumerator；CMake 链 rtsc_urbrdc/rtsc_usb_win32；`RTSC_REDIRECT_USB` 安全门控（默认空=不重定向）。

**第⑤步验证抓到 2 项阻断 FAIL（均已 web/源码核实）**：
- FAIL-1 `drdynvc_client.cpp:74-90`：CREATE_RSP 按 NUL 名字定界；规范 2.2.2.2 无 ChannelName（只有 ChannelId+CreationStatus 4B）→ 捆绑时第二条丢失；单测用错误布局假绿。
- FAIL-2 `usb_win32.cpp:235-236`：Control OUT 只零初始化 buffer，`input` 未拷入 → 发全零载荷（Bulk OUT `:279` 正确）。

**P2 同批**：CAPS 定界按版本（V2/3 PriorityCharge）、`RTSC_REDIRECT_USB` 空时仍广告 drdynvc 静态通道。

**真机未验证**：Windows RDS + USB 实体设备双向 I/O（需用户环境）。

## USB 批次（2026-10-28）后续待办清单

### P2（架构级，需新增回调）
- **AddDevice 异步反馈缺失**：`RdpUsbClient::AddDevice` 返回 true 只代表本地 Open + 发 ADD_VIRTUAL_CHANNEL + 本地 CreateChannel；服务器拒绝设备级 DVC create/ADD_DEVICE 时计数不回滚 → 隐私文案可能虚高。修复需 `RdpUsbClient` 增加 create 失败/close 回调（`OnChannelCreated` 里 status!=0 时回调 provider），GUI 侧据此修正。fails-closed，无授权后果。
- **DVC create 失败不可恢复**：`drdynvc_client.cpp` 清 `pending_` 后不再重试，id 永久不可用（设计明确只要求"不悬挂"；如需恢复需加退避重试）。

### P3（功能完整度，非阻断）
- 复合设备：`usb_win32.cpp:158` 只 `WinUsb_Initialize` 绑 interface 0，缺 `WinUsb_GetAssociatedInterface`
- `kIoControl`/`kInternalIoControl` 无 case（`rdpusb_client.cpp` default break）→ 无 IO_CONTROL_COMPLETION
- 控制类 URB 合成 setup packet（Descriptor/Feature/GetStatus），当前全返 kInvalidUrbFunction
- 热插拔 RemoveDevice 未监测
- 同步 WinUSB 阻塞消息泵
- Isoch 传输无实现
- `hresult` 恒 0（status 已在 ts_urb_result.usbd_status）
- NoAck 未抑制补全帧
- `SelectInterface` 服务器请求 alt-setting 不在表内 → kInvalidParameter

### W5 未验证（需真机）
- Windows RDS + USB 实体设备双向 I/O 闭环
- 拔出 → RETRACT → 通道关闭 → 设备移除
- mstsc 互通（服务器每进程自签 RSA，需手动信任）

### 其他功能缺口（全局盘点）
- **Gateway**：当前是 HTTP CONNECT 代理，非 [MS-TSGU] 3.3.5.1 RDGSP，零接线（需完整实现）

### 审计发现（乙第一轮，待甲交叉验证后定案）

**P1**
1. `gateway.cpp:263` Host 头写成路径 `/remoteDesktopGateway/`（应为 authority）。
2. SOAP Body 缺 `<CreateTunnel>` 包装（`gateway.cpp:324-328`）。
3. 头部方向性错误：`RDG-Correlation-Id`/`RDG-User-Id` 应 OUT-only，当前无条件写（`:270-273`）。
4. `Content-Length: 0`（`:268`）与 OUT 通道 chunked 流式体矛盾。
5. **chunked 解码完全缺失**（`gateway_transport.cpp:279-293` Read 原样泄流）→ 接真网关必坏。
6. 证据头全集缺失（Diagnostics/AppBuild/Generation/ChannelBind/Auth-Scheme/LB cookie/remotappRetryMode）。

**P2**
7. `o.method` 无默认值（`gateway.h:143`）。
8. `parse_www_authenticate`（`gateway.cpp:280-302`）不支持多挑战/多参数。
9. UDP 序号 2^32 回绕误判（`gateway_transport.cpp:72-73,104`）。
10. `UdpSyn::parse` SYNEX 探测 `remaining>=4` 尾部歧义（`gateway.cpp:448`）。

**P3**
11. 畸形 datagram → 立即断连（`gateway_transport.cpp:113-114/78`）。
12. FEC 位帧/FIN 帧未处理。
13. `MultitransportResponse` 字段序 UNVERIFIED。

**安全**
- S1/S2/S4 通过。
- **S3（P1 接入安全）**：TLS 默认 `kTofu`（`tls.h:118`）；网关自签下首连 MITM 窗口；`kInsecure` 则 CredSSP step5 明文密码（`credssp.cpp:391`）。需网关专属策略（kStrict / pinned SPKI / 用户确认）。
- S5：SOAP 无 XML 转义（`gateway.cpp:320-326`）→ 配置注入面。

**UDP 正确性**
- **C1（P1 丢帧，已核实）**：`gateway_transport.cpp:126-128` 单帧 stash 无条件覆盖 + `:111` 每帧立即 ACK → 未消费帧永久丢失。`receive_window_size=64` 与实现缓冲 1 不符。
- C2：ACK 与超时同返 0（`:29-31`）语义失真。
- C3：重发复用原字节正确。

**实施风险（双通道包 ByteTransport）**
- `Client::Connect/Pump/SendPdu` 吃单 `Transport&` → 需自定义 `RdgByteTransport`。
- RDGSP 同连接上行/下行交错，需自定义复用（否则写等读排空死锁）。
- `Client::Connect` 硬 30s（`client.cpp:136`）+ 握手在构造内 → 冻结 GUI 消息泵。
- `ConnectionDriver` 状态机不可重入（`connection_driver.cpp:35-41`）→ 断线必须重建；`GatewayTunnel` 持 `inner_` 引用无所有权无重建路径。

---

# 当前状态（2026-10-31）

## 已入库（Gateway + TLS 安全）
| 提交 | 内容 |
|---|---|
| `5a361e0` | Gateway RDGSP 阶段 1（协议层：头部/chunked/状态映射/多挑战/UDP） |
| `fce4ac4` | TLS 证书策略真正生效（SChannel DEFERRED + 链/主机名/pin；OpenSSL kTofu+pin 对齐；rtsc_connect/bench 默认 kStrict） |
| `ae3f08a` | Gateway RDGSP 阶段 2（双连接 RdgspTransport + RFC6455 + TlsByteTransport 修复 + GUI 接线） |
| `f213457` | Linux 门禁首次通过的 9 处移植修复 |
| `a2cfebe` | OpenSSL kTofu+pin 行为验证 + `kCertRejected` 映射修复 |
| `9791fc4` | UDP 测试数据竞争 + 基准预算余量修正 |

## 验收现状
- **Windows**：构建 0 err/0 warn（/W4 /WX）；`ctest` **62/62**
- **Linux**（WSL Ubuntu 24.04，g++ 13.3，OpenSSL 3.0.13）：构建 0 err（-Werror）；`ctest` **61/61**
- 性能（1920x1080）：解码 109-200 fps；端到端 **193.5 fps**（5.168 ms）；CPU 100%（单核饱和）
- 服务器模式：**8 会话并发压力测试通过**（`server_multisession` 7 tests/184 checks）

## 已完成：OpenSSL 后端 server 角色（84cf12b）
Linux 上 
tsc_server 现可提供 TLS/CredSSP。本批修复 3 个 P0：
1. **D1** Handshake 的 consumed 语义错误（模拟 SSPI EXTRA，OpenSSL EXTRA 恒 0）→ 重放同记录 → **AES-GCM nonce 重用**
2. **drain 门控死锁**：pending_cipher_ 为空时跳过 drain → 合段的 CredSSP NEGOTIATE 滞留 → 客户端等 CHALLENGE、服务端等字节
3. **server 角色缺失**：TLS_client_method 无条件 → Linux 服务器只能走 Standard RDP Security

实现要点：A2 进程级临时 RSA-2048 自签（call_once，只缓存 DER 字节）+ B 可选 PEM 层；
Local* 用 i2d_X509 / X509_PUBKEY_get0_param（禁固定偏移）；policy 校验仅 kClient。
测试：	ls_openssl 16/134、server_security 8/67；变异 4/4 + 双审各 2 项独立复现。

## 待处理

### ~~P0 —— D1 的耦合问题~~ 已修（84cf12b）
server_security_layer.cpp:194 与 security_layer.cpp:244 的 drain 已移出 if；保留 kNeedMoreInput break。
P0 回归用例 	ls_server_regression_coalesced_first_record_no_stall 锁层集成，
openssl_server_coalesced_final_flight_plus_first_record 锁后端契约（变异证明两层分离成立）。
残留 P3：security_layer.cpp:321 DriveEuar 的 drain 仍门控，但 EUAR 是 step5 后独立消息，无死锁路径。

### ~~主机名硬化 + Sec-WebSocket-Accept~~ 已修（`407d03e`）
- `DnsNameMatches` 尾点归一 + 结构拒 `*.com` + ccSLD 表（447 条）拒 `*.co.uk`；探针 9/9 PASS（原 4 FAIL 全转绿）。
- WebSocket 101 三条件校验 + key 生命周期打通 + 401 刷新；RFC 官方样例锁定。
- 两后端验证名统一；两处单侧差异（ccSLD / 尾点）双端注释。

### P3（记录，未修）
- ccSLD 表为**手工维护的简化集**（非全 PSL），漏项则公共后缀通配仍可能过（已注释）
- OpenSSL 后端未引入 ccSLD 检查（`*.co.uk` 在 Linux 仍过；SChannel 更严，安全方向正确）
- IDN/punycode 归一未做（假阴性）
- `0x6a4`/`0x6a6` 异值场景 UNVERIFIED
- USB：P2 AddDevice 异步反馈；P3 复合设备/kIoControl/控制 URB 合成/热插拔/Isoch/hresult/NoAck

### W5（需真机）
- 真 RD Gateway：200 vs 101 互通、会话超时表
- USB 实体设备双向 I/O；驱动器重定向；音频
- SChannel 自签证书位数（439B DER 推断 RSA-1024，未直接探测）
- `kTofu` 无 pin 的主机名行为（SChannel deferred 可能附带自身 SPN 校验，方向保守）

## 已作废的旧结论
- ~~单连接多路复用~~ → 双连接（`gateway-stage2-evidence.md` §10）
- ~~需自定义 `RdgByteTransport`~~ → 路线 A'（单 Transport 外观 + 内部双连接）
- ~~TLS 默认 kTofu 安全~~ → SChannel 三策略全零校验（已修，`fce4ac4`）
- ~~按报错文本推头部方向~~ → `gateway-header-direction-ruling.md`

## 缺陷（P0 级功能缺口，2026-10-31 第148轮）：服务器模式「只能看不能操作」

**症状**：`rtsc_server` 能向客户端推送桌面帧（GDI 捕获 → 编码 → 发送），但**远程用户的键鼠无法注入本地桌面**。
→ 实际不可用作远程桌面（只能当"屏幕直播"）。

**证据（W5）**
1. `[BASH: grep 'SendInput|keybd_event|mouse_event|SetCursorPos' src/ include/ tools/]` → 4 命中，
   **全部是客户端侧**：
   - `src/client/client.cpp:267` `Client::SendInput(...)`（把本地输入发给远端）
   - `include/rtsc/client/client.h:95` 同上声明
   - `tools/rtsc_gui/main.cpp:1186,1190` 调用上述客户端函数
   → **服务器侧调用 Win32 注入 API 的次数 = 0**
2. `[READ:tools/rtsc_server/main.cpp:453-463]` 唯一的 `SetInputCallback` 生产调用**只写日志**：
   ```cpp
   server.SetInputCallback([&log](const rtsc::server::InputEvent& ev) {
       ... log.line(std::string("session active: ") + kind + " event forwarded");
   });
   ```
   注释还明说"是会话到达 active 阶段的证明"——即它被当作**探针/日志**用，不是功能实现。
3. `[READ:include/rtsc/server/server.h:191-224]` `InputEvent` 结构（kKey/kMouse/kWheel/kSync/kUnicode
   + scancode/unicode/button/wheel_delta/sync_flags）与 `InputCallback` seam **已就绪**。
   → 缺口不在协议解析层，在**最后一步"注入本地桌面"**完全没写。

**影响**
- 目标明确要求"推进 RDP 服务器模式（家庭版解禁、多远程用户）"——输入注入是可用性的**定义性前提**，
  不是增强项。
- 多会话（8 会话并发已通过）在无输入时只是 8 个只读镜像。

**为什么此前没被发现**
- `server_multisession` 压力测试只验证**并发正确性与隔离**（剪贴板、帧分发），
  输入回调在测试里只断言"收到事件"，从未断言"桌面真的被操作"。
- 测试固化了"callback 被调用 = 功能正常"的假设（同型家族：测试固化缺陷方向）。

**待做**：派 W11 双审计设计输入注入方案（Win32 `SendInput` 语义、扫描码映射、绝对/相对坐标、
多会话时的桌面归属、UIPI/权限提升输入、Ctrl+Alt+Del 特例）。

---

# 输入注入批次（round 793 新增，P0）

## 现状证据
- 服务器侧 Win32 注入调用 = 0；`SetInputCallback` 只写日志（`tools/rtsc_server/main.cpp:453-463`）。
- 解码缺陷已定案（`docs/spec/input-injection-evidence.md` 498 行 + `input-injection-seam.md` 382 行）：
  P-1 HWHEEL 丢弃、P-2 滚轮单位、P-3 相对移动、P-4 幻影按键（`server.cpp:1610-1621` 回调前置缺陷）、
  P-5 move/release 歧义 + 测试固化（`tests/test_server.cpp:695-703`）、P-6 EXTENDEDKEY 仅 0xE0、
  P-9 未广告 `INPUT_FLAG_FASTPATH_INPUT2 0x0020`、P-10 慢路径 `0x1C` 静默丢弃
  （`server.cpp:1479-1521` 仅 RefreshRect/SuppressOutput，主代理已复核）、P-11 未知 eventCode 不断连、
  P-12 `session_id=0` 无法归属（`server.cpp:1843/1962`）。

## 分批（每批独立 TDD + 双审复验 + 变异）
- [ ] 批 1 协议完整性：P-1..P-6、P-11（编码/解码 + 断言语义；滚轮部分已在 round 793 落地）
- [ ] 批 2 capability 与慢路径：P-9（0x0020）、P-10（0x1C 慢路径输入解码）
- [ ] 批 3 注入器骨架：`InputSink` + 单工作线程队列 + `--allow-input` 默认 off +
      拒绝组合（`--no-enhanced`/`--allow-any-credentials`）+ `ReleaseSession` 补 keyup +
      纯函数 `Translate(InputEvent, InjectGeometry) -> PlatformInput`（不引 windows.h）
- [ ] 批 4 真机验证：UIPI 落点、多会话、安全桌面、Pause、kSync、DPI/多屏（UNVERIFIED 清单）
## 输入注入批次进展（round 800-801）
- [x] 批 1 协议完整性 P-3/P-4/P-5/P-6/P-11 → `e0bee4b`
- [x] 批 2 客户端滚轮切块 N1/N2/N3/N6 → `10b3b20`
- [x] 批 3 慢路径 0x1C + 能力位 0x0008/0x0020 → `10b3b20`
- [x] 批 5 切块上限可观测 → `e6c4ad7`
- [x] 批 4 注入器骨架（DesktopInputSink，默认 off、危险组合 EXIT=2）→ `afb2a69`
- [ ] 批 6 F-1 慢路径 MOUSEREL 解码 / F-4 队列硬上限 / F-5 Stats / F-6 last_move_sent_ /
      F-7 SetInputSink 时序 / GAP② numberEvents 计数 / GAP④ was_share_data 白名单（在途）
- [ ] 批 7（甲2 新发现）：② `scancode==0` 映射层过滤；⑤ sink↔server 集成测试；
      ⑥ `max_input_sessions=1` 单会话控制租约（设计文档要求，未实现）
- [ ] 真机验证：按 `docs/spec/input-injection-real-machine-checklist.md` 逐项（UIPI/多会话/SAS/Pause/多屏）
## 批 9 设计定案（限流与可观测，round 805 预写）
> 目的：把 `docs/spec/input-injection-seam.md` §2 的限流要求落到实现，并消除文档漂移。

### 限流（令牌桶，注入器内部，单 worker 线程执行）
- 单会话：`400 evt/s`，桶容量 `800`（2s 突发）。
- 全局：`1000 evt/s`，桶容量 `2000`。
- 超限：**丢弃该事件并计数**（`InputStats.dropped_rate_limited`），不排队、不断连、不打日志每事件；
  每 5s 限流窗口最多一条 WARN（复用现有 5s 限流日志机制）。
- 例外：**释放类事件（keyup / 按钮 up）不受限流**（与 F1 同理：丢释放比丢按下危险）。
- 计数器：`InputStats { injected, dropped_queue_full, dropped_rate_limited, send_failures }`；
  `RdpServer::input_dropped_count()` 汇总（可选）。
- 可观测：启动行打印 `input=on|off input_max_sessions=N`；运行期每秒最多一条 lease-denied 汇总
  （`input_lease_denied_count()` 已有，改为启动后周期性打印或首次拒绝时打印一次 + 计数）。

### 文档回写（`docs/spec/input-injection-seam.md`）
- §1.5 队列：软上限 256（驱逐最旧移动）/ 硬上限 1024（无可驱逐时丢非释放事件并计数）/
  释放事件永不被队列上限丢弃。
- §2.3：`kMouseRel` **已上送**（`Kind::kMouseRel`），v1 注入器不注入（相对移动受加速污染）；
  `kSync` 不注入。
- §2.4：限流与告警按本节实现（若实现与本定案有偏差，以代码+测试为准并回写本文件）。
## 批 11 定案（审计 G 的 E7 + E1-T，round 815 预写）
> 范围：仅文档/注释与 1 条测试，**不动产品逻辑**（G 已判 E1/E5/E6 PASS）。

### 文档/注释（4 处）
1. `docs/spec/input-injection-seam.md:137` 与 `src/server/desktop_input_win32.cpp:26-27`：
   峰值上界必须写全两段：
   - 对端可入队事件：`peak(queue) ≤ kHardQueueLimit + |pressed|@饱和 = 1024 + 515 = 1539`
   - **合成 up**：`AppendReleasesLocked`（`win32.cpp:232-254`）按 `pressed` 直推、不受队列上限，
     且 purge 保留 `synthetic`（`307-315`）→ 追加 `+ Σ 会话 |pressed| ≤ 会话数 × 515`
   - 明确"不得读作瞬时不变式"（释放后 queue=1534 / pressed=0 的探针事实）。
2. `include/rtsc/server/desktop_input.h:41-43`：`dropped_queue_full` 定义补"**会话结束时 purge 的排队项**"
   （`win32.cpp:310` 路径），否则读计数器的人会以为只统计硬限丢弃。
3. `seam.md:168`："退出前终值"限定为**正常退出**（`--seconds` 到期 / `--once`）；
   无界模式无 SIGINT 处理（`main.cpp:713-722`）→ 必须写明"Ctrl+C 不打印 final"。
4. `seam.md:170`：删"Inject 返回 false"（`Inject` 是 void，`desktop_input.h:71`）。

### 测试（E1-T 缺口）
新增 `desktop_input_rate_limit_held_release_keeps_token`：
- 给定：会话耗尽到仅剩 1 令牌（799 presses，burst 800）
- 当：发 100 条 **held** up（先按下再抬起）
- 则：全部放行且 `dropped_delta == 0`，**且保留的 1 令牌仍可花**（下一次 press 放行）
- 变异 mutC（held up 豁免但扣令牌）必须使该用例转红。

### 验收
- `cmake --build build --config Release` 0 err 0 warn
- `ctest --test-dir build -C Release` 独占 63/63
- mutC 红 → 恢复绿 + `Get-FileHash` 双证
- 文档与代码逐条对照，禁止保留任何"文档说 X、代码是 Y"的句子
## 批 17 定案（round 833 预写）：kSync 终止 PAUSE 窗口 + seam.md 全文重写
### A. 代码（1 行 + 1 测试）
审计 K §9.3 观察：`PauseSequenceFilter::ShouldDrop` 只处理 `kKey`，`kSync` 不清 `ctrl_armed_`
→ "E1 → SYNC → NumLock tap" 整组被吞。按 P-7 语义 `kSync` = 按键状态重置，应视作序列终止。
- `include/rtsc/server/desktop_input_map.h:92` 之后加：
  `if (ev.kind == InputEvent::Kind::kSync) { ctrl_armed_ = false; return false; }`
- 测试：`desktop_input_pause_window_closed_by_sync` —— armed 后发 kSync，再发 NumLock tap → tap 产出 2 个动作
  （变异：删掉该分支 → 红）。

### B. 文档（`docs/spec/input-injection-seam.md` 全文对账后重写）
依据 `docs/spec/input-batch12-review-I.md`（48 条失效引用清单）与后续各批进展：
1. §0 结论过期（P 项状态）→ 按当前实现重写状态表。
2. §1.3/§1.4 接口名整体失效 → 改为实际名称：`DesktopInputSink`（`include/rtsc/server/desktop_input.h`）、
   `desktop_input_map.{h,cpp}`、`MakeWin32DesktopInputSink()`、`Shutdown()`；
   删 `InputSink`/`input_inject*.h`/`CreatePlatformInputSink`/`ReleaseAll`。
3. §1.3 与 §1.6 的 `Inject` 返回值自相矛盾 → 统一为 **void**。
4. §1.7 第 2 条（几何）保持 OPEN，并写明实测错位点：无 origin、恒 `VIRTUALDESK`、`--monitor N` 子矩形。
5. §1.8 Win32 缺口清单：**已部分闭合**（`RTSC_DESKTOP_INPUT_TESTING` 测试缝已覆盖 N-1/N-2），改为现状描述。
6. §2.3 限流：补 `held_release` 语义、`kGlobalBurst=2000` 的理由、`release_failures` 计数。
7. §3 P-1…P-12 状态列按实现更新（P-1/P-2/P-3解码/P-4/P-5/P-6/P-9/P-10 已修；P-7/P-8/P-11 保持）。
8. §4.1 T 表按实现修正（T4 中点期望、T6 几何不可用=不产出、T10 零滚轮=不产出、T15 Pause=整序列不注入）。
9. §4.4 变异表 M1-M6 标注"有真实用例/无覆盖"。
10. §7 追加「与甲/各轮审计的收敛记录」（H/I/K/J 的结论与处置）。
11. 全文行号引用重新核对（禁止保留失效行号；无法确定的行号宁可写符号名不写行号）。

### 验收
- 代码：build 0/0；两套件 `0 failing`（**不钉 checks 数**，见 memory 第 74 条）；ctest 独占 63/63；变异 1 个红/绿 + 哈希
- 文档：与代码逐条对照，逐项在报告中列出"文档断言 → 代码事实"
## 批 20 范围（round 840）：§1.7 第 2 条「几何来自协商尺寸而非捕获矩形」
### 现状（主代理取证）
- `include/rtsc/server/desktop_input.h:31-34` `InjectGeometry { uint16_t width, height; }` —— **只有协商 framebuffer 尺寸，无 origin、无虚拟桌面范围**
- `src/server/server.cpp:1324` `inject_geometry_ = InjectGeometry{desktop_width_, desktop_height_}`（协商并钳制后的尺寸）
- `src/server/desktop_input_win32.cpp:518-522` `BuildNative` 恒发 `MOUSEEVENTF_MOVE|ABSOLUTE|VIRTUALDESK`
- 捕获侧 `MakeGdiDesktopSource(monitor_index, x, y, width, height)`（`include/rtsc/server/desktop_gdi.h:40-42`）支持"单显示器 + 子矩形"，并把该矩形**缩放**到协商几何
### 缺陷
`--monitor N`（或子矩形捕获）时：客户端坐标以"捕获矩形"为域，注入却按"整个虚拟桌面"归一化 ⇒ **指针整体偏移/缩放错**（默认 `--monitor -1` 全虚拟桌面时才对）。
### 目标契约（执行 AI 需按 MS 文档校准后确认）
`InjectGeometry` 必须能表达：①捕获矩形在**虚拟桌面坐标**中的 `origin_x/origin_y` ②捕获矩形尺寸 ③虚拟桌面总范围
④是否使用 `VIRTUALDESK`。归一化分两步：framebuffer 坐标 → 捕获矩形像素 → 虚拟桌面归一化 0..65535。
### 交付要求
1. 先给"设计 + 规范依据"（`MOUSEINPUT`/`MOUSEEVENTF_VIRTUALDESK` 原文 + 成熟实现交叉），再动手
2. TDD：先写"单显示器 + origin 偏移 + 缩放"的多组用例（含 1:1、2x、origin 非零、虚拟桌面多屏）
3. `DesktopSource` 需能报告捕获矩形（新增可选接口或工厂返回值），服务端据此填 `InjectGeometry`
4. 变异：①忽略 origin ②忽略虚拟桌面范围 ③恒发/不发 VIRTUALDESK —— 各必红
5. 真机项（`--monitor N` 落点）仍 UNVERIFIED，写入清单
## 批 22 定案（round 851，M/N 收敛 + 主代理裁决）

### 设计依据
- `docs/spec/input-geometry-design-M.md`（M 修订版，待其修完 §8/§3.3/§6.1 三处）
- `docs/spec/input-geometry-design-N.md`（N 交叉审计）
- `docs/spec/input-geometry-probe-evidence.md`（主代理独立探针，含真实库复现）

### 已定案（不可再改，除非新证据）
1. **采样相位**：`fb → capture` 用**中心采样**
   `lx = min(cw-1, ((2*fx+1)*cw) / (2*fbw))`（int64，floor）
2. **分母**：`capture → wire` 用**混合式**
   `nx = (rx >= dw-1) ? 65535 : min(65535, ceil(rx*65536/dw))`
3. **字段**：`InjectGeometry{ width, height, InjectRect capture, InjectRect desktop, bool mapped, bool pixels_are_physical }`
4. **fail-closed**：`!mapped` 或 `!pixels_are_physical` → 丢弃 `kMouseMove`（按钮/滚轮/键盘不受影响）
5. **flags**：`MOUSEEVENTF_MOVE|ABSOLUTE|VIRTUALDESK` 不变

### 验收判据（执行 AI 必须逐条给出证据）
- [ ] `TranslateInput(ev(640,512), InjectGeometry{1280,1024, capture{1920,0,1280,1024}, desktop{0,0,3200,1024}, mapped=true, pixels_are_physical=true})`
      → `n=(52429,32768)`，按 `floor(n*3200/65536)` 落 `(2560,512)`
- [ ] 1:1 路径（capture==desktop==fb）与现状逐点一致（回归）
- [ ] `w=1280, rel=1` → `n=52`（杀 M5/M5b）
- [ ] `rel=w-1` → `n=65535`（末像素端点）
- [ ] `mapped=false` / `pixels_are_physical=false` → 无 `kMouseMove`，但按钮仍产出
- [ ] `desktop_gdi.cpp` 的 `SetProcessDpiAwarenessContext` 返回值不再丢弃，且
      `pixels_are_physical = (SM_*VIRTUALSCREEN == DESKTOPHORZRES/VERTRES)`
- [ ] 全量 ctest 63/63、`/W4 /WX` 零警告
- [ ] 变异：改坏中心采样 / 改坏末像素特判 / 改坏 fail-closed，各自必须转红

### 明确不做
- 不加 DPI 数值字段、不加 `use_virtual_desk`
- 不改 `tests/test_desktop_input.cpp:272-279` 的既有断言
- 真机落点（U1/U2/U4-U9）不在本批验收范围，标注 UNVERIFIED

## 【归档压缩：批 23 / 批 24 清单（原 161 行，已完成项）】

### 批 23（提交 `12a9348`，14 项全部落地并验收）
- 原 8 项：`dropped_unmapped` 接日志、`RecordingInputSink` 全字段、`desktop` 负原点用例、
  `AbsoluteMoveMappable` 补 capture⊆desktop 与 ≤65536、`IsInjectable(ev,g)` 几何门槛、
  修正过时注释、M 文档同步、plan 改判记录。
- 追加 6 项（双审 P/Q 签字后）：**H1 重写结构守卫为行为 seam**（删读源码、`MetricSource` 注入）、
  **H2 接线四字段 + `Geometry()` 调用计数**、M5 四处覆盖（cap<fb 下采样 / 内部像素 / y 轴解耦 / 稠密表）、
  M6 `dropped_unmapped` 语义（不双计、不过计）、H3 删除"取租约复测"承诺。
- 我亲测：17 变异中重做 H1 变异 → `:346/:349` 红；稠密表与 §9 oracle 一致。

### 批 24（提交 `fa79fec`，9 项全部落地并验收）
- R1 工厂接线（抽 `AssembleGdiDesktopSource` 共用 + `MakeGdiDesktopSourceWithMetrics`）
- R2/R4/R5 文档修正（M §6.4 落点、§10 两数字、四处状态过期）
- R3 日志验收去文本匹配（`FormatInputStats`/`InputStatsChanged` 纯函数 + 新 TU）
- R6 H2 接线 y 轴用非零异值
- S1 可观测回归（`DesktopInputSink::NoteUnmappableMove`）
- S2 三处边界（capture.x=1 / capture.height=0 / desktop.height=65536）
- S3 清理（删 `MakeWin32MetricSource` 与两处过期 `RTSC_SOURCE_DIR`）
- 我亲测：决策改 VIRTUALSCREEN → `:392` 红（此前假绿）；desktop.right 改 CY → 3 failing。

**R7 [Low·诚实登记] host 的 `main.cpp` 调用点仍无行为测试**
批 24 把日志行构造抽成纯函数 `FormatInputStats` / `InputStatsChanged`（`src/server/desktop_input_stats.cpp`），
测试只验证**纯函数**。`tests/test_desktop_input.cpp` 里原来那条读源码文本的宿主测试已按 R3 删除。
⇒ 若 `tools/rtsc_server/main.cpp:611/616` 不再调用这两个函数，**没有任何测试会红**。
这是第 35 例（seam 须经装配点覆盖）在 host 层的同型残留。
**为何本轮不修**：`rtsc_server_host.exe --once` 实测会**阻塞等待客户端**（`[BASH] 超时 120s 无输出`），
要走到 stats 行需要模拟完整 RDP 会话；现有 ctest 没有跑 host 可执行文件的用例。
**处置**：已把它下沉为**真机验收项**（`input-injection-real-machine-checklist.md` §10 新增两条：
`input_dropped_unmapped` 必须打印、未持租约会话也必须计数）。UNVERIFIED 保留。
**若将来要自动化**：加一条 ctest 启动 host + 用测试客户端建会话再断言 stdout，
或把 `LogInputStats` 的参数从 `InputStats` 改为可注入的输出回调（sink），在单测里捕获。

## 【归档压缩：批 25 / 批 26（原 70 行，已完成项）】

### 批 25（`dab111d`）—— 闭合 R7 的"装配点"部分
新增 `tests/host_cli_check.cmake`（`cmake -P` + `execute_process`，跨平台），5 个 CASE：
`help` / `refuse_no_enhanced` / `refuse_any_credentials` / `acknowledged_start` / `stats_line`。
`--port 0` 避让端口，`--seconds 1` 让 host 自行退出（无孤儿）。
变异 `main.cpp:611`→`log.line(reason)` → **只有 `host_cli_stats_line` 红**；
拒绝路径 `return 2`→`0` → 两个 `refuse_*` 红。首次覆盖宿主的启动安全闸。

### 批 26（`2dfedac`）—— 审计 T/U 九项收口
| 项 | 内容 | 变异证据 |
|---|---|---|
| F1 | 装配内所有 SM_* 走注入 `metrics`，删除全局 `Metric()` | `desktop.right`→`SM_CXSCREEN` → 红 |
| F2（返工） | 新增 `MakeGdiDesktopSourceWithDpiProbe`，生产入口变一行胶水 | 装配忽略 probe → 红 :561/:571 |
| F3 | 零标志位指针事件用例 | 删 `ev.is_move` → 红；删 `ev.button==0` → 绿（冗余已注明） |
| F4/U-7 | checklist 七个计数；seam.md 七字段表 + `InjectGeometry` 2→6 字段 | grep 1:1 |
| U-1 | `InputStatsChanged` 七字段**双向** | `!=`→`<` → 红 8 处 |
| U-2 | `FormatInputStats` 整行相等（锁顺序） | 整段换位 → 红 |
| U-3 | `reason==nullptr` 前缀断言 | 回退串 `"none"` → 红 |
| U-4 | `FakeMetrics` 补 `virtual_x/y` + 非零原点断言 | `desktop.left=0` → 红 |
| T 新发现 | 几何用例 `nullptr` 由 SKIP 改 `CHECK` | seam 恒 nullptr → 红 3 tests |

**关键教训（discover 例 38）**：我首版 F2 用 `String.Replace` 打在一个出现 2 次的字符串上，
生产入口与 seam 被同时改掉，`:461` 变红被误当"生产入口已覆盖"。审计 U 用 13/73 全绿推翻我；
单点定位重跑确认 **U 对、我错**。
## 批 27/27b/28（round 868-869，提交 `2ebac6d` / `db5f764` / `1da9e67`）

### 批 27 —— R7 宿主调用点闭合（`2ebac6d`）
**推导**：原需求"只在计数变化时打印"导致**空闲宿主永远不打印任何 periodic 行**——这本身是运维缺口。
让首次采样无条件打印基线，既补上可见性，又使调用点可从 `--seconds` 观测。
**不需要** env 门控 sink、生产后可替换后端、安全评审（这是审计 U 方案1 的代价）。
`PeriodicInputStatsLine(const InputStats*, ...)`：`nullptr` = 无基线必打印。

### 批 27b —— 自审判据盲区（`db5f764`，discover 例 40）
`--seconds 7` 而采样间隔 5 s ⇒ 窗口只有 1 次采样，"打印一次"与"每次打印"观测相同，
刷屏变异下用例**仍绿**。修：`--seconds 12` + `execute_process TIMEOUT 10→25`。

### 批 28 —— 审计 W 的 D1/D2（`1da9e67`，discover 例 41）
**D1 [中] 假测试**：基线行只断言"非空 + 前缀"，夹具 `base` 全 0 ⇒
`MUT-D1 = FormatInputStats("periodic", InputStats{})` 下 **68 tests/13912 checks 全绿**（我复现）。
修：`base.injected=7 / dropped_unmapped=5`（两个**不同**非零值）+ 断言两者出现在基线行 →
同一变异 **红 :1820/:1821**。
**D2 [低]** `--once` 只走 `log_input_stats("final")`，checklist:91 补注"仅 --seconds/无界模式"。

### 变异矩阵（全部实测）
| 变异 | 结果 |
|---|---|
| 删 `log_input_stats_if_changed()` 调用 | 仅 `host_cli_periodic_stats_line` 红 |
| lambda 整体 `return;` | 同上红 |
| 恒传 nullptr | 红 |
| `printed==nullptr` 返空 | `desktop_input` + `host_cli` 双红 |
| 删 `printed_input_valid = true`（刷屏） | 12s 窗口下红 `found 2`；7s 下**曾假绿** |
| 基线打印 `InputStats{}`（D1） | 修复前全绿；修复后红 :1820/:1821 |

### 验证
构建 exit 0 / 六类诊断全 0；`ctest -j1` **69/69, 0 failed**（87.98s）；`MUT-` 残留 0。

### OPEN / UNVERIFIED
- Linux 上 `host_cli_*` 实跑 **UNVERIFIED**：全量构建被 `server.cpp` 既有 `-Werror=reorder` 阻断
  （**非本批引入**，属独立缺陷，见下）。
- 真机 U1/U2/U4–U9、`--monitor N` 落点、真实 mstsc 连入时的 periodic 变化行：**UNVERIFIED**。

### 新发现（待立项，非本批引入）
`src/server/server.cpp` 在非 MSVC/非 Windows 构建下存在 `-Werror=reorder` 报错，
阻断 Linux 全量构建与 ctest，从而无法验证 `host_cli_*` 在 Linux 的行为。

## 批 30/31（round 870-871，提交 `bc8e41f` / `62eaf2c`）—— 双审收口，已闭合

### 批 29（`bc8e41f`）—— 审计 W 的 B1/D1e
**B1 是我在批 28 引入的判据回归**：用行索引切片重建用例时删掉了 change 分支的
`CHECK(line.find("input_dropped_unmapped=3")...)` 且未补等价物。
`MUT-B1`（change 分支打印旧快照）在修复前 **68 tests/13912 checks 全绿**，
同一变异在 `db5f764` 下是红的（discover 例 42）。
修复：补 `input_injected=8` / `input_dropped_unmapped=3` 字面量 + `line == FormatInputStats("periodic", moved)`。
D1e：基线夹具改七字段互异非零（11..17）+ 整行相等 + 七条字面量。

### 批 30/31（`62eaf2c`）—— verify.ps1 机械门自身假绿（discover 例 43）
新增"变异残留门"防 B2 类事故。首版用 `StartsWith('//'|'#'|'*'|'/*')` 豁免"仅注释"行 ⇒
C++ 里 `// log(); // MUT-X`（注释掉的调用）、`#define X 1 /* MUT-X */`、`*p=5; // MUT-X`
全是代码却被放行（3 行夹具只报 1 条）。而这正是 B2 残留的形态（`:714` 是纯注释行）。
修复：**零豁免**（任何命中即失败）+ `git -C $root`（D3）+ `--untracked`（D4）+
校验退出码 `>1`（D6）+ 注释写明范围依据（D7）+ 去掉测试注释里的变异名字面量。

### 变异矩阵（全部实测）
| 变异 / 场景 | 结果 |
|---|---|
| `MUT-B1` change 分支打印旧快照 | 红 :1846/:1847/:1848 |
| `MUT-D1` 基线打印全 0 | 红 :1825-1832（8 checks） |
| `MUT-D1e` 单字段归零 / queue-rate 换位 | 红 |
| 门：3 行变异夹具（外部 CWD + 未跟踪） | 3 条全报，EXIT=1（旧门只报 1 条） |
| 门：干净仓库（从 `C:\Windows` 跑） | `passed`, EXIT=0 |
| 门：非仓库路径 | `git grep` 128 → 门报错退出 1 |
| 门：`MUT-V27ONCE` 采样移出循环 | `stats_line` 红（`must_not_have`） |

### 验证
构建 exit 0 / 六类诊断全 0；`ctest -j1` **69/69, 0 failed**（82.21s）；
全仓 `MUT-` 残留 **0**（含注释）；`main.cpp` blob 与 HEAD 逐字节一致。
双审 W/V 独立复现并一致 **PASS（提交级）**，两角色已 `delete` 解散。

### 登录的防复发机制
`verify.ps1` 现有预检门：`git -C <repo> grep -n --untracked 'MUT-' -- src include tools tests`，
任何命中即失败，并校验 git 退出码（1=无匹配属正常，>1=失败）。
## 批 32/33（round 872，提交 `150a6ea` / `22876f2`）—— Linux gate 首次真正跑通

### 转折点：UNVERIFIED 被当成"无需验证"
此前多轮把 Linux 记为 UNVERIFIED（理由："被 `server.cpp` 既有 `-Werror=reorder` 阻断，非本批引入"），
**从未实际执行过 gate**。本轮执行发现 `FAILED_COUNT=4`，实际 **5 个错误**，其中 **2 个在生产代码**。

### 批 32（`150a6ea`）—— 5 个跨平台真错误
| # | 位置 | 错误 | 修法 |
|---|---|---|---|
| 1 | `src/server/server.cpp:1400` | `InjectGeometry{w,h}` 只初始化前 2 成员 → `-Wmissing-field-initializers` | 改逐字段赋值（`= InjectGeometry{}` 后逐项设） |
| 2 | `src/server/server.cpp:715` | 初始化列表顺序 ≠ 成员声明顺序 → `-Wreorder` | 按声明序重排（`input_lease_` 提到前） |
| 3 | `tests/test_desktop_input.cpp` ×5 | 2 参聚合初始化 | 新增 `PartialGeometry(w,h)`（只设 span，`mapped` 保持 false） |
| 4 | `tests/test_desktop_input.cpp:108` | `WaitUntil` 在非 Win32 构建未使用 → `-Wunused-function` | 用 `RTSC_DESKTOP_INPUT_TESTING` 围住定义 |
| 5 | `tools/rtsc_server/main.cpp:593` | switch 漏 `kMouseRel` → `-Wswitch` | 补 case |
| 6 | `tests/test_server_security.cpp` | `!defined(_WIN32)` 守卫 OpenSSL，但 `RTSC_TLS_OPENSSL` 默认 OFF → `undefined reference to SSL_*` | 改为 `#if defined(RTSC_TLS_OPENSSL)` |

**变异验证**：`inject_geometry_.width` 改取 `desktop_height_` → 红 `:4099` / `:4491`（值断言有效）；
恢复后全绿。

### 批 33（`22876f2`）—— gate 的 Debug 性能预算
gate 用 `-DCMAKE_BUILD_TYPE=Debug`（`-g` 无优化），`view_scale_benchmark_budget` 预算按 Release 实测 ×3。
Debug 下 7 个形状中 3 个超预算（最慢 256ms / 预算 90ms；同机 Release 43.7ms）。
**性能预算不能在未优化构建上判定**：用 `#if defined(NDEBUG)` 围住判定；未优化构建打印
`skipped: timing budgets require an optimized build (NDEBUG)`（诚实跳过，不伪装通过）。

### 验证
| 项 | 结果 |
|---|---|
| **Linux gate** | `LINUX GATE PASS`；`CONFIGURE_EXIT=0 BUILD_EXIT=0 FAILED_COUNT=0 WINDOWS_H_COUNT=0 FACTORY_SYMBOL=present`；`67/67 tests passed` |
| Windows 构建 | exit 0；六类诊断全 0 |
| Windows ctest | **69/69, 0 failed**（77.45s，独占运行） |
| 变异 | width 取值错误 → 红 :4099/:4491 |
| MUT- 残留 | 0 |

### 教训（discover 例 44）
- **UNVERIFIED 必须定期重试**：它表示"本轮没验证"，不是"无需验证"。
- **"非本批引入"只影响归因，不豁免修复**：它阻塞验证就必须处理。
- **MSVC 全绿 ≠ GCC 全绿**：`-Wmissing-field-initializers` / `-Wswitch` 的默认集合不同。
- 看到 `FAILED_COUNT=N` 要读 N 个目标的**全部** error，不能只读第一条。
- 本机 `ctest` 与 WSL gate **并行跑**会造成 `desktop_gdi` 伪红（资源竞争），必须独占复跑核实。

### 状态
Linux 的 `host_cli_*` / `desktop_gui` 等此前 UNVERIFIED 项现已有 gate 级证据；
真机项（U1/U2/U4–U9、`--monitor N` 落点）仍 **UNVERIFIED**（需真实多显示器桌面）。
### 批 34（`36430c1`）—— 验证工具自身的两层缺陷

**为什么继续**：批 32/33 让 gate 通过了，但我在复核 `RTSC_TLS_OPENSSL` 传播时发现更深的问题。

| 层 | 问题 | 证据 | 修复 |
|---|---|---|---|
| 1 | `scripts/linux-build-gate.sh` 被 `core.autocrlf=true` 检出成 CRLF，bash 无法执行 | `file` → `with CRLF line terminators`；`wsl bash gate` → `line 29: $'\r': command not found`（EXIT=2） | 新增 `.gitattributes`（`*.sh text eol=lf`）+ `git add --renormalize` |
| 2 | gate 用 `RTSC_TLS_OPENSSL` 默认 **OFF** 构建 ⇒ OpenSSL 后端从未编译，P0 用例 `tls_server_regression_coalesced_first_record_no_stall` 被 `#if` 守卫掉 | Linux `server_security` **`Passed 0.01 sec`**，7 tests/45 checks（Windows 7/60） | gate 显式 `-DRTSC_TLS_OPENSSL=ON` |

**验证**
| 配置 | 结果 |
|---|---|
| gate + `RTSC_TLS_OPENSSL=ON` | `LINUX GATE PASS`；**68/68 tests passed**；`server_security` **8 tests/67 checks**；P0 用例 `[ OK ]` |
| gate 默认（OFF） | 构建 0 失败；`server_security` 7/45 全过（守卫是设计性降级，**不是删测试**） |
| `.gitattributes` 生效 | 删除后 `git checkout` → CR 字节 **0**，`file` 报纯 ASCII |
| Windows Release | 构建 exit 0、六类诊断全 0；`ctest -j1` **69/69, 0 failed**（99.96s） |

**结论**：Linux 的 UNVERIFIED 状态此前是**假 UNVERIFIED**——不是"环境缺失"，而是
"验证工具坏着 + 认证了错误配置"。现已用真实证据替代。

**教训（discover 例 45）**
- 验证工具本身必须被验证（"故意改坏 → gate 是否真的失败"演练）。
- 可选后端默认 OFF 时，gate 必须显式打开，否则测试被 `#if` 静默编译掉。
- `core.autocrlf=true` 的仓库必须有 `.gitattributes` 钉 `*.sh` 为 `eol=lf`。
- **0.01 秒"通过"是可疑信号**：含 TLS 握手的套件瞬间通过，应怀疑"没跑"。
### 批 35（`3bb033f`）—— gate 只信退出码 ⇒ 抓不住"用例被守卫掉"

**问题**：批 34 修了 gate 的配置，但 gate 的断言仍全是聚合结果
（`BUILD_EXIT`/`FAILED_COUNT`/`CTEST_EXIT`）。被 `#if` 守卫掉的用例在 ctest 上
照样 `100% tests passed` ⇒ **批 34 修的缺陷，批 34 的 gate 抓不住**。

**修复**：两道身份断言
1. `ctest -N` 必须列出 `tls_openssl server_security desktop_input host_cli_periodic_stats_line`
2. 直接执行 `rtsc_server_security_tests`，要求含
   `OK ... tls_server_regression_coalesced_first_record_no_stall`

**可证伪性（第16条：红→红→绿）**
| 变异 | 输出 |
|---|---|
| M1 gate `ON`→`OFF` | `LINUX GATE FAIL: required tests missing: tls_openssl` |
| M2 `:444 #if defined(RTSC_TLS_OPENSSL)`→`#if 0` | `P0 ... did not execute` **且** `REQUIRED_TESTS=present` ⇒ 第2道断言独立有效 |
| 恢复 | SHA256 `3AE7AFC7...9A8A` 一致；全仓 `MUT-` 残留 0 |
| 绿证 | `LINUX GATE PASS`、68/68、`P0_REGRESSION=executed`、`FAILED_COUNT=0`、`WINDOWS_H_COUNT=0` |
| 语法 | `bash -n` → `SYNTAX_OK` |

**平台差异精确化**（`ctest -N --show-only=json-v1` 对比）
- Linux 68 / Windows 69
- Windows-only: `desktop_gdi`, `tls`
- Linux-only: `tls_openssl`
- 其余 67 项完全同名 ⇒ 差异是平台后端替换，**不是用例丢失**

**教训（discover 例 46）**：聚合断言不覆盖身份；修"验证漏检"后必须问
"我的 gate 现在能抓住它吗"；新增断言必须构造**只触发该断言**的变异来证明其独立有效。
### 批 36（`d46b2c3`）—— 断言链端到端：verify.ps1 必须校验 gate 的新断言

**问题**：批 35 给 gate 加了两道身份断言，但 gate 的唯一消费者
`verify.ps1:448-464` 仍只校验四项（`FAILED_COUNT`/`WINDOWS_H_COUNT`/`FACTORY_SYMBOL`）。
**断言存在 ≠ 断言被消费** —— 这是批 34/35 教训（discover 例 46）的同型复发。

**修复**：`verify.ps1:458` needle 列表补 `REQUIRED_TESTS=present`、`P0_REGRESSION=executed`，
沿用既有 line-anchored 正则（不放宽为子串）。

**可证伪性**
| 变异 | 输出 |
|---|---|
| gate 两条 `echo` → `true`（gate 仍 EXIT=0） | `verify.ps1` 断言块：`MISSING -> REQUIRED_TESTS=present`、`MISSING -> P0_REGRESSION=executed` |
| 恢复 | 全仓 `MUT-` 残留 0 |
| 编码保真 | 首字节 `35`（无 BOM）、`CR=482` 均未变（字节级替换） |
| 语法 | PowerShell 5.1 Parser `PARSE_OK` |

**教训（discover 例 47）**
- 断言链必须端到端：每加一条断言，立刻在**消费方**补一条对应校验。
- 改非 UTF-8/LF 文件必须用字节级替换；`ReadAllText`+`WriteAllText` 会加 BOM 并换行符，
  制造与内容无关的伪 diff（本轮我犯过一次，已回滚重做）。
### 批 37（`44636b8`）—— 两审计 CONDITIONAL 收口：四条"跑了什么无人断言"

**审计结论**：X 与 Y 独立均判 CONDITIONAL，缺陷同属一族。对 `RTSC_TLS_OPENSSL` 传播链双方结论一致且与我一致：
**传播成功；批 32 关掉的是一个有效测试，批 34 是真修复（有红证：把 drain 改坏 → P0 用例红）**。

| # | 缺陷 | 来源 | 修法 |
|---|---|---|---|
| D1 | gate 的 `OK` 行可被"用例体 printf(`skipped:`)+return"短路（框架仍打印 `[  OK  ]`）⇒ 门自我认证 | X | OK 行 + 无 `skipped:` + `tests>=8 / checks>=67` **下限**（采纳 X：`server_tests` 655–657 漂移，等号只用于稳定套件） |
| D3 | gate 用 Debug，`test_view.cpp` 的 `#if defined(NDEBUG)` 预算断言**从未执行** | Y/X | gate 追加 `RelWithDebInfo` 构建，只跑 `rtsc_view_tests`，要求 `VIEW_BUDGETS=executed` |
| 新 | `test_gui_send.cpp` 全在 `#if defined(_WIN32)`，Linux 注册 0 用例却 exit 0（`gui_send` 长期假绿）；**修 D1 时被 gate 自己抓出** | 我 | `test_main.h` `ran_tests==0`→`exit 2`；`gui_send add_test` 加 `if(WIN32)`（目标保留编译） |
| P1 | `PartialGeometry` 的 `mapped=false` 语义无守护；既有用例因信任位在最前永远打不到 mapped 分支 | Y（X 纠正归因） | 两例从 `PhysicalGeometry(2,2)` 各坏一个信任位 + 按钮对照组 |
| P2 | `CONFIGURE_EXIT` 被批 34 重写时删掉 | Y | 恢复 |

**可证伪性（每项红→绿）**
| 变异 | 结果 |
|---|---|
| P0 用例体 → `if(true){skipped;return;}` | `EXIT=1`，`suite self-skipped` |
| 删 P0 体内 1 条 CHECK | `EXIT=1`，`checks=66 want >=67` |
| `CHECK(best < budget*1e-7)` | `VIEW_RELEASE_EXIT=1`，`:1473` 三条 FAIL |
| 删 `!g.mapped` | `:751/:905/:914` 红 |
| 删 `!g.pixels_are_physical` | `:755/:908` 红 |
| 拼错 `RTSC_TEST_FILTER` | exit 2（修前 exit 0） |

**验证**：Linux `LINUX GATE PASS` 67/67 + `VIEW_BUDGETS=executed`（Release 7348 / Debug 7341 checks）；Windows 构建六类诊断全 0 + ctest **69/69**；全仓 `MUT-` 0。

**未修（登记，不假装处理）**：`kind="relative-move"` 日志文本零守护（纯日志，断言成本高于收益）；Windows `-Wswitch` 零守护；`rtsc_server_tests` checks 漂移；`real-server-test.ps1` 不调 ctest。

**教训（discover 例 48）**：断言"执行了什么"而非"是否失败"；门必须能被打红（每道断言配一个只触发它的变异体）；修 A 类缺陷可能暴露 B 类（改 `test_main.h` 后 `gui_send` 现形）；注释里的"两者都坏会红"必须用变异兑现。
### 批 38（`b9a633f`）—— 堵 D3 的同形洞（审计 X 的 V8）

**缺陷**：批 37 的 D3 只断言 `VIEW_RELEASE_EXIT==0` 与"日志无 `skipped: timing budgets` 字面量"，
**check 数只打印不断言**。X 的 V8 红证（`#if defined(NDEBUG)`→`#if 0` + 改 skip 文案）：
`VIEW_RELEASE_EXIT=0` / `7341 checks`（Debug 数，预算一条没跑）/ `VIEW_BUDGETS=executed` /
`LINUX GATE PASS` / `EXIT=0` —— **假绿**。

**这本身是 D1 的同形复发**：我刚在 D1 立下"断言产出量而非字符串缺席"，同批的 D3 就违反了。

**修复**：`VIEW_MIN_CHECKS=7348`，断言 `VIEW_CHECKS >= 7348`（下限）。
差值 7 = 七条 bench CHECK；**差值把"配置形状"翻译成"执行结果"**。

**可证伪性**
| 变异 | 结果 |
|---|---|
| V8 复现 | `EXIT=1`，`view budget bodies did not run (checks=7341, want >=7348)`，且 `VIEW_RELEASE_EXIT=0`（不依赖退出码） |
| 恢复 | SHA256 `775301AB...8866`；全仓 `MUT-` 0；`7348 checks`；`LINUX GATE PASS` |
| 语法 | `bash -n` → `SYNTAX_OK` |

**X 对批 37 的复核**：6 项中 D1 / Release delta / `gui_send` / `exit 2` 三态 / `CONFIGURE_EXIT` 均 PASS；
唯一未过的是本批修的 V8。X 另纠正：删 1 条 CHECK=66、删 3 条=64，均红（变异强度差异，非判据差异）。

**教训（discover 例 49）**："能观测"≠"已断言"——凡被打印出来的数字，问"它错了谁会失败"；
新原则必须立刻回扫本次改动；可观测量的差值比绝对值更可靠。
### 批 39（`cc1591e`）—— 两审计 P1 收口（重复覆盖 / 事实错误 / 未守护层）

两审计双向收敛判 **PASS**（批 32/33/34/37/38），附两条非阻塞项。本批处理。

| 项 | 事实 | 处置 |
|---|---|---|
| 我的重复覆盖 | 批 37 的 `:903-914` 与旧用例 `:750-766`（自 `150a6ea^`）重复；删新块后 `:751/:755` 仍红（X 的 T0/T1） | **删除**，无覆盖损失 |
| 我的注释事实错误 | `PartialGeometry(1920,1080)` 的 span 合法，先拒的是 `:80` trust 再 `:82` 空 capture；被 span 拒的是**调用点**不是辅助函数（Y 指出） | 按事实重写，显式区分两层 |
| 真正无人守护的层 | `PartialGeometry` 三种变异全绿（68/13922）——打的是调用点下游规则 | 新增 `desktop_input_partial_geometry_helper_contract` 断言**辅助函数自身输出**；三变异皆红 |
| Y 的 P1-c | `main.cpp` 内联 switch 不可断言，MSVC `-Wswitch` 不保护（仅 `/w44062` C4062） | 提为 `InputEventKindToken()` 放 `desktop_input_stats.cpp`；switch 结构性消失；新增逐值枚举用例；`kMouseRel→"mouse"` 红 |

**未采纳**：Y 的"`VIEW_MIN_CHECKS=7348` 是魔数"。理由：7348 是"七条预算执行过"的唯一可观测证据，从运行结果推导即自证；已用下限比较 + 注释"增减 bench 须重新标定"。

**验证**：Windows 构建六类诊断全 0 + ctest **69/69**；Linux `LINUX GATE PASS` 67/67 + `VIEW_BUDGETS=executed`(7348)；`rtsc_desktop_input_tests` **70 tests / 13934 checks**；HEAD blob 四文件纯 LF。

**教训（discover 例 50）**："变异全绿"≠"规则无人守"——必须先枚举全部拒绝路径再判断变异打到哪一道；"无人守护"必须给反证（删既有用例后是否仍红）；注释里的因果链是不可执行断言，写"X 拒绝了 Y"前必须逐行核对判定顺序；MSVC 默认不报漏枚举，要守住枚举完备性必须把 switch 提成可单测纯函数。
### 批 41（`9e30a01`）—— `verify.ps1` 主路径从未通过（Debug 下的相对倍率断言）

**发现**（本轮首次端到端跑 `verify.ps1 -LinuxBuild`）：`ui` 测试在 Debug 下确定性失败。
```
FAIL tests/test_ui.cpp:252  new_us <= 0.6 * ref_us
Debug ratio 0.77 / 0.79 / 0.77 (三次稳定)   Release ratio 0.39 / 0.41
```
该断言是**相对倍率**，`-Od` 下标量参考循环与被向量化的快路径一起放慢、比值反转。
⇒ 自 `f77b90f` 引入起，`verify.ps1` 的默认路径**每次都红**。

**为什么长期未发现**：我所有"全绿"都来自 Release 的 `build`；`verify.ps1` 用 Debug 的 `build\verify`。
**两个构建目录，只盯了一个**。且 `-LinuxBuild` 连续多轮记 UNVERIFIED 而未运行（例 44 形态）。

| 项 | 处置 |
|---|---|
| `test_ui.cpp` | `#if defined(NDEBUG)` 围住测量 + 两条断言；Debug 打印 `skipped: relative timing requires an optimized build (NDEBUG)` |
| gate | RelWithDebInfo 阶段增建并执行 `rtsc_ui_tests`，断言 `UI_RELEASE_EXIT=0` + 无 skip 文案 + `checks >= 86`；**不重犯批 33 的"改成 skip 就完事"** |
| `verify.ps1` | needle 补 `UI_RATIO=executed`；124/137 拆两种措辞（采纳审计 X） |
| 注释 | 修正批 39 那段自相矛盾的注释（求值顺序 + `:81/:82` 对 PG 输出不起决定作用） |
| 文档 | `docs/spec/input-injection-seam.md` 补 `InputEventKindToken` 声明（批 39 漏） |

**`UI_MIN_CHECKS=86` 来由**：Linux 20 tests/86 checks；Windows 50/265（Win32-only 用例差额）。
实测 Linux Debug 84 / Release 86，差 2 = 两条计时断言。

**可证伪性**
| 变异 | 结果 |
|---|---|
| `RgbaToBgra` 每次迭代插 64 次 volatile 自旋 | Release ratio 11.31，`:253`/`:254` 双红 |
| `#if defined(NDEBUG)`→`#if 0` + 改 skip 文案 | `UI_RELEASE_EXIT=0` 但 `ui ratio body did not run (checks=84, want >=86)` |

**验证**：Windows Release 六类诊断全 0 + ctest **69/69**；Windows Debug ctest **69/69**（修前 68/69）；Linux `LINUX GATE PASS` 67/67 + `VIEW_BUDGETS=executed`(7348) + `UI_RATIO=executed`(86)。

**教训（discover 例 51）**："全绿"必须指明构建类型与目录；默认配置才是主路径；UNVERIFIED 会累积成盲区；修一类缺陷必须全仓扫描同型（本例 7 处计时断言中仅 2 处是相对倍率）。
### 批 42（`1b38b8c`）—— checks 下限可被补足（审计 X）：改用体内部标记行

**缺陷**（同族第三次复发）：批 41 的 `UI_MIN_CHECKS=86` / `VIEW_MIN_CHECKS=7348` 是"产出量下限"，
而 checks 统计的是"执行了多少次 CHECK" ⇒ **任何无关恒真 CHECK 都能补足**。

| 攻击（真 gate 端到端） | 旧代码结果 |
|---|---|
| ratio 体 `#if 0` + 改文案 + 补 2 个恒真 CHECK | `86 checks` / `UI_RATIO=executed` / `LINUX GATE PASS` |
| bench 体 `#if 0` + 补 7 个恒真 CHECK | `7348` / `7348 >= 7348` / gate PASSES |

**非对抗也会打开**：X 的 GROW 实验——正常给 `test_ui.cpp` 加 2 个 CHECK 后基线变 88，
此后 body 失效正好落在 86 下限上（GROW=2 → PASSES）。测试自然增长会自己打开这个洞。

**修复**：断言**只有该体才产生**的副作用（体内部 `printf` 输出行）
- view：`grep -c "\[bench\]" >= 7`
- ui：`grep -q "rgba->bgra 1280x1024:"`
- checks 下限**降级**为"套件规模异常"的辅助检查，不再承担举证责任

**可证伪性**
| 攻击 | 结果 |
|---|---|
| view `#if 0`+补7 CHECK+改文案 | `EXIT=1`，`bench lines=0, want 7` |
| ui `#if 0`+改文案+补2 CHECK | `EXIT=1`，`measurement line missing` |
| ui `#if 0`+改文案+补3 CHECK（GROW） | 同上 `EXIT=1` |
| 未改代码 | `VIEW_BUDGETS=executed` / `UI_RATIO=executed` / `LINUX GATE PASS` |

**顺带修注释第 4 版**（例 53）：`:80` 是 `!mapped || !pixels_are_physical`（OR），
任一半翻转仍被拒、两半全 true 才通过；且 `PartialGeometry` 即使两半全 true 仍被 `:82`
空 capture 拒（`InjectRect` 默认 width/height=0），**永远不会 mapping**。
（v1 错"span 先拒"、v2 自相矛盾、v3 把 OR 当 AND 且错说会 mapping。）

**验证**：Linux `LINUX GATE PASS` 67/67 + `VIEW_BUDGETS=executed`(7348) + `UI_RATIO=executed`(86)；
Windows Release 六类诊断全 0 + **69/69**(74.33s)；Windows Debug **69/69**(75.82s)；全仓 `MUT-` 0。

**结论更正**：接受审计 X 对批 38 的更正（PASS → PASS-with-caveat，当时未验"补 CHECK"路径）。
本批 view/ui 一并收口，批 33/35/38/41/42 这一族（"用可被补足的聚合量举证执行"）结束。

**教训（discover 例 52/53）**：判断"某段代码执行了吗"的唯一可靠证据是该段代码**自己产生的副作用**；
写注释前必须逐行核对判定顺序、`&&`/`||` 方向与默认值，改三次仍错就改为先做实验。
### 批 43（`f8c24e8`）—— 用例 52 的原则回头扫：P0 断言也有"补 CHECK"洞

批 42 修完 view/ui 后，把例 52 的判据（**"这个证据，除了我要证明的那段代码，还有谁能产生？"**）
当作**检查项**回头扫 gate 的其余断言，当场发现批 35 的 P0 有完全相同的洞。

| 项 | 内容 |
|---|---|
| 缺陷 | gate 断言 `tests>=8 && checks>=67`；把 `CHECK(got_challenge)` 换成两个 `CHECK(true)`，checks 67→68（仍≥67）⇒ `EXIT=0` / `P0_REGRESSION=executed` / `LINUX GATE PASS`，drain 回归断言消失 |
| 修复 | P0 成功路径打印 `  drain: challenge surfaced after coalesced record`（全仓唯一）；gate 断言该行 |
| 红证 | 同一攻击 ⇒ `EXIT=1`，`drain marker missing`，且变异体 checks=68 **仍高于 67** ⇒ 抓住它的是标记行 |
| 绿证 | 未改代码 ⇒ `P0_REGRESSION=executed`，8 tests/**67** checks，PASS |

**gate 断言分类自查（此后必须维持）**
- **身份类**（不可被别处产生）：`REQUIRED_TESTS`(ctest -N 名字) / `FACTORY_SYMBOL`(nm 符号) /
  `P0_REGRESSION`(体内标记行) / `VIEW_BUDGETS`([bench] 行数) / `UI_RATIO`(测量行)
- **零值类**（不能假）：`FAILED_COUNT=0` / `WINDOWS_H_COUNT=0` / 各 `*_EXIT=0`
- **下限类**（仅辅助，不再承担举证）：`SEC/VIEW/UI_MIN_CHECKS`
⇒ 已无任何断言依赖"总数达到下限"来证明某段代码执行过。

**本轮自身失误**：提交信息写"修后 8 tests/68 checks"，实测仍是 **67**（新增 printf 不产生 CHECK）。
凭推理写数字 = 未验证断言，已更正。

**验证**：Linux `LINUX GATE PASS` 67/67 + `P0_REGRESSION=executed` + `VIEW_BUDGETS=executed`(7348) + `UI_RATIO=executed`(86)；Windows Release 六类全 0 + **69/69**(73.93s)；全仓 `MUT-` 0。

**教训（discover 例 54）**：新原则确立后必须立刻回扫既有全部同类断言；"加了两道断言"≠"两道都可靠"（可能依赖同一个可旁路量，应按证据来源分组而非按条数）；**修改后必须重新测量数字，凭推理写的数字同样是未验证断言**。
### 批 44（`a9f69ca`）—— 更正批 43 的覆盖声明：标记行证明路径，不证明断言存在

审计 X 用真 gate 推翻我两处结论，我独立复现确认**他全对**。

| 我的错误 | 实测 |
|---|---|
| 批 43 声称"攻击 B（`CHECK` → 两个 `CHECK(true)`）→ EXIT=1, drain marker missing" | **EXIT=0 / LINUX GATE PASS**。我当时把 printf 与 CHECK **一起删了**，那才是 marker 消失的原因 |
| 断言分类把 `P0_REGRESSION` 归入"身份类（不可补足）" | 攻击 C（只删 `CHECK(got_challenge)`、保留 printf）→ **EXIT=0**。它是**路径类** |

**根因（原理性）**：`CHECK` 宏只调 `report_failure`，**不中止、不改控制流**（`tests/test_framework.h:47-53`）。
任何"产出物断言"（日志行 / 文件 / 计数）只能证明**这段路径被走到**，不能证明**某条断言语句还在**。
X 验证了互斥成功/失败双标记设计，同样关不掉"删断言"。

**处置**：不加新机制（不存在能检测"删断言"的机制），而是**把边界写进代码**
- `scripts/linux-build-gate.sh`：新增 COVERAGE BOUNDARY 段
- `tests/test_server_security.cpp`：写明 What it proves / What it does NOT prove

**gate 断言三档分类（更正后）**
| 档 | 断言 | 能力 |
|---|---|---|
| 身份类 | `REQUIRED_TESTS`(ctest -N 名字) / `FACTORY_SYMBOL`(nm 符号) | 不可被补足 |
| **路径类** | `P0_REGRESSION` / `VIEW_BUDGETS` / `UI_RATIO` | 证明"走到了"，不证明"断言还在" |
| 计数类 | `SEC/VIEW/UI_MIN_CHECKS` | 仅辅助 |

**额外探查（未改代码，登记为未验证）**：为确认 P0 是否守护 drain 实现，对
`tls_schannel.cpp` / `tls_openssl.cpp` / `security_layer.cpp` 的 4 处 drain 位置做变异，
**P0 均未变红**（`M7`、`max_out>=1`、两处 `buffered_input` 循环、`pending_cipher_` 不 Receive）。
最后一种被其它用例抓到（3 failing），但 P0 不是守卫者。
⇒ **P0 的 drain 语义守护强度 UNVERIFIED，不宣称它守住了 drain。**

**验证**：Linux `LINUX GATE PASS` + 三标记均 executed；Windows Release 六类全 0 + **69/69**(81.79s)；全仓 `MUT-` 0。

**教训（discover 例 55）**：变异必须唯一且**先跑后写**——我这次先写结论后跑变异，结果两者不对应；
"修复生效"的证据必须由脚本原始输出产生；产出物断言的覆盖上限是"路径"而非"断言存在"。
### 批 45（`261582c`）—— 更正 P0 守护点：是 `server_security_layer.cpp:194`，不是客户端 mirror

**我批 44 第 3 节错了**：4 个变异全部打错文件，因此"P0 没守住 drain"是错误结论。
审计 X 指出并复现，我独立确认。

| 我改的 | 实际是什么 | 为何无效 |
|---|---|---|
| `tls_schannel.cpp` M7 | Windows 后端 | Linux gate 不编译 |
| `tls_openssl.cpp` 的 `max_out` 分支 | 后端通用 | 本用例 `max_out=0`，走不到 |
| `security_layer.cpp:244/:321` | **客户端 mirror** | 注释自述 "The server half is the critical path; this client mirror…" |
| 同文件 `pending_cipher_` 不 Receive | 同上 | 同上 |

P0 用 `ServerSecurityLayer`，drain 在 `src/security/server_security_layer.cpp:194`；
`tests/test_server_security.cpp:35` 注释**本身就写着** "which lives in ServerSecurityLayer::DriveCredssp"。

**更正后的结论**
- 改 `:194` → P0 **红**（`test_server_security.cpp:611 got_challenge`，**唯一失败用例**）
  ⇒ P0 是 `:194` 的唯一守卫，**批 34 结论成立，UNVERIFIED → VERIFIED**
- 改 `:292`（`ReceivePdu` 数据面 drain）→ 整棵 ctest **67/67 全绿**
  ⇒ **新登记（中）**：`:292` 无任何用例守护

**处置**
- `server_security_layer.cpp:292` 加 COVERAGE 注记（无覆盖 / 关掉全绿 / `:194` 在另一阶段不能替代 / 触达条件）
- `test_server_security.cpp:600-603` 补"守护点是 `:194`，本用例是它唯一守卫"
- gate COVERAGE BOUNDARY 同步；`LIB_BYTES` 标注 `output only, not asserted`

**本轮自身失误**：`WriteAllLines` 改 gate 时**又**写 CRLF 导致 `bash -n` 失败（例 47 复发，已记过一次）。

**验证**：Linux `LINUX GATE PASS` 67/67 + 三标记 + `FAILED_COUNT=0`；Windows Release 六类诊断全 0 + **69/69**(87.04s)；`bash -n` SYNTAX_OK；全仓 `MUT-` 0。

**教训（discover 例 56）**：变异必须先从测试里的类名 grep 出**被测对象的实现文件**再下手；
"变异全绿"除了"无人守护"还有"打错位置"这一解释；镜像/对称实现是最危险的误伤点。
### 批 46（`8739643`）—— 给 `:292` 数据面 drain 补用例（采纳审计 X 的 59+8 行方案）

**我批 45 的判断错了**：我写 `:292` "no current test constructs"，只留边界注释。
审计 X 反对并**自己写出用例跑通红→绿**。我采纳。

**我的推理缺陷**：只搜了 `ReceivePdu`（测试里无调用）就断定"无法构造"。
**到达该循环的配方就在同一测试文件里**——`server_security_layer_hybrid_without_ex_omits_euar`
（`:231-291`）用 `ScriptedTls` + 3 次 `Step()` + 5 步 CredSSP 到 `Want::kDone`，
唯一缺的是 `ScriptedTls::buffered_input()` 硬编码 `return 0`。

**实现**
- `tests/test_tls_scripted.h`（+24 行）：`buffered_input()` 返回 `buffered_`（默认 0）；
  `stage_for_test(bytes)`；`Receive(nullptr,0)` 吐出暂存并清零
- `tests/test_server_security.cpp`（+72 行）：`server_security_layer_data_plane_drain_lifts_coalesced_record`
  —— 驱动到 `kDone` → stage 一条完整 TPKT → `ReceivePdu(nullptr,0)` → 要求 1 个 frame 且内容相同

**可证伪性（Linux RelWithDebInfo 真跑）**
| 状态 | 结果 |
|---|---|
| 正常 | 9 tests / 79 checks, 0 failing |
| `:292` → `while(false)` | **9 tests / 78 checks, 1 failing**，`:361 frames.size()==1u (got 0, want 1)`，**唯一失败者** |
| 恢复 | 全绿，`MUT-` 0 |

**顺带**：`:292` 注释由 "no test exercises this branch" 改为 "Guarded by <用例名>"
（消除会过期的断言与悬空 plan.md 批号引用）；gate 的 COVERAGE BOUNDARY 保留（描述 P0 marker 的能力边界）。

**验证**：Linux `LINUX GATE PASS` 67/67 + 三标记 + `FAILED_COUNT=0`；
Windows Release 六类诊断全 0 + 直接跑 8/72（含新用例）+ ctest **69/69**(85.94s)；全仓 `MUT-` 0。

**教训（discover 例 57）**："没有现成用法" ≠ "无法构造"——宣布不可测前必须问
"进入该状态的最短路径是什么、哪个已有测试到达了相邻状态"；
边界注释是会过期的断言，**可验证的就不该只写边界**（W5 的"写明"仅适用于原理上不可验证的情形）。
### 批 47（`abd1f3e`）—— C9 同型排查：客户端 3 处 drain 全部无守护

批46 修 `:292` 时我只看了记忆里的同型点。`git grep -n buffered_input` 真扫全仓
（6 实现 + 5 调用点）发现 `src/security/security_layer.cpp` 还有 3 处 drain：
`:244`（DriveCredssp）、`:321`（DriveEuar）、`:409`（ReceivePdu）。
**逐个 `while(false)` 后整棵 ctest 67/67 全绿 —— 三处都无守护。**

新增 3 个用例（tests/test_security_layer.cpp，+120 行），复用已有配方 +
`ScriptedTls*` 裸指针 + `stage_for_test`。红证：

| 变异 | 结果 |
|---|---|
| `:244` → `while(false)` | 22/162，**1 failing**；`:368 r.want == kWrite` |
| `:321` → `while(false)` | **1 failing**；`:406 r.want == kDone` + `:407` |
| `:409` → `while(false)` | **1 failing**；`:449 frames.size() == 1` |
| 恢复 | 22/162，**0 failing**；`MUT-` 0 |

三处注释改为 "Guarded by <用例名>"；原 :242 "The server half is the critical path;
this client mirror keeps the two symmetric." 已不成立，一并替换。

验证：Linux gate `LINUX GATE PASS` 67/67 + 五标记 + `FAILED_COUNT=0`；
Windows Release 六类诊断全 0 + ctest **69/69**（78.95s）；`bash -n` SYNTAX_OK；`MUT-` 0。

教训（discover 例 58）：WriteAllLines 恒用环境换行（与扩展名无关，例 47 的根因）；
按行号改文件前必须核对目标行内容，能按文本锚点替换就不要按索引，改完必须 `git diff` 逐行确认。
### 批 48（`7bfb413`）—— 修 `TlsByteTransport::Read` 死循环

`src/net/gateway_transport.cpp:555` 的 `if (tls_->buffered_input() > 0) continue;` 在
`for(;;)` 里：后端持**不完整** TLS 记录时 `Receive(nullptr,0)` 返回 `kNeedMoreInput`
且不消耗，`buffered_input()` 永远 > 0 → 死循环。

**红证**：`ScriptedPartialRecordTls` + 新用例，修复前 `receive_calls == 1 (got 101)`、
`n == kReadTimeout (got -1)`；修复后 120/1210 全绿。

**修法**：`buffered_before` 前后对比，只有缓冲**减少**才 `continue`；否则落到 `raw_->Read`。

**C9 复扫**：全仓 5 个 `buffered_input()` 循环，仅此一处缺逃逸；其余四处都是
`while` + `if (status == kNeedMoreInput) break;`。

验证：Linux gate `LINUX GATE PASS` 67/67 + 五标记；Windows 六类诊断全 0 + ctest **69/69**(74.55s)；
`MUT-` 0。首次 gate 因 view bench 偶发红（0.89 vs 0.60），同二进制连跑 5 次 0.11-0.12 全绿，
判定环境噪声（discover 例 60），未调 budget。
### 批 49（`5300160`）—— 修行号引用漂移 + 更正例58 编造出处

审计 X 复核批46/47 全 PASS，提 2 条文档缺陷，我自验两条都成立。

**缺陷 1（中）**：批47 插注释导致行号下移，注释里的 3 处引用没同步
（`test_security_layer.cpp:373` 应 `:323`、`:411` 应 `:413`、
`test_server_security.cpp:294` 应 `:300`）。**修法：5 处全改符号引用**
（`SecurityLayer::DriveEuar` 等），`git grep` 行号引用归 0。

**缺陷 2（低但性质严重）**：例58 我写"例47 记的是改 .sh 禁止 WriteAllLines"——
**编造出处**。例47（`:724`）实际讲 `ReadAllText`+`WriteAllText` 加 BOM、CRLF→LF，
方向相反。已用实测替换：`ReadAllText`+`WriteAllText(UTF8 no BOM)` 忠实保留行尾；
`WriteAllLines` 恒用环境换行且非幂等（每次 +1 尾部换行）。
唯一规则：只用 ReadAllText→Replace→WriteAllText，禁用 WriteAllLines，写完必查 CR/LF。

采纳 X 第三条：多处按索引插入必须从后往前。

验证：C0 六类诊断全 0；Linux ctest 67/67；Windows ctest 69/69（73.79s）；
Linux gate `LINUX GATE PASS` + `FAILED_COUNT=0`；`MUT-` 0。
### 批 50（`2d07aee`）—— 修 `orders_apply.h` 的过期断言

`include/rtsc/render/orders_apply.h:50` 称 "BS_HATCHED and BS_PATTERN are not implemented yet
(TODO 3b3)"，实际 `src/render/orders_apply.cpp:337-342` 早已分发。与例57 同族：会过期的断言。

变异证明新注释为真：`BS_PATTERN` → `false &&` = 5 failing/224 failed checks；
`BS_HATCHED` → `false &&` = 5 failing/1870 failed checks；恢复 103/5793 全绿。

C9 同型复查：`capabilities.cpp:722`、`orders_apply.cpp:347`、`gateway_transport.h:299` 均准确；
`cliprdr_client.h:94`/`file_list.h:5` 属 feature-gap（UNVERIFIED）。

验证：C0 六类诊断全 0；Linux 重建 0 错误 + 103/5793；Windows ctest **69/69**（78.35s）；`MUT-` 0。
### 批 52（`5349d77`）—— kClosed 明文丢失 + 陈旧构建守卫

**B（审计 X 报，低-中）**：`gateway_transport.cpp` 两处 `&& status != kClosed`
把"明文非空 + 同时报关闭"的数据丢弃。两后端均可达（OpenSSL `:390-398`、
SChannel `:654-658`）。新增 `ScriptedClosingTls` + 2 用例，红→绿，各自变异唯一守护。
drain 分支加 hardened EOF。

**C**：`orders_apply.h` 的 kUnsupported 说明补上"已处理但参数越界"。

**顺带**：`Write` 期间明文入队（`pending_.insert`）此前零覆盖，新增
`ScriptedReadDuringWriteTls` + 用例，变异验证。

**更正**：`:655` 的 `e.status` 是我自己的变异残留，HEAD 无此缺陷。

**verify.ps1 陈旧构建守卫**：批51 的 dry-run 判据抓不到 mtime 回退；
改为内容+size+mtime 指纹，不一致即删目录重建。红证：mtime 回退 30 天触发重建。

验证：C0 全 0；gateway 124/1234；Linux ctest 67/67；Windows ctest 69/69；
`verify.ps1` 与 `-LinuxBuild` 均 EXIT=0（后者 LINUX GATE PASS）。
### 批 53（`9389bd8`）—— verify.ps1 指纹改内容哈希 + M3/M5 覆盖

**4 个指纹洞（审计 X 攻击，实测确认）**：A `assume-unchanged`、B 未跟踪文件、
C `showUntrackedFiles=no` 三种都能让旧指纹"不变"；D git 失败时 fp 退化为 `SHA256("")`（fail-open）。
**修法**：改为 `Get-ChildItem -Recurse -File -Force` + 逐文件 SHA-256，不依赖 git；枚举为空即 `exit 1`。
顺带解决"改 docs 就全量重建"的成本问题（实测不再触发）。

**M3**：hardened EOF（`:565`）零覆盖 → 补二次 Read 断言，红证 `:3931`/`:3932`。
**M5**：`ScriptedReadDuringWriteTls` 加 `close_with_data`，新增 kClosed-during-Write 用例，
红证 `:4007`。注：X 的 `&& e.status` 变异是等价变异（e 恒 kOk），不可杀也不说明测试弱。

**注释更正**：`ScriptedClosingTls` 的 "real backend answers kNeedMoreInput" 只对 SChannel 成立。

验证：C0 全 0；gateway 125/1243；Linux 67/67；Windows 69/69；Linux gate PASS；`MUT-` 0。
### 批 54（`40d2d47`）—— 指纹补 reparse point fail-closed

审计 X 复核批53 全 PASS，残留 1 洞：`Get-ChildItem -Recurse -File` 静默跳过接合点/目录符号链接
（我自己复现：接合点下的 `value.h` 完全不在结果里且不报错）。配 mtime 回填 → Ninja 也不重编
→ "树变了但 verify 报绿"。

修法：遍历前扫 reparse，有则 `exit 1`。红证（抽取 verify.ps1 真实代码块）：干净树 exit=0，
加接合点 → `fingerprint refuses to run: 1 reparse point(s) ... cannot be hashed` exit=1。
当前四树 reparse=0，两个 verify 入口均 EXIT=0。

表述更正：n2 断言 `:3934/:3935`、Write-kClosed `:4010`；"MUT- 0" 精确为"构建输入 0"。
### 批 55（`5993d24`）—— 只拒绝目录型 reparse + 显式 -ErrorAction Stop

审计 X 复核批54 PASS，报两条加固项，实测均成立。

**加固 1**：两处 `Get-ChildItem` 缺 `-ErrorAction Stop`，权限拒绝的子树只靠全局 EAP 兜底。
实测无该参数 + EAP=Continue + deny 时，fp 与"文件不存在"**逐字节相同**（静默跳过）。已补。

**加固 2**：批54 拒绝所有 reparse，但 OneDrive 未水合文件也是 reparse（实测 392/400），
会永久 exit 1。实测发现**文件型 reparse 会被 `-Recurse -File` 枚举**（可哈希），
只有目录型是盲区。改为只拒绝 `PSIsContainer -and ReparsePoint`。

红证（抽取真实代码块）：干净 exit=0；文件链接不拒绝且目标变化被抓；目录接合点 exit=1；恢复 fp 原值。
验证：`verify.ps1` 与 `-LinuxBuild` 均 EXIT=0（后者 LINUX GATE PASS）；构建输入 MUT- 0。
### 批 56（`d4f341a`）—— view bench 按测量重设

三个数：空闲 0.11-0.16ms / 噪声峰值 0.89ms（并行构建，7.4x）/ 真实回归 1.47-1.53ms（12-14x）。
每用例新增 `iters` 使样本 ≥10ms（抹平小用例 7.4x vs 大用例 2.1x 的负载敏感度差异）；
预算改为约 4x 空闲值；有界单次重试。
Rule 16：逐像素+除法 → 11 用例红；float 混合 → 1:1 22ms、6 用例红；恢复全绿。

### 批 57（`f68eeb9`）—— flood witness 确定性化

X 报负载下 flaky，我 14 次全绿未复现，但代码结构分析出真因：launcher 在 accept 循环里同步
调用（`server.cpp:2491`），旧实现赌测试线程在 40ms 内反应。改为入口计数识别最后一个 launcher +
有界等待 `stop_began`。
Rule 16：跳过所有 `session->Stop()` → `RED_TIMEOUT live=8` + `FAIL stop_cleared`，不变量仍 load-bearing。

### 环境（例 70）
WSL 被 `/mnt/f/tctp` 交叉编译占满（load 8.7）+ sqlservr/beam.smp，解释三次 bench 偶发红。

验证：C0 全 0；server 55/641；view 60/7348；Linux 67/67；Windows 69/69；Linux gate PASS；MUT- 0。

### 批 58（`9beeab0`）—— flood 测试的注册等待预算随 launcher 暂停缩放

按"分支完备"逐个跑 `RTSC_TEST_LAUNCH_DELAY_MS`，发现 **`delay_ms=200` 时测试自己红**
（`launches=6 registered=-1`、2 failed checks），`{0,1,5,40}` 全绿。
根因：launcher 在 accept 循环里同步执行 ⇒ `delay_ms × (kConnect-1)` 串行化注册，
而用例的注册等待固定 1 s。失效阈值约 140 ms。
修法：`register_budget_ms = min(2000 + 4 × delay_ms × kConnect, 60000)`。
验证：delay ∈ {0,1,5,40,200,1000} × 2 次 = 12/12 绿，`started_after_stop=1` 恒定。
Rule 16：缩放预算 → 固定 1000 ⇒ **只有 delay=200 红**，其余全绿。
C0：六类诊断全 0；Linux 67/67（84.84s）；Windows 69/69（74.37s）；Linux gate PASS；MUT- 0。