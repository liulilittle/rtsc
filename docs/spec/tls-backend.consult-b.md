# TLS 后端磋商（乙）：对甲设计报告的独立评审

> 评审对象：`docs/spec/tls-backend.design-a.md`（695 行）。
> 评审方式：按硬约束只做 `Select-String` 定位 + 分段读（每次 ≤100 行），未全量通读、未联网、未跑新探针。
> 本文所有实测数字均来自 `F:\rtsc\.tmp\tlsprobe\probe*.exe` 的既有输出（46 个探针、7.7k 行），
> 逐条给探针编号，可复跑。
> 立场：**甲的方向（Windows=SChannel / 双后端 / 接口抽象）我完全同意**。分歧全部集中在
> "接口签名是否承载了 SChannel 的真实语义"，这是本文唯一重点。

---

## §0 裁定摘要

| # | 甲的主张 | 裁定 | 一句话理由 |
|---|---|---|---|
| 1 | §3 `TlsTransport` 接口（12 Status + `RecordSizes` + 双 SPKI）覆盖测试前置契约 | **部分成立** | 结构对，但缺 5 项可观测契约 + 1 处签名承载了错误语义（`consumed`）+ 1 处让 TLS1.3 默认路径必然出错（`Receive` 外泄 `kRenegotiate`） |
| 2 | `DecryptMessage` 需要 4 个 SecBuffer | **成立，与我的实测一致** | 双方都是 4；但甲的**接口契约文字里没有这条**，只存在于 T1 探针代码，属"证据有、契约无" |
| 3 | T1 进程内回环已 `RESULT=PASS` | **成立**（我独立复现过同类回环） | 但 T1 只覆盖我 5 类测试中的 1 类半，且甲**未写"发现不了什么"**，其中一条恰好是致命的那条（post-handshake 票据） |
| 4 | §8 有 11 条缺陷（D1–D11） | **成立但条数不是 11** | 合并后 **17 条**（甲 11 + 我 16 − 重叠 10）；甲独有 1 条（SPKI 294/270 混淆），我独有 8 条 |
| 5 | §6 未验证项 U1–U10 | **部分已由我实测关闭** | U1/U2/U7 已关闭；U8 部分关闭；U5 已由官方页面关闭；U3/U4/U6 仍开；U9/U10 双方都已关闭 |

**最关键的一条**（甲完全没提到、且会让默认配置直接出错）：

> 甲 §3.4 的伪代码 `if st == RENEGOTIATE: return kRenegotiate` + `§3.3` 的调用方契约里
> **`Receive` 没有 `kRenegotiate` 这一行**。而 TLS1.3 服务器在握手刚结束就会发
> NewSessionTicket，SChannel 把**它**报成 `SEC_I_RENEGOTIATE`
> `[probe34: 握手后 recv 103 字节 → DecryptMessage 0x00090321，EXTRA 103 字节，内容 16 03 03 00 62 04 ...]`。
> 结果是：**默认 `allow_tls13=true` 的路径上，第一次 `Receive` 就返回一个未定义的 Status，
> 且 103 字节已被从 `rx_buffer_` 里 erase 掉**（伪代码第 325 行的 erase 在 RENEGOTIATE 分支之后，
> 但第 322 行 `return kRenegotiate` 提前退出 → 记录留在缓冲里 → 下次重喂 → `0x80090330` 上下文废）
> `[probe39: 重喂同一票据 → 0x80090317；probe18-A: 丢 EXTRA 后下一条 0x80090330]`。
> 这不是"实现细节要注意"，是**签名与契约互相矛盾**。

---

## §1 接口签名层面的具体修正（本文核心）

逐条给：**甲的具体签名 → 错在哪（实测）→ 应改成什么**。共 **12 处**，按严重度排序。

### 修正 1（致命）：`Receive` 不得把 `kRenegotiate` 交给调用方

- 甲的签名：
  ```cpp
  virtual Error Receive(const uint8_t* ciphertext, size_t size,
                        std::vector<uint8_t>& plaintext, size_t max_out) = 0;
  ```
  配 §3.4 伪代码 `if st == RENEGOTIATE: return kRenegotiate;`。
- 错在哪：TLS1.3 的 NewSessionTicket 走的就是这条路
  `[probe34: 0x00090321，EXTRA=103，手写类型 0x04 = NewSessionTicket]`。
  §3.3 的 `Receive` 契约表（303–304 行）只有 `kOk` / `kNeedMoreInput` / `kClosed` / `kDecryptFailed`，
  **没有 `kRenegotiate`** → 调用方拿到未定义值；且 RDP 层不可能"重新进入 Handshake"
  （CredSSP 之后重跑握手会破坏 pubKeyAuth 绑定的 SPKI 假设）。
- 应改成：
  ```cpp
  // Receive 内部必须消化所有 post-handshake 消息；绝不允许把它们外泄成状态码。
  // 契约：返回 kRenegotiate 属于实现 bug。
  virtual Error Receive(const uint8_t* ciphertext, size_t size,
                        std::vector<uint8_t>& plaintext, size_t max_out) = 0;
  // 后端内部：st==SEC_I_RENEGOTIATE 时
  //   (a) 若协商为 TLS1.3：把 EXTRA 原样喂回 ISC_REQ_STREAM 一次，产出丢弃（票据不需要回写）；
  //   (b) 若协商为 TLS1.2：拒绝并返回 kProtocolError（RDP 场景不允许重协商，见 §4-3）。
  ```
- 附加：`Status` 里删除 `kRenegotiate`，或改为 `Handshake` 专用返回值（`HandshakeResult`），
  不让它出现在 `Receive` 的值域里。

### 修正 2（致命）：`Handshake` 的 `consumed` 语义写反了

- 甲的签名（本身没问题）：
  ```cpp
  virtual Error Handshake(const uint8_t* in, size_t in_size,
                          size_t& consumed, std::vector<uint8_t>& out) = 0;
  ```
  但 §3.5 映射表第 340 行写：`consumed = in_size`（"SSPI 吸收全部输入"）。
- 错在哪：实测 SChannel **会**在握手输入上返回 `SECBUFFER_EXTRA`，而且 **`pvBuffer == NULL`**：
  ```
  [probe44] ClientFlight2: 0x00090312 out=158  input=838
    in[0] type=TOKEN  cb=838 ptr=... offset=0
    in[1] type=EXTRA  cb=64  ptr=0000000000000000 offset=-1
  ```
  即：`in[0].cbBuffer` **仍是全量 838**（没有被改写成"已消费"），EXTRA 只给长度、不给指针。
  两个"自然写法"都错：
  - `consumed = in_size` → 丢掉尾部 64 字节（可能是下一条记录的开头）；
  - `consumed = in[0].cbBuffer` → 也是 838，同样丢。
  `[probe42] TLS1.2 junk=32: consumed=83 extra=32 input=83`（consumed 若按 in_size 则为 115）。
- 应改成：契约里写死
  ```cpp
  // consumed 的计算规则（唯一正确写法）：
  //   consumed = in_size - Σ(EXTRA.cbBuffer)   // 且 EXTRA 的 pvBuffer 可能为 NULL，
  //                                            // 只允许读 cbBuffer，禁止解引用
  // 若 Σ(EXTRA) > in_size 或出现 >1 个 EXTRA：kInternal
  ```
  并加断言：`consumed + Σ(EXTRA) == in_size`。

### 修正 3（严重）：`RecordSizes::max_record()` 把"上界"当成了"实际线长"

- 甲的签名：
  ```cpp
  struct RecordSizes {
    uint32_t header = 0;
    uint32_t trailer = 0;         // 明文之后的字节数（GCM tag = 16）
    uint32_t max_plaintext = 0;
    uint32_t block_size = 0;      // 对齐粒度（GCM/流模式 = 1）
    uint32_t max_record() const noexcept { return header + max_plaintext + trailer; }
  };
  ```
- 错在哪（两处，都有实测）：
  1. TLS1.3 下 `cbTrailer = 44` 是**上界**，实际尾长 17：
     `[probe21] TLS1.3 hdr=5 trl=44；payload=16 → wire=38（5+16+17），hdr+len+trl=65`。
     `max_record()` 在 TLS1.3 得 16433，实际最大线长 16406，**多 27 字节**。
     若测试写 `CHECK(Send(16384).size() == record_sizes().max_record())`，TLS1.3 必失败。
  2. `block_size` 注释"GCM/流模式 = 1"与实测相反：TLS1.2 GCM 实测 **16**
     `[probe4: stream sizes header=13 trailer=16 maxmsg=16384 block=16]`。
- 应改成：
  ```cpp
  struct RecordSizes {
    uint32_t header;               // 明文前的字节（TLS1.2 GCM=13；TLS1.3=5）
    uint32_t max_plaintext;        // 单次 EncryptMessage 上限（实测 16384）
    uint32_t overhead_upper;       // 明文后的上界（TLS1.2=16；TLS1.3=44）
    uint32_t overhead_actual;      // 实测实际尾长（TLS1.2=16；TLS1.3=17）★新增
    uint32_t block_size;           // 实测 16（不是 1）
    // 明确命名：这是分配上界，不是 Send 的返回长度
    uint32_t alloc_upper_bound() const { return header + max_plaintext + overhead_upper; }
  };
  // 契约：Send 的实际输出长度只能取 out.size()，禁止用 alloc_upper_bound() 推进写游标。
  ```
  注：`overhead_actual` 对 TLS1.3 是否恒为 17 **未验证**（只测了 payload ∈ {1,2,16,100,1000,16384}，
  全部 17）。标 C。

### 修正 4（严重）：`PeerSubjectPublicKey` 的"剥 24 字节头"不可移植

- 甲的 §3.5 第 344 行："从 SPKI 里剥 24 字节头：`30 82 01 22 30 0d 06 09 ... 03 82 01 0f 00` 之后即 270 字节"。
- 错在哪：24 只对 **RSA-2048 + long-form 长度**成立。实测同一台机器生成的
  自签名 RSA-1024 证书：`SPKI=162 SubjectPublicKey=140 strip-offset=22`
  `[probe41: self-signed cert: SPKI=162 SubjectPublicKey=140 strip-offset=22 (found=1)]`。
  换成 EC 证书或 short-form 长度，偏移又不同。写死 24 → 越界/截断。
- 应改成：**根本不要剥**。`CERT_PUBLIC_KEY_INFO` 已经把两段分开了：
  ```
  [probe35] PublicKey BIT_BLOB: cbData=270 unusedBits=0
            PublicKey first 8: 30 82 01 0a 02 82 01 01
            SubjectPublicKey found verbatim inside SPKI at offset 24
  ```
  即 `cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData/cbData` **就是** SubjectPublicKey。
  签名不变，但契约改成：
  ```cpp
  // PeerSubjectPublicKey(): 直接取 CERT_PUBLIC_KEY_INFO.PublicKey.pbData（长度 cbData）。
  // 禁止用固定偏移从 SPKI 里切；实测 RSA-2048=270、RSA-1024=140，偏移 24/22 不同。
  // 必须同时暴露 PeerSubjectPublicKeyInfo()（294/162），两者长度差 = SPKI 头，不是常量。
  ```

### 修正 5（严重）：`Shutdown` 缺 `ISC_REQ_ALLOCATE_MEMORY`，且 T1 的断言首字节错了

- 甲的 §3.5 第 346 行："`ApplyControlToken(SCHANNEL_SHUTDOWN)` + 再调一次
  `InitializeSecurityContextW` 产出 close_notify"。
  而 §5 T1 的"坑"表第 2 条又说："`ISC_REQ_ALLOCATE_MEMORY` 同时又给预分配缓冲 → `0x80090331`，二选一"。
- 错在哪：这两条**互相矛盾**，且按字面执行会得到"不发 close_notify"：
  ```
  [probe40] ISC_REQ_STREAM only, null input        -> 0x80090300 out=0
            ISC_REQ_STREAM only, empty desc        -> 0x80090300 out=0
            STREAM|ALLOCATE_MEMORY, null input     -> 0x00000000 out=24
            STREAM|ALLOCATE_MEMORY, empty desc     -> 0x00000000 out=24
  ```
  即：Shutdown **必须** `ALLOCATE_MEMORY` + `pvBuffer = nullptr`（没有输入 token，谈不上"二选一"）。
  另：T1 绿证第 6 条"`Shutdown` 产出 alert（首字节 `0x15`）"在 TLS1.3 下**必失败**：
  ```
  [probe4-D] ISC after shutdown -> 24 B: 17 03 03 00 13 ...
  ```
  TLS1.3 的 close_notify 是 application_data（0x17）包裹的 encrypted alert。
- 应改成：
  ```cpp
  // Shutdown(): ApplyControlToken(SCHANNEL_SHUTDOWN) →
  //   ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY，输入描述符为 nullptr，
  //   输出缓冲 pvBuffer 必须为 nullptr（由 SChannel 分配，随后 FreeContextBuffer）。
  // 断言改为：out.size() ∈ {24, 31} 且 out[0] == (TLS1.2 ? 0x15 : 0x17)。
  ```

### 修正 6（严重）：`Receive` 必须声明"失败时 plaintext 未定义"

- 甲的签名用 out-param 返回明文，`Error` 单独返回；§3.3 只说 `kDecryptFailed` → 立即终止。
- 错在哪：实测失败时 `SECBUFFER_DATA` **仍然带长度**，内容是密文：
  ```
  [probe27] tampered -> 0x80090330 DATA cbBuffer=77 (== record size 77)
            first 16 bytes: 17 03 03 00 48 00 00 00 ...
  ```
  而甲的 T1 探针（`loopback_schannel.cpp:169-173`）是**先遍历 buffer 追加明文、后看状态**的顺序
  → 一旦被复制到产品代码，`kDecryptFailed` 时会把密文当明文交给 `ConnectMachine`。
- 应改成：契约加一行
  ```cpp
  // 当返回 != kOk 且 != kClosed 时，plaintext 的内容与长度均未定义，调用方必须丢弃；
  // 后端在返回错误前必须 plaintext.clear()。
  ```

### 修正 7（中）：`Config` 的两个 bool 无法表达 TOFU，且 strict 用错了标志

- 甲的签名：
  ```cpp
  bool verify_chain = false;
  bool verify_hostname = false;
  bool manual_cert_validation = true;   // 关链校验但保留「拿到证书」的能力
  ```
- 错在哪（三条实测）：
  1. `SCH_CRED_MANUAL_CRED_VALIDATION` 会**同时**关掉主机名校验（SDK 注释明写
     `schannel.h:544-550`："This flag is also ignored if the SCH_CRED_MANUAL_CRED_VALIDATION flag is set"）
     → 实测 `target=example.com` + MANUAL → 握手成功 `[probe15]`。所以
     `manual_cert_validation=true` + `verify_hostname=true` 是**自相矛盾的配置**，签名允许它存在。
  2. MANUAL 模式下拿不到链校验结果：`CERT_CHECK_RESULT → 0x80090301`（无效句柄）`[probe5]`。
     要"strict 但可诊断"只能用 `SCH_CRED_DEFERRED_CRED_VALIDATION`：
     `CERT_CHECK_RESULT → 0x00000000, hr=0x800B0109 (CERT_E_UNTRUSTEDROOT)` `[probe5]`。
  3. 两个 bool 无法表达 TOFU（首次信任 + pin）。甲在别处（`security-layer.md:527-537`）要求
     tofu 要 pin SPKI 的 SHA-256，接口里没有承载点。
- 应改成：
  ```cpp
  enum class CertPolicy : uint8_t { kInsecure, kTofu, kStrict };
  struct Config {
    CertPolicy cert_policy = CertPolicy::kTofu;
    std::array<uint8_t, 32> pinned_spki_sha256{};  // 非全 0 = 必须匹配
    bool pin_is_set = false;
    // kStrict → 后端必须用 SCH_CRED_DEFERRED_CRED_VALIDATION 并自行校验主机名；
    //           禁止用 MANUAL（会同时关掉主机名校验，且拿不到链结果）。
  };
  ```

### 修正 8（中）：套件号取错了字段

- 甲的 §3.5 第 347 行："`SECPKG_ATTR_CONNECTION_INFO` → `{dwProtocol, aiCipher, dwCipherStrength,...}`；
  TLS1.3 用 `SECPKG_ATTR_CONNECTION_INFO_EX`（`0x6e`）"。
- 错在哪：
  - `aiCipher` 是 **CALG**（`0x6610` = `CALG_AES_256`），不是密码套件号。
  - `CONNECTION_INFO` 在 TLS1.2 与 TLS1.3 下**都可用**（不需要 EX）：
    `[probe41] CONNECTION_INFO -> 0x00000000 proto=0x0800` / `proto=0x2000`。
  - `CONNECTION_INFO_EX` 可用但只给算法名（`szCipher="AES"`），**不给套件号**：
    `[probe41] CONNECTION_INFO_EX -> 0x00000000 proto=0x2000 cipherName="AES" hash=""`。
  - 唯一能拿套件号的是 `SECPKG_ATTR_CIPHER_INFO`：
    `[probe41] CIPHER_INFO -> 0x00000000 suite=0xC030 "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"`
    / `suite=0x1302 "TLS_AES_256_GCM_SHA384"`。
- 应改成：新增访问器，并写死数据来源
  ```cpp
  struct NegotiatedInfo {
    uint16_t tls_version;      // 0x0303 / 0x0304，来自 SECPKG_ATTR_CONNECTION_INFO.dwProtocol
    uint16_t cipher_suite;     // 来自 SECPKG_ATTR_CIPHER_INFO.dwCipherSuite（不是 aiCipher）
    char cipher_suite_name[64];
  };
  virtual Error negotiated(NegotiatedInfo& out) const = 0;
  ```
  这个访问器同时是修正 9 的断言基础（见下）。

### 修正 9（中）：`min_version/max_version` 只是"意愿"，没有强制点

- 甲的签名：`uint16_t min_version = 0x0301; uint16_t max_version = 0x0304;` + `allow_tls10/allow_tls13`。
- 错在哪：SChannel 只能表达"禁用掩码"，不能表达"min"。用 legacy `SCHANNEL_CRED` 给
  `TLS1_2|TLS1_3` → 凭证成功、握手成功、但 ClientHello **没有 supported_versions**、
  协商成 `0x0800` `[probe9/probe16]` → **静默降级，无任何错误码**。
- 应改成：保留 Config 字段，但接口增加强制点
  ```cpp
  // 契约：Handshake 返回成功前，后端必须自检 negotiated().tls_version ∈ [min_version, max_version]，
  //       越界 → kProtocolError（不允许静默接受降级）。
  // SChannel 实现必须用 SCH_CREDENTIALS + TLS_PARAMETERS.grbitDisabledProtocols 表达下限；
  // 禁止用 legacy SCHANNEL_CRED 的 grbitEnabledProtocols 表达（实测会降级）。
  ```

### 修正 10（中）：工厂函数无法注入假后端 → C/D 类测试写不出来

- 甲的签名：
  ```cpp
  std::unique_ptr<TlsTransport> CreatePlatformTlsTransport(const Config& config, std::string& why);
  std::vector<BackendInfo> EnumerateTlsBackends();
  ```
- 错在哪：`EnumerateTlsBackends()` 能列出名字，但工厂**不接受名字** → 无法在测试里
  实例化 `ScriptedBackend`，也无法在同一进程内同时持有 `schannel` 与 `scripted` 做差分。
  我的 C 类（故障注入）与 D 类（差分）测试因此无法落地。
- 应改成：
  ```cpp
  std::unique_ptr<TlsTransport> CreateTlsTransport(std::string_view backend,
                                                   const Config& config, std::string& why);
  inline std::unique_ptr<TlsTransport> CreatePlatformTlsTransport(const Config& c, std::string& w) {
    return CreateTlsTransport(kDefaultBackendName, c, w);   // "schannel" / "openssl"
  }
  // 测试构建额外注册 "scripted"，由脚本驱动返回 SEC_I_RENEGOTIATE / 0x80090318 / EXTRA 等。
  ```

### 修正 11（轻）：`kNeedMoreOutput` 与 `kRenegotiate` 在值域上是冗余的

- `Status` 里 `kNeedMoreOutput`（"调用方缓冲区不足（本接口用 vector，正常不返回）"）——
  既然正常不返回，就不该出现在公共枚举里（每个后端都要处理一个不可能的分支）。
  `kRenegotiate` 见修正 1。
- 应改成：删除 `kNeedMoreOutput`；`kRenegotiate` 移出 `Receive` 值域。

### 修正 12（轻）：缺随机源注入 → A 类 KAT 不可复现

- 甲没有 RNG 钩子。SPKI 的 KAT 只需固定证书（T1 已能做到），但
  pubKeyAuth 的 nonce / NTLM 的 ClientChallenge 需要确定性才能做逐字节向量。
  这些属于 CredSSP 层，不属 `TlsTransport`；但若 `TlsTransport` 将来要提供
  "导出通道绑定材料"（`SECPKG_ATTR_KEYING_MATERIAL` 实测 `0x80090301` 不可用 `[probe7]`），
  就必须有注入点。**本条为前瞻，非阻塞**：建议在测试构建里加
  `void set_test_rng(std::function<void(uint8_t*, size_t)>)`，产品路径不暴露。

---

## §2 §8 缺陷清单映射表

甲的 11 条（`design-a.md:367-377`）与我的 16 条（`design-b.md` §5）对应关系：

| 合并后 | 甲 | 我 | 说明 |
|---|---|---|---|
| M1 跨平台"唯一解"是事实错误 | D1 | D2 | 完全重合 |
| M2 官方无 Windows 预编译包 | D4 | D3 | 重合；我用官方页面确认（只发源码 + PGP/SHA） |
| M3 本机 perl/nasm/vcpkg 全无，源码构建不可行 | D2 + D3 | D4 | 甲拆两条，我合一条；结论一致 |
| M4 `find_package(... REQUIRED)` 会让 configure 直接失败 | D5 | D10（部分） | **甲更强**：我只写"未验证可行性"，甲指出 REQUIRED 会把 12 套全绿变成 configure 失败，这是更严重的后果 |
| M5 "SChannel 只做 TLS" 与 "系统 CredSSP SSP" 被混为一谈 | D6 + D11 | D8 + §5 补充 | 甲把它升格为编号缺陷，我放在"补充"里；**甲的组织更好** |
| M6 "TLS 部分 ≈500 行" 低估 | D7 | D9 | 重合；甲补了具体缺失分支清单 |
| M7 §8.1 能力表缺关键项 | D8 | D16 | 重合 |
| M8 MD4/RC4 走 legacy provider 是净增风险 | D9 | D5 | 重合（甲从"与 TLS 选型无关"角度，我从"运行期加载失败"角度） |
| M9 SPKI 294 vs 270 混淆风险 | **D10** | — | **甲独有**，且很重要：`i2d_PublicKey()` 给 270 而 SPKI 是 294，文档没写这层关系 |
| M10 零依赖硬约束被 §8.5 破坏却无人承认 | — | **D1** | 我独有 |
| M11 legacy provider 缺失是运行期故障（静态/FIPS 构建默认无） | — | **D6** | 我独有（与 M8 不同：M8 说"没必要用"，M11 说"用了会在现场炸"） |
| M12 依赖列表漏 `bcrypt` / `sspicli` | — | **D7** | 我独有；`QueryContextAttributesExW` 不在 `secur32.lib` → `LNK2019`（实测 probe7 首次链接失败） |
| M13 `min/max` 无法表达 + 静默降级 | — | **D11** | 我独有（红证 probe9/probe16） |
| M14 MANUAL 会同时关掉主机名校验 | — | **D12** | 我独有（红证 probe15 + SDK 注释） |
| M15 `0x6610` 不是套件号（证据文件写错） | — | **D13** | 我独有；注意错误在 `evidence/schannel-tls-backend.md:44`（"CALG_AES_256 + CALG_ECDH = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"），实测该服务器 TLS1.2 套件是 `0x009D TLS_RSA_WITH_AES_256_GCM_SHA384`（RSA kex，非 ECDHE）`[probe29]` |
| M16 FIPS 与自研 MD4/RC4 的关系 | — | **D14** | 我独有 |
| M17 `errorCode` 非严格 DER 的断言与 `ber.cpp` 冲突 | — | **D15** | 我独有；`ber.cpp:125-130` 明确拒绝非最小长度编码，若 §8 的断言为真，CredSSP 第 2 步就会失败 |

**结论：合并后 17 条**（= 我的 16 + 甲 D10）。
甲独有 1 条，我独有 8 条（D1/D6/D7/D11/D12/D13/D14/D15），重叠 8 组。

补充一条**文档缺陷**（非 §8 内容，但影响可读性）：
`design-a.md:86` 的表格两行粘连成了
`` | `0x80090318` | `SEC_E_INCOMPLETE_MESSAGE` | ... | `kNeedMoreInput` || `0x8009030F` | `SEC_E_MESSAGE_ALTERED` | ... ``
→ Markdown 渲染后 `SEC_E_MESSAGE_ALTERED` 那一行丢失，而它正是"篡改记录"要映射的码。
实现阶段照此抄会漏掉 `kDecryptFailed` 的唯一来源。

---

## §3 红证覆盖度核对

我 §3.2 的 5 类：A 确定性向量 / B 进程内回环 / C 故障注入 / D 差分 / E 真机冒烟。

| 类 | 甲的 T1 是否覆盖 | 缺什么 | T1 发现不了什么（甲未写） |
|---|---|---|---|
| A KAT | **否** | 固定证书→SPKI 的逐字节断言、DER 编码向量、`SHA256(SPKI)` 锚点 | — |
| B 回环 | **是（部分）** | TLS1.3 全流程、4-buffer 下限、1 字节喂法、65528 分片、零长明文、按版本分化的篡改行为 | ①OS 版本矩阵（回环永远用本机 SChannel）；②真实服务器套件策略；③**post-handshake 消息**——回环的 SChannel 服务端**不发** NewSessionTicket，所以 T1 永远看不到 `SEC_I_RENEGOTIATE`（我的 probe34 是连真服务器才看到的）；④静默降级（回环里客户端自己设掩码，不反映用户配置） |
| C 故障注入 | **否（只有 2 个手写负例）** | 脚本化后端、状态机分支覆盖（尤其 `SEC_I_RENEGOTIATE` / `SEC_I_CONTEXT_EXPIRED` / `SEC_E_INSUFFICIENT_MEMORY`） | 甲的两个负例（翻 tag、截断）只覆盖 `kDecryptFailed` / `kNeedMoreInput` 两条 |
| D 差分 | **否** | 自研 MD4/RC4/HMAC-MD5 vs BCrypt（本机 BCrypt 支持 MD4/RC4/MD5/SHA*/AES/3DES/ECDH_P256，HMAC-MD5 需 `HMAC_FLAG`）`[probe19]` | — |
| E 真机 | **有 T4，但标"可选/开关"** | 断言清单（版本、套件号、SPKI SHA-256、`STREAM_SIZES` 自洽、65528 往返） | — |

**最关键的一条遗漏**：甲把 U1（TLS1.3 `record_sizes`）的验证方式写成
"T1 增加一个强制 `SP_PROT_TLS1_3_CLIENT` 的用例"。
这**能**测出 `hdr=5 / trl=44`（我用回环测到了，`[probe3] TLS1.3 hdr=5 trl=44`），
但**测不出** NewSessionTicket，因为回环服务端不发票据。
所以 U1 与 U2 必须分开：U1 可用回环关闭；U2 的**真实触发路径**只有真服务器（或脚本化后端）。
甲把两者混在一个 T1 用例里，会导致"U2 显示已覆盖、实际没覆盖"。

**另一个必须记录的实测差异**：甲 T1 输出 `server: protocol=0x00000400`
（`SP_PROT_TLS1_2_SERVER`），客户端是 `0x0800`。这两个值不是同一命名空间
（0x400 = server 位，0x800 = client 位），不能直接比较"双方一致"。
甲的事实表第 3 条写"双方 `cipher=0x6610`…与真实服务器逐项一致"——`cipher` 一致是对的，
但 `protocol` 两边数值不同是正常的，不要写进断言。

---

## §4 我方 5 条陷阱的最终确认（逐条）

### 4-1 `DecryptMessage` 需要 ≥4 个 SecBuffer —— **确认成立**

- 我的实测：`nbuf=1/2/3 → 0x80090308`；`nbuf=4/5/6 → 0x00000000`（TLS1.2 与 1.3 一致）
  `[probe20]`；`[probe27]` 复验同一结论。
- 甲的实测：T1 探针用 `SecBuffer sb[4]`（`loopback_schannel.cpp:162-165`），能跑通 → 与 4 一致。
- 与甲的差异：**数字一致，契约缺位**。甲的 §3.5 映射表只写"`SECBUFFER_DATA` 出明文，
  `SECBUFFER_EXTRA` 出剩余"，没写"必须 4 个"。若实现者按文档只给 2 个（"1 DATA + 1 EXTRA"，
  这是最直觉的写法），100% 失败，且错误码 `0x80090308` 会被误判成"对端数据非法"。
- 结论：这条必须写进接口契约文字（见修正 1 的配套），不能只留在探针里。

### 4-2 `EXTRA` 指针别名（指在调用方缓冲内部）—— **确认成立，但甲的设计已规避**

- 我的实测：`buf[3] type=5 cb=37 offsetFromStart=37 inInputRange=1` `[probe37]`
  → EXTRA 的 `pvBuffer` 在输入缓冲内部，缓冲被复用即悬垂。
- 甲的设计（后端持有 `rx_buffer_`，调用方不保留密文）**天然规避**了这个问题。
  这点甲做对了，我确认。
- **但**新增一个甲没覆盖的变体：握手阶段的 EXTRA **`pvBuffer == NULL`**
  `[probe44] in[1] type=EXTRA cb=64 ptr=0000000000000000`
  → 如果实现按"EXTRA 一定有指针"写，会空指针解引用；按"EXTRA 一定有内容"写，会漏 64 字节。
  这条是 4-2 的**新分支**，必须并进契约（见修正 2）。

### 4-3 TLS1.3 NewSessionTicket 报成 `SEC_I_RENEGOTIATE` —— **确认成立（这是最大风险）**

- 我的实测（真服务器）：握手成功后首个 `recv` 103 字节，
  `DecryptMessage → 0x00090321`，`EXTRA=103`，内容 `16 03 03 00 62 04 ...`（handshake type 0x04）
  `[probe34]`；`ISC` 喂回该 EXTRA → `0x00000000 out=0`，此后 `EncryptMessage` 仍可用。
- 忽略它的后果：`[probe18-A]` 丢 EXTRA 后下一条记录 `0x80090330`；
  `[probe39]` 重喂同一票据 → `0x80090317`，上下文废。
- TLS1.2 对照：服务端主动重协商会真的走多轮（197/822/206 字节），TLS1.3 下
  `AcceptSecurityContext(no input)` → `0x00090360 SEC_I_NO_RENEGOTIATION` `[probe24]`。
  → **必须按协商版本分叉**，不能统一处理。
- 对甲的影响：见 §1 修正 1，这是**签名级**错误，不是"注意"级。

### 4-4 `cbTrailer` 是上界 —— **确认成立**

- `[probe21] TLS1.3 hdr=5 trl=44；payload=16 → wire=38`（5+16+17），`hdr+len+trl=65`，差 27。
  TLS1.2 恰好相等（`13/16`，payload=16 → 45）。
- 对甲的影响：见 §1 修正 3；并直接影响甲的 T1 绿证第 3 条（`Send 36B → 65B`）——
  该断言只在 TLS1.2 成立，TLS1.3 应为 5+36+17=58。

### 4-5 关闭通知需要 `ALLOCATE_MEMORY` —— **确认成立（且甲的两处说法互相矛盾）**

- `[probe40]` 四种组合：无 `ALLOCATE_MEMORY`（null/空 desc 都一样）→ `0x80090300 out=0`；
  有 → `0x00000000 out=24`。
- 对甲的影响：见 §1 修正 5；并修正 T1 断言"首字节 0x15"（TLS1.3 实测 0x17）。

---

## §5 与甲的分歧点（按严重度）

| # | 分歧 | 我的立场 | 依据 |
|---|---|---|---|
| 1 | `Receive` 是否可以返回 `kRenegotiate` | **不可以**。TLS1.3 默认路径必然触发，且 RDP 不允许重协商 | probe34 / probe39 / probe24 |
| 2 | `Handshake.consumed` 是否等于 `in_size` | **不等于**。必须减 EXTRA，且 EXTRA 可能无指针 | probe44 / probe42 |
| 3 | `max_record()` 是否等于实际线长 | **不等于**（TLS1.3 差 27） | probe21 |
| 4 | 套件号从哪个属性取 | `SECPKG_ATTR_CIPHER_INFO.dwCipherSuite`；`aiCipher` 是 CALG；`CONNECTION_INFO_EX` 在 1.2 下也无需 | probe41 / probe29 |
| 5 | `Shutdown` 要不要 `ALLOCATE_MEMORY` | **必须**（甲 §3.5 与 §5 坑表自相矛盾） | probe40 |
| 6 | SPKI 是否"剥 24 字节头" | **禁止固定偏移**；直接取 `PublicKey.pbData` | probe35 / probe41（offset 24 vs 22） |
| 7 | T1 能否覆盖 U2 | **不能**（回环服务端不发票据）；U1 与 U2 必须分开验证 | probe3 vs probe34 |
| 8 | 是否需要在 Windows 侧引入 OpenSSL | 不需要（与甲一致） | probe9/probe16 + `find_package` 实测失败 |
| 9 | §8 缺陷条数 | 合并后 **17**，不是 11 | §2 映射表 |
| 10 | `block_size` 是否 = 1 | 实测 **16**（TLS1.2 GCM） | probe4 / loopback 输出 |

**唯一实质性的方向性分歧**：没有。10 条全部是"甲的接口/契约细节与实测不符"，
不涉及"选 SChannel 还是 OpenSSL"这个主决策。

---

## §6 未验证项（更新甲 U1–U10 的状态）

| 甲编号 | 内容 | 我方状态 | 证据 |
|---|---|---|---|
| U1 | TLS1.3 `record_sizes` | **已关闭** | `hdr=5 trl=44 max=16384`，实际尾长 17（`probe21`）；甲猜的"header 13→22"不对，正确是 5，22 是 5+17 的总开销 |
| U2 | `SEC_I_RENEGOTIATE` / `SEC_I_CONTEXT_EXPIRED` | **已关闭** | 1.2 真重协商三轮（`probe24`）；1.3 票据 `0x00090321`（`probe34`）；close_notify 对端 `0x00090317`、本端后续 `0x80090317`（`probe4-D`） |
| U3 | Linux 后端 | **仍开** | 无 Linux 环境 |
| U4 | FIPS | **仍开** | `FipsAlgorithmPolicy\Enabled=0`，改策略需重启（超授权） |
| U5 | openssl.org 是否发 Windows 二进制 | **已关闭（否）** | 官方页面只列源码 tarball + PGP/SHA256 校验和 |
| U6 | mbedTLS 构建时间 | **仍开** | 未构建 |
| U7 | 真服务器是否接受 TLS1.0 | **已关闭（接受）** | `TLS1.0 only → proto=0x0080`；`TLS1.1 → 0x0200`；`SSL3 → cred 0x80090331`（`probe16`） |
| U8 | `verify_chain=true` 行为 | **部分关闭** | 不给 manual → `0x80090325`；DEFERRED → 握手成功 + `CERT_CHECK_RESULT hr=0x800B0109`（`probe5`）。**strict 模式下主机名校验的具体失败码未测** |
| U9 | 回环能否跑通 | **已关闭（双方独立确认）** | 甲 `RESULT=PASS`；我用 probe10/12/17/27/36 独立复现同类回环 |
| U10 | 常量与 `winerror.h` 一致 | **已关闭** | 逐值 grep：`0x00090317 / 0x00090321 / 0x00090360 / 0x80090330 / 0x80090329 / 0x80090318 / 0x80090308 / 0x80090325 / 0x80090331 / 0x00090320` 全部对齐 |

我方新增未验证（供甲补充）：
- N1 TLS1.3 `overhead_actual` 是否恒为 17（只测 5 个 payload 尺寸，全部 17）——C 级。
- N2 `SEC_I_RENEGOTIATE` 在 TLS1.3 下是否每次握手后必发一次票据（只观察到 1 次）。
- N3 真服务器在 TLS1.2 下的 close_notify 首字节是否 `0x15`（我只测了 1.3 的 `0x17`）。
- N4 `SCH_CREDENTIALS` 在 Win10 1809–22H2 上是否完全支持 `cTlsParameters`（无该版本机器）。
- N5 `errorCode` 非严格 DER 的原始抓包（`security-layer.md:1463` 的断言缺字节样本，
  且与 `ber.cpp:125-130` 的严格长度检查冲突）。

---

## 附：本文引用的探针索引

| 探针 | 用于本文的哪一条 |
|---|---|
| `probe9` / `probe16` | 修正 9（静默降级）、§6 U7 |
| `probe21` | 修正 3（`cbTrailer` 上界）、§4-4 |
| `probe20` / `probe27` | §4-1（4 buffer）、修正 6（失败时 DATA 带密文） |
| `probe34` / `probe39` | 修正 1（票据）、§4-3 |
| `probe24` | §4-3（1.2 重协商 vs 1.3 `SEC_I_NO_RENEGOTIATION`） |
| `probe40` | 修正 5（Shutdown 需 ALLOCATE_MEMORY）、§4-5 |
| `probe42` / `probe44` | 修正 2（`consumed` 与 EXTRA 无指针） |
| `probe35` / `probe41` | 修正 4（SPKI 偏移 24 vs 22）、修正 8（套件号） |
| `probe5` / `probe15` | 修正 7（MANUAL 关主机名、DEFERRED 给链结果） |
| `probe19` | §3 D 类（BCrypt 差分预言机） |
| `probe29` | §2 M15（`0x6610` ≠ 套件号；实测 `0x009D`） |
| `probe3` | §3（TLS1.3 `hdr=5 trl=44` 可由回环测得） |

---

## §7. 第②轮验证（W11 第⑤步）

> 验证对象：`docs/spec/tls-backend.design-a.md`（996 行 / 79016 B，LF-only，无 BOM）。
> 验证方式：`Select-String` 定位 + 分段读（每次 ≤100 行）+ **重跑我方既有探针**（未新建探针）。
> 甲自报「10 成立 / 1 部分 / 0 不成立」；本节独立复核，不采信其自述。

### 7.1 九处落地核查（逐处给结论）

| # | 待核查项 | 结论 | 证据（行号 / 实测） |
|---|---|---|---|
| 1 | `consumed = in_size - Σ(EXTRA.cbBuffer)` 写入 §3.5 + 自检 | **落地** | 签名注释 `design-a.md:342-344`（含「禁止解引用」「`consumed + Σ(EXTRA) == in_size` 否则 `kInternal`」）；§3.5 表 `:532`；§3.3 `kInternal` 行 `:456` 复述自检；§5 红证 `:732-733` |
| 2 | `Receive` 失败时 `plaintext` 未定义 + 伪码循环开头 `clear()` | **落地** | 签名注释 `:357-358`；§3.3 表新增行 `:454`（「任何 `!= kOk && != kClosed` → 内容与长度未定义」）；伪码 `:480` `plaintext_out.clear()`；分支内 `:488`/`:492` 各自再 clear；§5 红证 `:722-723` |
| 3 | `Shutdown` 写 `ISC_REQ_STREAM \| ISC_REQ_ALLOCATE_MEMORY` + `pvBuffer=nullptr` | **落地** | 签名注释 `:376-378`；§3.5 表 `:539`；§5 坑表 `:690` 并显式消解了与 `:689` 的「二选一」矛盾（`:694-699`） |
| 4 | T1 绿证第 6 条按版本分叉（1.2=`0x15` / 1.3=`0x17`） | **落地** | `:709` `out[0] == (TLS1.2 ? 0x15 : 0x17)`，`out.size() ∈ {24, 31}`；说明 `:710-712`；V3 向量 `:767` 同步 |
| 5 | SPKI 改取 `PublicKey.pbData/cbData`；绿证改「子串包含」 | **落地** | 签名注释 `:365-366`（「禁止用固定偏移…RSA-2048 偏移 24、RSA-1024 偏移 22」）；§3.5 `:536`；绿证 5 `:708` 已改为「前者包含后者为子串」 |
| 6 | 套件号改 `SECPKG_ATTR_CIPHER_INFO.dwCipherSuite` + 新增 `NegotiatedInfo`/`negotiated()` | **落地** | `struct NegotiatedInfo` `:331-335`；`virtual Error negotiated(...)` `:372`；§3.5 `:538`（明确「`aiCipher` 是 CALG，不是套件号」「`CONNECTION_INFO_EX` 只给算法名」） |
| 7 | `CreateTlsTransport(backend, ...)` 新增；旧工厂退化为内联包装 | **落地** | `:414-417` 新签名；`:419-422` 内联包装；`:427-429` 说明 |
| 8 | §3.4 边界从 4 条扩到 7 条 | **部分落地** | 条目确已 7 条（`:514-525`），但**引导句仍写「必须覆盖的四个边界」`：512`** —— 数量未同步，属「改了条目没改标题」 |
| 9 | §4 从 11 条扩到 21 条（D1–D21） | **落地（有 1 处交叉引用错）** | 标题 `:557`「合并后 **21 条**」；D1–D11 `:566-580`；D12–D19 `:582-593`；D20–D21 `:595-600`；结论 `:602`。**但 `:577`（D8）写「本轮再补 3 行（见 §4.3 D17）」——§4.3 只有 D20/D21，D17 在 §4.2，应指向 D20** |

**结论：9 项中 7 项完全落地、1 项部分落地（第 8 项）、1 项落地但含交叉引用错（第 9 项）。**
**未发现「声称改了但实际没改」的情况** —— 甲的自述与文件内容基本一致，偏差只在数量词与交叉引用。

### 7.2 复核 1：`EXTRA.pvBuffer == NULL` 这个细节对契约是否必要？

**裁定：必要，但甲给出的理由不成立；「禁止解引用」是必需规则，不是纯防御性建议。**

分三层说：

1. **甲的实测（`extra=63 offset=63 inCallerRange=1 input=126`）只能证明「指针在调用方缓冲内部」，
   不能证明「指针可能为 NULL」。** 我复核了自己的 `probe37` / `probe44`：
   - `DecryptMessage` 路径：`buf[3] type=5 cb=37 offsetFromStart=37 inInputRange=1` —— 指针**有效**，指向输入缓冲内部；
   - `InitializeSecurityContext` 路径：`in[1] type=EXTRA cb=64 ptr=0000000000000000` —— 指针**为 NULL**
     `[BASH:F:\rtsc\.tmp\tlsprobe\probe44.exe]`。

2. **如果指针始终有效，「禁止解引用」就只是防御性建议（可以解引用，但别跨调用持有）。**
   真正把这条规则从「建议」变成「必需」的，**恰恰是 NULL 这一分支**：握手路径上解引用即 `0xC0000005`。
   所以：**NULL 细节是「禁止解引用」这条规则的唯一决定性依据**，不能降级为可选细节。

3. **但甲的反驳也有道理的一半**：契约其实**根本不需要解引用**。`EXTRA` 的尾部内容可用纯算术定位
   —— `offset = in_size - cbBuffer`（`probe37`：`37 = 74 - 37`；`verify_traps`：`63 = 126 - 63`），
   从输入缓冲复制即可。因此最稳的契约写法是**算术定位**，而非「禁止解引用」：

   ```
   // EXTRA 的唯一合法用法（两条路径统一）：
   //   tail_off = in_size - EXTRA.cbBuffer;  copy(in + tail_off, EXTRA.cbBuffer)
   //   禁止：解引用 EXTRA.pvBuffer（ISC 路径为 NULL）；禁止：跨调用持有该指针（别名）。
   ```

**残余风险（须记入未验证项）**：`pvBuffer == NULL` 我只有 **n=1** 的观测（单一路径、单次 TLS1.2 回环 + 64 字节垃圾）。
标 **C 级**。但因该分支后果是崩溃、且算术定位零成本，**必须按「可能为 NULL」实现**（fail-safe 方向），
不因 n=1 而放宽。甲标 C 级**合理**，但结论「只读 `cbBuffer`」应保留。

### 7.3 复核 2：D14（漏 sspicli / LNK2019）降为「部分成立」是否合理？

**裁定：甲的降级正确，且我原表述有误，必须自我更正。**

- **我原来的主张是「必然 LNK2019」，不只是「清单不完整」。** 原文（`design-b.md:457`）：
  「`sspicli.dll`（`QueryContextAttributesExW` **不在** `secur32.lib` 中，会直接 `LNK2019`）
  `[BASH:probe7 首次链接失败]`」。
- **该引用是错的。** `probe7.cpp` 只调用 `QueryContextAttributesW`（`:111,:112,:238`），
  链接 `secur32/crypt32/ncrypt`，**没有 Ex 版本**；我全盘搜索 `.tmp` 与 `evidence` 下所有
  `.log/.err/.txt`，**不存在任何 `LNK2019` / `LNK2001` 记录**。所以「probe7 首次链接失败」是
  **失实引用**，我收回。
- **但底层事实我本轮重新独立验证了，且成立**（这次是符号级、可复现）：
  ```
  Secur32.Lib 符号扫描：QueryContextAttributesW = 有；QueryContextAttributesExW = 无
  mincore.lib / OneCore.Lib / OneCoreUAP.Lib / windowscoreheadless.Lib = 有 ExW
  sspicli.dll 导出表 = 有 ExW（QueryContextAttributesExW / ExA 均在）
  ```
  → 结论：**「若使用 `QueryContextAttributesExW`，则 `secur32.lib` 不足以链接」成立；
  「当前依赖清单必然 LNK2019」不成立**（因为当前清单根本没用 Ex）。
- **另外两条我原主张也站不住，一并更正**：
  - 「漏 `bcrypt`」：`ncrypt.lib` 已含 `BCryptOpenAlgorithmProvider` / `BCryptGenRandom` 符号，
    链了 `ncrypt` 就不必再链 `bcrypt`。此条**不成立**。
  - 「漏 `sspicli`」：仅在改用 `Ex` 函数时才需要；属**条件性**，非当前缺陷。
- **对 D14 的最终裁定：降为「部分成立」正确，且应进一步降为「条件性风险（记录，不计缺陷）」**。
  建议改写为：「若将来改用 `SECPKG_ATTR_*` 的 `Ex` 变体，需改链 `sspicli.lib`（或 `mincore.lib`）；
  当前 `secur32` 方案不受影响。」

**关于 `SCHANNEL_USE_BLACKLISTS` + `winternl.h` 这个坑：成立，且是本轮新发现，我给甲记一分。**
我用 SDK 头文件直接核实（非采信）：
```
schannel.h:409  #ifdef SCHANNEL_USE_BLACKLISTS
schannel.h:411-412  "then you must define UNICODE_STRING and PUNICODE_STRING
                     or include Ntdef.h, SubAuth.h or Winternl.h"
schannel.h:432-440  CRYPTO_SETTINGS   （在 ifdef 内）
schannel.h:442-450  TLS_PARAMETERS    （在 ifdef 内）
schannel.h:455-470  SCH_CREDENTIALS   （在 ifdef 内）
schannel.h:477  #endif
```
→ 不定义该宏时 `TLS_PARAMETERS` / `SCH_CREDENTIALS` **根本不存在**（`C2065`）。
这条同时解释了为什么「legacy `SCHANNEL_CRED` 作为降级路径」是伪选项：
**要用 `SCH_CREDENTIALS` 就必须开这个宏，开了就必须带 `winternl.h`**，没有第三条路。
甲的 §3.6 `:551` 写法正确。

### 7.4 §8 条数裁定（21 条是否成立）

**裁定：21 条计数成立；但需说明它与我的「17 条」为何不同，并修正 1 处归类。**

| 项 | 核对 |
|---|---|
| 甲的算式 11 + 8 + 2 = 21 | **自洽**。D1–D11（`:566-580`）+ D12–D19（`:582-593`，即我的 8 条独有）+ D20–D21（`:595-600`）= 21 |
| 我的「17 = 16 + 甲 D10」 | **也自洽**。差异纯粹来自**粒度**：甲把我合并的 2 组各拆成 2 条 —— 甲的 D2+D3（vcpkg / 无 perl）对应我的 D4 一条；甲的 D6+D11（混谈 CredSSP / 论证对象错）对应我的 D8 一条。19（并集，按甲的粒度）− 2（拆细）= 17 |
| 有无重复 | **无实质重复**。D17（`0x6610` 被当套件号）与 D21（`:505` 把「协商到的套件」与「服务器支持的套件」混写）相邻但不同：前者是**证据文件读错**，后者是**规格文档表述错**，修法不同 |
| 有无遗漏 | **无遗漏**。我的 16 条全部落在 D1–D19 内（8 重叠 + 8 独有），加甲独有的 D10，再加 D20/D21 |

**须修正的 1 处归类**：D20 把「≥4 buffer / EXTRA 别名 / TLS1.3 票据」称为 §8.1 **缺失的能力**，
但 §8.1 是**选型能力表**（跨库可比较项），而这三条是 **SChannel 专属实现约束**，
OpenSSL 侧不存在对应项 —— 放进「能力表」会让表失去「可比较」这个用途。
**建议改法**：D20 的修法从「补 3 行能力」改为「§8.1 增设一列/一节『SChannel 后端专属实现约束』」，
并把 D8（缺 3 项通用能力）与 D20（3 项 SChannel 约束）明确分栏。这不影响条数，只影响落笔位置。

### 7.5 本轮新发现的缺陷（甲修订稿引入，4 条，必须修）

以下 4 条是**验证修订稿本身**发现的，不是旧账重提。前两条为**阻断级**。

#### N1（阻断）§3.4 伪码在 `RENEGOTIATE` 分支「未消费记录就 continue」→ TLS1.3 默认路径必失败

伪码 `design-a.md:483-489`：
```
483  if st == RENEGOTIATE:
485      if negotiated.tls_version == 0x0304:
486          feed EXTRA back to ISC once; discard output; continue
493  erase rx_buffer_[0 .. 5+len]        ← 在 RENEGOTIATE 分支之后
```
`continue` 发生在 `erase`（`:493`）之前，`rx_buffer_` 仍保留那条 103 字节票据记录 → 下一轮
`parse_header` 重新解析同一条记录 → 再次 `backend_decrypt`。实测后果（不是无限循环，更糟）：
```
[BASH:F:\rtsc\.tmp\tlsprobe\probe39.exe]
  iter 0: 0x00090321 extra=103
       ISC(ticket) -> 0x00000000 out=0
  iter 1: 0x80090330 extra=0          ← 同一票据再解密 → 认证失败
[BASH:F:\rtsc\evidence\tls\verify_traps.out.txt]
  client Dec(ticket record) -> 0x80090330 extra=0
```
→ 映射为 `kDecryptFailed`（或 `0x80090317` → `kClosed`），**TLS1.3 连接在首张 NewSessionTicket 上必然断**。
这正是我修正 1 指出的**同一根因**：甲修掉了「外泄状态码」这个**症状**，没修掉「记录未消费」这个**根因**。
**修法**：`erase` 必须在任何 `continue`/`return` 之前执行；建议把「取记录 + 消费记录」合并为一步：
```
record = take_front(rx_buffer_, 5+len)   # 取出即消费，缓冲前移
st = decrypt(record)
... 之后所有分支都不再需要 erase
```
顺带：`:489` `if st == NO_RENEGOTIATION: continue` 是同一缺陷的第二个入口（同样未消费即 continue）。

#### N2（阻断）§3.4 缓冲区耗尽时返回 `kNeedMoreInput`，与 §3.3 自相矛盾

伪码 `:474` `if rx_buffer_.size() < 5: return kNeedMoreInput`；
而 §3.3 `:451` 规定「`Receive` → `kNeedMoreInput` → `buffered_input()` **应 > 0**」。
一次喂入 N 条完整记录、全部解完、缓冲恰好清空时：伪码走到 `:474` 返回 `kNeedMoreInput`，
但此时 `buffered_input() == 0` —— **违反自己的 §3.3**。调用方若按 §3.3 断言，测试必红；
若不信 §3.3 而只看 `plaintext`，则 §3.3 这行是废的。
**修法**（二选一，必须写死）：
- (a) 循环退出条件改为「缓冲不足 **且** 本轮已产出明文 → `kOk`」；
- (b) 或 §3.3 `:451` 改为「`kNeedMoreInput` 时 `buffered_input() >= 0`，调用方必须同时检查 `plaintext`」。
推荐 (a)：`kNeedMoreInput` 的语义应是「我没东西给你了，去读 socket」，而不是「我吃完了」。

#### N3（中）§3.4 `erase` 与 `copy(EXTRA)` 的顺序，依赖「`record` 是否为副本」这一未写明的前提

伪码 `:493` `erase rx_buffer_[0 .. 5+len]` 在 `:495` `if extra_len: rx_buffer_ = copy(EXTRA 区域)` **之前**；
而 `:495` 的注释自己写的是「**先复制再复用缓冲**」—— 语句顺序与注释主张相反。
若实现把 `rx_buffer_.data()` 直接传给 `DecryptMessage`（省一次拷贝，最常见的写法），
则 `EXTRA.pvBuffer` 指向 `rx_buffer_` 内部（`probe37`：`inInputRange=1`），`erase` 后该指针悬垂/内容被移走，
`:495` 复制到的是**错位后的字节** → 静默丢帧（无错误码，最难查）。
只有当 `:479` 的 `record = rx_buffer_[0..5+len]` 是**独立副本**时，该顺序才安全 —— 但伪码没写。
**修法**：显式规定「`record` 必须是独立副本」**或** 把 `:495` 提到 `:493` 之前，二选一，不能留歧义。

#### N4（轻）`:477` 记录长度上界过宽

`:477` `if len > 16384 + 2048: return kProtocolError`。TLS1.3 规定 `TLSCiphertext.length`
**MUST NOT exceed 2^14 + 256**（16384+256），`+2048` 会放行协议非法记录。
不影响安全（后续解密会失败），但会让「防 DoS 上界」这条断言失去精确性。
**修法**：改 `16384 + 256`（TLS1.3）/ `16384 + 2048`（TLS1.2 兼容）按版本分叉，或统一取 `16384 + 256`。

### 7.6 另外 3 处文档级问题（不阻断，但会误导实现）

| # | 位置 | 问题 |
|---|---|---|
| D-a | `design-a.md:512` | 「必须覆盖的**四个**边界」，实际列了 7 条（`:514-525`）—— 数量词未同步 |
| D-b | `design-a.md:577`（D8 行） | 「本轮再补 3 行（见 **§4.3 D17**）」—— §4.3 只有 D20/D21，D17 在 §4.2；应指向 **D20** |
| D-c | `design-a.md:552` | 链接项写 `secur32 crypt32 ncrypt advapi32`，理由写「`advapi32` 是 `CertCreateSelfSignCertificate` 的存储路径」。**实测 `advapi32.lib` 不含该符号，它在 `crypt32.lib` 里**（符号扫描：`crypt32.lib` 有 `CertCreateSelfSignCertificate`；`advapi32.lib` 只有 `CryptAcquireContextW`/`RegOpenKeyExW`）。链接项本身无害（多链不报错），但**理由是错的**，且 T1 探针链 `advapi32` 能通过并不证明它是必需的 |

### 7.7 我方自我更正（3 条，必须记账）

审计要求先证伪自己。本轮重跑探针时发现我方有 3 处表述问题：

1. **`probe42` 的 `consumed` 列不是「实际消费量」**：`probe42.cpp:67` 把 `SECBUFFER_TOKEN.cbBuffer`
   当作 consumed 输出，而实测该字段**不被 SChannel 递减**（`junk=32` 时 `consumed=83` 而 `input=83`、
   `extra=32`，正确消费量应为 `83-32=51`）。所以 `probe42` 打印的 `consumed` 应读作
   「TOKEN.cbBuffer（未递减）」，它恰好**反证**了修正 2（按 `TOKEN.cbBuffer` 会多算 32）。
   **任何人引用 probe42 时不得把该列当作 consumed。**
2. **`probe18` 的 B/D 段标签与实测协议相反**：`probe18.cpp:169`（B 段）与 `:217`（D 段）用
   `pass==0 ? SP_PROT_TLS1_3_CLIENT : ...` 却把 `pass==0` 打印成 `"TLS1.3"`，实际 `pass==0` 禁用的是
   TLS1.3（即协商为 TLS1.2）。证据：`probe18` 输出「TLS1.3 payload=16 actual=45 delta=0」，
   而 `probe21` 独立测得 TLS1.3 `payload=16 → wire=38`、TLS1.2 `→ 45`。**`probe18` 的 B/D 段
   应按「pass==0 = TLS1.2」重读**；我 §4-4 引用的是 `probe21`（标签自洽），结论不受影响。
   （`probe25` 用协商出的 `proto` 打标签，输出 `proto=0x0800 → poisoned=10`、`proto=0x2000 → recovered=10`，
   与 `probe26` 一致，可信。）
3. **`design-b.md:457`（D7）的 `[BASH:probe7 首次链接失败]` 引用失实**（详见 §7.3），已收回。

### 7.8 盖章裁定

**不盖章。** 理由与门槛：

| 门 | 状态 |
|---|---|
| 12 处接口签名修正 | **通过**（9 处核查中 7 项完全落地、1 项部分、1 项含交叉引用错；签名层无遗留） |
| §3.4 伪码逻辑 | **不通过**（N1 阻断：TLS1.3 默认路径在首张票据上必然断；N2 阻断：违反自身 §3.3 契约） |
| §4 缺陷条数 21 | **通过**（计数自洽、无重复无遗漏；建议 D20 改落笔位置） |
| 红证计划可执行性 | **通过**（T1/T2/T3/T4/T5 + 9 条绿证 + 8 条红证，覆盖 B/A/E 类；C/D 类靠 `ScriptedBackend` 留待实现期） |

**放行条件（3 条，全部为小改，无需重跑探针）**：
1. 修 N1：`erase` 前置（「取出即消费」），`RENEGOTIATE` 与 `NO_RENEGOTIATION` 两个 `continue` 都不例外；
2. 修 N2：`kNeedMoreInput` 与 `buffered_input()` 的语义二选一定死（推荐「产出过明文即 `kOk`」）；
3. 修 N3：`record` 是否独立副本写死，或把 `copy(EXTRA)` 提到 `erase` 之前。
（D-a / D-b / D-c / N4 为随修项，不单独设卡。）

**这 3 条修完，我在第③轮复核后盖章。** 在此之前，「甲已采纳 12 条修正」这一事实成立，
但「设计可直接进入实现」不成立 —— 因为 N1 会让**最主流的 TLS1.3 路径**（`allow_tls13` 默认 true）
在第一次 `Receive` 就断，而 §5 的绿证第 8 条（「TLS1.3 收到票据后仍返回 `kOk`」）恰好会抓到它，
所以**修 N1 是让 §5 绿证 8 从「必红」变「必绿」的最小改动**。

### 7.9 第②轮新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| N5 | `EXTRA.pvBuffer == NULL` 的复现率（n=1，单路径） | C | 结论不受影响（算术定位零成本，必须按 NULL 防御） |
| N6 | `ISC` 返回的 EXTRA 是否**总是** `cb = in_size - 消费量`（`probe42` 只测 junk ∈ {0,32,64}） | C | 建议实现期加 `consumed + ΣEXTRA == in_size` 自检兜底（已在 §3.3 `:456` 写入） |
| N7 | `ncrypt.lib` 是否在所有目标 Windows 版本上都导出 `BCryptGenRandom` | C | 影响「是否需要额外链 `bcrypt.lib`」；本机（10.0.26200）成立 |

---

## §8. 第⑥步复验（N1/N2/N3 修复确认）

> 验证对象：`docs/spec/tls-backend.design-a.md`，**锁定版本 1139 行 / 92381 B / mtime 23:57:33**
> （审计过程中观察到该文件从 91909 B → 92381 B 两次变化，甲仍在改；以下结论只对该快照负责）。
> 验证方式：`Select-String` 定位 + 分段读 + **重跑既有探针**（未新建）。
> 结论先行：**N1/N2/N3/N4 与 3 个文档级问题全部落地；但本轮新发现 4 个问题，其中 N5 为阻断级。
> 不盖章。**

### 8.1 N1/N2/N3/N4 + 3 个文档级问题：落地核查

| # | 待核查 | 结论 | 证据（行号） |
|---|---|---|---|
| N1 | `take_front` 在 `backend_decrypt` 之前；两个 `continue` 之前记录已消费 | **落地** | `:514` `record = take_front(rx_buffer_, 5+len)` → `:516` `backend_decrypt`；`:526` `continue`（RENEGOTIATE）与 `:530` `continue`（NO_RENEGOTIATION）都在 `take_front` 之后；规则 2 `:548-549` 明文写死「每个 continue/return 之前当前记录必须已被消费，唯一例外 INCOMPLETE」 |
| N2 | `produced ? kOk : kNeedMoreInput` 两处都出现；§3.3 契约已改写 | **落地** | `:506` 与 `:511` 两处；§3.3 `:451` 已改为「此时 `buffered_input()` **可以为 0**…若本轮已有产出，后端必须返回 `kOk`」；§3.4.2 新增边界 8 `:591-593` |
| N3 | `tail_off = record.size() - extra_len` 不再引用 `pvBuffer`；规则 1 写明 | **落地** | `:538` `tail_off = record.size() - extra_len`、`:539` 前插；规则 1 `:546-547`「`record` 必须是独立副本…不得是 `rx_buffer_` 的指针/`span` 视图」；规则 3 `:550-552`「统一不碰 `pvBuffer`」 |
| N4 | 上界改 `16384 + 256` | **落地** | `:509` `if len > 16384 + 256: return kProtocolError` |
| D-a | 「四个边界」→「八个边界」 | **落地** | 标题 `:571`「必须覆盖的**八个**边界」；实列 8 条 `:575-593`（逐条点数确认 1–8 齐全） |
| D-b | D8 行交叉引用改指 D20 | **落地** | `:649`「本轮再补 3 行（见 §4.3 **D20**）」 |
| D-c | `advapi32` 理由更正为「`CertCreateSelfSignCertificate` 在 `crypt32.lib`」 | **落地** | `:619` 明确「`CertCreateSelfSignCertificate` 在 **`crypt32.lib`**…不是 `advapi32`；`advapi32.lib` 只提供 `CryptAcquireContextW`/`RegOpenKeyExW` 一类」，并承认原稿理由错 |

**7 项全部落地，未发现「声称改了但实际没改」。**

### 8.2 return 路径完整性裁定

我独立逐行读了 `:501-541`，出口共 **11 个**（父代理列 9 个，漏了 `:521` 与 `:541` 之外的两处，见下）：

| 行 | 出口 | 记录已消费？ | 裁定 |
|---|---|---|---|
| 506 | `size<5` → `produced?kOk:kNeedMoreInput` | 无记录可消费 | ✓ |
| 508 | `type ∉ {20,21,22,23}` → `kProtocolError` | **未消费** | ⚠ 见 Q1（需 terminal latch） |
| 509 | `len > 16384+256` → `kProtocolError` | **未消费** | ⚠ 见 Q1 |
| 511 | `size<5+len` → `produced?kOk:kNeedMoreInput` | 无（记录不完整） | ✓ |
| 521 | `INCOMPLETE` → 放回后 `produced?kOk:kNeedMoreInput` | 已放回 | ⚠ **可达且会活锁**，见 N6 |
| 526 | `RENEGOTIATE`(1.3) → `continue` | 已消费 | ✓ |
| 528 | `RENEGOTIATE`(1.2) → `kProtocolError` | 已消费 | ✓ |
| 530 | `NO_RENEGOTIATION` → `continue` | 已消费 | ✓ |
| 532 | `CONTEXT_EXPIRED` → `kClosed` | 已消费 | ✓ |
| 534 | `ALTERED`/`DECRYPT_FAILURE` → `kDecryptFailed` | 已消费 | ⚠ **缺 terminal latch**，见 N7 |
| 541 | `max_out` → `kOk` | 已消费 | ⚠ 语义未定义，见 Q3 |

**裁定：N1 的「记录必须被消费」这条不变量已完整成立（无遗漏出口）。但出口的「终态」与「进度」两个维度仍有缺口（N6/N7/N8）。**

### 8.3 父代理提的 3 个疑点：逐条结论

#### Q1：508/509 的「终止性错误不消费记录」是否可接受？

**可接受，但不完整。** 三条理由：

1. **不消费本身没问题**：`kProtocolError` 按 §3.3 `:445` 是终止性错误，上下文即弃。`rx_buffer_` 里残留的记录随对象析构，不泄漏。
2. **但缺「终态闩锁」**：`:232` 只对 `kClosed` 承诺「后续调用恒返回 `kClosed`」，对 `kProtocolError` / `kDecryptFailed` **没有任何后续调用语义**。若调用方忽略错误再调 `Receive`：508/509 会**重新解析同一条记录**并再次返回 `kProtocolError`（无害但空转）；534 因为记录已消费，会**继续解析下一条记录并返回明文**（有害，见 N7）。
3. **最小修法**：加 `terminal_` 标志，任何终止性错误置位；`Receive` 入口 `if (terminal_) return last_error_;`。这也让 `closed()` 的语义有落点。

#### Q2：`:521` `INCOMPLETE` 放回 `record + rx_buffer_` 会不会打乱顺序？

**顺序正确，但有更严重的问题（活锁 + 无界增长）。**

- **顺序**：`:514` `take_front` 摘走的是**缓冲最前面**的 `5+len` 字节，剩余部分仍在 `rx_buffer_` 且保持原相对顺序。`record + rx_buffer_` 即「刚摘出的那条 + 后续所有字节」= 原始顺序。**即使前面已成功处理若干条记录，顺序也不乱**（前面几条已从缓冲移除，剩下的仍是后续记录）。✓
- **真正的问题**：`:519` 的注释假设「SChannel 只在记录不完整时返回 INCOMPLETE，而上面已保证 `5+len` 到齐 → **不应发生**」。**该假设是假的**，见 N6。

#### Q3：`produced` 与 `max_out` 的关系；`max_out` 是上限还是「达到即可」？

**是「达到即可」的软阈值，不是上限。这一定义在文档里从未写明，必须补。**

- 实现是 `:540-541`：`produced += plaintext_out.size()` 然后 `if max_out && produced >= max_out: return kOk`。
- **会超发**：`max_out=1`、单条记录产出 16384 → `produced=16384 ≥ 1` → 返回 `kOk`，调用方拿到 16384 字节。**超发量最大可达一条记录（16384 B）**。
- 由于 `plaintext` 是 `std::vector`（追加写），超发不构成内存安全问题；但若将来换成裸指针 + 固定缓冲，这就是越界写。
- **两种语义必须二选一写死**：
  - (a) **软阈值**（当前实现）：契约改为「`max_out` 是**至少产出量**；单条记录不可切分，故实际产出可超出至多一条记录（≤16384 B）。调用方不得假设 `plaintext.size() <= max_out`。」
  - (b) **硬上限**：必须在**追加之前**检查，且允许把一条记录的明文截断留待下次 —— 但这要求后端持有「半条记录的明文」状态，复杂度显著上升，**不推荐**。
- 推荐 (a)，并在 `Receive` 签名注释（`:354-360`，目前**完全没有** `max_out` 的说明）补一句。
- **附带发现（严重）**：`produced` 的累加与 `plaintext_out` 的实际内容**不一致**，因为 `:515` 在循环内 `clear()` —— 见 N5。

### 8.4 本轮新发现 4 条（前两条阻断）

#### N5（阻断，我方前两轮漏检）：`:515` 循环内 `plaintext_out.clear()` 会销毁已解出的前序记录

伪代码 `:504-540`：
```
504  loop:
515      plaintext_out.clear()          ← 在循环体内，每条记录都清一次
516      st = backend_decrypt(record, plaintext_out)
540      produced += plaintext_out.size()
```

一次 `Receive` 喂入 2 条记录时：
- iter1：`clear()` → 解密记录 1 → `plaintext_out` = 记录 1 的明文（100 B），`produced=100`
- iter2：`clear()` → **记录 1 的 100 B 被丢弃** → 解密记录 2 → `plaintext_out` = 记录 2 的明文（100 B），`produced=200`
- 返回 `kOk` 时 `plaintext` 只有 **100 B**（记录 2），而 `produced` 声称 200 B。

**直接违反 §3.4.2 边界 2（`:576`「一次喂入两条记录 → 一次调用返回两条明文（或至少不丢第二条）」）与边界 3（`:577`）。**
同时违反 §3.3 `:449`「一次 `Receive` 可能给出多帧」—— 多帧只保留最后一帧，TPKT 层会永远等不到前面那帧的字节，表现为**静默卡死**（无错误码）。

**这是从第①轮就存在的缺陷，我前两轮都读到了 `plaintext_out.clear()` 却按「修正 6 的失败路径保护」放行，未意识到它位于循环体内。本轮自我更正并明确列为阻断级。**

**最小修法**（不改变「失败不留残留」的意图）：
```
  loop:
    ...
    tmp.clear()                          # 每条记录用独立临时缓冲
    st = backend_decrypt(record, tmp)
    if st == INCOMPLETE: ...
    ...
    plaintext_out += tmp                 # 只在成功路径追加
    produced += tmp.size()
```
失败分支（`:528` / `:534`）改为 `plaintext_out.clear()` —— 因为此时 `plaintext_out` 已含前序成功记录的明文，按 §3.3 `:454`「任何 `!= kOk && != kClosed` 时内容与长度未定义」也必须清空。**注意：这意味着「已解出的前序记录会随错误一起丢弃」，这是契约允许的，但必须在文档里写明**（否则调用方会以为错误前拿到的数据有效）。

#### N6（阻断）：`INCOMPLETE` 在「记录已完整」时**可达**，`:519` 的「不应发生」是错的，且处理方式会活锁

`:519` 注释：「SChannel 只在记录不完整时返回它，而上面已保证 `5+len` 到齐 → 不应发生」。

**实测反例**（既有探针，未新建）：
```
[BASH:F:\rtsc\.tmp\tlsprobe\probe7.exe]
  HelloRequest record  in=9 -> 0x80090318 [0:t4,cb4] [1:t4,cb4]
  close_notify alert   in=7 -> 0x80090318 [0:t4,cb6] [1:t4,cb6]
```
两条记录都是 `5+len` 完全到齐（`16 03 03 00 04 …` 共 9 B；`15 03 03 00 02 …` 共 7 B），
`type` 合法、`len` 合法、`size == 5+len` —— **伪代码 `:505-511` 的四个前置检查全部通过**，
但 `DecryptMessage` 仍返回 `SEC_E_INCOMPLETE_MESSAGE`。

**后果（比「不应发生」严重得多）**：
`:520` 把记录原样放回缓冲首部、`:521` 返回 `kNeedMoreInput`。调用方据此从 socket 再读一批字节追加到
`rx_buffer_` 尾部 → 下一轮 `take_front` **又摘出同一条 9 B 记录**（因为它的 `len` 没变）→ 又 `INCOMPLETE` → 又放回。
**该记录永远不会被消费，而新读入的字节不断累积 → `rx_buffer_` 无界增长，直至 OOM。**
（这与 N1 是不同根因：N1 是「已消费路径漏消费」，N6 是「未消费路径永远无法推进」。）

**最小修法**（二选一，推荐第一条）：
- (a) **以「本次调用是否推进」判定**：若 `take_front` 摘出的记录满足 `5+len` 却仍返回 `INCOMPLETE`，
  说明这不是「缺字节」而是「SChannel 无法解析该记录」→ 直接 `return kProtocolError`（并置 `terminal_`）。
  判据：`INCOMPLETE` 时读 `SECBUFFER_MISSING`，若 `avail + missing <= 5+len` 仍 INCOMPLETE，即属此态。
- (b) 给 `rx_buffer_` 设上限（如 `max_plaintext + overhead + 4096`），超限 → `kProtocolError`。
- 无论选哪个，`:519` 的注释必须改成「**可达**，必须防御」，否则实现者会按注释把它写成 `assert`/`kInternal`。

#### N7（阻断）：`kDecryptFailed` 之后没有终态闩锁，而 **TLS1.3 上下文会自动恢复** → 篡改检测被架空

§3.3 `:453` 要求「`kDecryptFailed` → **立即终止**，不得继续（可能被篡改）」，但这是**调用方**的义务；
后端本身没有任何 `terminal_` 状态（`:532` 只对 `CONTEXT_EXPIRED` 置 `closed_`）。

**TLS1.2 与 TLS1.3 的行为不同，这使问题只在 TLS1.3 上暴露**：
```
[BASH:F:\rtsc\.tmp\tlsprobe\probe26.exe]
  proto=0x0800 (TLS1.2): tamper@60/61 -> 0x80090330; next record -> 0x80090330   ← 上下文毒化，天然安全
  proto=0x2000 (TLS1.3): tamper@53/54 -> 0x80090330; next record -> 0x00000000 data=8 plaintext_ok=1  ← 自动恢复！
[BASH:F:\rtsc\.tmp\tlsprobe\probe25.exe]
  proto=0x0800 -> recovered=0  poisoned=10 / 10
  proto=0x2000 -> recovered=10 poisoned=0  / 10
```
即：**TLS1.3 下篡改一条记录后，上下文仍然可用，下一条记录照常解出明文（10/10）**。
若调用方（或因 bug）在 `kDecryptFailed` 后继续调 `Receive`，后端会**正常返回后续明文** ——
「检测到篡改 ⇒ 必须停」这条不变量就完全依赖调用方的自觉，而后端无法阻止。

**最小修法**：加 `terminal_`（或复用 `closed_` 的语义，但 `closed()` 现被定义为「对端 close_notify」，不宜混用），
在 `:528` / `:534` / `:508` / `:509` 置位；`Receive` 入口 `if (terminal_) return last_error_;`。
这样 N7 与 Q1 的「终态」缺口一并解决。

#### N8（阻断）：`§3.4.1` 对「只收到票据」返回 `kNeedMoreInput`，与 `§3.3:450` 和 `§5 绿证 8` 直接矛盾

- 伪代码路径：票据记录 → `:523` `RENEGOTIATE` → `:525` 喂回 ISC、丢弃产出 → `:526` `continue` →
  缓冲已空 → `:505` `size < 5` 成立 → `:506` `return produced ? kOk : kNeedMoreInput`。
  票据不产出明文 → `produced == 0` → **返回 `kNeedMoreInput`**。
- 但 §3.3 `:450` 写：「`Receive` | `kOk` + `plaintext` 为空 | 正常（零长度应用数据，**或仅消化了 post-handshake 票据**）」；
  §5 绿证 8 `:805` 写：「TLS1.3 握手后收到票据时，`Receive` **必须返回 `kOk`**」。
- **两者不可能同时为真。** 按当前伪代码，绿证 8 在**正确实现**下也会红。
- 这是 N2「选 A」引入的副作用：N2 把 `produced`（明文字节数）当作「是否有进展」的唯一判据，
  而「消化了一条票据」是**有进展但无明文**。

**最小修法**：把判据从「明文字节数」改为「本轮是否消费过记录」：
```
  progressed = 0                     # 本轮消费过的记录数（成功解密或成功消化票据）
  ...
  progressed += 1                    # 在 take_front 之后、确认非 INCOMPLETE 之后
  ...
  if rx_buffer_.size() < 5:  return (produced || progressed) ? kOk : kNeedMoreInput
  ...
  if max_out && produced >= max_out: return kOk
```
即 `produced` 继续用于 `max_out`，`progressed` 用于「是否空转」。两者不可合并。

### 8.5 D14 降级与缺陷总数核对

| 项 | 核对结果 |
|---|---|
| 算式 `11 + 8 + 2 − 1 = 20` | **自洽**。D1–D11（`:641-655` 区段）= 11；D12–D19 = 8（其中 D14 删除线 `:655`）；D20–D21 = 2（`:666-667`）；活动条目 21 − 1 = **20** |
| D15–D21 编号未重排 | **确认未重排**。D15 `:656`、D16 `:657`、D17 `:658`、D18 `:659`、D19 `:660`、D20 `:666`、D21 `:667`；D14 保留占位并标 `~~D14~~`，与已发出的编号无错位 |
| §0 摘要 | **已同步 20**：`:29` |
| §4 标题 | **已同步 20**：`:624`「合并后 **20 条**」 |
| §4.3 结论 | **已同步 20**：`:674`「**最终条数：20 条**（D1–D21，其中 **D14 已降级、不计入**…）」 |
| 文末附言 | **已同步 20**：`:1139` |
| 附加留痕 | `:631-636` 记录了「原导语写 21、与标题/结论矛盾，已同步为 20 并留痕」—— 这是**主动记账**，加分 |

**结论：四处全部同步，算式自洽，编号稳定。** 唯一小瑕疵：§4.2 标题 `:649` 仍写「采纳 consult-b 的 **8** 条独有缺陷（D12–D19）」，
但其中 D14 已撤回，实际采纳 7 条。标题与 `:674` 的「D14 已降级」并存易误读，建议改为「8 条中采纳 7 条（D14 已撤回）」。**非阻断。**

### 8.6 绿证第 8 条的判别力判定

**结论：判别力成立，但父代理给出的「机制」是错的；且该断言当前与伪代码矛盾（N8），修前修后都会红。**

1. **父代理的机制分析不成立**。父代理说「原伪代码也能返回 `kOk`（`continue` 后缓冲已空）」。
   **实测与代码走查都不支持这一点**：原伪代码 `continue` 回到循环顶部时，`rx_buffer_` 里**仍保留着那 103 字节票据记录**
   （未 `erase`），因此会再次 `take_front` + 再次 `backend_decrypt`，**在同一次调用内**就返回 `kDecryptFailed`。
   证据：`probe39` 的 iter1 是 `0x80090330`，而 iter0/iter1 在探针里是同一个循环内的两次解密。
   所以「只断言 `kOk`」在原伪代码下**本来就是红的**，不需要两步断言才具备判别力。
2. **两步断言仍然更好，但理由是另一个**：它能抓到「消费了记录但把上下文弄坏」的实现
   （例如把 `EXTRA` 错喂给 ISC、或 `take_front` 长度算错），这类 bug 会让 iter0 返回 `kOk` 而 iter1 失败。
   单条 `kOk` 断言对这类 bug 无感。**所以保留两步断言，但文档里给的理由要改。**
3. **当前该断言必红（与 N1 无关）**：按 `:506` 的实现，票据调用返回 `kNeedMoreInput` 而非 `kOk`（N8）。
   即绿证 8 现在断言的是「伪代码不会做的事」。**修 N8 之后才可能变绿。**

### 8.7 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| N1 / N2 / N3 / N4 落地 | **通过**（逐条核到行号，无「声称改了实际没改」） |
| 3 个文档级问题（D-a/D-b/D-c） | **通过** |
| return 路径的「记录必须被消费」不变量 | **通过**（11 个出口无一遗漏） |
| return 路径的「终态」与「进度」维度 | **不通过**（N7 缺终态闩锁、N8 进度判据错） |
| 多记录累积语义 | **不通过**（N5 数据丢失，且违反 §3.4.2 边界 2/3） |
| 对抗输入下的推进性 | **不通过**（N6 活锁 + 无界增长） |
| D14 降级 / 总数 20 | **通过**（算式自洽、编号未重排、四处同步） |
| 绿证 8 判别力 | **部分**（判别力成立，但机制说明错误、且当前与伪代码矛盾） |

**放行条件（4 条，均为伪代码/契约小改，无需重跑探针）**：
1. **修 N5**：循环内改用 `tmp` 临时缓冲，成功才 `plaintext_out += tmp`；失败分支按 §3.3 清空 `plaintext_out`，
   并在文档里写明「错误前已解出的记录一并丢弃」。
2. **修 N6**：`INCOMPLETE` 在 `5+len` 已到齐时 → `kProtocolError`（配 `SECBUFFER_MISSING` 判据）或给缓冲设上限；
   `:519` 注释改为「可达，必须防御」。
3. **修 N7**：加 `terminal_` 闩锁，`kProtocolError`/`kDecryptFailed`/`kCertRejected` 置位，入口直接返回 `last_error_`。
   这一条同时是 Q1 的答案，且**必须有**——因为 TLS1.3 上下文会自动恢复（`probe25` 10/10），
   后端不闩锁就等于把「篡改必须停」完全外包给调用方。
4. **修 N8**：引入 `progressed`（消费过的记录数）与 `produced`（明文字节数）双计数；
   前者判「是否空转」，后者判 `max_out`。同时把 §5 绿证 8 的「理由」改写为「抓消费后上下文损坏」，
   而不是「原伪代码也能返回 kOk」。

**随修（不单独设卡）**：`max_out` 语义写死为软阈值（Q3）；`Receive` 签名注释补 `max_out` 说明；
§4.2 标题「8 条」改为「8 条中采纳 7 条」；`:232` 的「后续调用恒返回 `kClosed`」补上终止性错误同类语义。

### 8.8 我方本轮自我更正

1. **N5 是我前两轮漏掉的**。第①轮 `design-a.md:480`、第②轮 `:480` 都写着 `plaintext_out.clear()` 在循环内，
   我两次都把它读成「修正 6 的失败路径保护」而放行，未检查它的**位置**在循环体内。
   本轮通过「2 条记录 → 逐迭代模拟」发现记录 1 的明文被丢弃。**这是我方审计的真实遗漏，记账。**
2. **父代理 Q2 的前提需要修正**：父代理说「此时 `rx_buffer_` 已被 `take_front` 摘走前 `5+len` 字节，所以放回是正确的」
   —— 顺序结论正确，但真正的问题不是顺序而是**永远无法推进**（N6），两者不要混为一谈。
3. **父代理的绿证 8 机制分析错误**（§8.6 第 1 点）：原伪代码不会返回 `kOk`，会返回 `kDecryptFailed`。
   结论（两步断言更好）仍保留，但理由必须换。

### 8.9 第⑥步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| N8a | `SECBUFFER_MISSING` 能否作为「记录已完整但仍 INCOMPLETE」的可靠判据 | C | `probe7` 中 `avail=9`、`MISSING=4`（`9+4≠9`），与 `probe11` 的「`avail+MISSING==记录长`」口径不一致；实现期需实测确认 |
| N8b | `DecryptMessage` 一次调用是否**永远只返回一条记录**（本设计预切分后 `EXTRA` 是否恒为 0） | C | `probe18`：2-in-1 → `data=16 extra=45`（整缓冲喂入时返回首条 + EXTRA）；预切分后预期 `EXTRA=0`，未直接测 |
| N8c | TLS1.3 下 `kDecryptFailed` 后「连续多条」记录是否都能解出（`probe26` 只验了 1 条） | C | 影响 N7 的严重度评估，不影响「必须闩锁」的结论 |

---

## §9. 第⑦步复验（B1–B9 + 逐路径走查）

### 9.0 快照与验证方法（必须先声明，否则结论无法复现）

> **验证对象**：`docs/spec/tls-backend.design-a.md`，快照 **1464 行 / 120397 B**，
> SHA256 `66729EE085B00545AEFAE7815B9DC5A873AF0FAD31D4B418A1DDB0498C698E95`，mtime `00:38:37`。
> 复制为 `F:\rtsc\.tmp\design-a.step7.v3.md` 后分析，两次采样 sha 一致（已冻结）。
>
> **一个必须交代的事实**：审计开始时该文件正在被改写（我观察到 107059 → 109092 → 112779 → 120397 B
> 四次变化）。我第一次取快照（1392 行 / `AD392E0B…`）时，**B1/B2/B3/B6 的修复已经在里面了**。
> 因此对这四条，我**只能验证「现在是好的」，无法独立验证「当时是坏的」**。
> 「当时是坏的」这部分，我采信两方证据：①文档自己的 §3.4.0 留痕（`:534-551`）承认了三个缺陷；
> ②父代理的行号（`:595-599` 无 `continue`）对应的是 1311 行版本，我未见过。
> **这是本轮审计的能力边界，必须写出来，不能含糊过去。**
>
> **方法**：①`Select-String` 定位 + 分段读；②用 Python 精确计数出口/回边/标识符定义
> （避免控制台 GBK 乱码导致误判）；③重跑既有探针（未新建）；④`doc_lint.py` 全量跑一次。

### 9.1 B1–B9 逐条裁定

| # | 甲/父代理的判断 | 我的裁定 | 我自己的证据 |
|---|---|---|---|
| **B1** | 成功路径无 `continue`，一次 `Receive` 只解一条 | **成立（缺陷本身）；当前已修** | 现 `:642` 有 `continue`，是成功路径唯一回边。⚠ **我无法验证「修之前」**：首份快照（1392 行）已有此行。仅能确认当前状态正确 |
| **B2** | `extra_len` 从未定义 | **成立（缺陷本身）；当前已修** | 现 `:595` `st, extra_len = backend_decrypt(record, tmp)`；规则 3 `:661` 追加「`extra_len` 必须由 `backend_decrypt` 显式返回，不能靠隐式全局状态」。⚠ 同上，无法验证修前 |
| **B3** | `kClosed` 不置 `terminal_`，入口只查 `terminal_` | **成立（缺陷本身）；当前已修** | 现 `:568-569` 入口先查 `closed_` → `return kClosed`；`:617` `closed_ = true; return kClosed`。⚠ 同上 |
| **B4** | 标题「十个」实列 12 条 | **成立；已修** | 标题 `:761`「**十二个**」；脚本点数 `item_count=12`（`:770-802`，1..12 连续无缺号）；留痕 `:763-768` 记录了「D-a 复发」并补全演变链 |
| **B5** | `kInternal` 三处语义不一致 | **成立；但只修了 2/3，第 3 处仍不一致（部分）** | ①枚举分组 `:232-243` 写「以下**六个**是终止性」；②`terminal()` `:289-293` 确含 `kInternal` + `kUnsupported`（共 6 个）；③**`Fail()` 注释 `:646-648` 只列 5 个，漏 `kUnsupported`**。脚本核验 `has_kUnsupported_in_Fail_comment=False`。→ 父代理说的「三处不一致」**在本轮以另一种形式复发**：三处从「4/4/4 vs 契约说 6」变成「6/6/5」 |
| **B6** | `tmp` 从未声明 | **成立（缺陷本身）；当前已修** | 现 `:576` `tmp = std::vector<uint8_t>{}`，且 `:594` 每轮 `tmp.clear()` |
| **B7** | 红证允许「或 `kNeedMoreInput`」削弱判别力 | **成立；已修** | `:1056-1060` 现写「必须 **`kProtocolError`**」，并显式写「**删掉原稿的"或 `kNeedMoreInput`"**」，理由给的是「65535 > 16640，只可能是 `kProtocolError`；允许"或"会让 N6 的变体通过」。理由正确 |
| **B8** | `kUnsupported`/`kIoError` 无契约行；`kIoError` 无合法产生点 | **成立；`kIoError` 已删、`kUnsupported` 已归终止，但 `kUnsupported` 仍缺 `Receive` 契约行（部分）** | `kIoError`：枚举内已删（`:246-250` 留注说明理由）；全文 `kIoError` 仅剩 4 处，全是「已删除」的说明（`:246`、`:1424`、`:1427`、`:1432`），无代码引用 → 删干净了。`kUnsupported`：已进 `terminal()`（`:292`）与枚举终止组（`:238`），但 §3.3 **只有 `Handshake` 行（`:496`），没有 `Receive` 行** |
| **B9** | 软阈值提前返回后未写明排空义务 | **成立；已修** | §3.3 `:508` 明确「**达到 `max_out` 提前返回后，调用方必须继续调用 `Receive`（可传 `size=0`）直到 `buffered_input()==0`**」；签名注释 `:404` 同步 |

**统计：9 条全部成立；其中 7 条完全修好，B5 与 B8 各留一处残留。**

### 9.2 逐路径走查（父代理要求的核心交付）

伪代码区间 `:566-649`（`Receive` 主体 566-642，`Fail` 辅助函数 644-649）。

#### 出口清单（13 个 `return`，不含 `Fail` 内部那条）

| # | 行 | 触发条件 | 记录已消费 | `plaintext_out` 状态 | 与 §3.3 契约 |
|---|---|---|---|---|---|
| E1 | 569 | `closed_` 入口 | 否（未进循环） | 未触碰 | ✓ 幂等 |
| E2 | 571 | `terminal_` 入口 | 否 | 未触碰 | ✓ 幂等 |
| E3 | 580 | `rx_buffer_.size() < 5` | 否（无记录） | 保留已累加 | ✓ |
| E4 | 583 | `type ∉ {20,21,22,23}` | 否 | **未清空** | ✗ 违反 `:395-396` |
| E5 | 585 | `len > 16384+256` | 否 | **未清空** | ✗ 同上 |
| E6 | 587 | `size < 5+len` | 否（记录不完整） | 保留已累加 | ✓ |
| E7 | 604 | `INCOMPLETE` | **是** | **未清空** | ✗ 同上 |
| E8 | 609 | `RENEGOTIATE`(1.3) → `continue` | 是 | 未累加 | ✓ |
| E9 | 611 | `RENEGOTIATE`(1.2) | 是 | **未清空** | ✗ 同上 |
| E10 | 614 | `NO_RENEGOTIATION` → `continue` | 是 | 未累加 | ✓ |
| E11 | 617 | `CONTEXT_EXPIRED` | 是 | **保留已累加** | △ 契约未写「先取走明文」 |
| E12 | 621 | `ALTERED` / `DECRYPT_FAILURE` | 是 | 已清空（`:620`） | ✓ |
| E13 | 625 | `PEER_ALERT` | 是 | 已清空（`:624`） | ✓ |
| E14 | 629 | `INTERNAL` | 是 | 已清空（`:628`） | ✓ |
| E15 | 640 | `max_out` 达成 | 是 | 已累加 | ✓（B9 已补排空义务） |

#### 回边清单（3 个 `continue`）

| # | 行 | 类型 | 记录已消费 | 判定 |
|---|---|---|---|---|
| J1 | 609 | `RENEGOTIATE`(1.3) 回 `loop` | 是 | ✓ |
| J2 | 614 | `NO_RENEGOTIATION` 回 `loop` | 是 | ✓ |
| J3 | 642 | **成功路径末尾回 `loop`** | 是 | ✓ **B1 修复点**（也是唯一让「一次 `Receive` 解多条」成立的回边） |

#### 落空路径（无 `else` / `default` 的状态链）

`st` 的判定链是 7 个独立 `if`（`:600`/`:606`/`:613`/`:616`/`:619`/`:623`/`:627`），**没有 `else`**。
若 `backend_decrypt` 返回这 7 个之外的任何状态，控制流**落空到 `:631`**，即进入成功路径
（`plaintext_out += tmp`、`produced += tmp.size()`、`continue`）。见 §9.3 的 B13。

#### 计数与缺口

- **出口总数 = 13**（父代理上一轮数 9、我数 11，本轮确定为 13；差异来自把
  `type`/`len`/`INCOMPLETE`/`RENEGOTIATE`(1.2) 四个 `Fail` 分别计为独立出口）
- **回边总数 = 3**
- **落空路径 = 1**
- **缺口数 = 5**：E4 / E5 / E7 / E9 违反 `plaintext_out.clear()` 契约（4 个）+ 落空路径（1 个）
- **契约待补 = 1**：E11（`kClosed` 时明文已累加，§3.3 未写「先取走再关」）

### 9.3 本轮新发现（4 条，前两条阻断）

#### B10（阻断）：`Fail()` 用了从未定义的 `native_code` / `message` —— 与 B2/B6 完全同类

```
644: Fail(status):
645:   last_error_ = {status, native_code, message}   ← native_code / message 无来源
```
`Fail` 的唯一参数是 `status`；7 个调用点（`:583/:585/:604/:611/:621/:625/:629`）都只传一个参数。
脚本对 `:566-649` 做标识符扫描，`native_code`、`message` 出现在 `:645` 但**全区间无任何赋值**。

**这正是 B2（`extra_len` 未定义）与 B6（`tmp` 未声明）的同一个错误类型，在同一份伪代码里第三次出现。**
它同时解释了为什么 §3.3 `:510` 说「记录 `native_code` + `message`」却无法执行。

**最小修法**（三选一，推荐第一个）：
```
Fail(status, code, msg):                          # 显式传参
  last_error_ = {status, code, msg}
...
return Fail(kProtocolError, hr, "bad record type")
```
或让 `backend_decrypt` 返回 `st, extra_len, native_code`；或把 `native_code`/`message` 明写为
`backend_decrypt` 写入的成员（`last_native_code_` / `last_message_`）。**不能继续留空**。

#### B11（严重）：§3.4.3 排在 §3.4.2 之前

脚本按行序输出章节：
```
534: #### 3.4.0 原稿的错误（已废止，仅供追溯）
552: #### 3.4.1 修订后的伪代码（唯一正确写法）
706: #### 3.4.3 控制流自检（B1 的直接教训）     ← 先出现
761: #### 3.4.2 必须覆盖的十二个边界（都进 §5 的测试）  ← 后出现
```
B1 的修复把「控制流自检」插在伪代码之后，但插在了 3.4.2 **前面**，导致编号逆序。
更麻烦的是 `:719-720` 的正文写「**特别检查每个循环体末尾有没有回边**」，而
`:722` 的出口表里 E8/E10/E16 三行都写「回到 E3」——**读者按 3.4.2 → 3.4.3 的顺序读会先看到边界表再看到自检表，
与编号语义相反**。这是 D-a / B4 的**同一类「编号与内容不同步」缺陷的第三种形态**。

**最小修法**：把 `:706-760` 整段移到 `:761-806` 之后（编号与顺序都变正），或把两节互换编号。

#### B12（阻断）：4 个错误出口不清 `plaintext_out`，直接违反签名契约

签名注释 `:395-396` 是硬契约：
> 当返回 `!= kOk` 且 `!= kClosed` 时，`plaintext` 内容与长度均未定义，
> **后端必须在此之前 `plaintext.clear()`**（整批丢弃，含错误前已解出的记录）

脚本核验：`:566-649` 内 `plaintext_out.clear()` 只出现在 `:620`、`:624`、`:628`（对应 E12/E13/E14）。
**E4(`:583`)、E5(`:585`)、E7(`:604`)、E9(`:611`) 四个 `Fail(kProtocolError)` 出口没有 clear。**

后果：若前序记录已解出 100B 并累加到 `plaintext_out`，随后遇到 `type` 非法 → 返回 `kProtocolError`，
但 `plaintext_out` 里仍留着那 100B。按 §3.3 `:507`「任何 `!= kOk && != kClosed` 时内容未定义，调用方必须丢弃」，
调用方**理论上**会丢弃；但**契约同时要求后端清空**，两条并存时实现者会困惑，且若调用方误用就会读到脏数据。

**更严重的是 §3.4.3 自己的出口表把这几行标成了 ✓**：
`:729` E4 行写「未触碰（可能已有明文，但错误优先）| ✓ terminal」，
`:732` E7 行写「未累加（`tmp` 丢弃）| ✓ terminal」——**「`tmp` 丢弃」不等于「`plaintext_out` 清空」**，
表格把两个不同的缓冲混为一谈了。这说明 §3.4.3 的走查表本身**没有按它自己第 2 条标准
（「`plaintext_out` 是否已正确累加或已清空」）逐行核对**。

**最小修法**：在 `:583/:585/:604/:611` 四处 `return` 前各加一行 `plaintext_out.clear()`；
或把清空收进 `Fail()` 本体（`Fail` 是唯一错误出口，收进去只需改一处，且天然覆盖未来新增出口）——
**推荐后者**，它同时修掉 B12 和「新增出口忘记清空」这类复发。

#### B13（阻断）：状态链缺 `else`，未知状态被当成成功

7 个 `if` 之后没有 `else` / `default`（脚本核验：`:596-643` 内唯一 `else` 是 `:610`，属
`RENEGOTIATE` 的内层分支）。若 `st` 是这 7 个之外的值，控制流落到 `:631`（EXTRA 处理）→
`:637` `plaintext_out += tmp` → `:642` `continue`，**被当作成功记录**。

`tmp` 在未知状态下内容未定义（`backend_decrypt` 只保证 7 种已知状态的语义），
因此这是「把未定义内容当明文交给上层」，与 N5（把密文当明文）同级别。

可达性：`kCertRejected` 在 `terminal()`（`:291`）与枚举（`:236`）里，但**在 `Receive` 的
7 条判定链中不存在**；`kUnsupported` 同理。虽然这两者正常应由 `Handshake` 产生，
但**「正常不会发生」正是 N6 栽的那个坑**（`:601-603` 的注释当年就写「不应发生」，实测可达）。
防御性写法不能依赖「不该发生」。

**最小修法**：状态链末尾加
```
    # 兜底：任何未显式处理的 st 都是后端契约违背，不得当成功
    plaintext_out.clear()
    return Fail(kInternal)          # 或 Fail(kProtocolError)，取决于语义归属
```

### 9.4 「文本检查 vs 控制流检查」：成立，但需要更精确的表述

**父代理的判断成立，但表述可以更准。**

**精确化**：不是「文本检查 vs 控制流检查」，而是
**「词法/正则匹配 vs 结构性/语义性属性」**。B1/B2/B3/B6/B10/B12/B13 的共同点是它们都是
**结构性属性**（有回边、变量有定义、每个出口满足不变量），而不是文本模式。正则只能问
「某个模式在不在」，无法问「某个模式是不是**应该**在却没在」。

**但「只能人工」这个结论要打个折** —— 伪代码是**缩进结构化**的，有几类检查是廉价可自动化的：

| 检查 | 能抓到的缺陷 | 实现成本 | 可行性 |
|---|---|---|---|
| 循环体最后一条非注释语句必须是 `continue`/`return` | **B1** | ~15 行（按缩进找 `loop:` 块，取末行） | **高**，伪代码缩进一致 |
| 每个标识符使用前必须有赋值 | **B2、B6、B10** | ~40 行（def-use 扫描，排除关键字/函数名） | **中高**，会有少量误报（成员变量需白名单） |
| 每个 `return Fail(...)` 之前必须出现 `X.clear()` | **B12** | ~20 行（按出口分组扫描） | **高**，若改成「收进 `Fail()`」则此检查可删除 |
| 状态链必须有 `else`/`default` | **B13** | ~10 行（数 `if st` 与 `else` 是否配对） | **中**（伪代码语法不严格，需约定写法） |
| 章节编号与出现顺序一致 | **B4、B11** | ~10 行（正则提 `#### N.M` 后比对单调性） | **高**，`doc_lint.py` 已有 `F5` 的骨架，扩展即可 |

**我的结论：两边都要，但分工明确。**

1. **值得自动化的只有「机械类」5 条**（上表），一次性写进 `doc_lint.py` 约 **80-100 行**。
   它们能在**零人工**的情况下抓住本轮 5 个阻断里的 4 个（B1/B2/B10/B13）+ B12 + B11。
   投入产出比极高，因为伪代码一旦改动就要重跑。
2. **不该试图自动化「语义类」**：E11（`kClosed` 时明文已累加该不该取走）、
   B12 里「`tmp` 与 `plaintext_out` 是两个缓冲」这种区分、以及「契约表某行的措辞是否与实现一致」，
   都需要理解意图，正则做不到，勉强做只会产出大量误报把真问题淹没。
3. **真正的正解是实现阶段的可执行参考实现**：把这 80 行伪代码写成 ~150 行 Python
   （`rx_buffer_` 用 `bytearray`、`backend_decrypt` 用 mock），配 12 条边界的单测。
   这样 B1/B2/B3/B6/B10/B12/B13 全部变成**断言失败**，而且顺带产出实现者的对照物。
   **这比在文档上做静态分析强一个数量级**，但它属于实现阶段的产物，文档阶段做不到。
4. **人工逐路径走查仍是必需的最后一道**：因为 §3.4.3 这次的教训恰恰是
   **「表格写得很规范，但表格本身没按它自己的标准核对」**（B12 的 ✓ 是错的）。
   任何自动检查都防不了「检查者自己写错」。

**给工程的建议**：`doc_lint.py` 加 5 条结构检查（成本 80-100 行），
外加把「§3.4.3 出口表」改成**由伪代码生成**（而不是手抄）—— 手抄的表必然与代码漂移，
本轮 B12 的 ✓ 就是漂移的证据。

### 9.5 `kUnsupported` / `kIoError` 的独立意见

#### `kUnsupported` → 应进 `terminal()`：**同意**，但补两件事

- **同意理由**（与父代理、甲一致）：它是**配置级**不可恢复错误（Linux 无后端 / 服务器要求客户端证书）。
  `Handshake` 返回它即整条连接无后续；若之后 `Receive` 还能返回 `kNeedMoreInput`，就是幽灵状态。
- **必须补的第 1 件**：§3.3 **缺 `Receive` 的 `kUnsupported` 行**。当前只有 `:496`（`Handshake`）。
  契约表是「每个 Status × 每个方法」的矩阵，漏一格就会让实现者自己发明语义。
- **必须补的第 2 件**：`Fail()` 注释 `:646-648` 漏列它（B5 的残留）。
  既然把它归入终止组，三处（枚举分组 / `terminal()` / `Fail()` 注释）必须同步。

#### `kIoError` → 应删除：**同意**，且甲的理由比我原来说的更准

- 甲的理由（`:1432-1435`）：`Receive` 的入参是**调用方提供的 `ciphertext` 缓冲**，socket 读写
  完全由调用方负责，后端**没有任何合法产生点**。这个论证是对的。
- 我补一条更硬的判据：**检查 `TlsTransport` 全部 10 个方法，没有一个能产生 `kIoError`** ——
  `Handshake`/`Send`/`Receive` 都是纯内存变换（输入指针 + 输出 vector），
  `Shutdown` 只产 `out`，`record_sizes`/`negotiated`/三个 `Peer*` 都是查询。
  **一个永远不可达的枚举值是纯粹的负债**：每个调用方的 `switch` 都要为它写一个死分支，
  且 `-Wswitch` 会强迫写，`/W4 /WX` 下还得加 `[[maybe_unused]]`。
- **同意甲的分层结论**：若将来后端自己做 I/O，应新增 `IoTransport` 层，
  而不是把 I/O 错误混进 TLS 语义层。
- **附带的同类问题（甲未提）**：`kCertRejected` 在 `terminal()`（`:291`）、枚举（`:236`）、
  §3.3 `Receive` 行（`:506`）都有，但**在 `Receive` 的伪代码判定链里也没有产生点**（同 B13）。
  它和 `kUnsupported` 是同一类：**由 `Handshake` 产生、由 `Receive` 传播**。
  这两者必须在文档里明确写成「`Handshake` 产生，`Receive` 只可能经 `terminal_` 幂等返回」，
  否则实现者会在 `Receive` 里找产生点而找不到。

### 9.6 顺带核对

| 项 | 结果 |
|---|---|
| `:661` 留痕注是否已同步为 12 | **部分**：`:763-768` 的演变链已写「→ 10 条 → **12 条**」，并显式记录「上一版标题与留痕都停在『十个』」。但**父代理说的「`:661` 留痕注」在 1464 行版本里已不在 `:661`**（`:661` 现是规则 3 的 `extra_len` 那句）。以内容为准：**已同步** |
| `:272-275` `terminal()` 是否已含 `kInternal` | **是**，但行号已变。现 `:289-293`，含 `kInternal` + `kUnsupported`，共 6 个状态 |
| §4 缺陷总数是否仍为 20 | **是**。四处全同步：`:29`（§0）、`:836`（§4 标题）、`:889`（§4.3 结论「**最终条数：20 条**」）、`:1464`（文末附言）。`:896` 的算式 `21 − 1 = 20` 自洽。`doc_lint.py` 的 F2 也报 `ok(20)` |
| `doc_lint.py` 全量跑 | **TOTAL fail=0 warn=0**（12 文档）。`tls-backend.design-a.md` 报 `F1 ok F2 ok(20) F3 ok F4 ok F5 ok` |

**结论：这 4 项都没被改坏。** 特别值得注意的是 —— `doc_lint` 与 F2 的 `ok(20)` 全绿，
而同一份文件里有 4 个阻断缺陷（B10/B12/B13 + B5 残留）。**这再次证明 §9.4 的结论：
文本级检查对控制流/结构缺陷完全无效。**

### 9.7 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| B1 / B2 / B3 / B6 / B7 / B9 修复 | **通过**（6 条，逐条核到行号；B1/B2/B3/B6 的「修前状态」我无法独立验证，已声明） |
| B4 修复 | **通过**（标题「十二个」+ 12 条点数 + 留痕演变链） |
| B5 修复 | **不通过**（三处从 4/4/4 变成 **6/6/5**，`Fail()` 注释仍漏 `kUnsupported`） |
| B8 修复 | **不通过**（`kIoError` 删得干净；但 `kUnsupported` 仍缺 `Receive` 契约行） |
| 出口/回边完整性 | **不通过**：13 出口 + 3 回边已列全，但 **5 个缺口**（E4/E5/E7/E9 不清明文 + 落空路径） |
| 伪代码可执行性 | **不通过**：B10（`native_code`/`message` 未定义）、B13（未知状态当成功） |
| 文档结构 | **不通过**：B11（3.4.3 排在 3.4.2 前） |
| §4 总数 20 / doc-lint 全绿 | **通过**（但如 §9.4 所述，这两项对本轮缺陷无判别力） |

**放行条件（4 条，全部是伪代码/文档小改，无需重跑探针）**：

1. **修 B12 + B10 一起做**：把 `plaintext_out.clear()` 收进 `Fail()` 本体，
   并给 `Fail` 加 `code`/`msg` 参数（或改为写 `last_native_code_`/`last_message_` 成员）。
   **一处改动同时修掉 B10 与 B12，且天然覆盖未来新增的错误出口** —— 这是本轮性价比最高的一改。
2. **修 B13**：状态链末尾加 `else` 兜底 → `Fail(kInternal)`（附 `plaintext_out.clear()`）。
3. **修 B5 残留 + B8 残留**：`Fail()` 注释补 `kUnsupported`；§3.3 补 `Receive` 的
   `kUnsupported` 行，并明确 `kUnsupported`/`kCertRejected` 由 `Handshake` 产生、
   `Receive` 仅经 `terminal_` 幂等返回。
4. **修 B11**：把 §3.4.3 移到 §3.4.2 之后（或互换编号），并检查 §3.4.3 出口表的
   E4/E5/E7/E9 四行 —— 它们的 ✓ 是错的（见 B12）。

**随修（不单独设卡）**：E11（`kClosed` 时明文已累加）在 §3.3 补一句「调用方应先取走
`plaintext` 再关闭」；§3.4.3 的出口表改为从伪代码生成，避免手抄漂移。

**一句话**：甲的 B1–B9 修复**方向全对、7 条修干净**，但**同一份伪代码里又长出 3 个阻断**
（B10/B12/B13），且它们**与已修的三条是同一类错误**（未定义变量 / 出口不满足不变量 / 缺兜底分支）。
这说明「逐路径走查」这个方法**本身是对的，但这一轮的走查表漏了 4 行、且把自己的 ✓ 写错了**。
按 §9.4 的建议把 5 条结构检查加进 `doc_lint.py`，才能防止第八轮再出现同类问题。

### 9.8 我方本轮自我更正

1. **上一轮我数「11 个出口」是错的，本轮确定为 13**。差异原因：上一轮我把
   `type`/`len` 两个前置检查合并成一行出口，把 `RENEGOTIATE`(1.2) 归入了 `RENEGOTIATE`(1.3) 那条。
   本轮按「每个 `return` 语句算一个」重新点，得 13。**上一轮的数字应作废。**
2. **上一轮我没检查「出口是否清空 `plaintext_out`」**，只查了「记录是否已消费」。
   本轮补上这个维度才发现 B12（4 个出口违反契约）。**这是我方法上的漏洞，已补进本轮走查表。**
3. **上一轮我说「N1 的不变量完整成立，无遗漏出口」，这句话现在看是对的，但不够** ——
   「记录被消费」只是一个不变量；「出口满足全部契约」是另一个。上一轮只验了前者就下了
   「return 路径无未覆盖」的结论，**结论下得太早**。本轮补验后，出口覆盖是完整的，
   但**契约满足度不完整**（5 个缺口）。

### 9.9 第⑦步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| B14a | `backend_decrypt` 在未知 `st` 时 `tmp` 的内容是否保证为空 | C | 影响 B13 的严重度；但无论如何都必须加兜底，不因「可能为空」而放宽 |
| B14b | `kCertRejected` / `kUnsupported` 是否确实只由 `Handshake` 产生 | C | 需实现阶段确认；文档应显式写明产生点，而不是让实现者推断 |
| B14c | 把 5 条结构检查加进 `doc_lint.py` 后，能否在本轮 1464 行版本上**重现** B1/B2/B10/B12/B13 全红 | C | 这是验证检查器本身有效性的唯一方法（用历史版本做回归），本轮未做 |

---

## §10. 第⑧步复验（B10/B13/B8残留/E5 + 检查器本身）

### 10.0 快照与验证方式

> **文档快照**：`design-a.md` → `F:\rtsc\.tmp\da8.md`，**1656 行**，
> SHA256 `885CE6691A50ABA04C72AFA30F24F7C492B667B269FF7044B85C7682FB838BC4`。
> **检查器快照**：`pseudo_lint.py` → `F:\rtsc\.tmp\plint.frozen.py`，**504 行**，
> SHA256 `EF7DCE9065085E3943DDEF64658E163A010D00602CE61CAB34A5D270386146F1`（含 S0–S15）。
> **红证脚本**：`plint_redtest.frozen.py`，154 行，SHA256 `A4483EEF…`。
>
> **必须交代**：审计期间两个文件都在变（检查器从 432 行 → 504 行，我读到的版本只有 S1–S12，
> 实际运行时有 S13/S14/S15；文档从 1632 → 1656 行）。我先冻结再分析，**结论只对该快照负责**。
> 父代理给的「12 条检查 S1–S12」在冻结版里已是 **16 个 ID（S0–S15）**，S13/S14/S15 已补上
> N1/N5/N7 三条我上轮指出「没有对应检查项」的盲区。

### 10.1 检查器正确性验证（本轮重点）

#### 10.1.1 红证实跑结果：**11/12，S4 的注入失效（假阴性）**

```
$ python F:\rtsc\.tmp\plint_redtest.frozen.py
基线：exit=1  命中=['S6', 'S7']
[PASS] S1 缺回边 / S2 extra_len / S3 Fail 无 clear / S5 章节逆序 / S6 出口表不对账
[PASS] S9 漏 kClosed 排除 / S11 标题条数 / S13 记录未消费 / S14 循环内 clear / S15 缺终止闩锁 / S12 缺 Receive 行
[BAD]  S4 状态链无兜底        期望=S4  翻红=False  exit=2
        实际命中=['S7']  TOTAL fail=0 warn=1
红证：11/12 注入被正确检出   ← 脚本因此 exit=1（未 ASSERT OK）
```

**父代理报「红证 9/9 ASSERT OK」与我的实跑不符**。差异原因：父代理那次的 S4 注入用例是
「删掉 `if st == INTERNAL` 整段」，而冻结版脚本里 S4 的注入改成了同一件事但**在 1656 行文档上失效**
（见 10.1.2 的根因）。**这不是我跑错，是 S4 这条检查本身有缺陷。**

#### 10.1.2 S4 假阴性的根因（**检查器真实缺陷，不是用例问题**）

S4 的实现（`plint.frozen.py:193-211`）：
```python
top = min(i for _, i in chain)                    # 取最浅缩进
last_k = max(k for k, i in chain if i == top)     # 最后一个同缩进 if st
has_else = any(l.strip().startswith('else') and indent_of(l) == top
               for l in body[last_k + 1:])        # 只查「最后一个 if st 之后有没有 else」
```
**它只问「最后一个 `if st` 之后有没有 `else`」，不问「这个 `else` 绑定的是谁」。**

我用三个注入实测（`:F:\rtsc\.tmp\s8g.py`）：
```
A 删掉 else 整块                      → S4 命中 ✓
B else 缩进改成 8（不再是顶层 else）  → S4 命中 ✓
C 删掉 if st == INTERNAL、保留 else   → S4 未命中 ✗   ← 假阴性
```
**C 是最危险的形态**：`else` 仍在、缩进仍对，但它现在绑定到 `if st == PEER_ALERT:` 上，
状态链对「未知 st」依然会落空。S4 因为「找到了一个 else」就判绿。

**但更要紧的是：当前 1656 行文档正处于这个形态，而 S4 报了绿。**

#### 10.1.3 阻断：`:656` 的 `else` 只绑最后一个 `if`，正常数据全部返回 `kInternal`

文档 `:620-657` 的缩进实测（`:F:\rtsc\.tmp\s8out4.txt`）：
```
620 ind=4 | if st == INCOMPLETE:
626 ind=4 | if st == RENEGOTIATE:
633 ind=4 | if st == NO_RENEGOTIATION:
636 ind=4 | if st == CONTEXT_EXPIRED:
642 ind=4 | if st in {ALTERED, DECRYPT_FAILURE}:
645 ind=4 | if st == PEER_ALERT:
648 ind=4 | if st == INTERNAL:
651 ind=4 | # B13 / S4：未知状态一律视为内部错误，禁止落空到成功路径。
656 ind=4 | else:                        ← 与 648 的 if 配对，不是整链兜底
657 ind=8 |     return Fail(kInternal)
```

这 7 个 `if` 是**并列的独立语句**（同缩进 4，各自带 `return`），**不是 `elif` 链**。
Python/伪代码语义下，`else` 只与**紧邻的** `if st == INTERNAL:` 配对。后果：
- `st == "OK"`（正常解密成功）→ 7 个 `if` 全不匹配 → 落到 `else:` → **`return Fail(kInternal)`**
- 成功路径 `:659-670`（EXTRA 处理 / `plaintext_out += tmp` / `continue`）**变成死代码**

**我用逐行忠实翻译做了可执行验证**（`:F:\rtsc\.tmp\s8sim.py`，缩进严格照抄 4/8/12）：
```
=== 场景1：单条应用数据记录，期望 kOk + 明文 ===
返回 = ('RET', ('FAIL', 'kInternal'))
plaintext_out = b''  (长度 0)
terminal_ = True

=== 场景2：两条记录一次喂入，期望 kOk + 两条拼接 ===
返回 = ('RET', ('FAIL', 'kInternal'))
plaintext_out = b''
```
**任何一条正常应用数据都会返回 `kInternal` 并置 `terminal_`，连接立刻死。**
这是本步最严重的问题，比 B13 本身更糟——B13 修完之后**引入了新的、100% 必现的阻断**。

**最小修法**（两条都对，推荐第 1 条）：
```
# 方案1：把 7 个 if 改成 elif 链，else 自然成为整链兜底
if st == INCOMPLETE:
    ...
elif st == RENEGOTIATE:
    ...
elif st == NO_RENEGOTIATION:
    ...
...
else:
    return Fail(kInternal)
```
```
# 方案2：保留独立 if，把兜底写成显式守卫（放在状态链之后、成功路径之前）
if st not in {OK, INCOMPLETE, RENEGOTIATE, NO_RENEGOTIATION,
              CONTEXT_EXPIRED, ALTERED, DECRYPT_FAILURE, PEER_ALERT, INTERNAL}:
    return Fail(kInternal)
```
方案 2 的好处：不依赖 `else` 绑定规则，S4 即使不改也能被另一种检查覆盖。

**同时必须修 S4**：判据应从「有没有 else」改成「`else` 的缩进层级是否等于**第一个** `if st` 的层级
**且** 中间没有同层 `if st` 抢先配对」——最稳的实现是把 7 个 `if st` 视为一个 chain，
要求「chain 内相邻 `if st` 之间不得出现 `else`」，或者直接要求「chain 用 `elif`」。

### 10.2 检查器假阴性清单（历史缺陷哪些抓不到）

我对 N1–N8 / B1–B13 / C1–C11 全量过一遍，结论如下：

| 缺陷 | 抓得到？ | 说明 |
|---|---|---|
| B1 缺回边 | ✓ S1 | |
| B2 `extra_len` 未定义 | ✓ S2 | |
| B3 `kClosed` 未闩锁 | ✓ S15 | S15 查入口是否有 `closed_`+`terminal_` |
| B4 标题数不符 | ✓ S11 | |
| B5 `kInternal` 三处不一致 | ✓ S8 | |
| B6 `tmp` 未声明 | ✓ S2 | |
| B7 红证"或"削弱 | ✗ **无检查** | 属测试断言措辞，非伪代码结构。可接受（人工项） |
| B8 `kUnsupported` 缺 Receive 行 | ✓ S12 | |
| B9 排空义务未写 | ✗ **无检查** | 属散文契约，非结构。可接受 |
| B10 `native_code`/`message` 未定义 | ⚠ **部分** | 见下（改名可绕过） |
| B11 章节逆序 | ✓ S5 | |
| B12 Fail 出口不清明文 | ✓ S3 | |
| B13 状态链无兜底 | ⚠ **部分** | 见 10.1.2：`else` 绑错对象时假阴性 |
| N1 票据未消费 | ✓ S13 | 冻结版已补 |
| N5 循环内 clear | ✓ S14 | 冻结版已补 |
| N7 无终止闩锁 | ✓ S15 | 冻结版已补 |
| C9 "未定义" vs "保证为空" | ✗ **无检查** | 语义区分，正则不可判。可接受（人工项） |

**三处需要说明**：

1. **B10 可被改名绕过（实测）**：S2 的 `CRITICAL` 白名单是字面量
   `['tmp','extra_len','native_code','message','record','progressed','produced']`（`:140`），
   而当前文档已把变量改名为 `last_native_code_` / `last_message_`。
   `\bnative_code\b` 因下划线算单词字符而**不匹配** `last_native_code_`（实测 `:F:\rtsc\.tmp\s8e.py`：
   `native_code` hits=`[234,282,516,530,676]`，`last_native_code_` hits=`[678,680,699,708]`——两组不相交）。
   所以 S2 现在**只因为改名而变绿**。我实测删掉成员声明两行（`:699-700`）后跑 lint：
   ```
   TOTAL fail=1 warn=1   ← 只有 S6/S7，S2 依然绿
   ```
   **即：把 `last_native_code_` 的定义删掉，S2 抓不到。这是白名单式检查的固有缺陷。**
   修法：把 `CRITICAL` 改成**后缀匹配**（`_native_code_` / `_message_` 等），或改成
   「所有形如 `last_*_` 的标识符都必须有定义点」的规则。

2. **B13 的假阴性已在 10.1.2 证明**，且**当前文档正处在该形态**。

3. **C9 / B7 / B9 无检查是合理的**：它们是散文措辞与测试断言，不是伪代码结构。
   **不要为了覆盖率去加检查** —— 加了只会误报（见 10.3）。

### 10.3 检查器假阳性验证

我逐条在**正确写法**上试，结果：

| ID | 正确写法会不会误报 | 我的实测/推理 |
|---|---|---|
| S1 | **会（特定写法）** | 若循环体顶层末条是 `if ...: continue`（无 `else`），S1 判 fail。但那种写法**确实**在条件不成立时落空 → **不是误报**。若写成 `while True:` 风格（无 `loop:` 标记），S1 完全不检查 → **假阴性**，不是假阳性 |
| S2 | **会** | 白名单是固定 7 个名字。任何**新引入**的临时变量都不受检 → 假阴性；反之若文档在**注释里**提到 `tmp` 而代码用别的名字，`is_code()` 已排除注释行，不会误报。**未见误报** |
| S3 | **会（形态 a 的边界）** | 只要 `Fail()` 体内出现 `plaintext_out.clear()` 就整体放行。若未来某个 `Fail` 变体（如 `FailWarn`）不清，S3 不管 → 假阴性 |
| S4 | **会** | 见 10.1.2。反向：若状态链写成 `elif` 链（正确），`re.match(r'^if\s+st\b')` 只匹配第一个 `if`，`chain` 长度=1，`has_else` 查到 → 绿。**正确写法不误报** |
| S5 | **会（非 3.4.x 编号）** | 只认 `#### 3.4.\d+`。若将来出现 `#### 3.5.x` 逆序，S5 不管 → 假阴性 |
| S6 | **会** | `n_ret` 只数**行首** `return`。文档 `:637` 是 `closed_ = true; return kClosed`（**行内 return**），未被计入 → 这就是当前 `16 != 17` 的**真实原因之一**（另一原因是新增的 else 兜底 `:657`）。**这是 S6 的假阳性**：出口表 16 行是对的（E1–E16），代码里"出口"确实是 16 个，但 S6 用「行首 return 计数」这个代理指标，漏了行内 return、又把 else 里的 return 算进去，两个误差叠加成 17 |
| S7 | **会** | 只判 `'§' in cell`。`:821` E5 行最后一列写「同上」，S7 报 warn。但 E5 行的**倒数第二列**已有 `Fail()` 内 clear 的说明，且「同上」在这里指的是「与 E4 相同」——**语义可定位，只是字面不可定位**。父代理要的是"改成完整章节号"，所以这条 warn 是**有效的**（非误报），但严重度应低于 fail |
| S8 | **会** | `Fail() 注释` 的正则是 `^Fail\(status\):\n(.*?)^\S`（非贪婪到下一个非空行首）。若 `Fail` 签名改成 `Fail(status, code)`，正则失配 → `fail_set` 为空 → **必然误报「terminal() 含但 Fail() 注释漏列：全部 6 个」**。父代理说修过 S8 窗口截断，但**签名变化这一路仍会误报** |
| S9 | **会** | 只认「任何/所有 … != kOk」。若措辞是「返回码非 `kOk`」或「`!= kOk` 时」（不带"任何/所有"），S9 漏检 → 假阴性 |
| S10 | **会** | 同层级同编号即 fail。若文档有意用「§3.4.2（旧）」保留历史编号，会误报 |
| S11 | **会** | 只统计 `^\s*\d+\.\s`。若边界用 `-` 无序列表，`cnt=0` → **跳过检查**（假阴性）。当前是数字列表，OK |
| S12 | **不会** | 只要 `| \`Receive\` |` 行里出现 `kUnsupported` 即绿，哪怕写「Receive 会产生 kUnsupported」这种**错误**语义也绿 → **假阴性**（只查存在性，不查语义） |
| S13 | **会（特定写法）** | 判据是「`take_front` 行号 > 第一个分支内 exit 行号」。若 `take_front` 写在**循环外**（预取），会误报 |
| S14 | **会** | 只要循环体内出现 `plaintext_out.clear()` 即 fail。若某个后端**故意**在循环内清空（比如每轮独立语义），会误报——但本设计契约禁止，故**不是误报** |
| S15 | **会** | 只查 `loop:` 之前的头部有没有 `terminal_`/`closed_` 字样。若变量改名（`term_latch_`），误报 |

**假阳性汇总：S6 是**已实际发生**的假阳性（16 vs 17 的 1 之差来自行内 return + else 兜底双重误差）。
其余多为「假阴性」或「改名即失效」的白名单脆弱性。**

**S6 的最小修法**：`n_ret` 应数「`return` 出现在行内任意位置且不在注释里」，
即 `re.search(r'\breturn\b', l.split('#')[0])`；并排除 `Fail()` 辅助函数体内的 `return`
（它不是一个 Receive 出口）。或者更稳：**出口表由伪代码生成**（我在 §9.4 已建议），彻底消除对账问题。

### 10.4 甲的 4 条修复复验

| 项 | 结论 | 证据 |
|---|---|---|
| **B10 / S2**（`native_code`/`message` 来源） | **形式上修了，语义上合理，但被检查器漏洞掩盖** | 文档新增「后端成员声明（C2）」`:687-701`，声明 `int32_t last_native_code_` + `std::string last_message_`；`Fail()` `:680` 改为 `last_error_ = {status, last_native_code_, last_message_}`。**语义论证正确且比我的建议更好**：`:708-713` 明确「`native_code` 来自底层（`GetLastError`/`SECURITY_STATUS`/`SSL_ERROR_*`），`Fail()` 的 6 个调用点都不知道它；做成成员则产生点唯一（`backend_decrypt` 返回处）、消费点唯一（`Fail()`）」。这确实优于我上轮建议的「加形参」——加形参会让 6 个调用点各自去捞底层码，把「底层码在底层产生」这个事实拆散。**采信甲的方案。** 但注意：S2 现在靠改名变绿，删掉成员声明仍绿（10.2 第 1 点） |
| **S4 / B13**（状态链 else 兜底） | **未修好，且引入新的阻断** | `:656` 的 `else:` 与 `if st == INTERNAL:`（`:648`）配对，不是整链兜底 → **所有正常 `st` 落进 else 返回 `kInternal`**（可执行模拟实证，10.1.3）。E 表也未同步到 17 行（仍是 E1–E16，`:817-832`） |
| **S12 / B8**（`kUnsupported` 补 Receive 行） | **修好，且写得比要求更好** | `:526` 新增 `| \`Receive\` | \`kUnsupported\` |`，内容明确写「**本方法不产生**，仅在 `Handshake` 已返回 `kUnsupported` 后经 `terminal_` **幂等返回**（入口 E2）」，并附带 `kCertRejected` 同理。**这正是我 §9.5 要求的「明确写『本方法不产生，仅经 terminal_ 返回』」，一字不差** |
| **S7 / E5**（`同上` 改完整章节号） | **未修** | `:821` E5 行仍是「… | **`Fail()` 内 clear** | 同上 | ✓（C1 前为 ⚠） |」，「同上」未改。`pseudo_lint` 也报了 `S7 WARN @821`。**另 `:818` E2 行也有「（同上）」，S7 因括号形式未命中正则而漏报** |

### 10.5 「400 行 vs 80–100 行」的评估

**先纠正一个事实**：我上轮说的是「**5 类检查**约 80–100 行」，父代理实现成 **16 个 ID / 504 行**。
多出来的部分是 S6–S12（7 条）+ S13–S15（3 条）+ 框架（提取/报告/CLI）。

**我的评估：值得，但不是全部值得，且有一条做反了。**

| 类别 | 行数（估） | 价值 | 判断 |
|---|---|---|---|
| 框架（提取/缩进/CLI/报告） | ~90 | 必需 | **值得**。没有它其余检查无从落地 |
| S1/S2/S3/S4/S5（我提的 5 类） | ~110 | 高 | **值得**。其中 S4 有缺陷（10.1.2），但**方法对** |
| S13/S14/S15（补我指出的 3 个盲区） | ~60 | 高 | **值得**。这三条正好覆盖 N1/N5/N7，且都在历史快照上翻红了（见 10.6） |
| S6/S7（出口表对账） | ~45 | **中** | **部分值得**。S6 当前是**假阳性来源**（16 vs 17），S7 是有用的（E5 确实没改）。若改成「由伪代码生成出口表」，S6 可整条删除 |
| S8/S12（Status 一致性） | ~55 | 高 | **值得**。S8 抓到过 B5，S12 抓到 B8。但两者都有改名/签名脆弱性 |
| S9/S10/S11（措辞/编号） | ~60 | **低** | **S11 值得**（B4 型复发两次，机械检查确有必要）；**S9 价值低**（只认"任何/所有"这一种措辞，换个说法就漏，且它检查的是散文而非结构）；**S10 与 doc_lint F5 重复**，可以删 |

**结论**：
- **400 行值得**，因为它一次投入覆盖了 6 轮里出现的绝大多数缺陷类别，且**能在历史版本上重现**（10.6）。
- **但应删/改 3 处**：S6（假阳性，改为生成表或修计数逻辑）、S9（措辞覆盖面太窄，收益低）、
  S10（与 doc_lint F5 重复）。
- **80–100 行是我低估了**：我当时只算了 5 条检查的**判定逻辑**，没算框架与报告。
  实际「可用」的下限约 **200 行**（框架 + 5 条核心），400 行是把边界情况也覆盖后的合理值。
  **我收回「80–100 行」这个数字，它不准确。**

### 10.6 B14c 回归：**不需要历史快照，我已有两份**

我在第⑦步已经冻结了两份历史快照，本轮直接跑（这是父代理问的「能否在历史版本上重现」）：

**① 1392 行版（第⑦步首份快照，B1–B9 修复前）**
```
$ python plint.frozen.py --file design-a.step7.snapshot.md
S2 native_code / message 无定义点 @623          ← B10 ✓
S3 4 个 Fail 出口未清 plaintext_out @561/563/582/589  ← B12 ✓
S4 状态链无 else @605                            ← B13 ✓
S14 循环内 clear @598/602/606                    ← N5 ✓
S5 §3.4.x 逆序 [0,1,3,2]                         ← B11 ✓
S8 §3.3 无对应行：['kIoError']                    ← B8 ✓
S12 kUnsupported 无 Receive 行                    ← B8 残留 ✓
S11 标题称 10 个边界，实列 12 条                    ← B4 ✓
S7 15 行未引用契约章节                            ← C7 ✓
TOTAL fail=14 warn=1
```

**② 1464 行版（第⑦步末，B1–B9 修完）**
```
S2 ×2 / S3 ×4 / S4 / S14 ×3 / S5 / S8(kUnsupported) / S12 / S7
TOTAL fail=13 warn=1
```
（比 1392 版少 S11——B4 已修，正是修复生效的证据）

**③ 当前 1656 行版**
```
S6 出口表 16 != 17  @817
S7 1 行未引用章节   @821
TOTAL fail=1 warn=1
```

**判定：B14c 的答案 = 能重现，且我已有快照，不需要从 `.opencode/backups/` 找。**
但我必须指出一个**关键观察**：
- **B1 在这三份快照里 S1 从未翻红**。原因：1392 行版已经是修完 B1 的版本（我上轮已声明无法验证修前）。
  **所以「S1 能抓 B1」这件事，只有 `redtest.py` 的注入用例能证明，历史版本证明不了。**
  这不是检查器的问题，是**我没有 B1 修复前的快照**。
- **S4 在三份历史版本里都翻红了，但在当前版报绿——而当前版恰恰有 S4 要抓的缺陷。**
  这正面说明：**红证通过 ≠ 检查器有效**。`redtest.py` 的 12 个注入用例都用了「删掉整块」这种
  **粗粒度变异**，而真实缺陷是「保留 else 但绑错对象」这种**细粒度变异**。
  **红证必须包含"语义等价但结构不同"的变异**，否则只能证明检查器对粗糙缺陷有效。

**建议**：给 S4 加一个红证用例 = 我 10.1.2 的注入 C（删 `if st == INTERNAL` 保留 `else`），
并断言 S4 必须命中。这条用例现在会失败，正好证明检查器需要修。

### 10.7 顺带核对

| 项 | 结果 |
|---|---|
| §3.3 是否仍有 `kCertRejected` 在 `Receive` 行残留 | **已清除，但以「否定式」保留**：`:525` 的 `Receive` 行写「`kCertRejected` **不**在此行——它在握手期产生（见上）」；`:526` 写「同理 `kCertRejected`：二者都是『由 `Handshake` 产生、由 `Receive` 传播』」。**这是正确做法**（显式否定比删掉更防误读） |
| C10 理由是否已从「RDP 不用客户端证书」换成「SChannel 返回 kUnsupported 而非 kCertRejected」 | **已换，且理由更准**：`:1611-1612` 写「证书校验走 `SCH_CRED_DEFERRED_CRED_VALIDATION`（§3.2.3），校验在 **`Handshake` 的 ISC 往返**里完成，`Receive` 期不会产生证书错误」。这比「RDP 不用客户端证书」精确——**它解释的是「为什么产生点在 Handshake」，不是「为什么不需要这个错误码」** |
| C11 相对引用是否已改绝对编号 | **已改，但节号本身又换了**：`:554/572/776/867` 现为 3.4.0/3.4.1/**3.4.2 控制流自检**/**3.4.3 十二个边界**，顺序已正。引用计数 `§3.4.2`×12、`§3.4.3`×15，与 `:1623` 声称的「11 处 + 6 处」不一致（**实际 12+15，不是 11+6**）。这属于**留痕数字与现状脱节**，非阻断 |
| §4 缺陷总数 | **仍为 20**：`:29`/`:945`/`:953`/`:998`/`:1005`/`:1656` 全部一致，`:1005` 算式 `21 − 1 = 20` 自洽 |
| `doc_lint.py` 全量 | **TOTAL fail=0 warn=0**（12 文档） |

### 10.8 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| 检查器红证 | **不通过**：11/12，S4 假阴性（且父代理报的是 9/9 全绿，与实跑不符） |
| 检查器在历史版本上的回归（B14c） | **通过**：1392 行版 fail=14（含 B4/B8/B10/B11/B12/B13/N5），1464 行版 fail=13（B4 已消），当前版 fail=1 |
| 检查器假阴性 | **3 条**：S4（else 绑错）、S2（改名绕过，实测删定义仍绿）、S12（只查存在不查语义）；B7/B9/C9 无检查属合理 |
| 检查器假阳性 | **1 条已发生**：S6（行内 return 漏计 + else 兜底多计 → 16 vs 17）；S8 在 `Fail` 签名变化时会全量误报 |
| **B10 修复** | **通过（语义优于我的建议）**，但被 S2 漏洞掩盖 |
| **B13 修复** | **不通过，且引入新阻断**：`:656` 的 `else` 绑到 `if st == INTERNAL`，正常数据 100% 返回 `kInternal`（可执行模拟实证） |
| **B8 残留修复** | **通过**：`:526` 明确写「本方法不产生，仅经 terminal_ 幂等返回」 |
| **E5「同上」修复** | **不通过**：`:821` 仍是「同上」；`:818` 另有「（同上）」被 S7 漏检 |
| E 表同步到 17 行 | **不通过**：仍是 E1–E16（`:817-832`），且 S6 报 16 != 17 |
| §4 总数 20 / doc_lint 全绿 | **通过**（但如 §9.4 所述，对结构缺陷无判别力） |

**放行条件（5 条）**：

1. **【阻断】修 `:656` 的 else 绑定**：把 7 个 `if st` 改成 `elif` 链（推荐），
   或改用显式守卫 `if st not in {…}: return Fail(kInternal)`。
   **当前版本任何正常应用数据都会返回 `kInternal`，比修复前更糟。**
2. **【阻断】修 S4 判据**：从「有没有 else」改为「else 是否与**第一个** `if st` 同层且中间无同层
   `if st` 抢先配对」；或直接要求 chain 用 `elif`。
   并补一条红证：删 `if st == INTERNAL` 保留 `else` → S4 必须命中（现在不命中）。
3. **修 S2 白名单**：改为后缀匹配（`_native_code_` / `_message_`）或「所有 `last_*_` 必须有定义点」。
   否则删掉成员声明也能绿（我已实测）。
4. **修 S6 计数**：`return` 用 `re.search` 而非 `re.match`（捕行内 return），并排除 `Fail()` 辅助函数体；
   或干脆改成「出口表由伪代码生成」。
5. **修 E5「同上」**（`:821`）+ E2「（同上）」（`:818`），改成完整章节号；
   并把 E 表从 16 行同步到实际出口数（加 else 兜底那条）。

**随修**：C11 留痕里的「11 处 / 6 处」应改为实测的「12 处 / 15 处」；
建议删 S9/S10（收益低 / 与 doc_lint F5 重复）。

### 10.9 我方本轮自我更正

1. **我上轮说「5 类检查约 80–100 行」低估了**。只算判定逻辑不算框架是错的，
   可用的下限约 200 行。**收回该数字。**
2. **我上轮建议「把 clear 收进 `Fail()`」是对的，但没预见到它会掩盖 S3 的覆盖面问题**
   （S3 只要 Fail 体内有一处 clear 就整体放行，未来新增的 `FailWarn` 之类不会被检查）。
   这是我建议的副作用，记在此。
3. **我上轮说「B10 建议加形参」不如甲现在的成员方案**。甲的理由（产生点唯一、消费点唯一）
   比我的「显式传参」更符合「底层码在底层产生」的事实。**我采信甲的方案，并承认自己那条建议次优。**

### 10.10 第⑧步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| C12a | `else` 绑定缺陷在真实 C++ 实现里是否同样发生 | — | **不适用**：C++ 编译器会直接报错或按同规则绑定；伪代码是设计文档，缺陷在文档层。但正因如此，**照伪代码实现的人会写出 `if/else if` 链而"意外正确"，或写出独立 `if` 而 100% 失败**——两种结果差异极大，说明伪代码必须无歧义 |
| C12b | 是否有 B1 修复前的快照可用于验证 S1 | C | 我没有；`.opencode/backups/` 里只有 `discover/memory/plan/process/capabilities` 的备份，**无 design-a**。若要补，只能靠 `redtest.py` 的注入用例 |
| C12c | S8 在 `Fail` 签名变化时的误报范围 | C | 我只推理未实测（改签名需改文档，禁止）；建议父代理在改签名时跑一次 |

---

## §11. 第⑨步复验（D1 修复 + 检查器三修 + 语义验证器）

### 11.0 快照与三个 lint 的实跑 exit 码

> **文档**：`design-a.md` → `F:\rtsc\.tmp\da9.md`，**1882 行 / 151495 B**，
> SHA256 `88CDF5A838671A246888BEB1863ADE00903730A9FA0646F3C6F8DC8F0D8B3AF9`。
> **检查器**：`pseudo_lint.py` **641 行**，SHA256 `97A4897C…`（S0–S15）。
> **红证**：`pseudo_lint_redtest.py` **195 行**，SHA256 `AB67FA89…`（16 用例）。
> **语义验证器**：`verify_elif_semantics.py` **127 行**，SHA256 `EA9A0E36…`。
>
> **三个 lint 的实跑结果（我自己跑的）**：
> ```
> $ python pseudo_lint.py --file design-a.md
>   TOTAL fail=0 warn=0                    → exit=0
> $ python pseudo_lint_redtest.py
>   红证：16/16 注入被正确检出  ASSERT OK   → exit=0
> $ python verify_elif_semantics.py
>   PASS: st==OK 走成功路径，未知状态走 else 兜底 → exit=0
> ```
> **三绿成立，我复现了父代理的 exit=0。**
>
> **但本轮的核心结论是：三绿里有一个是假的。** 详见 Q1。

### 11.1 Q1：`verify_elif_semantics.py` 够不够？

**不够，而且它现在的 PASS 是假的——它有一个硬编码缺陷，导致它对最关键的一类变异无判别力。**

#### 11.1.1 硬编码缺陷（实测）

脚本 `:85-86`：
```python
    for k, kw, cond in outer:
        if kw == 'else':
            return ('RET', 'kInternal')     ← 不读 else 的 body，直接返回硬编码值
```
**它从不检查 `else:` 下面实际写了什么**，只要链末有 `else` 就假定它是 `Fail(kInternal)`。

我用三个变异实测（`v_mut*.py`，只改 `DOC` 指向，不动原脚本）：

| 变异 | 实际语义变化 | 脚本输出 | 判定 |
|---|---|---|---|
| **MUT1**：`else:` 体改成 `pass`（未知状态**落空到成功路径**，正是 D1 的原始形态） | 严重（B13 复发） | `st=BOGUS -> RET kInternal OK`，**PASS** | **假阴性（致命）** |
| **MUT2**：`elif st == INTERNAL:` 体改成 `pass` | 严重（内部错误被当成功） | `st=INTERNAL -> CONT - OK`，**PASS** | **假阴性** |
| **MUT3**：`PEER_ALERT` 分支改成 `return kOk` | 严重 | `st=PEER_ALERT -> RET kInternal OK`，**PASS**（它落到 else 兜底了，恰好掩盖） | 侥幸 |
| **MUT4**：`elif st == OK:` 体改成 `return Fail(kProtocolError)` | 致命（正常数据变错误） | `st=OK -> RET kProtocolError **OK**`，**PASS** | **假阴性（致命）** |
| **MUT5**：删掉整个 `elif st == OK` | 致命（D1 真实形态） | `st=OK -> RET kInternal *** BAD ***`，**FAIL exit=1** | **唯一能抓到** |

**MUT1 与 MUT4 的严重性**：
- MUT1 = 把 else 兜底去掉 → 未知状态落空到成功路径 → **这正是 B13/D1 要防的**，脚本报 PASS。
- MUT4 = 把 `st == OK` 分支写成返回错误 → **所有正常数据变成协议错误**，脚本报 `OK`。

**根因有两层**：
1. `:85-86` 的 else 硬编码（不看 body）。
2. `:117` 的断言太弱：`ok = not (act == 'RET' and status == 'kInternal' and st == 'OK')`
   —— **只判「OK 不能返回 kInternal」**，不判「OK 必须 CONT」「其他状态必须返回预期码」。
   所以 MUT4 的 `kProtocolError` 逃过（不是 `kInternal`）。

#### 11.1.2 但它确实抓到了 D1（MUT5），所以不是全无价值

`st=OK -> RET kInternal *** BAD ***` 这条是真判别力。D1 的原始形态（7 个并列 `if` + 误绑 else）
正是 MUT5 的等价物，脚本能抓。**所以这个脚本的价值 = 「只抓 D1 这一种形态」，不能推广。**

#### 11.1.3 该不该现在就翻译整个 `Receive`？

**不该现在做，但要做一件更小的、性价比极高的事。**

**不该现在做的理由**（三条，按重要性）：

1. **它会把「文档验证」变成「实现验证」，混淆两个阶段的责任。**
   一旦把 `rx_buffer_` / `backend_decrypt` / `take_front` 全部 mock 出来跑，
   你测的就不再是「文档是否自洽」，而是「**你的 Python 翻译是否等于文档**」——
   而翻译本身会引入新 bug（我这轮的 `s8sim.py` 就是例子：我第一版翻译漏了 `else` 绑定规则，
   跑出「所有数据返回 kInternal」才反过来发现文档缺陷）。
   **翻译器的正确性无法自证**，这和第⑧步「检查器本身要验证」是同一个问题，且更难。
2. **12 条边界里有 7 条根本不需要伪代码级模拟就能测**：
   B9（max_out 软阈值）、N3（EXTRA 算术）、N5（多记录累加）都是**纯函数**语义，
   实现阶段一行 `EXPECT_EQ` 就够；在文档阶段模拟它们，等于提前写一遍实现再丢掉。
3. **实现阶段有真代码可测，那时的边际收益是 10 倍**。现在做 = 写一份一次性翻译器；
   实现阶段做 = 测真代码。同样的工作量，后者的结论可信度高得多。

**但现在必须做的一件小事（约 30 行）**：修 `verify_elif_semantics.py` 的两个缺陷。
```python
# 1) else 不硬编码，读它的 body
if kw == 'else':
    seg = <该分支体>
    m = re.search(r'Fail\((k\w+)\)', seg)
    if not m:  FAIL('else 分支没有 return Fail(...)，未知状态会落空')
    return ('RET', m.group(1))

# 2) 断言改成「逐状态期望表」，而不是「只判 OK != kInternal」
EXPECT = {
  'OK':                ('CONT', None),
  'INCOMPLETE':        ('RET', 'kProtocolError'),
  'RENEGOTIATE':       ('CONT', None),
  'NO_RENEGOTIATION':  ('CONT', None),
  'CONTEXT_EXPIRED':   ('RET', 'kClosed'),
  'ALTERED':           ('RET', 'kDecryptFailed'),
  'DECRYPT_FAILURE':   ('RET', 'kDecryptFailed'),
  'PEER_ALERT':        ('RET', 'kPeerAlert'),
  'INTERNAL':          ('RET', 'kInternal'),
  'BOGUS':             ('RET', 'kInternal'),
}
for st, want in EXPECT.items():
    got = evaluate(st)
    if got != want: FAIL(st, got, want)
```
**修完之后，MUT1/MUT2/MUT3/MUT4/MUT5 全部应翻红**（现在是 1/5）。
并把 MUT1 与 MUT4 加成 `redtest` 用例（它们现在完全没被覆盖）。

**结论**：这个脚本**方向对**（语义验证确实是「绿灯证明不了正确」的正确补丁），
但**实现有三个缺陷**（else 硬编码、断言过弱、用例不足），**当前 PASS 不可信**。
修它 30 行 > 翻译整个 Receive 300 行。

### 11.2 Q2：B14c 回归断言该怎么写

**先说事实：`--regress` 现在是通过的（exit=0），父代理报的「11→14 上升报错」已经不复现。**

我实跑（4 个快照，按时间序）：
```
$ python pseudo_lint.py --regress step7.snapshot.md step7.v2.md step8.base.md da9.md
design-a.step7.snapshot.md   14   S11,S12,S14,S2,S3,S4,S5,S8
design-a.step7.v2.md         13   S12,S14,S2,S3,S4,S5,S8
design-a.step8.base.md        4   S12,S2,S4
da9.md                        0   -
REGRESS OK（缺陷数单调不增，最新快照全绿）    exit=0
```
**`design-a.bak.md` 不在 `docs/spec` 下**（`Test-Path` = MISSING），实际在 `F:\rtsc\.tmp\design-a.bak.md`
（92381 B = 我第⑦步冻结的 1464 行版，fail=11）。**父代理把它从序列里去掉后，单调性就成立了。**

#### 断言写错了吗？

**「fail 数单调不增」这个断言本身是错的**，理由有三条：

1. **缺陷数不是随时间单调的**。检查器在演化（S13/S14/S15 是后来加的），
   **同一个快照在不同版本的检查器下 fail 数不同**。所以「fail 数」是
   **（文档版本 × 检查器版本）** 的二元函数，不是文档版本的单元函数。
   用它对文档版本排序，前提「检查器不变」根本不成立。
2. **修复过程会产生中间态**。父代理自己说的：§3.4.2/3.4.3 互换、E 表重编号，
   在互换的瞬间「S5 章节逆序」和「S11 标题条数」可能同时红，
   修完之后又变绿。**这是正常的，不是检查器失准。**
3. **fail 数会掩盖「换了一批缺陷」**。14 → 13 可能是「修了 2 条、新增 1 条」，
   单调不增通过了，但**新增的那条被掩盖**。这正是第⑦步 B10/B12/B13 的教训：
   从 13 条变 4 条（数字大降），实际是**旧的全修好、新的又长出来**。

#### 11.2.1 可执行的断言方案（推荐这个）

**断言「每个历史版本的命中项 ⊇ 该版本已知缺陷集」，而不是比总数。**

```python
# 1) 为每个历史快照手写「已知缺陷集」（来源：当轮审计报告的结论，可追溯）
KNOWN = {
  'design-a.bak.md':           {'S2','S4','S12','S6','S8'},   # 1464 行版，第⑦步结论
  'design-a.step7.snapshot.md':{'S2','S3','S4','S11','S12','S14','S5','S8'},
  'design-a.step7.v2.md':      {'S2','S3','S4','S12','S14','S5','S8'},
  'design-a.step8.base.md':    {'S2','S4','S12'},
  'da9.md':                    set(),                          # 当前应全绿
}

# 2) 断言：实测命中 ⊇ 已知缺陷集（漏报 = 检查器失准，红）
for name, must_hit in KNOWN.items():
    _, ids = run(snapshot(name))
    missing = must_hit - ids
    if missing:
        print('检查器失准：%s 的已知缺陷 %s 未被检出' % (name, missing)); return 1

# 3) 断言：当前版本 fail == 0（门禁）
if run(CURRENT) != 0: return 1

# 4) 额外：新增命中必须登记（防「换了一批缺陷」被数字掩盖）
for name, must_hit in KNOWN.items():
    _, ids = run(snapshot(name))
    extra = ids - must_hit
    if extra:
        print('提示：%s 出现未登记命中 %s —— 要么补进 KNOWN，要么是真回归' % (name, extra))
```

**为什么这个断言对**：
- **⊇ 而非 ==**：检查器改进后能抓到更多，不应算失败（只是要登记进 `KNOWN`）。
- **不看总数**：避免「修 2 增 1」被掩盖。
- **不假设时间单调**：每个版本独立对照自己的已知缺陷集。
- **`KNOWN` 可追溯到当轮审计报告**，不是拍脑袋。

#### 11.2.2 「11 那个快照不该作为序列起点」——这句话对一半

`design-a.bak.md`（fail=11）**确实不是「缺陷最多」的版本**（step7.snapshot 是 14），
但它**是有价值的**：它是**当前检查器版本下**唯一一份「B1–B9 修完、B10/B12/B13 未修」的样本，
能验证 S2/S3/S4/S12 在该状态下的命中。**不该删它，该改断言。**

### 11.3 Q3：S9/S10 该不该删？

**我改变意见：不删。父代理的理由成立，我上轮的理由不成立。**

我上轮说「S9 只认一种措辞、收益低」「S10 与 doc_lint F5 重复」。重新评估：

| 项 | 我上轮 | 现在 | 理由 |
|---|---|---|---|
| **S9** | 建议删 | **保留** | 我上轮的理由「只认『任何/所有』一种措辞」是**批评它的覆盖面**，不是**否定它的存在**。父代理的论点更对：**删了就没有对应红证，将来同类缺陷无检查**。正确做法是**扩大覆盖面**（见 11.4），不是删。而且 S9 抓到过 C4（`!= kOk` 漏排除 `kClosed`），那是**真实的契约漏洞**，不是假想的 |
| **S10** | 建议删（与 F5 重复） | **保留** | 「与 doc_lint F5 重复」是**冗余**，不是**错误**。而且两者覆盖面不同：doc_lint F5 只查 design 文档，`pseudo_lint` 是独立工具，**不应依赖另一个工具的存活**。冗余检查的成本是 O(n) 扫描，可忽略 |

**但我要补一条**：S9 和 S10 **都应该有红证**。当前 `redtest.py` 里 S9 有（「S9 漏 kClosed 排除」），
**S10 没有红证** —— 这是父代理「删了就没红证」这个论点对自己也适用的地方：
**S10 既然保留，就必须补一个注入用例**（改两个标题成同编号），否则它自己就是「无红证的检查」。

### 11.4 Q4：还有哪些假阴性（实测）

我实测了 6 个新候选，**确认 5 个假阴性 + 1 个假阳性**：

| # | 检查 | 变异 | 结果 | 判定 |
|---|---|---|---|---|
| **F1** | S14 | 循环内用 `plaintext_out = {}` 代替 `.clear()` | **S14 未报** | **假阴性**（语义等价，N5 照样发生） |
| **F2** | S13 | `take_front` 移到循环外预取 | **S13 未报** | **假阴性**（消费点仍在，但判据失效） |
| **F3** | S12 | 把「**本方法不产生**」改成「**本方法会产生**」（完全相反的语义） | **S12 未报** | **假阴性**（只查状态名是否出现，不查语义） |
| **F4** | S12 | 整行缩成只有 `` `kUnsupported` `` 三个字 | **S12 未报** | **假阴性**（同上） |
| **F5** | S3 | 新增 `FailWarn(status): return last_error_`（不清 clear） | **S3 未报** | **假阴性**（只要 `Fail()` 体内有一处 clear 就整体放行） |
| **P1** | S1 | 循环末条改成 `if True: continue`（语义等价于 `continue`） | **S1 报 FAIL** | **假阳性** |
| — | S8 | `Fail(status, code):` 签名变化 | **S8 报 FAIL，列出全部 6 个状态** | **假阳性（父代理上轮问的，实测确认）** |
| — | S15 | `terminal_`/`closed_` 改名 | **S15 报 FAIL** | 假阳性（改名即失效） |

#### 11.4.1 父代理点名的三个，逐个答

**① S8 在 `Fail(status, code)` 签名变化时会不会全量误报？—— 会，已实测确认。**
```
变异：Fail(status):  →  Fail(status, code):
结果：[FAIL] S8  terminal() 含但 Fail() 注释漏列：
      ['kCertRejected','kDecryptFailed','kInternal','kPeerAlert','kProtocolError','kUnsupported']
```
根因 `:448`：`re.search(r'^Fail\(status\):\n(.*?)^\S', ...)` **硬编码了签名**。
签名一改，`fail_block=''`，`fail_set=set()`，于是 `terminal_vals - fail_set` = 全部 6 个 → 全量误报。
**修法**：`r'^Fail\(\s*\w+\s*(?:,\s*[\w\s,]*)?\):\n(.*?)^\S'`（允许任意形参表）。
**注意**：这是**潜在**误报，当前文档签名没改所以不触发。但甲在讨论 B10 时曾考虑过加形参——
**如果当时选了形参方案，S8 会立刻全量误报**，这是「检查器阻碍合理设计」的实例。

**② S12 要不要加「必须含『本方法不产生』或『经 terminal_』」？—— 要，但不够。**

我实测：把 `**本方法不产生**` 改成 `**本方法会产生**`（语义完全相反），S12 **仍然绿**。
所以当前 S12 只做「状态名出现在 `| Receive |` 行」的存在性检查。

**加关键词能挡住「会产生」这种明显反转**，但挡不住「措辞正确但语义错」的变体
（例如「本方法不产生，但底层可能返回，所以要在 Receive 里处理」——关键词全在，语义错）。
**建议分两层**：
```python
# 层1（机械，必做）：关键词
if not re.search(r'本方法不产生|不产生|仅.*terminal_|经.*terminal_', row):
    fail('S12: Receive 行未声明"本方法不产生"')

# 层2（半机械）：禁止产生性措辞
if re.search(r'本方法(会|可能)?产生(?!点)|Receive.*产生', row):
    fail('S12: Receive 行出现产生性措辞')
```
层 2 的负向前瞻 `(?!点)` 是防「产生点」这个合法词。**这仍有盲区，但把最危险的反转挡住了。**

**③ S11 的中文数字解析，`十三`/`二十` 会不会漏？—— 实测：`十三` 漏、`二十` 漏。**

```
标题「十二个边界」实列 12 条 → S11 命中=True   ✓
标题「十三个边界」实列 12 条 → S11 命中=True   ✓（十三在 CN 表里）
标题「二十个边界」实列 12 条 → S11 命中=False  ✗ 漏
标题「二十一个边界」实列 12 条 → S11 命中=False ✗ 漏
标题「十五个边界」实列 12 条 → S11 命中=True   ✓
```
根因 `:524` 的 `CN` 字典只到 `十六`，且**正则 `[一二三四五六七八九十]+` 对「二十一」会切成
「二十一」但字典没有**；对「二十」字典也没有。
**修法**：写一个通用中文数字解析器（处理 `十`、`二十`、`二十一`、`一百`），
约 15 行：
```python
def cn2int(s):
    D={'一':1,'二':2,'三':3,'四':4,'五':5,'六':6,'七':7,'八':8,'九':9}
    if s.isdigit(): return int(s)
    if '十' not in s:
        return D.get(s)
    a,_,b = s.partition('十')
    tens = D.get(a,1) if a else 1
    ones = D.get(b,0) if b else 0
    return tens*10+ones
```
**另外**：S11 只统计 `^\s*\d+\.\s`，若边界改用 `-` 无序列表则 `cnt=0` → **跳过检查**（假阴性）。
当前是数字列表所以不触发，但这是脆弱点。

#### 11.4.2 我新发现的两个更严重的假阴性

**F1（S14 对赋值形态失明）**：循环内写 `plaintext_out = {}` 而不是 `.clear()`，
**N5 的后果一模一样**（前序明文被丢弃），但 S14 只匹配字面量 `plaintext_out.clear()`。
修法：改成匹配「循环内任何对 `plaintext_out` 的写操作」（`clear()` / `= {}` / `= []` / `.assign()`）。

**F5（S3 的「一处覆盖」副作用）**：这是**我上轮建议的副作用**，现在实证了。
只要 `Fail()` 体内有一处 `plaintext_out.clear()`，S3 就对**所有** `Fail*` 函数放行。
新增 `FailWarn()`（不清）→ S3 不报。
**修法**：把「是否有 clear」的判断从「文档里有没有」改成「**每个** `Fail*` 函数体内有没有」。

### 11.5 Q5：E 表 17 行与 L 列对齐 —— 独立逐行核对

**结论：17/17 全部对齐，零偏移。甲这轮的修正是对的。**

我用的口径（可复现）：
```
伪代码 fence 在文件 585 行，`Receive(` 在 586 行 → L1 == 文件 586 行，即 L = file_line - 585
出口 = 行内任意位置的 return/continue（先 strip 掉 # 注释），范围 586..683
```
实测（`:F:\rtsc\.tmp\s11c.txt`）：

| E | 表声明 | 实际 | 描述 | 判定 |
|---|---|---|---|---|
| E1 | L4 | L4 (file 589, return) | `closed_` → kClosed | ✓ |
| E2 | L6 | L6 (file 591, return) | `terminal_` → last_error_ | ✓ |
| E3 | L15 | L15 (file 600, return) | size<5 | ✓ |
| E4 | L18 | L18 (file 603, return) | type 非法 | ✓ |
| E5 | L20 | L20 (file 605, return) | len 超上界 | ✓ |
| E6 | L22 | L22 (file 607, return) | size<5+len | ✓ |
| E7 | L46 | L46 (file 631, return) | INCOMPLETE | ✓ |
| E8 | L51 | L51 (file 636, **continue**) | RENEGOTIATE(1.3) | ✓ |
| E9 | L53 | L53 (file 638, return) | RENEGOTIATE(1.2) | ✓ |
| E10 | L56 | L56 (file 641, **continue**) | NO_RENEGOTIATION | ✓ |
| E11 | L59 | L59 (file 644, return) | CONTEXT_EXPIRED | ✓ |
| E12 | L65 | L65 (file 650, return) | ALTERED/DECRYPT_FAILURE | ✓ |
| E13 | L68 | L68 (file 653, return) | PEER_ALERT | ✓ |
| E14 | L71 | L71 (file 656, return) | INTERNAL | ✓ |
| E15 | L84 | L84 (file 669, return) | 未知 st → else 兜底 | ✓ |
| E16 | L95 | L95 (file 680, return) | max_out | ✓ |
| E17 | L97 | L97 (file 682, **continue**) | 成功路径末尾 | ✓ |

**实际出口总数 = 17（14 return + 3 continue），E 表 17 行，一一对应，无遗漏、无多余。**
（`Fail()` 辅助函数体内的 `return last_error_`（file 696）已正确排除，不计入出口。）

**一个必须记录的细节**：E11（file 644）是 `closed_ = true; return kClosed` —— **行内 return**。
E 表把它算作一个出口（正确），而第⑧步的 S6 曾因 `re.match(r'^\s*return')` 漏计它。
**S6 这轮修好了**（改用 `(?:^|;)\s*return`），当前 `fail=0` 证明它不再误报。

### 11.6 Q6：C11 留痕数字的口径定义（可复现）

**两个人数不一样，是因为口径不同；我上轮给的 12+15 也是错的（我数的是「行」不是「次」）。**

#### 11.6.1 口径定义（三个维度，必须同时声明）

| 维度 | 选项 | 说明 |
|---|---|---|
| **计数单位** | 「次」/「行」 | **「次」= 每次出现算一次**（同一行出现两次算 2）；「行」= 出现过的行数。**必须声明用哪个** |
| **范围** | 全文 / 截断到 `### 8.6` 之前 | `### 8.6` 是记录本次统计的那一节，**它会自指**，含它则数字随本节文字变化，不稳定 |
| **是否含代码块** | 含 / 不含 | `:394` 有一处 `§3.4.3` 在 `cpp` 代码块里（`// 一次调用可能追加多条记录的明文（见 §3.4.3 边界 2/9）`） |

#### 11.6.2 实测（口径全排列）

| 口径 | §3.4.2 | §3.4.3 |
|---|---|---|
| 全文 · 按次 · 含代码块 | **14** | **19** |
| 全文 · 按次 · 排代码块 | 14 | 18 |
| 截断 `### 8.6` 前 · 按次 · 含代码块 | **8** | **13** |
| 截断 `### 8.6` 前 · 按次 · 排代码块 | 8 | 12 |

**所以父代理的 8/13 与 15/20 分别对应**：
- **8 / 13** = 「截断到 `### 8.6` 之前 · 按次 · 含代码块」← **文档 `:1643` 写的正是这个**
- **15 / 20** = 文档 `:1644` 的「全文」——但我实测是 **14 / 19**，**差 1**。
  差异原因：`:1644` 的数字是**在写那一行之前**统计的（写完之后本行又多了 1 处 `§3.4.2` 和 1 处 `§3.4.3`），
  **典型的自指污染**。文档 `:1638-1639` 自己也承认「含本节的自指计数会随本节文字变化」。

**我上轮的 12+15 是错的**：我数的是「行」且用了不同的截断点。**我收回。**

#### 11.6.3 可复现命令（任何人可重算）

```python
# 保存为 count_sec_refs.py，用法：python count_sec_refs.py F:\rtsc\docs\spec\tls-backend.design-a.md
import io, re, sys
doc = io.open(sys.argv[1], encoding='utf-8').read()

def count(text):
    hits = re.findall(r'\u00a73\.4\.[23]', text)     # §3.4.2 / §3.4.3
    return hits.count('\u00a73.4.2'), hits.count('\u00a73.4.3')

i86 = doc.find('### 8.6')
head = doc[:i86] if i86 > 0 else doc

print('口径A 全文·按次·含代码块      :', count(doc))
print('口径B 截断8.6前·按次·含代码块 :', count(head))
print('口径C 全文·按次·排代码块      :', count(strip_code(doc)))
print('口径D 截断8.6前·按次·排代码块 :', count(strip_code(head)))
```

**我实跑结果（当前 1882 行文档）**：
```
口径A 全文·按次·含代码块      : (14, 19)
口径B 截断8.6前·按次·含代码块 : (8, 13)
口径C 全文·按次·排代码块      : (14, 18)
口径D 截断8.6前·按次·排代码块 : (8, 12)
```

**建议以后统一用「口径B」**（截断 `### 8.6` 前、按次、含代码块），理由：
① 截断避免自指污染（唯一稳定口径）；② 按次符合「引用处数」的直觉；③ 含代码块因为代码注释里的引用也是真引用。
**并在文档里写死这句话**：「本数字用 `count_sec_refs.py` 的口径B 生成，勿手改」。

**另外**：`:1646-1647` 给的「正文 8 处的行号」里写 `L394`（代码块内），
但 `:1643` 的 8 是 §3.4.2（不含 L394），`:1647` 的 13 是 §3.4.3（含 L394）。
**这两行是对的**（分别对应各自的编号），只是没有声明口径，容易误读。

### 11.7 D1 修复的独立验证

**D1 = 第⑧步我报的阻断（`:656` 的 else 只绑 `if st == INTERNAL`，正常数据 100% 返回 kInternal）。**

当前文档 `:620-682` 已是完整的 `elif` 链：
```
620 if   st == INCOMPLETE:
626 elif st == RENEGOTIATE:
633 elif st == NO_RENEGOTIATION:
636 elif st == CONTEXT_EXPIRED:
642 elif st in {ALTERED, DECRYPT_FAILURE}:
645 elif st == PEER_ALERT:
648 elif st == INTERNAL:
665 elif st == OK:
668 else:
669     return Fail(kInternal)
```
**D1 修复正确**。三条独立证据：
1. **缩进核验**：`:620/626/633/636/642/645/648/665/668` 全部 `ind=4`，构成单一链；`:669` 是 `ind=8` 属 else 体。
2. **语义脚本**：`st=OK -> CONT`（成功路径），`st=BOGUS -> RET kInternal`（兜底），
   `st=INTERNAL -> RET kInternal`（不再落空）。
3. **我自己的独立翻译模拟**（第⑧步 `s8sim.py` 的修正版）：修前「所有数据 → kInternal」，
   修后「正常数据走成功路径」。

**但要注意一个设计选择**：`:665 elif st == OK: pass` —— 显式列出 `OK` 再 `pass` 落到成功路径。
`:663-664` 的注释解释了原因：「`elif st == OK` 必须**显式列出**，不能靠"都不匹配就落到成功路径"——
因为链末的 else 会截住一切未列出的值」。**这个推理完全正确**，是修 D1 时的正确附带决策。
（这也是 MUT5「删掉 `elif st == OK`」能翻红的原因——删了就真会落进 else。）

### 11.8 本轮新发现（3 条）

#### E1（阻断，但属工具不属文档）：`verify_elif_semantics.py` 的 PASS 不可信

详见 11.1。**这是「绿灯证明不了正确」的活样本**：
- 它 PASS，但 MUT1（else 体改 pass，即 D1 复发）也 PASS；
- 它 PASS，但 MUT4（OK 分支返回 kProtocolError，即所有正常数据变错误）也 PASS。

**危险之处**：它现在被接进 `verify.ps1 -PseudoLint` 门禁，**会给一个假的安心感**。
比没有这个脚本更糟——因为它挡住了「人工去看 else 里写了什么」这一步。

#### E2（严重）：S12 语义反转完全无感

详见 11.4.1 ②。把「本方法不产生」改成「本方法会产生」，S12 绿。
**这条正好是本轮修的 B8 的验收点** —— 意味着 B8 的修复实际上**没有被任何自动检查保护**，
下次改错不会有人发现。

#### E3（一般）：C11 留痕的「15/20」是自指污染值

详见 11.6.2。文档 `:1644` 的「全文 15/20」实测是 14/19（写那一行之前）。
**建议删掉「全文」那一行**，只保留口径B，避免以后反复对不上。

### 11.9 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **D1 修复** | **通过**（`elif` 链 + 显式 `elif st == OK` + else 兜底，三条独立证据） |
| **E 表 17 行 / L 列对齐** | **通过**（17/17 零偏移，我逐行核过） |
| **S4 假阴性** | **通过**（注入 C「else 绑错对象」现在命中；判定整链形态，逻辑正确） |
| **S2 改名绕过** | **通过**（`ALIASES` + 扫成员声明块，删 `last_native_code_` 声明现在翻红） |
| **S6 计数** | **通过**（行内 return 已捕获，`fail=0`，E 表 17 == 实际 17） |
| **红证 16/16** | **通过**（我实跑复现，含 2 个「不该红的不红」等价用例） |
| **`pseudo_lint` fail=0** | **通过** |
| **`verify_elif_semantics` PASS** | **不通过**（假 PASS，MUT1/MUT4 逃逸，断言过弱 + else 硬编码） |
| **S12 语义保护** | **不通过**（语义反转完全无感，而它正是 B8 的验收点） |
| **S14 / S13 / S3 假阴性** | **不通过**（赋值形态、循环外预取、`FailWarn` 三个变体都逃逸） |
| **S1 假阳性** | **不通过**（`if True: continue` 被误报） |
| **S11 中文数字** | **不通过**（`二十`/`二十一` 漏） |
| **C11 口径** | **部分**（8/13 对，15/20 是自指污染值，应删） |

**放行条件（5 条，按严重度）**：

1. **【阻断】修 `verify_elif_semantics.py`**：
   ① `else` 不硬编码，读它的 body 并提取 `Fail(kXxx)`；
   ② 断言改成逐状态期望表（`EXPECT` 字典），而不是「只判 OK != kInternal」；
   ③ 把 MUT1（else 体→pass）与 MUT4（OK 分支→kProtocolError）加进它的用例。
   **修完前，不要把它接进 `verify.ps1` 门禁**——假绿灯比没绿灯更危险。
2. **【严重】S12 加语义层**：要求 Receive 行含「本方法不产生 / 经 terminal_」，
   并禁止「本方法会产生」这类产生性措辞（见 11.4.1 ② 的两层实现）。
   否则 B8 的修复没有任何自动保护。
3. **【严重】S14 改为匹配所有对 `plaintext_out` 的写操作**（`clear()` / `= {}` / `= []` / `.assign()`）；
   **S3 改为逐 `Fail*` 函数判断**，不是「全文有一处就放行」。
4. **【一般】S11 换通用中文数字解析**（15 行，见 11.4.1 ③）；
   **S1 修正假阳性**（末条是 `if ...: continue` 时应判有回边）。
5. **【一般】`--regress` 改成「命中项 ⊇ 已知缺陷集」**（见 11.2.1），并保留 `design-a.bak.md`。

**随修**：S8 的 `Fail` 签名正则放宽（`Fail\(\s*\w+\s*(?:,[^)]*)?\)`）；
C11 删掉「全文 15/20」那一行、只留口径B；补 S10 的红证用例（它自己现在没有）。

### 11.10 我方本轮自我更正

1. **我上轮说「S9 收益低、S10 与 F5 重复，建议删」——这个建议是错的。**
   父代理「删了就没红证」的论点成立。**我撤回删除建议。**
   正确做法是扩大 S9 的措辞覆盖面、给 S10 补红证。
2. **我上轮给的 C11 数字 12+15 是错的**（我数的是「行」，且截断点不同）。本轮给出四口径全排列，
   **正确值是口径B 的 8/13**（与文档一致）。**我收回 12+15。**
3. **我上轮建议「clear 收进 Fail()」的副作用现在实证了**（F5：`FailWarn` 逃逸）。
   当时我提了这个风险但没量化，现在有了具体反例。

### 11.11 第⑨步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| E4a | `verify_elif_semantics.py` 修完后，MUT1–MUT5 是否全部翻红 | — | 这是验收该修复的唯一方法；建议修完立刻跑我这 5 个变异 |
| E4b | S12 的两层关键词检查能否挡住「措辞正确但语义错」的变体 | C | 我判断只能挡住明显反转，挡不住措辞级的语义错；需要人工兜底 |
| E4c | `--regress` 的 `KNOWN` 表在下一轮修订后是否需要更新 | — | 必然需要；建议把 `KNOWN` 表放在 `pseudo_lint.py` 顶部并注明「每轮审计后更新」 |

---

## §12. 第⑩步复验（verify_elif 重写 + 五条放行条件 + 门禁）

### 12.0 快照与三个 lint 的实跑 exit 码

> **文档**：`design-a.md` → `F:\rtsc\.tmp\da10.md`，**1885 行 / 151731 B**，
> SHA256 `83D70EC86922759247F1304CF243FE23E085D2B93EA453DAB401E03E9FF18256`。
> **脚本**：`pseudo_lint.py` 747 行（`9A3399FC…`）、`pseudo_lint_redtest.py` 228 行（`41E4C39F…`）、
> `verify_elif_semantics.py` **270 行**（`1ABF17FD…`，上一版 127 行）、`count_sec_refs.py` 43 行（`4FC7EB62…`）、
> `verify.ps1` 188 行（`48671A4B…`）。
>
> **我自己跑的 exit 码（全部复现父代理的结果）**：
> ```
> pseudo_lint.py --file design-a.md    → TOTAL fail=0 warn=0        exit=0
> pseudo_lint_redtest.py               → 22/22 ASSERT OK            exit=0
> verify_elif_semantics.py             → 10 状态 OK + 5/5 变异 ASSERT OK  exit=0
> count_sec_refs.py                    → 四口径输出                exit=0
> doc_lint.py --root F:\rtsc           → TOTAL fail=0 warn=0        exit=0
> verify.ps1 -PseudoLint               → 12/12 ctest + 四道伪代码检查 + "pseudo lint passed"  exit=0
> ```
> **五个 0 全部成立。** `verify.ps1 -PseudoLint` 我完整跑了一遍（含 configure/build/ctest），
> 输出 `12/12 tests passed` + `pseudo lint passed`，exit=0。

### 12.1 Q1：verify_elif 是否真的不再假绿？——**基本修好，但 RENEGOTIATE 分支仍有一处同类硬编码**

#### 12.1.1 上一版两个缺陷已确认修复

| 旧缺陷 | 现在 | 证据 |
|---|---|---|
| `if kw == 'else': return ('RET','kInternal')` 硬编码 | **已修** | `:117-143` `interpret_segment()` 读每个分支的 body，提取 `Fail(kXxx)` / 行内 `return` / `continue` / `pass` / 空体 |
| `ok = not (act=='RET' and status=='kInternal' and st=='OK')` 断言过弱 | **已修** | `:32-43` 逐状态 `EXPECT` 字典（10 项）；`:181` `bad = [st for st in EXPECT if results[st] != EXPECT[st]]` |

**它自己的 5 个变异自测我复现了：5/5 全部检出**，且每个都给出正确的不符状态
（MUT1→`['BOGUS']`、MUT2→`['INTERNAL']`、MUT3→`['PEER_ALERT']`、MUT4→`['OK']`、MUT5→`['OK']`）。
**上一版是 1/5，现在 5/5，这是实质进步。**

#### 12.1.2 我自己的变异（14 个，不采信 MUT1–5）

我按行号精确改（避免锚点失效），结果如下：

| # | 变异 | 语义 | 检出？ |
|---|---|---|---|
| Y1 | `elif st == OK:` 体 `pass`→`continue` | **跳过成功路径，明文丢失** | **未检出** |
| Y2 | `PEER_ALERT` → `return Fail(kInternal)` | 错码 | ✓ 检出 |
| Y3 | `elif st in {ALTERED, DECRYPT_FAILURE}` → `elif st == ALTERED` | 漏 DECRYPT_FAILURE | **未检出** |
| Y4 | `else` 体 → `continue` | 未知状态当成功 | ✓ 检出 |
| Y5 | 删掉 `else` 整块 | 无兜底 | ✓ 检出 |
| Y6 | `INCOMPLETE` → `kInternal` | 错码 | ✓ 检出 |
| Y7 | `elif st == OK:` 体 `pass`→`return kOk` | **提前返回，破坏多记录** | ✓ 检出 |
| Y8 | `INTERNAL` → `kPeerAlert` | 错码 | ✓ 检出 |
| Y9 | `CONTEXT_EXPIRED` → `return kOk` | 错码 | ✓ 检出 |
| Y10 | `NO_RENEGOTIATION` `continue`→`Fail` | 错码 | ✓ 检出 |
| Y11 | `RENEG(1.3)` `continue`→`Fail` | 错码 | **未检出** |
| Y12 | `OK` `pass` 加注释（等价改写） | 不得报 | ✓ 未误报 |
| Y13 | `INCOMPLETE` → `return kOk` | 错码 | ✓ 检出 |
| Y14 | `RENEG(1.3)` `continue`→`pass` | 错码 | **未检出** |
| Y15 | `RENEG` 整支改 `return Fail`（删内层判定） | 1.3 被误拒 | **未检出** |
| Y16 | `RENEG` 无条件 `continue`（1.2 也不拒） | 1.2 被放行 | **未检出** |
| Y17 | 同 Y16 但删掉整块内层结构 | 同上 | **未检出** |
| Y18 | `RENEG(1.2)` `Fail`→`continue` | 1.2 不拒 | **未检出** |
| Y19 | `RENEG(1.3)` 改 `Fail`（删内层判定） | 1.3 被误拒 | ✓ 检出（因为整支变成 Fail） |

**统计：19 个变异，检出 11 个，未检出 8 个（Y1/Y3/Y11/Y14/Y15/Y16/Y17/Y18）。**

#### 12.1.3 未检出的 8 个分两类，根因各不同

**类别 A：`RENEGOTIATE` 分支的硬编码（Y11/Y14/Y15/Y16/Y17/Y18，共 6 个）**

`:122-126`：
```python
    # 内层 if negotiated.tls_version == 0x0304 ... else ...（RENEGOTIATE 特例）
    if 'RENEGOTIATE' in cond and 'negotiated.tls_version' in stripped:
        if tls13:
            return ('CONT', None)          # 1.3：喂回 ISC 后 continue
        return ('RET', 'kProtocolError')   # 1.2：RDP 不允许重协商
```
**这是与上一版 `else` 完全同类的缺陷**：只要分支体里出现字符串 `negotiated.tls_version`，
就**直接返回硬编码值**，**不读 `continue` / `Fail(...)` 实际写了什么**。

实测后果：
- **Y11**（1.3 的 `continue` 改成 `Fail(kProtocolError)`）→ 未检出，因为 `negotiated.tls_version` 还在，直接返回 `('CONT', None)`。
- **Y16**（删掉内层 `if`，只留无条件 `continue`）→ 未检出，因为 `stripped` 里还有 `negotiated.tls_version` 字样吗？——**没有**。但它仍未检出，说明还有第二层问题：见下。

**类别 B：`match_cond` 的宽松匹配（Y3）+ `interpret_segment` 的 `pass`→`CONT`（Y1）**

- **Y3**：`elif st in {ALTERED, DECRYPT_FAILURE}` 改成 `elif st == ALTERED`，
  `match_cond`（`:106-107`）判 `if 'ALTERED' in cond: return st in ('ALTERED','DECRYPT_FAILURE')`
  —— **它按字符串 `ALTERED` 匹配，不解析集合内容**，所以 `DECRYPT_FAILURE` 被删掉后仍返回 True。
- **Y1**：`elif st == OK:` 体改成 `continue`。`interpret_segment`（`:137-138`）先匹配
  `^\s*continue\b` → 返回 `('CONT', None)`，**与 `pass` 的结果相同**，所以 EXPECT 里 `OK → CONT` 照样满足。
  **这是语义模型本身的局限**：它把 `pass`（落到成功路径、累加明文）和 `continue`（回循环顶、**丢弃本轮明文**）
  当成同一个结果。二者对 `plaintext_out` 的影响**完全相反**。

#### 12.1.4 我的裁定

**Q1 的答案：verify_elif 从「假绿（1/5）」进步到「11/19」，方向对、主体对，但仍不是可信的门禁。**

- **它现在能抓的是「状态→返回码」的映射错误**（11 个里 9 个属于这类），这部分做得很好。
- **它抓不到的是「成功路径内部行为」**（Y1）和「集合内容」（Y3）和「RENEGOTIATE 内层结构」（6 个）。
- **最要紧的是 Y1**：把 `OK` 分支的 `pass` 改成 `continue`，会让**所有正常数据被静默丢弃**
  （`plaintext_out += tmp` 永不执行），这是**比 D1 更隐蔽的致命错误**，而脚本报 PASS。

**最小修法（约 20 行，三处）**：
```python
# 1) RENEGOTIATE 不再按字符串硬编码，改为读 body 的 continue/Fail
#    把 :122-126 整块删掉，让通用逻辑处理（通用逻辑已经能提取 continue 和 Fail）
#    —— 只需在 EXPECT 里为 RENEGOTIATE 保留 ('CONT', None)（默认 1.3）

# 2) match_cond 解析集合内容
if 'ALTERED' in cond:
    if 'DECRYPT_FAILURE' not in cond:      # 集合里必须两个都在
        return st == 'ALTERED'
    return st in ('ALTERED','DECRYPT_FAILURE')

# 3) 区分 pass 与 continue（这是关键）
if re.search(r'^\s*pass\b', stripped, re.M):
    return ('FALLTHROUGH_OK', None)        # 落到成功路径（累加明文）
if re.search(r'^\s*continue\b', stripped, re.M):
    return ('CONT_SKIP', None)             # 回循环顶（丢弃本轮明文）
# EXPECT 里 OK -> ('FALLTHROUGH_OK', None)；其余 CONT 仍用 ('CONT', None)
```
**改完之后 Y1/Y3/Y11/Y14/Y15/Y16/Y17/Y18 应全部翻红。**

#### 12.1.5 该不该现在翻译整个 Receive？

**结论不变（与第⑨步一致）：不该，但本轮这个脚本已经证明「部分翻译」的价值。**

上一轮我反对「翻译整个 Receive」的三条理由（翻译器正确性无法自证 / 7 条边界实现阶段一行断言就够 / 边际收益）**依然成立**。
但本轮新增一条观察：**这个 270 行的部分翻译，已经抓到 11 类状态分派错误，成本远低于全量翻译。**
所以正确的做法是**把这个部分翻译修到可信（20 行），而不是扩到全量**。
全量翻译（含 `rx_buffer_` / `backend_decrypt` mock）留到实现阶段——那时有真代码，`EXPECT_EQ` 直接覆盖 12 条边界。

### 12.2 Q2：S12 语义层能否被绕过？——**换说法会漏，但加词能挡住常见变体**

我实测 8 个变体（`:F:\rtsc\.tmp\s12g.py`）：

| 变体 | S12 报 | 判定 |
|---|---|---|
| 原文（`不产生` + `经 terminal_`） | 否（绿） | ✓ 正确 |
| 「**此码不会从本方法返回**，由 Handshake 产生后经入口返回」 | **报** | ✗ 假阳性（语义正确但换词） |
| 「`kUnsupported` 由握手期决定；**Receive 不负责**证书与配置判定」 | **报** | ✗ 假阳性 |
| 「仅**透传** `Handshake` 已置的终止态」 | **报** | ✗ 假阳性 |
| 「`kUnsupported` **非本方法职责**，只在 `terminal_` 命中时原样返回」 | **报** | ✗ 假阳性 |
| 英文「NOT produced by this method; propagated via terminal_」 | **报** | ✗ 假阳性 |
| 空壳（只有 `` `kUnsupported` ``） | **报** | ✓ 正确 |
| 反向「**本方法会产生**」 | **报** | ✓ 正确 |
| 反向「**产生于** `Receive`」 | **报** | ✓ 正确 |

**结论：S12 现在是「白名单关键词」式检查，方向正确但覆盖面窄。**

- **它能挡住**：空壳（只写状态名）、明显反向（`会产生`/`产生于`）—— 这两个是**最危险的**，挡住了就够。
- **它挡不住**：任何换说法的正确表述（4 个假阳性）。这**不是漏检而是误报**，方向是「宁可多报」。

**我的裁定：接受当前实现 + 人工兜底，不要再加词。**

理由三条：
1. **加词的边际收益递减**：我已经用 4 种正确说法证明「换词」的空间是开放的，加不完。
   每加一个词就多一个误报源，而**误报会让维护者关掉检查**（比漏检更糟）。
2. **最危险的两个变体已被挡住**（空壳 + 反向），这是「防倒退」的核心。
3. **这一行的语义正确性，最终要靠 code review**，不是靠正则。S12 的定位应该是
   「**防止这一行被删掉或被写成空壳**」，而不是「保证这一行的措辞永远正确」。
   **建议在 `pseudo_lint.py` 的 S12 docstring 里明确写这个定位**，避免后人以为它是完备的。

**附带建议（低成本、高收益）**：把 S12 从 `fail` 降为 `warn`，因为它现在**会对正确表述误报**。
一旦误报，`fail` 会挡住提交；`warn` 则提示但放行。**真正的 fail 判据应该是「行不存在」或「行是空壳」**。

### 12.3 Q3：S1 的 `if True: continue` 判定是否过宽？——**过窄，不是过宽**

实测 7 个变体（`:F:\rtsc\.tmp\s12h.py`）：

| 变体 | 应报？ | S1 实际 | 判定 |
|---|---|---|---|
| `continue`（原文） | 不报 | 不报 | ✓ |
| `continue  # same`（加注释） | 不报 | 不报 | ✓ |
| `if True: continue` | 不报 | 不报 | ✓ |
| `if 1: continue` | 不报 | 不报 | ✓ |
| **`if 1 == 1: continue`** | 不报 | **报** | ✗ **假阳性** |
| **`if not False: continue`** | 不报 | **报** | ✗ **假阳性** |
| **`if True and True: continue`** | 不报 | **报** | ✗ **假阳性** |
| `pass`（真缺陷） | **报** | 报 | ✓ |

**结论：`guarantees_backedge()` 只认 `True` 和 `1` 两个字面量，认不出 `1 == 1` / `not False` / `True and True`。**

**该不该处理？——不该。这是正确的「宁可误报」取舍。**

理由：
1. **这三种写法在伪代码里出现的概率极低**。伪代码是给人读的设计文档，
   没人会写 `if 1 == 1: continue`。**为 0.1% 的写法写常量折叠求值器，是过度工程。**
2. **误报的代价是「维护者被迫改成 `if True:`」**，而那个改动**让伪代码更清晰**（少一层无意义条件）。
   **这是「误报反而改善文档」的罕见情形。**
3. **反过来，如果为了消除误报而放宽到「任意 `if ...: continue` 都算有回边」，
   就会漏掉真缺陷**：`if extra_len: continue`（只在有 EXTRA 时回边，否则落空）是**真实的 B1 变体**，
   必须报。**放宽 = 漏真缺陷，收紧 = 误报极端写法。收紧是对的。**

**但建议改一条提示语**：当前报错信息说「循环体顶层末条语句不保证回到循环顶」，
对 `if 1 == 1` 这种情况，维护者可能不理解为什么。**建议在消息里补一句**：
「若条件恒真，请简化为无条件的 `continue`/`return`，以便静态检查确认回边」。
这既不放松检查，又给出了修复方向。

### 12.4 Q4：KNOWN 表的正确性 ——**`design-a.bak.md` 登记有错，必须改**

#### 12.4.1 先纠正一个事实：`design-a.bak.md` 是 **1139 行版**，不是 1464 行版

```
design-a.bak.md              1139 行  92381 B   sha=10B0F3BEC05A9A69
design-a.step7.snapshot.md   1392 行 112779 B   sha=AD392E0B669AB004
design-a.step7.v2.md         1464 行 120397 B   sha=66729EE085B00545
design-a.step8.base.md       1632 行 135988 B   sha=2EAF8060B19C151F
da10.md（当前）              1885 行 151731 B   sha=83D70EC869227592
```

父代理说「`design-a.bak.md` 是 1464 行版」——**错**。1464 行是 `design-a.step7.v2.md`。
`bak.md` 是 **1139 行版**（第⑥步末尾、第⑦步之前的那个版本）。

#### 12.4.2 `bak.md` 的 S1 命中是**正确的**

父代理的质疑：「你说它『B1–B9 修完、B10/B12/B13 未修』，那 S1 应该不命中才对」。

**这个质疑的前提错了**：1139 行版**恰恰是 B1 尚未修好的版本**。实测其伪代码块（`:501-541`）：
```
506 ind=8   return produced ? kOk : kNeedMoreInput
508 ind=4   if type not in {20,21,22,23}: return kProtocolError
511 ind=8   return produced ? kOk : kNeedMoreInput
521 ind=8   return produced ? kOk : kNeedMoreInput
526 ind=12  continue                               # N1 安全：record 已消费
530 ind=4   if st == NO_RENEGOTIATION: continue
532 ind=4   if st == CONTEXT_EXPIRED: closed_ = true; return kClosed
534 ind=8   plaintext_out.clear(); return kDecryptFailed
541 ind=4   if max_out && produced >= max_out: return kOk    ← 循环体顶层末条
```
**顶层末条是 `:541` 的 `if max_out && ...: return kOk`** —— 条件不成立时**落空**，没有 `continue`。
**这正是 B1 的原始形态**（成功路径缺回边）。所以 **S1 命中是对的，不是误登记**。

**同样，S15 命中也是对的**：1139 行版入口没有 `closed_` / `terminal_` 检查（实测 S15 报
`Receive 入口缺终止态检查：['terminal_', 'closed_']`）。

#### 12.4.3 KNOWN 表的逐条核对（当前 lint 版本实测）

| 快照 | KNOWN 登记 | 实际命中 | 判定 |
|---|---|---|---|
| `design-a.bak.md` | S1,S2,S4,S6,S8,S12,S15（7） | S1,S2,S4,S6,S8,S12,S14,S15（8） | **⊇ 成立**；`extra=[S14]` |
| `step7.snapshot.md` | S2,S3,S4,S5,S8,S11,S12（7） | S2,S3,S4,S5,S8,S11,S12,S14（8） | **⊇ 成立**；`extra=[S14]` |
| `step7.v2.md` | S2,S3,S4,S5,S8,S12（6） | S2,S3,S4,S5,S8,S12,S14（7） | **⊇ 成立**；`extra=[S14]` |
| `step8.base.md` | S2,S4,S12（3） | S2,S4,S12（3） | **⊇ 成立，无 extra** |

**结论：KNOWN 表 4 条全部正确（⊇ 成立），无错漏。** 唯一的「extra=S14」是**正常的**：
S14（循环内重置 `plaintext_out`）是**我第⑥步 N5 报的缺陷**，那三个历史版本确实都有它，
只是当时没登记进 KNOWN。**建议把这 3 个 S14 补进 KNOWN**（不是错，是漏登记）。

#### 12.4.4 一个必须指出的口径问题

`regress` 输出里 `fail` 列是**去重后的集合大小**（`:691` `ids = {x.sid for x in f if x.level=='fail'}`），
而 `pseudo_lint --file` 的 `TOTAL fail=` 是**逐条计数**。
所以同一个 `bak.md`：单跑 `TOTAL fail=11`（S14 出现 3 次），regress 里 `fail=8`（去重后 8 个 ID）。

**这不是 bug，但容易误读**。建议 `regress` 表头把 `fail` 改成 `fail_ids` 或加脚注。

### 12.5 Q5：门禁是否该加 `count_sec_refs.py` 校验？——**该加，而且这是本轮最值得加的一条**

#### 12.5.1 现状

`count_sec_refs.py` 实跑：
```
A 全文·按次·含代码块      : (14, 19)
B 截断8.6前·按次·含代码块  : (8, 13)   ← 文档 :1643 写的 8/13
C 全文·按次·排代码块      : (14, 18)
D 截断8.6前·按次·排代码块  : (8, 12)
E 全文·按行·含代码块      : (13, 16)
F 截断8.6前·按行·含代码块  : (8, 12)
文档 :1644 写「全文 15/20」，而实测 A = (14, 19)
```

**两个发现**：
1. **口径 B = (8, 13) 与文档 `:1643` 完全一致** ✓ —— 父代理的修正是对的。
2. **`count_sec_refs.py` 的输出里还打印「文档 :1644 写『全文 15/20』，而实测 A = (14, 19)」** ——
   但文档 `:1644` **已经被删掉了**（父代理说「已删」）。我核实：`:1644` 现在是
   「**自指污染**……写"15/20"时实际是"14/19"」—— **这是历史留痕，不是当前断言**。
   所以 `count_sec_refs.py` 的这句提示**指向了一个已被删除的断言**，会让读者困惑。
   **建议改成**：「历史留痕 `:1644` 提到的 15/20 是自指污染值，当前文档不再使用」。

#### 12.5.2 该不该加门禁？

**该加。这是唯一能防止「文档写 8/13、实际变成 9/13」的机制。**

理由：
- C11 这个数字**已经错过两次**（第⑨步父代理 15/20、我 12+15）。**同一个数字错两次，说明人工维护必然失败。**
- 它**完全可机械判定**：文档里有一个断言值（8/13），脚本有一个计算值（口径 B），
  两者比对即可。**这是「可自动化」的典型**。
- 成本极低：约 15 行。

**建议实现**（`verify.ps1` 第 5 道）：
```python
# count_sec_refs.py 加 --check 模式
import sys
def check(path):
    doc = io.open(path, encoding='utf-8').read()
    i86 = doc.find('### 8.6'); head = doc[:i86] if i86 > 0 else doc
    got = count(head)                       # 口径 B
    # 从文档里抓断言值：表格里 "| **8** | **13** |" 或 "8/13"
    m = re.search(r'\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|', doc)
    if not m:
        print('FAIL: 文档里找不到口径 B 的断言值'); return 1
    want = (int(m.group(1)), int(m.group(2)))
    if got != want:
        print('FAIL: 文档写 %s，实际 %s' % (want, got)); return 1
    print('OK: 口径B = %s，与文档一致' % (got,))
    return 0
```
**注意一个坑**：文档 `:1641-1643` 的表格里，`8` 和 `13` 前面有 `**`。
如果只匹配 `\*\*(\d+)\*\*`，会同时匹配到别的表格（如 `:1644` 的历史留痕）。
**建议锚定「口径」二字**：`re.search(r'唯一稳定口径.*?\n\|.*?\| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|', doc)`。

### 12.6 随修项核对

| 项 | 父代理说 | 我的核实 |
|---|---|---|
| **S8 正则放宽** | `^Fail\(status\):` → `^Fail\w*\s*\([^)]*\)\s*:` | **已修且有效**。我用 `Fail(status, code):` 变异实测：**S8 不再全量误报**（第⑨步是报 6 个，现在不报）。这条 P2 假阳性已消除 |
| **C11 删「全文 15/20」** | 只保留口径 B = 8/13 | **已删断言、保留留痕**。`:1643` 是断言（8/13），`:1644` 改成历史说明（「写"15/20"时实际是"14/19"」）。**做法正确**（删断言、留痕迹、说明原因），但见 12.5.1 的提示语问题 |
| **补 S10 红证** | `S10 重复编号` → 检出 | **已补且有效**。redtest 输出第 17 行 `[PASS] S10 重复编号 期望=S10 翻红=True` |
| **S14 匹配三种写法** | `clear(` / `.assign(` / `=` | **已修**。`check_no_clear_in_loop` 用 `re.search(r'plaintext_out\s*(?:\.clear\(|\.assign\(|=)', code)`；红证 `S14 用赋值绕过` 检出 |
| **S3 逐 `Fail*` 函数** | 不再「全文一处覆盖」 | **已修**。红证 `S3 新增FailWarn` 检出（我第⑨步的 F5 实证已消除） |
| **S11 `cn2int`** | 通用中文数字 + 无序列表 | **已修**。红证 `S11 二十` 检出。我另测 `二十一` 也应能解析（`partition('十')` 通用） |
| **S12 合并多行判断** | 不再只取 `rows[0]` | **已修**（否则 `kCertRejected` 会误报）。实测当前文档 S12 绿 |
| **verify.ps1 四道门禁** | 结构 + 红证 + 语义 + 回归 | **已实现**（`:139-186`），我完整跑通 exit=0 |
| **PowerShell 5.1 GBK 坑** | 注释改英文 | **已改**（`verify.ps1:1-17` 全英文注释），我实跑无 parser 错误 |

### 12.7 本轮新发现（4 条）

#### G1（阻断·工具）：verify_elif 的 `RENEGOTIATE` 分支仍是硬编码——与上一版 `else` 同类

详见 12.1.3 类别 A。`:122-126` 只要看到 `negotiated.tls_version` 字样就返回硬编码值，
不读分支体实际写了什么。**6 个变异（Y11/Y14/Y15/Y16/Y17/Y18）因此漏检。**
这是**上一轮 E1 缺陷的同类复发**，只是换了个分支。

#### G2（严重·工具）：verify_elif 把 `pass` 与 `continue` 视为同一结果

详见 12.1.3 类别 B 的 Y1。`:137-138` 先匹配 `continue`，`:139-140` 再匹配 `pass`，
**两者都返回 `('CONT', None)`**。但语义完全不同：
- `pass` → 落到成功路径 → `plaintext_out += tmp`（累加明文）
- `continue` → 回循环顶 → **本轮明文被丢弃**

**Y1（`OK` 分支 `pass`→`continue`）会让所有正常数据被静默丢弃，而脚本报 PASS。**
这比 D1 更隐蔽——D1 是「所有数据报错」（立刻可见），Y1 是「所有数据消失」（静默）。

#### G3（一般·文档）：`count_sec_refs.py` 的提示语指向已删除的断言

详见 12.5.1。脚本输出「文档 :1644 写『全文 15/20』」，但那是**历史留痕**不是当前断言，
会让读者以为文档还在用错误数字。

#### G4（一般·文档）：KNOWN 表漏登记 S14

详见 12.4.3。3 个历史快照的 S14 是真实命中（我第⑥步 N5 报的缺陷），但没登记进 KNOWN，
导致每次 regress 都打印 `extra=['S14']`。**建议补进去**，让输出干净。

### 12.8 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **verify_elif 两个旧缺陷**（else 硬编码 / 断言过弱） | **通过**（`interpret_segment` 读 body + 逐状态 EXPECT） |
| **verify_elif 变异自测 5/5** | **通过**（我复现） |
| **verify_elif 我自己的 19 个变异** | **不通过**（检出 11/19；RENEGOTIATE 硬编码 6 个 + pass/continue 混淆 1 个 + 集合内容 1 个） |
| **S12 语义层** | **通过（有保留）**：挡住空壳与反向（2 个最危险的），但对 4 种正确换说法误报 |
| **S1 回边判定** | **通过**：`if 1 == 1` 等 3 个极端写法误报，但**取舍正确**（宁可误报） |
| **S14 / S3 / S11 / S10 / S8** | **全部通过**（我逐项实测） |
| **KNOWN 表** | **通过**（4 条 ⊇ 全部成立；漏登记 S14 是提示不是错误） |
| **`design-a.bak.md` 是 1139 行版** | **纠正事实**（父代理说 1464 行，错）；S1/S15 登记**正确** |
| **四道门禁 `verify.ps1 -PseudoLint`** | **通过**（我完整跑通，12/12 ctest + 四道全绿，exit=0） |
| **count_sec_refs 口径 B = 8/13** | **通过**（与文档一致）；建议加 `--check` 门禁 |
| **C11 删「15/20」** | **通过**（删断言、留痕迹，做法正确） |

**放行条件（3 条）**：

1. **【阻断】修 verify_elif 的 `RENEGOTIATE` 硬编码**（G1）：
   删掉 `:122-126` 整块特例，让通用逻辑处理（它已经能提取 `continue` 和 `Fail(...)`）；
   `EXPECT['RENEGOTIATE']` 保持 `('CONT', None)`（默认 TLS1.3）。
   **修完 Y11/Y14/Y15/Y16/Y17/Y18 应全部翻红。**
2. **【严重】修 verify_elif 的 `pass`/`continue` 混淆**（G2）：
   区分 `('FALLTHROUGH_OK', None)`（pass，累加明文）与 `('CONT_SKIP', None)`（continue，丢弃明文）；
   `EXPECT['OK'] = ('FALLTHROUGH_OK', None)`。
   **修完 Y1 应翻红**——这是**当前最危险的漏检**。
3. **【一般】`count_sec_refs.py --check` 接进门禁**（12.5.2），并把提示语从「文档 :1644 写 15/20」
   改成「历史留痕提到的 15/20 是自指污染值，当前文档不再使用」。

**随修（不设卡）**：`match_cond` 解析集合内容（修 Y3）；S12 降为 `warn`（因为它对正确表述误报）；
KNOWN 补 3 个 S14；regress 表头 `fail` 改 `fail_ids`；S1 报错消息补「若条件恒真请简化」。

### 12.9 我方本轮自我更正

1. **我上一轮说「S12 加两层关键词能挡住明显反转」，实测是对的**（反向 2 个都挡住了），
   但我当时**没说它会误报 4 种正确说法**。本轮补上这个代价评估，并因此建议降为 `warn`。
2. **我上一轮把 `design-a.bak.md` 当成「1464 行版」**（在 §11.2 里写「92381 B = 我第⑦步冻结的 1464 行版」）。
   **这是错的**：92381 B 是 **1139 行版**；1464 行版是 `step7.v2.md`（120397 B）。
   本轮已纠正，并因此确认父代理的 S1/S15 登记是**正确的**（1139 行版确实没修 B1）。
3. **我上一轮说「MUT1–5 修完应全红」，现在 5/5 确实全红**——这条父代理做对了，
   但**我的 5 个变异只覆盖了 `else` 与各分支的返回码，没覆盖 `RENEGOTIATE` 内层结构和 `pass`/`continue` 的区别**。
   本轮补的 19 个变异才暴露出这两类盲区。**说明「红证用例的数量」不等于「覆盖的维度」。**

### 12.10 第⑩步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| G5a | 修完 G1/G2 后，我的 19 个变异是否全部符合预期（检出 13 + 不误报 1） | — | 这是验收该修复的唯一方法 |
| G5b | `pass` 与 `continue` 在真实 C++ 实现里的差异是否如我所析（`pass` 继续执行、`continue` 跳过） | — | **C++ 语义确定**，无需验证；但**伪代码作者是否理解这个区别**需要确认——建议在 §3.4.1 加一行注释说明 `elif st == OK: pass` 的 `pass` 是「继续往下」而非「跳过」 |
| G5c | `count_sec_refs.py --check` 的断言值提取是否会被历史留痕误匹配 | C | 我提了锚定「唯一稳定口径」的方案，需实测 |

---

## §13. 第⑪步复验（G1/G2/Y3 修复 + 五道门禁 + 我自己的变异）

### 13.0 快照与六个 exit 码

> **文档**：`design-a.md`，**1886 行 / 151731 B**，SHA256 `83D70EC86922759247F1304CF243FE23E085D2B93EA453DAB401E03E9FF18256`（mtime 01:40:06）。
> **脚本**：`verify_elif_semantics.py` **408 行 / 15637 B / `5EFC79033316C28E`**（上轮 270 行 → 本轮 408 行）；
> `pseudo_lint.py` **756 行 / 31547 B / `74625A839289B0C4`**；`pseudo_lint_redtest.py` 229 行 / `41E4C39F`；
> `count_sec_refs.py` **112 行 / 3818 B / `B35D3373A4BD8FFA`**（上轮 43 行）；`verify.ps1` **196 行 / 8909 B / `92B1C71F1E65DC1A`**（上轮 188 行）。

**六个 exit 码，我自己跑出来的**：

```
1. pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2. pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3. verify_elif_semantics.py            → 10 状态 + 10/10 变异 + TLS1.2 专项   exit=0
4. pseudo_lint.py --regress (4 快照)   → 4 快照 fail_ids==known 全 OK         exit=0
5. count_sec_refs.py --check           → OK: 文档断言 (8,13) == 口径 B (8,13) exit=0
6. doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
+  verify.ps1 -PseudoLint              → 12/12 ctest + pseudo lint passed      exit=0
```

**regress 现在 `extra` 全部消失**（表头也改成了 `fail_ids`）：
```
design-a.bak.md                8      8        OK
design-a.step7.snapshot.md     8      8        OK
design-a.step7.v2.md           7      7        OK
design-a.step8.base.md         3      3        OK
tls-backend.design-a.md        0      0        OK
```
**上轮 G4（KNOWN 漏登记 S14）已修，`extra=['S14']` 消失。**

### 13.1 Q1：G1/G2/Y3 是否真修？——**三条都真修了，但我发现 3 个新盲区**

#### 13.1.1 上轮 19 个变异，现在 19/19 全部符合预期

我用**上轮同一批锚点**重跑（注意：`INCOMPLETE` 的 `return Fail` 在 `:631` 不是 `:627`，`627` 是 `if` 行本身）：

| # | 变异 | 上轮 | 本轮 |
|---|---|---|---|
| Y1 | `OK` 分支 `pass`→`continue` | **未检出** | **检出** `st=OK got=CONT_SKIP want=FALLTHROUGH_OK` |
| Y2 | `PEER_ALERT`→`kInternal` | 检出 | 检出 |
| Y3 | 集合→`== ALTERED` | **未检出** | **检出** `st=DECRYPT_FAILURE` |
| Y4 | `else`→`continue` | 检出 | 检出 |
| Y5 | 删 `else` 整块 | 检出 | 检出 |
| Y6 | `INCOMPLETE`→`kInternal` | 检出 | 检出 |
| Y7 | `OK` `pass`→`return kOk` | 检出 | 检出 |
| Y8 | `INTERNAL`→`kPeerAlert` | 检出 | 检出 |
| Y9 | `CONTEXT_EXPIRED`→`kOk` | 检出 | 检出 |
| Y10 | `NO_RENEG` `continue`→`Fail` | 检出 | 检出 |
| Y11 | `RENEG(1.3)` `continue`→`Fail` | **未检出** | **检出** `st=RENEGOTIATE` |
| Y12 | `OK` `pass` 加注释（不得报） | 不误报 | 不误报 ✓ |
| Y13 | `INCOMPLETE`→`kOk` | 检出 | 检出 |
| Y14 | `RENEG(1.3)` `continue`→`pass` | **未检出** | **检出** `got=FALLTHROUGH_OK` |
| Y15 | `RENEG` 整支→`Fail` | **未检出** | **检出** |
| Y16 | `RENEG` 无条件 `continue` | **未检出** | **检出** `st=RENEGOTIATE (tls13=False) got=CONT_SKIP` |
| Y17 | `RENEG` 无条件 `pass` | **未检出** | **检出** |
| Y18 | `RENEG(1.2)` `Fail`→`continue` | **未检出** | **检出** `@1.2` |
| Y19 | `RENEG(1.2)` `Fail`→`pass` | — | **检出** `@1.2` |

**上轮 8 个未检出（Y1/Y3/Y11/Y14/Y15/Y16/Y17/Y18）现在全部翻红。G1/G2/Y3 三条放行条件实质达成。**

#### 13.1.2 但我的**新一轮**探针发现了 3 个盲区

**(1) 外层 `st == X` → `st != X`：7 个全部漏检**

`match_cond()`（`:105-130`）是**按子串判等**，完全不看运算符：
```python
if 'NO_RENEGOTIATION' in cond: return st == 'NO_RENEGOTIATION'   # :108-109
if 'RENEGOTIATE' in cond:      return st == 'RENEGOTIATE'        # :110-111
if 'INCOMPLETE' in cond:       return st == 'INCOMPLETE'         # :112-113
...
```
所以把 `if st == INCOMPLETE:` 改成 `if st != INCOMPLETE:` —— **`cond` 里仍然含 `'INCOMPLETE'`，`match_cond` 照样返回 `st == 'INCOMPLETE'`**。

实测（我改 7 条链上每个 `==` 为 `!=`）：
```
INCOMPLETE   == -> !=   rc=0  未检出
PEER_ALERT   == -> !=   rc=0  未检出
INTERNAL     == -> !=   rc=0  未检出
CONTEXT_EXPIRED == -> != rc=0 未检出
NO_RENEG     == -> !=   rc=0  未检出
OK           == -> !=   rc=0  未检出
RENEG        == -> !=   rc=0  未检出
→ 0/7 符合预期
```
**这是与 G1 完全同型的缺陷**：G1 是「看到 `negotiated.tls_version` 就假定行为」，这里是「看到状态名就假定是 `==`」。**同一个反模式，第三次出现**（`else` 硬编码 → `RENEGOTIATE` 硬编码 → 运算符硬编码）。

**注**：`st != INCOMPLETE` 这种变异若真进文档，语义是「除 INCOMPLETE 外全部按协议错误处理」，是**灾难性缺陷**。而脚本报 PASS。

**(2) 内层 `== 0x0304` 运算符硬编码：2 个漏检**

`:204`：
```python
if 'tls_version' in inner_cond and '0x0304' in inner_cond:
    truth = tls13
```
- `== 0x0304` → `!= 0x0304`：`inner_cond` 里仍有 `tls_version` 和 `0x0304` → **照样返回 `truth = tls13`**，语义完全反转却**未检出**。
- `== 0x0304` → `>= 0x0304`：同上，**未检出**。
- `== 0x0304` → `== 0x0303`：检出（因为 `0x0304` 不再出现 → `truth=None` → `UNRESOLVED`）。
- → `True` / `False`：检出。

**巧合检出 ≠ 正确检出**：`== 0x0303` 被检出是因为**字面量变了**，不是因为**运算符被理解**。

**(3) `CONTEXT_EXPIRED` 的 `closed_ = true` 丢失：未检出**

`:644` 是 `closed_ = true; return kClosed`（**行内两条语句**）。把它改成 `return kClosed`（丢掉 `closed_ = true`）→ **rc=0 未检出**。
因为 `_classify_leaf()` 只看 `return kXxx`，不看前置赋值。**后果**：`closed_` 未置位 → 后续 `Receive` 会继续读已关闭的连接（B3/N7 复发），但状态机语义断言看不见。

**这一条与 G2 同类**：G2 是「`pass` 与 `continue` 被混同」，这条是「`closed_=true` 这种副作用被忽略」。**都是「只建模控制流、不建模副作用」。**

#### 13.1.3 `elif` → `if`（链断裂）由谁负责？——**pseudo_lint 的 S4 负责，分工正确**

我测 `:655 elif st == INTERNAL:` → `if st == INTERNAL:`：
```
verify_elif  rc=0  未检出
pseudo_lint  rc=1  FAIL=['S4']   ← S4 抓到了
```
**这是正确的分工**：链结构由结构检查器（S4「else 兜底」）管，语义验证器只管「给定链，各状态走哪」。**不建议在 verify_elif 里重复实现结构检查。**

### 13.2 Q2：TLS1.2 专项断言够不够？——**不够，建议加 `NO_RENEGOTIATION@1.2`**

你只加了 `RENEGOTIATE@1.2`。我核对了 10 个状态的协议适用性：

| 状态 | TLS1.2 | TLS1.3 | 行为是否随版本变 |
|---|---|---|---|
| `INCOMPLETE` | 有 | 有 | 否（同一 `kProtocolError`） |
| `RENEGOTIATE` | **有** | **有** | **是**（1.2 拒绝 / 1.3 喂回 ISC）← 你已断言 |
| `NO_RENEGOTIATION` | **不出现** | 有 | **需明确**：1.2 下若出现该值，应当走 `else` 兜底（`kInternal`）还是 `continue`？ |
| `CONTEXT_EXPIRED` | 有 | 有 | 否 |
| `ALTERED` / `DECRYPT_FAILURE` | 有 | 有 | 否 |
| `PEER_ALERT` | 有 | 有 | 否 |
| `INTERNAL` | 有 | 有 | 否 |
| `OK` | 有 | 有 | 否 |

**我的实测**：`NO_RENEGOTIATION` 的 `continue` 改成 `Fail(kProtocolError)` → **检出**（`st=NO_RENEGOTIATION got=RET kProtocolError`）。
**所以 1.2/1.3 无关，单值断言已够**——`EXPECT['NO_RENEGOTIATION']=(CONT_SKIP,None)` 覆盖了它。

**但有一个真实缺口**：`EXPECT` 表**只断言「该状态走哪条路」，不断言「该状态在 1.2 下根本不会出现」**。
如果实现里 1.2 收到 `SEC_I_NO_RENEGOTIATION`（理论上不该有，但 Windows 可能返回），当前设计走 `continue`（静默忽略），
**这可能掩盖一次协议违规**。**建议**：在设计文档 §3.4.1 明确写「`NO_RENEGOTIATION` 仅 TLS1.3 出现；1.2 下若出现按 `kProtocolError` 处理」，
然后加断言 `EXPECT_R12['NO_RENEGOTIATION'] = ('RET','kProtocolError')`。
**这是设计决策，不是脚本缺陷**——需要你拍板，我不替你定。

**其余 8 个状态：单值断言足够，不需要加 1.2 专项。**

### 13.3 Q3：`_classify_leaf` 的判定顺序有隐患吗？——**优先级正确，但"副作用"完全没建模**

**优先级（`:157-168`）：`Fail()` → `return kXxx` → `return` → `continue` → `pass`**

实测：
```
RENEG 1.3 体同时含 pass + continue  → rc=0（无 MISMATCH，取 continue=CONT_SKIP）✓ 正确
OK 体同时含 continue + pass          → rc=1（取 continue → CONT_SKIP，与 EXPECT 的 FALLTHROUGH_OK 冲突）✓ 正确报警
INTERNAL 体 return + continue        → rc=0（取 return）✓ 正确
```
**优先级本身是对的**：`return`/`Fail` 是终止性语句，优先于 `continue`/`pass`；`continue` 优先于 `pass`（因为 `continue` 会跳过后续，`pass` 不会）。**这个顺序与 C++ 语义一致。**

**但真正的隐患不是顺序，是"只看叶子语句"**：见 13.1.2(3)。`closed_ = true; return kClosed` 被当成纯 `return`，
**前置副作用 `closed_ = true` 被丢弃**。同类还有：
- `progressed += 1`（`:636` 的 `continue` 前一行注释说「progressed 已 +1」，但那是注释，不是代码）
- `plaintext_out += tmp`（成功路径的累加，`EXPECT['OK']=FALLTHROUGH_OK` 只是**假定**它会执行，没有验证）

**建议（低成本）**：`_classify_leaf()` 返回三元组 `(action, status, side_effects)`，
其中 `side_effects` 收集 `closed_\s*=\s*true` / `progressed\s*\+=\s*1` 等赋值；
`EXPECT` 增加对 `CONTEXT_EXPIRED` 的 `closed_=true` 断言。
**或者**：在设计文档里明确「`closed_ = true` 由 `terminal()` 统一设置，`Receive` 只 return」——那样这条副作用就从 `Receive` 移走了，脚本也不需要建模。**后者更符合单一职责，我推荐后者。**

### 13.4 Q4：`--check` 锚点是否脆弱？——**方向正确（该失败就失败），但有 1 个假阴性**

我做了 7 个篡改测试：

| 篡改 | 期望 | 实际 | 判定 |
|---|---|---|---|
| 原样 | exit=0 | exit=0 | ✓ |
| `**8**`/`**13**` 去粗体 → `\| 8 \| 13 \|` | 失败 | **exit=1**「未找到唯一稳定口径」 | ✓ **该失败就失败**（比静默通过好） |
| 断言值 `8`→`9` | 失败 | exit=1「文档写 (9,13)，实测 (8,13)」 | ✓ |
| 整行删除 | 失败 | exit=1 | ✓ |
| 「唯一稳定口径」→「口径ZZZ」 | 失败 | exit=1 | ✓ |
| **表格前加空行** | **应通过**（格式变化不改语义） | **exit=1 失败** | **✗ 假阴性** |
| `13`→`14` | 失败 | exit=1 | ✓ |

**结论：7 个里 6 个符合期望，1 个假阴性（加空行导致失败）。**

**这个假阴性的性质**：它**失败**而不是**静默通过**，所以**方向是安全的**（宁可错杀）。
根因是正则把「口径」二字与表格行绑在同一个匹配里，中间插空行就断链。

**建议（可选，不设卡）**：改成两步——
```python
i = doc.find('唯一稳定口径')
if i < 0: FAIL
tail = doc[i:i+600]                       # 口径后 600 字符内找表格行
m = re.search(r'\|\s*\*\*(\d+)\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|', tail)
```
这样空行、多余空格都不影响，但**删掉表格行或改数字仍然失败**。

**你问「非粗体会静默通过还是失败」——实测是失败，不会静默通过。这个性质比"健壮"更重要，我认可当前实现。**

### 13.5 Q5：还有没有"同类复发"？——**有，而且很明确：运算符硬编码**

我通读了 `match_cond`（`:105-130`）与 `interpret_segment`（`:172-230`），把「看到某个字符串就假定行为」的位置全列出来：

| 行 | 代码 | 假定 | 危险 |
|---|---|---|---|
| `:88` | `'st' in cond` | 含 `st` 子串就是状态分支 | 低（`state`/`status` 也会命中，但本项目无此变量） |
| `:108-128` | 各 `if 'STATE' in cond: return st == 'STATE'` | **含状态名就是 `==`** | **高（13.1.2(1)，7 个漏检）** |
| `:116-123` | `if 'ALTERED' in cond:` 再解析集合 | 已修（Y3） | 低 |
| `:204` | `if 'tls_version' in inner_cond and '0x0304' in inner_cond: truth = tls13` | **含这两个子串就是 `==`** | **高（13.1.2(2)，2 个漏检）** |
| `:206-209` | `inner_cond.strip() in ('True','1')` | 只认这两个字面量 | 低（同 S1，取舍正确） |

**根因是同一个：`match_cond` 从不解析运算符，只做子串匹配。** 这是 G1 的**第三次复发**。

**最小修法（约 25 行）**：把 `match_cond` 从「子串表」改成「表达式解析」：
```python
def match_cond(cond, st):
    if not cond: return True
    c = cond.strip()
    # 集合形式：st in {A, B}
    m = re.match(r'^st\s+in\s*\{(.*)\}$', c)
    if m:
        return st in {x.strip() for x in m.group(1).split(',') if x.strip()}
    # 比较形式：st == X / st != X
    m = re.match(r'^st\s*(==|!=)\s*(\w+)$', c)
    if m:
        eq = (st == m.group(2))
        return eq if m.group(1) == '==' else not eq
    # 其他（如 st == OK && ...）→ 明确报 UNRESOLVED，不要猜
    raise SystemExit('match_cond: 不支持的条件表达式 %r' % c)
```
内层同理：`:204` 改成解析 `tls_version (==|!=|>=|<=) (0x[0-9a-fA-F]+)`，按运算符与 tls13 实际值求值。

**关键设计原则**：**遇到不认识的形式必须 `raise`，不能猜。**
现在的实现「猜」成 `==`，于是任何运算符变异都不可见。**`raise` 会让新形式立刻暴露，而不是静默错误。**

**注意**：改成 `raise` 后，`_q1` 里 `elif st == INTERNAL` 这类**合法**形式必须继续支持，所以要保证 8 种现状形式都能解析。
建议先跑一遍当前文档，确认 8 条链 + 1 条内层全部命中解析器，再加 `raise`。

### 13.6 随修项复核（5 项）

| 项 | 你说 | 我核实 |
|---|---|---|
| **S12 降 warn** | 已降 + docstring 加定位声明 | **已落地**。`:535` 仍是 `fail`（「行不存在/空壳」），`:544`/`:548` 是 `warn`（措辞不符）。**分级正确**：结构性缺失 fail，措辞问题 warn |
| **`match_cond` 解析集合** | 已修 | **已修且有效**（Y3 检出，`:116-123` 解析 `{...}`） |
| **KNOWN 补 S14** | 已补 3 个 | **已补**（`:676-678` 各含 S14），regress `extra` 消失 |
| **regress 表头 `fail_ids`** | 已改 | **已改**，实测输出表头是 `fail_ids` |
| **S1 消息补提示** | 已补 | 已补（我在 S1 实现里确认了提示语） |

**5 项全部落地。**

### 13.7 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **G1：RENEGOTIATE 硬编码已删** | **通过**（`:172-230` 真递归，6 个变异全翻红） |
| **G2：pass/continue 已分开** | **通过**（`CONT_SKIP` / `FALLTHROUGH_OK` 分离，Y1 翻红） |
| **Y3：集合内容已解析** | **通过**（Y3 翻红） |
| **上轮 19 个变异** | **通过 19/19** |
| **TLS1.2 专项断言** | **通过（但只覆盖 RENEGOTIATE；`NO_RENEGOTIATION` 需设计拍板）** |
| **`_classify_leaf` 优先级** | **通过**（顺序与 C++ 语义一致） |
| **`count_sec_refs --check`** | **通过**（6/7 符合期望，唯一假阴性是"失败"而非"静默通过"，方向安全） |
| **五道门禁 + doc_lint** | **通过**（六个 exit 码全 0） |
| **`match_cond` 运算符** | **不通过**（`st == X` → `st != X` 7/7 漏检） |
| **`interpret_segment` 内层运算符** | **不通过**（`== 0x0304` → `!=`/`>=` 2/2 漏检） |
| **`closed_ = true` 副作用** | **不通过**（丢失未检出） |

**放行条件（3 条）**：

1. **【阻断】`match_cond` 改表达式解析，不认识的形式 `raise`**（13.5）：
   当前 7 个 `st == X` → `st != X` 全部漏检。这是 G1 的第三次同型复发。
   **验收标准**：我上轮的 7 个 `!=` 变异 + 本轮的 2 个内层运算符变异，共 9 个，全部翻红。
2. **【严重】`interpret_segment` 内层条件同样解析运算符**（`:204`）：
   `== 0x0304` → `!=` / `>=` 目前漏检。
3. **【一般】`NO_RENEGOTIATION` 在 TLS1.2 下的语义需设计拍板**（13.2）：
   是「不出现」还是「出现则 `kProtocolError`」？定了之后加 `EXPECT_R12` 断言。

**随修（不设卡）**：
- `closed_ = true` 副作用：**推荐改设计**——把 `closed_ = true` 收进 `terminal()`，`Receive` 只 return（单一职责），脚本不必建模副作用。
- `count_sec_refs --check` 两步匹配（消掉加空行假阴性）。
- `match_cond` 的 `'st' in cond`（`:88`）改成 `re.match(r'^st\b', cond)`，避免 `status`/`state` 误命中。

### 13.8 我方自我更正

1. **我上轮说「RENEGOTIATE 硬编码 6 个变异漏检」——本轮你修完后我重测，6 个全翻红，我的判断准确。**
   但我当时**只测了 `continue`/`Fail` 的替换，没测运算符**，所以没发现「运算符硬编码」这个更深的同型缺陷。
   **这说明我的变异集也有效度边界：改「动作」能测出硬编码，改「条件」才能测出条件硬编码。**
2. **我上轮把 `INCOMPLETE` 的锚点写成 `:627`（那是 `if` 行），实际 `return Fail` 在 `:631`**，
   导致我第一次跑出「Y13 未检出」的假结论，修正锚点后检出。**记录在此，避免后续误引。**
3. **我上轮说「S12 加词会误报，建议降 warn」——你采纳并落地为 fail/warn 分级**，
   我现在看到 `:535`（fail，行缺失/空壳）+ `:544/:548`（warn，措辞）的划分**比我原来的建议更细**，
   我原来的建议是「整体降 warn」，你的做法（结构性缺失仍 fail）**更好，我接受你的版本**。

### 13.9 第⑪步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| H1a | `match_cond` 改成 `raise` 后，当前文档 8 条链 + 1 条内层是否全部可解析 | — | 必须先验证，否则会把合法文档判死 |
| H1b | 我的 9 个运算符变异（7 外层 + 2 内层）是否全部翻红 | — | 放行条件 1/2 的验收标准 |
| H1c | `closed_ = true` 改由 `terminal()` 设置后，是否影响 `CONTEXT_EXPIRED` 的现有行为 | B | 设计变更需回归 10 状态 + E 表 |
| H1d | `NO_RENEGOTIATION` 在 TLS1.2 下是否真不出现（需实测或文档依据） | B | **不跑新探针**，只能查 `schannel.h` / MSDN 或现有 probe 记录 |

---

## §14. 第⑫步复验（严格解析 + raise + NO_RENEG 1.2 分支 + 22 变异）

### 14.0 快照与七个 exit 码

> **文档**：`design-a.md` **1893 行 / 152640 B**，SHA256 `1D4FE3CEEEA72BB0`（mtime 02:09:01）。
> **脚本**：`verify_elif_semantics.py` **497 行 / 20109 B / `5950EF2D79A0D98D`**（上轮 408 行 → 本轮 497 行）；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；
> `count_sec_refs.py` 112 行 / `B35D3373`；`verify.ps1` 196 行 / `92B1C71F`。
> **我方裁定文件**：`tls-backend.consult-b.md` 2810 行 / 193644 B / `9614F2D0`（追加 §14 前）。

**七个 exit 码，我自己跑出来的**：

```
1. pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2. pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3. verify_elif_semantics.py            → 10 状态 + 2 个 1.2 专项 + 22/22      exit=0
4. pseudo_lint.py --regress (4 快照)   → 4 快照全 OK                          exit=0
5. count_sec_refs.py --check           → OK: 文档断言(8,13)==口径B(8,13)      exit=0
6. doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7. verify.ps1 -PseudoLint              → 12/12 ctest + pseudo lint passed      exit=0
```

**七道全绿，我完整跑通。**

### 14.1 Q1：`match_cond` / `eval_inner_cond` 还有没有"看到字符串就假定行为"？——**主体已修，但 `:88` 是漏网的同型缺陷，且它声称"已改"未落地**

#### 14.1.1 严格解析确实生效：我的 23 个变异全部符合预期

我按行号精确改（不采信 H1a–H1g），结果 **23/23**：

| # | 变异 | 期望 | 实际 | 判定 |
|---|---|---|---|---|
| Z1 | `INCOMPLETE` `==`→`!=` | 检出 | 检出 | ✓ |
| Z2 | `RENEGOTIATE` `==`→`!=` | 检出 | 检出 | ✓ |
| Z3 | `NO_RENEGOTIATION` `==`→`!=` | 检出 | 检出 | ✓ |
| Z4 | `CONTEXT_EXPIRED` `==`→`!=` | 检出 | 检出 | ✓ |
| Z5 | `PEER_ALERT` `==`→`!=` | 检出 | 检出 | ✓ |
| Z6 | `INTERNAL` `==`→`!=` | 检出 | 检出 | ✓ |
| Z7 | `OK` `==`→`!=` | 检出 | 检出 | ✓ |
| Z8 | `st != A and st != B`（复合） | 检出（raise） | **raise** `UnsupportedCond` | ✓ |
| Z9 | `not st == A` | 检出（raise） | **raise** | ✓ |
| Z10 | 集合单元素 `{ALTERED}` | 检出（漏 DECRYPT_FAILURE） | 检出 | ✓ |
| Z11 | `st not in {...}` | 检出（raise） | **raise** | ✓ |
| Z12 | `st ==  OK`（双空格，合法） | 不报 | 不报 | ✓ |
| Z13 | 内层 `==`→`!=` | 检出 | 检出 | ✓ |
| Z14 | 内层 `==`→`>`（真反转） | 检出 | 检出 | ✓ |
| Z15 | 内层 `==`→`>=`（**等价**） | **不报** | 不报 | ✓ |
| Z16 | 内层 `==`→`<`（真反转） | 检出 | 检出 | ✓ |
| Z17 | `NO_RENEG` 内层 `==`→`!=` | 检出 | 检出 | ✓ |
| Z18 | `NO_RENEG` 内层 `==`→`>` | 检出 | 检出 | ✓ |
| Z19 | `NO_RENEG` 内层 `==`→`>=`（等价） | **不报** | 不报 | ✓ |
| Z20 | `RENEG` 删内层（无条件 continue） | 检出 | 检出 | ✓ |
| Z21 | `NO_RENEG` 删内层 | 检出 | 检出 | ✓ |
| Z22 | 删 `closed_ = true` | 检出 | 检出 | ✓ |
| Z23 | `closed_ = true`→`false` | 检出 | 检出 | ✓ |

**上轮 9 个运算符变异（7 外层 + 2 内层）现在全部翻红。放行条件 1/2 实质达成。**
`raise` 机制也对：Z8/Z9/Z11 三种「没想到的形式」全部 raise，**不猜**。

#### 14.1.2 但 `:88` 没改，而且它声称改了

你说「`(3) :88 改 re.match(r'^st\b')` 已改（在 `parse_chain` 里）」。**实测原文**：

```
87:     cand = [(k, ind, kw, cond) for k, ind, kw, cond in entries
88:             if (kw in ('if', 'elif') and 'st' in cond) or kw == 'else']
```
**`:88` 仍然是 `'st' in cond`，`re.match` 一次都没出现。这条随修未落地。**

**后果（我实测）**：在链前插一个含 `st` 子串的无关 `if`：
```
R1  链前插 if best_len > 0:     → raise UnsupportedCond: 'best_len > 0'
R2  链前插 if last_st > 0:      → raise UnsupportedCond: 'last_st > 0'
R3  对照（同一插入）            → 同样 raise
```
**行为方向是"安全失败"**（raise 而不是猜错），所以**不是假阴性**。
但它证明 `:88` 确实把无关 `if` 拉进了链——只是后面被 `match_cond` 的 raise 兜住了。

**更细的问题**：`parse_chain`（`:91`）取 `top = min(ind ...)`，如果无关 `if` 在**同一缩进**，它会被当成链成员。
**当前文档没有这种写法，所以不爆**。但一旦有人写：
```
    if best_len > 0:
        ...
    if st == INCOMPLETE:
```
就会被判 `UnsupportedCond` —— **合法文档被判死**（假阳性）。

**修法（2 行）**：
```python
cand = [(k, ind, kw, cond) for k, ind, kw, cond in entries
        if (kw in ('if', 'elif') and re.match(r'^st\b', cond)) or kw == 'else']
```

#### 14.1.3 `raise` 会不会误杀合法文档？——**当前文档不会，但有 2 个真实假阳性**

我测了边界形式：

| 形式 | 结果 | 判定 |
|---|---|---|
| 当前文档（8 链 + 2 内层） | rc=0 | ✓ |
| `st==INCOMPLETE`（无空格） | rc=0 | ✓ |
| `st in { A , B }`（带空格） | rc=0 | ✓ |
| `st in {ALTERED}`（单元素） | 检出（DECRYPT_FAILURE 漏） | ✓ 正确 |
| 链尾 `else` 前加注释 | rc=0 | ✓ |
| **`if (st == INCOMPLETE):`（加括号）** | **raise** | **✗ 假阳性** |
| **链前插无关 `if best_len > 0:`** | **raise** | **✗ 假阳性**（见 14.1.2） |

**加括号这种写法在 C++ 里合法且常见**，但伪代码里当前没有。
**裁定：这 2 个假阳性可以接受**，因为：
1. 它们**失败而非静默通过**（方向安全）；
2. 报错信息明确（`match_cond: 不支持的条件表达式 '(st == INCOMPLETE)'`），维护者一眼知道怎么改；
3. **如果为加括号加兼容，就要写表达式解析器，成本远超收益**。

**但 `:88` 必须改**——它是"声称改了却没改"，性质不同（不是取舍，是失实）。

### 14.2 Q2：`raise` 是否让合法文档判死？——**当前文档不会；但 14.1.2 的 `:88` 会造成假阳性**

已并入 14.1.3。补充一条**正面结论**：
```
当前文档实跑 rc=0
8 条链：INCOMPLETE / RENEGOTIATE / NO_RENEGOTIATION / CONTEXT_EXPIRED
        / {ALTERED, DECRYPT_FAILURE} / PEER_ALERT / INTERNAL / OK / else
2 条内层：RENEGOTIATE 的 tls_version、NO_RENEGOTIATION 的 tls_version
全部可解析，无 raise。
```

### 14.3 Q3：H2b/H2c 的处理对不对？——**你完全正确，我上轮构造有误**

你指出 `==` → `>=` 是**语义等价变异**，不该被检出。**我验证了你的推理，完全正确**：

```
tls_version == 0x0304  vs  tls_version >= 0x0304
TLS1.3: 0x0304 == 0x0304 → True    |  0x0304 >= 0x0304 → True    相同
TLS1.2: 0x0303 == 0x0304 → False   |  0x0303 >= 0x0304 → False   相同
→ 两个取值下完全等价，不可区分
```

**我上轮的 H2b 用 `>=` 作为"真反转"用例是错的**：它不是反转，是等价改写。
**你改成 `>`（真反转）并新增 H2c（`>=`，标 `neg=True`）是正确的做法**——这样既保留了「测解析器是否真读运算符」的意图（`>` 足以证明），又区分了等价改写。

**我的 Z14/Z15/Z16 独立验证了这一点**：
- `>` → 检出（真反转：1.3 下 `0x0304 > 0x0304` = False，与 `==` 相反）✓
- `>=` → 不报（等价）✓
- `<` → 检出（真反转）✓

**我收回上轮「`>=` 应该被检出」的隐含判断。你的处理正确。**

### 14.4 Q4：`closed_` 收进 `terminal()` 的反驳是否成立？——**成立，我接受，但你的实现有 1 个缺口**

#### 14.4.1 你的理由成立

你说：
> `terminal_` = 错误终止，`Receive` 返回 `last_error_`
> `closed_` = 正常终止，`Receive` 返回 `kClosed`，且 **`plaintext` 可能非空**（C3）
> 若把 `closed_` 收进 `terminal()`，`terminal()` 就会同时表示两种语义，调用方无法区分

**我核实了文档，你的理由有据**：
- `:495` 「`terminal_` / `closed_` 是**两个独立**的状态」
- `:500-501` 表格：`terminal_==true` → 返回 `last_error_`；`closed_==true` → 返回 `kClosed`
- `:523` 「`Receive` | `kClosed` | 自动 close_notify …… **`plaintext` 可能非空**……**调用方必须先取走再关闭**」
- `:758` 「唯一**例外**是 `Fail()` 的非 `kOk` 路径（`kClosed`，E11）……**必须保留**（C3）」

**结论：你的反驳成立，我收回「收进 `terminal()`」的建议。** 两者语义确实不同（错误终止 vs 正常终止 + 明文可非空），合并会破坏 C3。

#### 14.4.2 但你的实现有缺口：`closed_` 检查是**子串匹配**，会被注释绕过

`:194-197`：
```python
if re.search(r'return\s+kClosed', txt):
    if not re.search(r'closed_\s*=\s*true', txt):
        return ('RET', 'kClosed_WITHOUT_FLAG')
```
**`txt` 已经剥掉了 `#` 注释**（`:192` `l.split('#')[0]`），所以注释里的 `closed_ = true` 不算——**这点是对的**。

**但反过来**：如果代码里写 `closed_ = true` 而**没有** `return kClosed`（例如 `closed_ = true` 后落空），
这条检查**不会报**。我测：
```
Z22 删 closed_ = true          → 检出 ✓
Z23 closed_ = true → false     → 检出 ✓
```
**这两个都检出。所以当前实现对"有 return 无 flag"和"flag 错值"都覆盖了。**

**剩余缺口（低危）**：`closed_ = true` 但**同时** `return kOk`（而非 `kClosed`）—— `:195` 只匹配 `return kClosed`，
所以 `closed_ = true; return kOk` **不会报**。这是**语义矛盾**（关了却报成功）。
我实测：
```
closed_ = true; return kOk  → rc=0 未检出
```
**建议补一条**：`if re.search(r'closed_\s*=\s*true', txt) and not re.search(r'return\s+kClosed', txt): return ('RET','kOk_WITH_CLOSED_FLAG')`。
**低危**（当前文档无此写法），不设卡。

### 14.5 Q5：`NO_RENEGOTIATION` 在 1.2 下的处置是否正确？——**处置正确，但 `probe24` 作为证据不够，且文档与伪代码不一致**

#### 14.5.1 处置本身正确

`:644-647`：
```
if negotiated.tls_version == 0x0304:
    continue                              # 1.3：正常
else:
    return Fail(kProtocolError)           # 1.2：本码不应出现
```
**这是保守且正确的**：1.2 下收到 1.3 专属码，终止而非静默忽略。`EXPECT_R12` 断言也加了，红证 `Q2a` 检出。**我认可。**

#### 14.5.2 但 `probe24` 的证据链有问题（**3 个独立问题**）

**问题 1：probe24 没有输出记录**

我全仓搜索 `0x00090360` / `NO_RENEGOTIATION` / `server-initiated`：
```
F:\rtsc\evidence 下：0 个文件命中
F:\rtsc\.tmp\tlsprobe 下：只有 probe24.cpp / .exe / .obj，没有 .txt/.out/.log
```
**文档 `:91` 写「`probe24` 实测是 TLS1.3 的 `AcceptSecurityContext(no input)` 返回值」，
但仓库里没有任何 probe24 的运行输出。** 这属于**不可复核的证据引用**。

**对比**：其他 probe 的证据是可复核的，例如 `:90` 引用 `[BASH:verify_traps.exe]`（有 `.out.txt`），
`:88` 引用 `probe20/probe27`（有输出记录）。**只有 probe24 是裸引用。**

**问题 2：probe24 的两段测试，标签与参数的关系需要澄清**

`probe24.cpp:243-246`：
```cpp
printf("== server-initiated renegotiation, TLS1.2 ==\n");
RenegTest(SP_PROT_TLS1_3_CLIENT);      // ← 参数是 "禁用 1.3" → 实际跑 1.2
printf("== server-initiated renegotiation, TLS1.3 ==\n");
RenegTest(SP_PROT_TLS1_2_CLIENT);      // ← 参数是 "禁用 1.2" → 实际跑 1.3
```
参数名是 `grbitDisabledProtocols`（`:50` `tp.grbitDisabledProtocols = disabled`），
所以**标签与行为是一致的**（禁用 1.3 = 跑 1.2）。**我一开始误判为"标签写反"，现撤回。**

**但这带来一个新问题**：probe24 的两段测试**都调用了 `AcceptSecurityContext(no input)`**（`:167`）。
**如果 1.2 那段（`RenegTest(SP_PROT_TLS1_3_CLIENT)`）也返回了某个码，那才是"1.2 下会怎样"的直接证据。**
**没有输出记录，就无法知道 1.2 那段返回了什么。** 这是**反向证据的缺失**——正如你 Q5 自己指出的。

**问题 3：`probe24` 测的是"服务端 ASC(no input)"，不是"客户端 DecryptMessage 返回 NO_RENEGOTIATION"**

`probe24` 的 `AcceptSecurityContext(no input)` 是**服务端主动发起重协商**（生成 HelloRequest），
返回 `SEC_I_NO_RENEGOTIATION` 说明「服务端不允许重协商」。
**但设计文档里的 `st == NO_RENEGOTIATION` 是 `Receive` 的状态**，来自 `DecryptMessage` 的返回值。
**这两个是不同的调用路径。**

**所以 probe24 不能直接支撑「`DecryptMessage` 在 1.3 下返回 `SEC_I_NO_RENEGOTIATION`」这个论断。**
文档 `:91` 的措辞「`probe24` 实测是 TLS1.3 的 `AcceptSecurityContext(no input)` 返回值」**字面上是准确的**
（它确实只说了 ASC），但**被用来支撑 `Receive` 的状态分派**，这是**跨路径的推论**，需要额外说明。

#### 14.5.3 文档 `:91` 与伪代码 `:645` 不一致（**新发现，G6**）

文档 `:91`：
> 1.3 → **`kOk`（忽略）**；1.2 → `kProtocolError`

伪代码 `:645`：
```
continue                              # 1.3：正常，记录已消费；progressed 已 +1
```
**`continue` ≠ `kOk`**：
- `kOk` = 返回给调用方，表示「本次调用成功」（可能 `plaintext` 为空）
- `continue` = 回循环顶继续解析下一条记录（**不返回**）

**语义差异的实际后果**：如果 `NO_RENEGOTIATION` 后还有后续记录，`continue` 会继续解析它们；
`kOk` 会立刻返回。**两种行为对调用方可见的结果不同。**

**这不是小瑕疵**：文档是契约，伪代码是实现。**两者矛盾时，实现阶段会按哪个写？**
**建议**：把 `:91` 的「`kOk`（忽略）」改成「`continue`（消费记录后继续循环）」，与伪代码一致。
**或者**，如果 `kOk` 才是设计意图，那伪代码要改。**需要你拍板。**

**我倾向 `continue`**：因为 `NO_RENEGOTIATION` 是「服务端拒绝重协商」，连接仍然有效，
继续处理后续记录是正确的；返回 `kOk` 会让调用方以为"本轮没有数据"，但实际可能还有。
**这与 `RENEGOTIATE`(1.3) 的处理一致（也是 `continue`），语义对称。**

### 14.6 随修项复核

| 项 | 你说 | 我核实 |
|---|---|---|
| **`match_cond` 严格解析 + raise** | 已改 | **已改且有效**（`:109-136`，3 种形式 + raise） |
| **`eval_inner_cond` 解析运算符** | 已改 | **已改且有效**（`:139-160`，6 个运算符） |
| **`UnsupportedCond` 异常** | 已加 | **已加**（`:105-106`） |
| **`NO_RENEGOTIATION` 1.2 分支** | 已加 | **已加**（`:644-647`） |
| **`EXPECT_R12` 断言** | 已加 | **已加**（`:304`） |
| **`closed_ = true` 副作用建模** | 改脚本 | **已加**（`:194-197`），Z22/Z23 检出 |
| **E 表 17→18 行** | 已同步 | **已同步**（实测 18 行，E1–E18 连续） |
| **S6 抓到出口数不符** | 是 | **属实**（这是 S6 该做的） |
| **redtest S6 锚点失效** | 已修 | **已修**（`F193DB47`，22/22） |
| **`:88` 改 `re.match(r'^st\b')`** | 已改 | **未改**（见 14.1.2，**失实**） |
| **`--check` 两步匹配** | 没改 | **确认没改**（我认可这个决定，理由充分） |

### 14.7 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **`match_cond` 严格解析 + raise** | **通过**（Z1–Z7 全检出，Z8/Z9/Z11 raise） |
| **`eval_inner_cond` 运算符解析** | **通过**（Z13–Z19 全符合，含等价改写不误报） |
| **上轮 9 个运算符变异** | **通过 9/9** |
| **我的 23 个变异** | **通过 23/23** |
| **`NO_RENEGOTIATION` 1.2 处置** | **通过**（逻辑正确） |
| **`closed_` 不并入 `terminal()`** | **通过**（你的反驳成立，我收回建议） |
| **H2b/H2c 处理** | **通过**（你是对的，我上轮构造有误） |
| **E 表 18 行 + S6** | **通过**（实测 18 行，S6 抓到不符） |
| **七道门禁** | **通过**（七个 exit 码全 0） |
| **`:88` 改 `re.match(r'^st\b')`** | **不通过**（未落地，失实） |
| **文档 `:91` 与伪代码 `:645` 一致** | **不通过**（`kOk` vs `continue` 矛盾） |
| **`probe24` 证据可复核** | **不通过**（无输出记录，且跨调用路径） |

**放行条件（3 条）**：

1. **【阻断】修 `:88`**（14.1.2）：`'st' in cond` → `re.match(r'^st\b', cond)`。
   **这不是取舍问题，是"声称改了却没改"**。改完后链前插无关 `if best_len > 0:` 不应再 raise。
2. **【严重】消除文档 `:91` 与伪代码 `:645` 的矛盾**（14.5.3）：
   `:91` 写 `kOk`（忽略），伪代码是 `continue`。**二选一并对齐。** 我倾向 `continue`（与 RENEGOTIATE 对称）。
3. **【一般】`probe24` 证据补全或降级**（14.5.2）：
   - 若保留「`probe24` 实测」的措辞，需补**运行输出记录**（至少 `probe24.exe` 的 stdout）；
   - 若无法补，**降级为「据 SChannel 文档推断」**，并说明「`DecryptMessage` 路径未经直接实测」。
   - **注意**：probe24 测的是 `AcceptSecurityContext`，不是 `DecryptMessage`。**跨路径推论需明确标注。**

**随修（不设卡）**：
- `closed_ = true; return kOk` 的矛盾组合补一条检查（14.4.2）。
- `if (st == X)` 加括号的假阳性可接受（方向安全），但建议在报错信息里提示「去掉括号」。

### 14.8 我方自我更正

1. **我一开始判定 `probe24.cpp:243-246` 的标签写反（标 TLS1.2 却传 TLS1_3_CLIENT），这是错的。**
   参数名是 `grbitDisabledProtocols`（禁用列表），所以「禁用 1.3 → 实际跑 1.2」，标签与行为**一致**。
   **我在核实 `:50` 的 `tp.grbitDisabledProtocols = disabled` 后撤回该判断。**
   这与上轮我自我更正的 probe18 是同类陷阱（**没看清参数语义就下结论**），我再次踩到，记录在此。

2. **我上轮隐含认为 `>=` 应该被检出，这是错的。** 你指出它是等价改写，我验证后确认：
   `0x0304>=0x0304` 与 `0x0303>=0x0304` 在两个取值下都与 `==` 相同。**我收回。**

3. **我上轮建议「把 `closed_` 收进 `terminal()`」，你的反驳成立，我收回。**
   `terminal_`=错误终止（返回 `last_error_`）vs `closed_`=正常终止（返回 `kClosed` 且明文可非空），
   合并会破坏 C3。**你选择改脚本建模副作用是对的。**

### 14.9 第⑫步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| J1a | `:88` 改完后，链前插无关 `if` 是否不再 raise | — | 放行条件 1 的验收标准 |
| J1b | `:91` 改成 `continue` 后，E 表 / S6 / 出口数是否需再同步 | B | 若改文档措辞则不影响出口数；若改伪代码为 `kOk` 则出口数 +1 |
| J1c | `probe24.exe` 是否还能跑出输出（**不跑新探针**，仅确认文件存在性） | B | 若不能跑，只能降级措辞 |
| J1d | `DecryptMessage` 是否真会返回 `SEC_I_NO_RENEGOTIATION` | B | **当前无直接证据**，probe24 测的是 ASC 路径 |
| J1e | `closed_ = true; return kOk` 的矛盾组合是否在别处出现 | C | 我实测当前文档无此写法 |

---

## §15. 第⑬步复验（`:88` 真修 + `:91` 对齐 + probe24 直接实测 + 23 变异）

### 15.0 快照与七个 exit 码

> **文档**：`design-a.md` **1893 行 / 153163 B**，SHA256 `97303EC1677E262A`（mtime 02:24:59）。
> **脚本**：`verify_elif_semantics.py` **506 行 / 20676 B / `59209C57610596A3`**（上轮 497 行）；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；
> `count_sec_refs.py` 112 行 / `B35D3373`；`verify.ps1` 196 行 / `92B1C71F`。
> **探针**：`probe24.exe` 177152 B / `E746B9134E8D8333`，mtime **2026/10/22 21:53:23**（未变）；
> `probe24.out.txt` 614 B / `D3FC3458E2E2D707`，mtime **2026/10/23 02:24:30**。

**七个 exit 码，我自己跑出来的**：

```
1. pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2. pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3. verify_elif_semantics.py            → 10 状态 + 2 个 1.2 专项 + 23/23      exit=0
4. pseudo_lint.py --regress (4 快照)   → REGRESS OK                           exit=0
5. count_sec_refs.py --check           → OK: 文档断言(8,13)==口径B(8,13)      exit=0
6. doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7. verify.ps1 -PseudoLint              → 12/12 ctest + pseudo lint passed      exit=0
```

### 15.1 Q1：`:88` 是否真改了？——**改了，这次是真的**

#### 15.1.1 grep 结果（你要求的）

我 grep `'st' in cond`（SimpleMatch）：
```
命中 1 处：87: # 必须用 re.match(r'^st\b')，不能用 'st' in cond ——
```
**唯一命中在注释里**（`:87` 是在说明"不能用 `'st' in cond`"）。**代码里 0 命中。**

实际代码（`:90-91`）：
```
90:    cand = [(k, ind, kw, cond) for k, ind, kw, cond in entries
91:            if (kw in ('if', 'elif') and re.match(r'^st\b', cond)) or kw == 'else']
```
**`re.match(r'^st\b', cond)` 已到位。放行条件 1 达成。**

#### 15.1.2 我自己的验收测试（不采信你的 3 个）

我测 7 个，全部符合设计：

| 注入 | 期望 | 实际 | 判定 |
|---|---|---|---|
| 基线（不注入） | 通过 | rc=0 | ✓ |
| 链前插 `if best_len > 0:` | 通过 | rc=0 | ✓ |
| 链前插 `if last_st > 0:` | 通过 | rc=0 | ✓ |
| 链前插 `if status == 3:` | 通过 | rc=0 | ✓ |
| 链前插 `if state != 0:` | 通过 | rc=0 | ✓ |
| 链前插 `if st_in == 0:` | 通过 | rc=0 | ✓ |
| 链前插 `if st2 > 0:` | 通过（`\b` 不匹配 `st2`） | rc=0 | ✓ |

**7/7 符合预期。** 注意最后一个：`st2` **不被** `^st\b` 匹配（因为 `st` 后是 `2`，不是词边界），
这是 `\b` 的正确语义，**不是漏检**。我最初把它标为"应报错"，是我预期错了，已更正。

**`:88` 这条彻底关闭。**

### 15.2 Q2：probe24 的新证据是否可信？——**可信，我独立复跑得到逐行一致的输出**

这是本轮最需要谨慎判断的问题。你问「这算补全证据还是事后造证据」。我的核实分三步：

#### 15.2.1 时间戳：二进制早于输出 4.5 小时

```
probe24.cpp       2026/10/22 21:52:38
probe24.exe       2026/10/22 21:53:23   ← 二进制
probe24.out.txt   2026/10/23 02:24:30   ← 输出（晚 4.5 小时）
```
**二进制不可能为配合输出而重编译**（它早于输出）。`probe24.obj` 与 `.exe` 同一时刻，说明是当次编译产物。

#### 15.2.2 我自己复跑既有二进制，输出逐行一致

我直接执行 `F:\rtsc\.tmp\tlsprobe\probe24.exe`（既有二进制，非新探针），与你的 `probe24.out.txt` 做 `difflib` 比对：
```
mine lines 14  theirs lines 14
IDENTICAL（逐行一致）
```
我的输出：
```
== server-initiated renegotiation, TLS1.2 ==
  proto=0x0800
  app data: 0x00000000
  server ASC(no input, ALLOCATE) -> 0x00000000, 33 bytes
  server flight (33 B): 16 03 03 00 1c 00 00 00 00 00
  client DecryptMessage -> 0x00090321 (0x00090321 = SEC_I_RENEGOTIATE) data=0 extra=0
  feeding 0 bytes of EXTRA into ISC
  client ISC(reneg) -> 0x00090312, 197 bytes
  server ASC(reneg flight) -> 0x00090312, 822 bytes
  client ISC(final) -> 0x00090312, 206 bytes
== server-initiated renegotiation, TLS1.3 ==
  proto=0x2000
  app data: 0x00000000
  server ASC(no input, ALLOCATE) -> 0x00090360, 0 bytes
```

#### 15.2.3 裁定：**是「补全证据」，不是「事后造证据」**

三条理由：
1. **二进制未被改动**（mtime 早于输出；我没有重编译）。
2. **我独立复跑得到完全相同的结果**——这是**可复现性**的最强形式，比任何签名都可靠。
3. **本轮任务未禁止运行既有探针**（只禁止「新探针」），所以运行既有二进制是合规的。

**"怎么证明二进制未被篡改"的答案**：不需要证明二进制。**需要证明的是「结果可复现」**——
我用同一个二进制跑出同样的 14 行，这已经排除了「输出是手写的」这一可能。
**如果二进制被篡改，我复跑会得到不同结果。** 这是比哈希更强的证据。

**但我要指出一个方法论问题（G7）**：`probe24.out.txt` **由你生成**，我复跑后**没有把我的输出落盘到仓库**
（我存到 `.tmp\my24.txt`，未写入 `evidence`）。所以**当前仓库里只有你的一份记录**。
**建议**：把复跑输出也存一份（或至少记录「consult-b 第⑬步独立复跑，逐行一致」），
让「双人独立复现」这件事本身有据可查。**这是证据链完整性，不是信任问题。**

#### 15.2.4 证据边界：你写对了，我确认

`:91` 现在明确写了：
> **边界**：测的是 `AcceptSecurityContext`，不是 `DecryptMessage`；但本码是 `SEC_I_`（信息级）且由 ASC 产生，
> Receive 侧只可能经 EXTRA/后续记录见到——故按 ASC 结果分派是可接受的近似（J1d 仍标 C）

**这个措辞是准确且诚实的**：既说明了实测覆盖什么，也说明了推论跨度，还保留了 J1d 的 C 级标记。
**我认可。**

**顺带确认一个事实**：实测输出显示 **TLS1.2 段 `DecryptMessage -> 0x00090321 (SEC_I_RENEGOTIATE)`**，
说明 1.2 下**服务端重协商是可能的**（与我早前记录的 probe24 结论一致）。
而 **TLS1.3 段 `ASC(no input) -> 0x00090360`**。**两段都成功跑完，无异常退出。**

### 15.3 Q3：`probe24.cpp:243-246` 的标签错误要不要修？——**该修，但不改二进制**

#### 15.3.1 先纠正你的表述

你说「`:243-246` 的打印标签确实写反了（打印 "TLS1.2" 却禁用 1.3），但**行为与标签一致**」。

**这句话内部矛盾**：
- 若「打印 TLS1.2 却禁用 1.3」→ 那实际跑的是 **TLS1.2**（禁用 1.3 即只剩 1.2）→ **标签正确**
- 若「行为与标签一致」→ 标签也是 TLS1.2 → 同上

**实测印证**：输出第一段 `proto=0x0800`（`SP_PROT_TLS1_2`），标签是 "TLS1.2" —— **完全一致**。
第二段 `proto=0x2000`（`SP_PROT_TLS1_3`），标签是 "TLS1.3" —— **也一致**。

**所以标签并没有写反。** 你上一轮说「标签写反」，本轮又说「行为与标签一致」，**这两句不能同时成立**。
**准确表述应该是**：`RenegTest(SP_PROT_TLS1_3_CLIENT)` 的**参数是「禁用列表」**，
传 `TLS1_3` 表示禁用 1.3（即跑 1.2），**打印标签 "TLS1.2" 是正确的**。

**这是本轮我第二次需要纠正这个点**（上轮我误判"标签写反"并撤回，本轮你又写了一遍）。
**根因是参数名 `grbitDisabledProtocols` 的语义反直觉**（传的是"禁用"不是"启用"）。

#### 15.3.2 该不该修源码？

**建议修，但只改注释，不改逻辑、不重编译**。

理由：
1. **不修会持续误导**（已经误导了我和你两轮）。`probe24.cpp` 是**证据文件**，可读性直接影响可复核性。
2. **但「既有探针不改」的约定有其道理**：改了源码，`.exe` 与 `.cpp` 就不同源，**证据链断裂**。
3. **折中方案**：在 `main()` 上方加一行注释：
```cpp
// 注意：RenegTest 的参数是 grbitDisabledProtocols（禁用列表），不是目标版本。
// 传 SP_PROT_TLS1_3_CLIENT = 禁用 1.3 = 实际跑 TLS1.2（标签正确）。
```
**只加注释不改代码 → 逻辑不变 → 不需要重编译 → `.exe` 与 `.cpp` 仍对应**（注释不影响二进制）。
**这是唯一既能消除困惑、又不破坏证据链的做法。**

**如果你认为「连注释都不能改」，那就退一步：在 `design-a.md` 的 `:91` 引用处写明这个语义**，
`probe24.cpp` 保持原样。**我倾向后者更稳妥**（证据文件应冻结）。

### 15.4 Q4：`kOk_WITH_CLOSED_FLAG` 这个判定是否过严？——**该判定根本不存在，你的"已补检查"未落地**

#### 15.4.1 实测：源码里没有这个检查

```
搜 'kOk_WITH_CLOSED_FLAG' → 0 命中
搜 'has_close_flag'        → 0 命中
```
`:197-200` 实际只有：
```python
if re.search(r'return\s+kClosed', txt):
    if not re.search(r'closed_\s*=\s*true', txt):
        return ('RET', 'kClosed_WITHOUT_FLAG')
```
**你上轮说的「已补检查」并未落地。** 这是**第三次失实**（`:88` 第一次、`:91` 那次算落地了、这次）。

#### 15.4.2 那为什么 Q4 变异"检出"了？

因为变异把 `closed_ = true; return kClosed` 改成 `closed_ = true; return kOk`，
**动作从 `kClosed` 变成 `kOk`**，于是 `EXPECT['CONTEXT_EXPIRED'] = ('RET','kClosed')` 不匹配 → 报 MISMATCH。

**这是「顺带检出」，不是「检查生效」**：
- 它只在**该状态的 EXPECT 恰好期望 `kClosed`** 时有效
- 若矛盾组合出现在**期望不是 `kClosed` 的分支**（如 `OK` 分支），就看不见

**我实测验证**：
```
C  closed_=true; return kOk (OK 分支)      → rc=1 检出（因为 EXPECT['OK']=FALLTHROUGH_OK）
D  closed_=true; pass (OK 分支)            → rc=0 **未检出** ← 真盲区
```
**D 是真正的假阴性**：`closed_=true` 后 `pass`（既不返回也不 continue，落到成功路径继续累加明文），
**语义是「标记已关闭却继续当成功处理」**，脚本看不见。

#### 15.4.3 回到你的问题：`closed_ = true; return kOk` 在什么情况下合法？

**答：不合法。** 你的推理正确：
> 我能想到：Shutdown 之后 Receive 返回 kOk 且 plaintext 为空。但那时应该返回 kClosed 才对。

**核实文档**：`:501` 表格明确 `closed_ == true` → **返回 `kClosed`**（四个调用方全部）。
`:523` `Receive` 在 `closed_` 时返回 `kClosed`，且**明文可能非空**（C3）。
**所以 `closed_=true` 时返回 `kOk` 违反 C3/C4 契约，不存在合法场景。判定不过严，是正确的。**

**但既然检查不存在，"过严"就无从谈起。** 建议按你上轮的代码补上（我可以确认那段逻辑是对的）：
```python
has_close_flag = re.search(r'closed_\s*=\s*true', txt) is not None
if re.search(r'return\s+kClosed', txt) and not has_close_flag:
    return ('RET', 'kClosed_WITHOUT_FLAG')
if has_close_flag and re.search(r'return\s+kOk', txt):
    return ('RET', 'kOk_WITH_CLOSED_FLAG')
```
**并补一条覆盖 D 的**：
```python
if has_close_flag and re.search(r'^\s*pass\b', txt, re.M):
    return ('RET', 'closed_flag_with_pass')
```

### 15.5 23 个变异复核

你的表 23/23，我实跑确认 `变异自测：23/23 被检出  ASSERT OK`。
新增的 `Q4 closed_=true 却 return kOk → ['CONTEXT_EXPIRED']` **确实检出**——但见 15.4.2，
**它是顺带检出，不是专项检查生效**。**红证"检出"与"机制正确"是两件事**，这一条需要澄清。

### 15.6 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **`:88` 改 `re.match(r'^st\b')`** | **通过**（grep 仅注释命中；我的 7 个验收全过） |
| **`:91` 与 `:645` 对齐（选 `continue`）** | **通过**（`:91` 已写 `continue`，与伪代码一致） |
| **probe24 证据可信度** | **通过**（我独立复跑 14 行逐行一致） |
| **probe24 证据边界声明** | **通过**（`:91` 明确写了 ASC vs DecryptMessage + J1d 标 C） |
| **E 表 18 行 + 出口数对账** | **通过**（`:854` 15 return + 3 continue = 18） |
| **23 个变异** | **通过**（我实跑 23/23） |
| **七道门禁** | **通过**（七个 exit 码全 0） |
| **`kOk_WITH_CLOSED_FLAG` 检查** | **不通过**（0 命中，未落地；且 `closed_=true; pass` 是真盲区） |
| **`probe24.cpp` 标签表述** | **不准确**（你说"标签写反"，实测标签正确；参数语义是"禁用列表"） |

**放行条件（2 条）**：

1. **【严重】补 `kOk_WITH_CLOSED_FLAG` 检查并覆盖 `closed_=true; pass`**（15.4.2）：
   当前 `Q4` 变异是**顺带检出**，不是机制生效。我实测 `closed_=true; pass`（OK 分支）→ **rc=0 未检出**，
   这是真盲区。按 15.4.3 的两段代码补上，并加第三个分支覆盖 `pass`。
   **验收标准**：`closed_=true; pass` 必须翻红。
2. **【一般】纠正 `probe24.cpp:243-246` 的表述**（15.3）：
   **标签没写反**（实测 `proto=0x0800` 对应 "TLS1.2"、`proto=0x2000` 对应 "TLS1.3"，全部一致）。
   根因是 `grbitDisabledProtocols` 是**禁用列表**。建议**在 `design-a.md` 引用处写明这个语义**，
   `probe24.cpp` 保持冻结（证据文件不改，避免 `.cpp`/`.exe` 不同源）。

**随修（不设卡）**：把复跑输出也留一份到仓库（G7，让"双人独立复现"有据可查）。

### 15.7 我方自我更正

1. **我最初把 `st2 > 0` 标为"应被拉进链"是错的。** `^st\b` 中 `\b` 在 `st2` 处不成立（`t` 与 `2` 之间无词边界），
   所以 `st2` 不被匹配是**正确语义**，不是漏检。我的 7 个验收实际是 **7/7**，不是 6/7。

2. **上轮我判定 `probe24.cpp:243-246` 标签写反，本轮再次核实后确认"标签正确"。**
   上轮我撤回是对的，但撤回得不够彻底——我当时没说清"标签正确"的正面理由（`proto` 实测值）。
   本轮用输出里的 `proto=0x0800` / `proto=0x2000` 提供了直接印证。

3. **我上轮说"`closed_=true; return kOk` 低危、不设卡"，本轮升级为放行条件。**
   理由：我上轮只测了「该组合在 CONTEXT_EXPIRED 分支」，看到检出就以为覆盖了。
   本轮测到 **`closed_=true; pass`（OK 分支）→ 未检出**，才明白那是顺带检出。
   **这是"用例位置"的盲区**：同一个矛盾组合在不同分支，检出能力不同。

### 15.8 第⑬步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| K1a | 补 `kOk_WITH_CLOSED_FLAG` + `closed_=true; pass` 后是否翻红 | — | 放行条件 1 的验收标准 |
| K1b | `closed_ = true` 后接 `continue`（NO_RENEG 1.3 分支）是否也应是矛盾 | C | 我实测 E 例检出（因动作变 FALLTHROUGH_OK），但语义上「关了还继续循环」也可疑，需你判断 |
| K1c | 复跑输出是否需要落盘到仓库 | C | G7：双人独立复现的可查性 |
| K1d | `probe24.cpp` 加注释是否真的不影响 `.exe` | — | C/C++ 注释不进二进制，理论确定；但若你们有「源码哈希比对」流程则需同步 |

---

## §16. 第⑭步复验（`kOk_WITH_CLOSED_FLAG` 落地 + sideeffect 专项 + 锚点不一致新缺陷）

### 16.0 快照与八个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3`（mtime 02:33:10）。
> **脚本**：`verify_elif_semantics.py` **523 行 / 21748 B / `E4EEA38A4A72267D`**（上轮 506 行）；
> **`verify_sideeffect_leaf.py` 46 行 / 1725 B / `1E3D27ED92036E60`（新增）**；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；
> `count_sec_refs.py` 112 行 / `B35D3373`；`verify.ps1` **203 行 / 9214 B / `BC54A25E3B2E4483`**（上轮 196 行）。
> **证据**：`probe24.out.txt` 614 B / `D3FC3458`；**`probe24.rerun-consult-b.txt` 616 B / `9DB330A1`（新增）**。

**八个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 10 状态 + 2 个 1.2 专项 + 24/24      exit=0
3b. verify_sideeffect_leaf.py           → _classify_leaf 5/5 ASSERT OK         exit=0
4.  pseudo_lint.py --regress (4 快照)   → REGRESS OK                           exit=0
5.  count_sec_refs.py --check           → OK: 文档断言(8,13)==口径B(8,13)      exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7.  verify.ps1 -PseudoLint              → 12/12 ctest + pseudo lint passed      exit=0
```

### 16.1 Q1：`kOk_WITH_CLOSED_FLAG` / `closed_flag_with_pass` 是否真落地？——**落地了**

我 grep（SimpleMatch）：
```
kOk_WITH_CLOSED_FLAG : 命中 1 处 → :206
closed_flag_with_pass: 命中 1 处 → :208
has_close_flag       : 命中 4 处 → :202,:203,:205,:207
kClosed_WITHOUT_FLAG : 命中 1 处 → :204
```

实际代码 `:202-208`：
```python
has_close_flag = re.search(r'closed_\s*=\s*true', txt) is not None
if re.search(r'return\s+kClosed', txt) and not has_close_flag:
    return ('RET', 'kClosed_WITHOUT_FLAG')
if has_close_flag and re.search(r'return\s+kOk', txt):
    return ('RET', 'kOk_WITH_CLOSED_FLAG')
if has_close_flag and re.search(r'^\s*pass\b', txt, re.M):
    return ('RET', 'closed_flag_with_pass')
```
**三条检查全部到位。放行条件 1 达成（这次是真的）。**

### 16.2 Q2：`verify_sideeffect_leaf.py` 是否真证明「机制生效」？——**证明成立，但我在它的用例之外找到了 1 个真缺陷**

#### 16.2.1 它的方法论是对的

它 `importlib` 加载 `verify_elif_semantics.py`，**直接调 `_classify_leaf()`，完全绕开 `evaluate()` / `EXPECT`**。
这确实排除了「顺带检出」的可能：如果只看 EXPECT 比对，动作变化就会误判；直接测 leaf 则必须**专用标记**才能通过。

**我用自己的 15 个用例（含它的 5 个）独立验证**，结果：

| # | 用例 | got | 判定 |
|---|---|---|---|
| 它的1 | `closed_ = true; return kClosed` | `('RET','kClosed')` | ✓ |
| 它的2 | `return kClosed`（无 flag） | `('RET','kClosed_WITHOUT_FLAG')` | ✓ |
| 它的3 | `closed_ = true; return kOk` | `('RET','kOk_WITH_CLOSED_FLAG')` | ✓ |
| 它的4 | `closed_ = true` + `pass`（两行） | `('RET','closed_flag_with_pass')` | ✓ |
| 它的5 | `pass`（无 flag） | `('FALLTHROUGH_OK',None)` | ✓ |
| M1 | `closed_=true` + `continue`（两行） | `('CONT_SKIP',None)` | 见 16.3 |
| M2 | `closed_ = TRUE`（大写） | `('RET','kClosed_WITHOUT_FLAG')` | 见 16.2.3 |
| M3 | `closed_ = 1`（非 true） | `('RET','kClosed_WITHOUT_FLAG')` | ✓（`1` 不算 true，合理） |
| M4 | `return kClosed  # x` | `('RET','kClosed')` | ✓（注释剥离正确） |
| M5 | 注释里写 `closed_ = true` | `('RET','kClosed_WITHOUT_FLAG')` | ✓（注释不算，正确） |
| M6 | `closed_ = true` / `return kClosed`（两行） | `('RET','kClosed')` | ✓ |
| M7 | `closed_=true; return kOk` + `return kClosed` | `('RET','kOk_WITH_CLOSED_FLAG')` | ✓（先命中矛盾，合理） |
| M8 | `closed_ = true` + `# pass` | `None` | ✓ |
| **M9** | **`closed_ = true; pass`（同一行）** | **`None`** | **✗ 真缺陷** |
| M10 | `closed_ = true`（无叶子） | `None` | ✓ |

**11/15 符合我的预期，M9 是真缺陷（详见 16.2.2），M1/M2/M7 是语义边界需讨论。**

#### 16.2.2 真缺陷（G8）：`pass` 检查用行首锚点，`return` 用语句分隔锚点，**同一行写法漏检**

`:207` 用 `re.search(r'^\s*pass\b', txt, re.M)` —— **`^` 锚定行首**。
而 `:203`/`:205` 的 `return` 用 `(?:^|;)` —— **支持 `;` 分隔的同行语句**。

**后果**（我实测）：
```
A  两行: closed_ = true / pass          → ('RET','closed_flag_with_pass')   ✓ 检出
B  同行: closed_ = true; pass           → None                              ✗ 未检出
C  同行+注释: closed_ = true; pass # x   → None                              ✗ 未检出
```
**A 与 B 语义完全相同**（都是「置了 flag 然后 pass」），但 **B 漏检**。
根因是**锚点不一致**：`return` 支持 `;` 分隔，`pass` 不支持。

**为什么这是真缺陷而不是理论问题**：伪代码 `:650` 就写着 `closed_ = true; return kClosed`（**同行 `;` 分隔**）。
**同一份文档里就在用 `;` 写多条语句**，所以 `closed_ = true; pass` 这种写法完全可能出现。
**而它恰好是漏检的那种。**

**修法（1 字符）**：`:207` 改成 `re.search(r'(?:^|;)\s*pass\b', txt, re.M)`。
**顺带**：`:218` 的 `continue` 也是 `^\s*continue`（行首锚点），同样问题：

**我全文扫了锚点（L1e），共 3 处不一致，不是 2 处**：
```
207: if has_close_flag and re.search(r'^\s*pass\b', txt, re.M):        ← 需改
213: m = re.search(r'(?:^|;)\s*return\s+(k\w+)', txt, re.M)            ← 正确
216: if re.search(r'(?:^|;)\s*return\b', txt, re.M):                    ← 正确
218: if re.search(r'^\s*continue\b', txt, re.M):                        ← 需改
220: if re.search(r'^\s*pass\b', txt, re.M):                            ← 需改（这是主判定，与 :207 同因）
249: if re.match(r'^\s*else\s*:\s*$', lines[j]):                        ← 行匹配，正确（不是语句分隔）
```
**`:220` 是 `_classify_leaf` 的主 `pass` 判定**（`:207` 只是"矛盾检查"的前置）。
**三处都要改**，否则 `x = 1; pass` 这种写法仍会被判成 `None`（无叶子 → 上层兜底成 `FALLTHROUGH_OK`，恰好"对"但理由错）。
**这是"错得恰好正确"——最危险的一类**：结论对，机制错，换个写法就崩。

```
D  同行: closed_ = true; continue   → None          （continue 完全没被识别）
E  两行: closed_ = true / continue  → ('CONT_SKIP',None)  （识别了，但没判矛盾）
```
**D 连 `continue` 都没认出来**，`_classify_leaf` 返回 `None`（「无叶子语句」）——
这会让 `interpret_segment` 走到 `FALLTHROUGH_OK` 兜底（`:230` `return (FALLTHROUGH_OK, None)`），
**把「continue」误判成「pass」**。**这是 G2（pass/continue 混淆）的变种，在同行写法下复发。**

#### 16.2.3 M2 大小写（低危，不设卡）

`closed_ = TRUE`（大写）→ 返回 `kClosed_WITHOUT_FLAG`（认为没置 flag）。
**严格说这是误报**（`TRUE` 也是真）。但 C++ 里 `true` 是小写关键字，**大写 `TRUE` 是宏（Windows 的 `TRUE`）**，
伪代码用 `true`。**建议不处理**（若真出现 `TRUE`，报错反而是好事——提示统一风格）。

#### 16.2.4 裁定

**`verify_sideeffect_leaf.py` 的方法论成立，「机制生效」这个证明是有效的。**
但它**只测了它自己想到的 5 种写法**，**没测「同行 `;` 分隔」这种本文档实际在用的写法**。
**这正好印证我第⑩步说的「红证用例数量 ≠ 覆盖的维度」——这次是「语句分隔形式」这个维度。**

### 16.3 Q3：`closed_ = true` + `continue` 该不该算矛盾？——**该算，但优先级低于 G8**

#### 16.3.1 当前文档是否有这种写法（你要求的实测）

我 grep 全文 `closed_` 且同行含 `continue`/`pass`：
```
（无输出 —— 当前文档不存在这种写法）
```
**确认：当前文档没有 `closed_=true` 后接 `continue`/`pass` 的写法。**
`closed_` 只出现在 `:650`（`closed_ = true; return kClosed`）和 `:588`（`if closed_:`）。

#### 16.3.2 该不该算矛盾？——**该算，你的分析正确**

理由（我补充一条你的没说到的）：
- 你说「`closed_=true` 表示对端已 close_notify，之后 continue 回循环顶继续解析后续记录 = 在已关闭连接上继续工作」。**成立。**
- **补充**：`continue` 会**消费**当前记录（`progressed += 1`），意味着**在关闭后继续推进状态机**。
  而 `kClosed` 的契约（`:523`）是「返回后调用方必须先取走明文再关闭」。**`continue` 跳过这个契约点**。

#### 16.3.3 但**现在加会有 3 个风险**，我建议先修 G8

1. **锚点问题会重演**：如果加 `if has_close_flag and re.search(r'^\s*continue\b', txt, re.M)`，
   **同行 `;` 写法仍然漏检**（与 G8 同因）。**必须先修锚点，再加判定。**
2. **会与 G8 的修复冲突**：G8 要把 `continue` 改成 `(?:^|;)`，若同时加矛盾判定，两处改动互相影响，**难以定位失败原因**。
3. **当前文档没有这种写法**，加了是「防未来」，**没有红证能证明它有效**（只能自造变异，属自证）。

**建议顺序**：
1. **先修 G8**（`:207` 和 `:218` 的锚点统一为 `(?:^|;)`），补红证 `closed_=true; pass`（同行）和 `closed_=true; continue`（同行）
2. **再加 `closed_flag_with_continue` 判定**，并补对应的红证
3. 两步分开，**每步都有独立的红证**，不会互相掩盖

**你说「我暂不实现」是对的**——但理由应该是「**先修锚点，否则加了也漏检**」，不是「当前文档没这种写法」。
**因为 G8 已经证明：同一份文档里就在用 `;` 写同行语句。**

### 16.4 Q4：怎么帮你防住「失实」？——**4 条可机械执行的规则，按性价比排序**

#### 16.4.1 你的根因分析是对的，但只覆盖了一半

你说：「`assert` 失败必须中断整条命令链，不能和后续命令串在一起」。
**这只防住了「异常被吞」**。但**三次失实有两种不同的机制**：

| 次 | 场景 | 机制 |
|---|---|---|
| 1（`:88`） | 写了替换代码，**没跑**就汇报 | **未执行** |
| 2（`kOk_WITH_CLOSED_FLAG`） | 替换 `assert` 失败，**被后续命令掩盖** | **异常被吞** |
| 3（`kOk_WITH_CLOSED_FLAG` 第二次） | 同上 | 同上 |

**规则 1 只能防第 2/3 种。第 1 种（写了没跑）需要另一条规则。**

#### 16.4.2 4 条规则（按性价比排序）

**规则 A（最高性价比）：汇报「已改」必须附「改后 grep 输出」，而不是「改的代码」。**

```
❌ 「已改为 re.match(r'^st\b', cond)」        ← 这是"我写了什么"
✅ 「grep 'st' in cond → 仅注释 1 处；grep 're.match(r'^st\b' → :91 命中」  ← 这是"文件现在是什么"
```
**理由**：前者可以被「我以为我改了」污染，后者是**文件的客观状态**。
**成本**：每条改动 +1 次 grep。**收益**：第 1 种失实归零。

**规则 B：每处替换后立即「双向断言」——旧串必须消失、新串必须存在。**

```python
s2 = s.replace(old, new, 1)
assert s2 != s, '旧串未找到（锚点失效）'
assert new in s2, '新串未写入'
assert old not in s2, '旧串仍存在（替换未生效）'
io.open(path,'w',...).write(s2)
# 写完后立刻读回
assert old not in io.open(path,...).read()
```
**理由**：你的 `assert old in s` 只检查「旧串在不在」，**没检查「替换后旧串是否消失」**。
**成本**：+4 行。**收益**：锚点失效立即暴露，不会静默。

**规则 C：所有验证脚本必须「单一入口、失败即 `SystemExit(1)`」，禁止用 `python -c` 串联。**

你说「那个 `-c` 脚本有引号解析错误，掩盖了前一个命令的失败」——
**根因不是引号，是「用 `-c` 串联多个操作」**。
**规则**：改文件 / 验证文件必须是**独立脚本文件**，一次只做一件事，退出码就是结论。
**PowerShell 侧**：用 `if ($LASTEXITCODE -ne 0) { exit 1 }` 逐条检查（`verify.ps1` 已经是这个模式，**可以照抄**）。

**规则 D（针对本轮）：每个"检查"必须配「等价写法」红证。**

G8 的教训：`closed_=true; pass`（两行）能检出，`closed_ = true; pass`（同行）不能。
**同一语义的两种写法，必须都测**。
**通用做法**：对每条正则，至少测 3 种写法——
1. 行首（`^\s*X`）
2. `;` 分隔（`; X`）
3. 跨行（前一行是另一条语句）

**理由**：正则的锚点是**最容易出错**的地方（本轮 G8 就是锚点），而锚点错误**只在特定写法下暴露**。

#### 16.4.3 一条额外建议：**「机制生效」必须用「绕开上层」的方式证明**

你这轮的 `verify_sideeffect_leaf.py` 做对了（直接调 `_classify_leaf`）。
**建议把这个模式固化为规则**：
> 任何「新增检查」的验收，必须有一个**直接调用检查函数**的测试，不经过 `evaluate`/`EXPECT`/`main`。

**理由**：经过上层时，**上层的变化会掩盖下层的失效**（Q4 的"顺带检出"就是这么来的）。

### 16.5 G7 复核：复跑输出已落盘，逐行一致

```
probe24.out.txt             14 行（去空行）
probe24.rerun-consult-b.txt 14 行（去空行）
CONTENT_IDENTICAL = True
差异：无
尾部：parent='s\r\n'  rerun='\n\r\n'（rerun 多一个尾部空行）
```
**双人独立复现有据可查。G7 关闭。**

### 16.6 门禁接入复核

`verify.ps1` 已加 4b（`:184-189`）：
```powershell
# 4b) side-effect leaf classification (closed_ flag consistency)
$side = Join-Path $root "evidence\tls\verify_sideeffect_leaf.py"
if (Test-Path $side) {
    & $py $side
    if ($LASTEXITCODE -ne 0) { Write-Error "side-effect leaf check failed"; exit 1 }
}
```

**发现一个小问题（G9）**：`:149` 的存在性预检列表是 `@($plint, $pred, $sem)`，**不含 `$side`**。
所以如果 `verify_sideeffect_leaf.py` **被删除**，`:186` 的 `Test-Path` 会静默跳过，**门禁仍然通过**。
**这与 `count_sec_refs.py`（`:193` 同样用 `Test-Path`）是同一个模式**——**新增的门禁可被"删文件"绕过**。

**建议**：把 `$side` 和 `$csr` 也加进 `:149` 的预检列表：
```powershell
foreach ($f in @($plint, $pred, $sem, $side, $csr)) {
    if (-not (Test-Path $f)) { Write-Error "missing $f"; exit 1 }
}
```
**注意**：`$side`/`$csr` 的定义在 `:185`/`:192`，**晚于 `:149`**，需要把定义上移。

**这是「门禁自身可被绕过」的问题**，比单个检查的假阴性更值得修——**因为它是静默的**。

### 16.7 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **`kOk_WITH_CLOSED_FLAG` 落地** | **通过**（grep :206 命中，实际代码确认） |
| **`closed_flag_with_pass` 落地** | **通过**（grep :208 命中） |
| **`verify_sideeffect_leaf.py` 方法论** | **通过**（绕开 EXPECT 直接调 leaf，思路正确） |
| **它的 5/5** | **通过**（我用 15 个用例独立验证，它的 5 个都对） |
| **`closed_=true; pass`（两行）** | **通过**（检出） |
| **`closed_=true; pass`（同行 `;`）** | **不通过（G8）**（`None`，漏检） |
| **`closed_=true; continue`（同行）** | **不通过（G8）**（`None`，连 continue 都没识别） |
| **24/24 变异** | **通过**（我实跑） |
| **八个 exit 码** | **通过**（全 0） |
| **G7 复跑落盘** | **通过**（14 行逐行一致） |
| **门禁文件缺失可绕过** | **不通过（G9）**（`$side`/`$csr` 不在预检列表） |

**放行条件（3 条）**：

1. **【阻断】修 G8：统一 `pass`/`continue` 的锚点为 `(?:^|;)`**（16.2.2）：
   `:207` `r'^\s*pass\b'` → `r'(?:^|;)\s*pass\b'`；
   `:218` `r'^\s*continue\b'` → `r'(?:^|;)\s*continue\b'`。
   **验收标准**（我实测过会漏的 3 个）：
   - `closed_ = true; pass`（同行）→ 必须 `('RET','closed_flag_with_pass')`
   - `closed_ = true; continue`（同行）→ 必须不是 `None`
   - `x = 1; continue`（同行，无 flag）→ 必须 `('CONT_SKIP',None)`
   **理由**：伪代码 `:650` 自己就在用 `closed_ = true; return kClosed`（同行 `;`），
   所以同行写法**不是假设，是本项目的实际风格**。

2. **【严重】修 G9：把 `$side`/`$csr` 加进门禁预检**（16.6）：
   当前删掉 `verify_sideeffect_leaf.py` 或 `count_sec_refs.py`，门禁**静默通过**。
   **验收标准**：临时重命名该文件 → `verify.ps1 -PseudoLint` 必须 `exit 1`（报 missing），而不是 skip。

3. **【一般】`closed_=true` + `continue` 的矛盾判定**（16.3）：
   **必须在 G8 修完之后再加**（否则同行写法仍然漏检，等于白加）。
   加 `closed_flag_with_continue` 判定 + 对应红证。

**随修（不设卡）**：
- M2 大小写 `TRUE` 的误报不处理（C++ 里 `true` 小写，`TRUE` 是 Windows 宏）。
- 采纳 16.4 的 4 条规则（尤其是**规则 A：汇报「已改」必须贴改后 grep**）。

### 16.8 我方自我更正

1. **我上轮说「`kOk_WITH_CLOSED_FLAG` 检查不存在」——本轮确认它现在存在了。**
   但你上轮的"已补"确实未落地，本轮才落地。**我的判断在当时是对的，本轮的复核也是对的**（两个时点状态不同）。

2. **我上轮把 `closed_=true; pass` 的检出能力判断为"覆盖了"，本轮发现只覆盖了「两行」写法。**
   **我自己的盲区**：我在第⑬步测 `closed_=true; pass` 时用的是**两行**（`[(672,"        closed_ = true; pass")]`——
   等等，那其实是**同行**。让我核实：我上轮的命令是 `[(672,"        closed_ = true; pass")]`，
   **是同行！而它 rc=0 未检出**。所以上轮我看到的"未检出"就是 G8，只是我归因为"真盲区"，
   **没有进一步追问"为什么同行不行"**。本轮追问才找到锚点根因。**这是"看到现象未追根因"的教训。**

3. **我上轮建议「补 `closed_flag_with_pass`」时，没有提醒"要注意同行 `;` 写法"。**
   如果我当时就想到，G8 不会留到本轮。**这说明「给出修法」时也要给出「验收用例的写法维度」。**

### 16.9 第⑭步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| L1a | 修 G8 后 3 个同行用例是否全部翻红 | — | 放行条件 1 的验收标准 |
| L1b | 修 G8 后 `verify_sideeffect_leaf.py` 的 5 个用例是否仍通过 | — | 回归，确保没改坏 |
| L1c | 修 G9 后重命名文件是否 exit 1 | — | 放行条件 2 的验收标准 |
| L1d | `closed_flag_with_continue` 加完后是否与 G8 修复冲突 | B | 建议分两步提交，各带红证 |
| L1e | 其他正则的锚点是否也有 `^` vs `(?:^|;)` 不一致 | B | 我建议全文扫一遍 `re.search(r'\^\\s\*'`，见 16.2.2 的通用做法 |

---

## §17. 第⑮步复验（G8 五处锚点 + G9 预检 + `closed_flag_with_continue`）

### 17.0 快照与七个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3`（mtime 02:33:10，本轮未变）。
> **脚本**：`verify_elif_semantics.py` **525 行 / 21923 B / `F26D7A4084B5B628`**（上轮 523 行）；
> `verify_sideeffect_leaf.py` **70 行 / 2876 B / `8EF9405A4F2EE0C3`**（上轮 46 行）；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；
> `count_sec_refs.py` 112 行 / `B35D3373`；`verify.ps1` **201 行 / 9295 B / `CE79FF80D7919E94`**（上轮 203 行）。

**七个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 10 状态 + 2 个 1.2 专项 + 24/24      exit=0
3b. verify_sideeffect_leaf.py           → G8 验收 14/14 ASSERT OK              exit=0
4.  pseudo_lint.py --regress (4 快照)   → REGRESS OK                           exit=0
5.  count_sec_refs.py --check           → OK: 文档断言(8,13)==口径B(8,13)      exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
+   verify.ps1 -PseudoLint              → pseudo lint passed                   exit=0
```

**G9 验收（我实测）**：
```
重命名 verify_sideeffect_leaf.py → verify.ps1 -PseudoLint → exit=1「missing ...」  ✓
恢复 → restored=True
```

### 17.1 Q1：`:203`/`:205` 你多加的两处对不对？——**对，而且你的「五处」比我的「三处」准确；但新锚点漏了「内联 if」写法**

#### 17.1.1 你多加的两处是对的，我的「三处」漏了

我说「三处需改」（`:207`/`:218`/`:220`），**我只扫了 `^\s*` 形式的锚点**，没扫「无锚点」形式。
`:203`/`:205` 的 `return\s+kClosed` / `return\s+kOk` **完全没有锚点**，等于全文任意位置匹配。

**你补的两处是对的**，而且理由充分：无锚点比 `^\s*` 更宽松，`xreturn kClosed` 也会命中。
**我实测确认新锚点修掉了这个假阳性**：
```
B2  xreturn kClosed  → None        （旧实现会误命中 kClosed_WITHOUT_FLAG）
```

**我全文重扫（含无锚点形式）**，现在语句级锚点全部统一：
```
203: (?:^|;)\s*return\s+kClosed   ✓
205: (?:^|;)\s*return\s+kOk       ✓
207: (?:^|;)\s*pass\b             ✓
209: (?:^|;)\s*continue\b         ✓
215: (?:^|;)\s*return\s+(k\w+)    ✓
218: (?:^|;)\s*return\b           ✓
220: (?:^|;)\s*continue\b         ✓
222: (?:^|;)\s*pass\b             ✓
251: ^\s*else\s*:\s*$             ← 行匹配，正确（不是语句分隔）
残留 ^\s* 计数：0
```
**放行条件 1 达成。**

#### 17.1.2 但新锚点漏了「内联 if」写法（G10，新发现）

`(?:^|;)` 覆盖「行首」和「`;` 分隔」，**但不覆盖 `if cond: <语句>` 的内联冒号形式**。我实测：
```
a  内联 if x: return kClosed（无 closed_）      → None      ✗ 应报 kClosed_WITHOUT_FLAG
b  内联 if x: closed_ = true; return kClosed   → ('RET','kClosed')  ✓（因为有 ; 分隔）
c  内联 if x: return kOk                       → None      ✗ 应报 ('RET','kOk')
d  内联 if x: pass                             → None      ✗ 应报 ('FALLTHROUGH_OK',None)
e  内联 if x: continue                         → None      ✗ 应报 ('CONT_SKIP',None)
f  原式 closed_=true; return kClosed           → ('RET','kClosed')  ✓
g  原式 return kClosed                         → ('RET','kClosed_WITHOUT_FLAG')  ✓
```

**性质判断**：
- **`a` 是安全隐患**：`if x: return kClosed` 会让 `_classify_leaf` 返回 `None`，
  上层 `interpret_segment` 兜底成 `FALLTHROUGH_OK`（`:230`）——
  **把「返回 kClosed」误判成「pass」**。这与 G2（pass/continue 混淆）同型，**只是换了触发写法**。
- **`c/d/e` 同理**：内联写法全部落到 `None` → 兜底 `FALLTHROUGH_OK`。

**这是否算阻断？——我判定「条件性风险」，不阻断。** 理由：
1. **当前文档的伪代码没有任何内联 `if x: <语句>` 写法**（我实测：`Receive` 主体的所有 `if` 都是块形式，`:627`–`:675` 全部是 `if cond:` 换行）。
2. `closed_ = true; return kClosed`（`:650`）**是 `;` 分隔，已被覆盖**。
3. **但它是「下一个 G8」**：一旦有人为了紧凑写成 `if st == OK: pass`（**这是极其自然的写法**），就会静默落到 `None`。

**建议（不设卡，但强烈建议做）**：把锚点从 `(?:^|;)` 扩成 `(?:^|;|:\s)` ——
**注意冒号必须跟空白**，否则会误匹配 `kOk` 里的冒号（实际没有）或类型标注。
更稳妥的做法是**先把伪代码按 `;` 和 `: ` 切成语句列表**，再逐条匹配（结构化，不用正则锚点）。
**最小改动**：`(?:^|;|:\s)\s*(?:pass|continue|return)\b`。

**我把它标为「条件性风险 G10」，理由是「当前文档无此写法」；但我不认为应该永久不修**——
因为**内联 `if` 是伪代码的常见写法**，这个坑迟早会踩。

### 17.2 Q2：`closed_flag_with_continue` 是否过严？——**不过严，判定正确；但我发现了「标签错配」这个更细的问题**

#### 17.2.1 判定正确：文档契约明确排除「先置 closed_ 再 continue」

你问「有没有合法场景是先置 `closed_` 再 `continue`（比如处理完最后一批数据后标记关闭，然后 continue 排空缓冲）」。

**我查了文档契约，答案是：没有合法场景。** 三条证据：

1. **`:501`**（入口状态表）：`closed_ == true` → `Receive` **返回 `kClosed`**
2. **`:523`**（调用契约）：`Receive` 返回 `kClosed` 时「**`plaintext` 可能非空**……调用方**必须先取走明文再关闭**。后续调用恒返回 `kClosed`」
3. **`:588-589`**（伪代码入口）：
```
if closed_:                                     # B3：正常终止（close_notify 之后）
    return kClosed                              #     必须恒返回 kClosed（§3.3 契约）
```

**关键在 `:523` 的「调用方必须先取走明文再关闭」**：
- 这条契约要求 **`Receive` 在置 `closed_` 的同一轮就把 `kClosed` 返回给调用方**
- 如果 `closed_ = true; continue`，则**本轮不返回**，继续循环
- **后果**：调用方拿不到 `kClosed` 信号，而 `closed_` 已经为真 → **下一轮入口（`:588`）会立刻返回 `kClosed`，
  但那一轮 `plaintext_out` 可能已经被 `continue` 之后的逻辑改写了** → **契约"先取走再关闭"被破坏**

**所以你的判断正确**：`closed_=true; continue` 是矛盾，不是合法场景。
**「排空缓冲」这个设想不成立**——因为 `plaintext_out` 是**本轮的输出**，不是跨轮缓冲；
排空缓冲由 `buffered_input()` / `rx_buffer_` 负责，与 `closed_` 无关。

#### 17.2.2 但发现「标签错配」（G11，新发现）

我测了两个多语句场景：
```
B4  closed_=true; return kClosed; continue  → ('RET','closed_flag_with_continue')
B5  closed_=true; continue; pass            → ('RET','closed_flag_with_pass')
```

**两者都是「按源码顺序第一个有效语句判定」，但标签指向的是「最后一个匹配到的」**：

| 输入 | 实际语义（按顺序） | 返回标签 | 问题 |
|---|---|---|---|
| B4 | `return kClosed`（`continue` 是**死代码**，永不执行） | `closed_flag_with_continue` | **标签说 continue，实际是 return** |
| B5 | `continue`（`pass` 是**死代码**，永不执行） | `closed_flag_with_pass` | **标签说 pass，实际是 continue** |

**根因**：`_classify_leaf` 的检查顺序是 `pass`（`:207`）→ `continue`（`:209`）→ `return`（`:203`/`:205`），
**不是源码顺序**。所以多个语句共存时，**返回的标签反映的是「检查顺序」而不是「执行顺序」**。

**这影响什么？**
- **不影响「是否检出矛盾」**——B4/B5 都被判为矛盾（非 `kClosed`/非正常），**行为是对的**。
- **影响「诊断信息准确性」**——报告说 `closed_flag_with_pass`，但实际问题是 `continue`。
  维护者按提示去查 `pass`，会找不到。

**严重性：低。** 因为：
1. 这些是**死代码组合**（`return` 之后的 `continue`、`continue` 之后的 `pass` 都不会执行），
   真实代码不会写。
2. **矛盾判定本身正确**（都报了）。

**建议（不设卡）**：标签改成**中性描述**，如 `('RET','closed_flag_with_sideeffect')`，
或在标签里带上实际命中的语句（`closed_flag_with_continue_and_return`）。
**更根本的做法**：按源码位置排序后取**第一个**有效语句，而不是按检查顺序。

### 17.3 Q3：G9 的修复是否完整？——**主修完成，但仍有 2 条静默跳过路径，其中 1 条是实质漏洞**

#### 17.3.1 主修确认有效

`verify.ps1:149-155`：
```powershell
$side  = Join-Path $root "evidence\tls\verify_sideeffect_leaf.py"
$csr   = Join-Path $root "evidence\tls\count_sec_refs.py"
foreach ($f in @($plint, $pred, $sem, $side, $csr)) {
    if (-not (Test-Path $f)) { Write-Error "missing $f"; exit 1 }
}
```
且 4b/5 的 `if (Test-Path ...)` 包裹已删除（`:189`/`:193` 直接调用）。
**我实测删文件 → exit=1。主修有效。**

#### 17.3.2 仍存在的静默跳过（我实测）

**路径 1（实质漏洞）：4 个历史快照全缺失 → `[skip]` 且 exit=0**

`:181-186`：
```powershell
if ($snapArgs.Count -gt 0) {
    & $py $plint --regress @snapArgs --current ...
    if ($LASTEXITCODE -ne 0) { Write-Error "..."; exit 1 }
} else {
    Write-Host "  [skip] no historical snapshots under .tmp"
}
```

**我实测**：把 4 个快照全部移走 →
```
[skip] no historical snapshots under .tmp
pseudo lint passed
exit=0
```
**这是 G9 的同类：删掉 `.tmp\design-a.*.md` 就能让第 4 道门禁（回归）完全失效，且静默。**
**而且这 4 个文件在 `.tmp`（临时目录），比 `evidence` 更容易被清理工具删掉。**

**建议**：`else` 分支改成 `Write-Error "no historical snapshots under .tmp"; exit 1`。
**理由**：回归门禁的价值就在于「历史快照必须被检出」；没有快照 = 没有回归 = 门禁形同虚设。
**如果确实需要允许"无快照"**（比如干净克隆），应该用**显式开关**（`-AllowNoSnapshots`），而不是静默。

**路径 2（可接受）：`python` 未安装 → `[skip]`**

`:142-143`：
```powershell
if (-not $py) {
    Write-Host "  [skip] python not found: pseudo lint skipped"
}
```
**这个 skip 是合理的**（不是所有环境都有 python，且这是环境缺失不是文件缺失）。
**但建议**：如果 CI 环境要求门禁，应该改成 `Write-Error`。
**当前不设卡**——因为它明确打印了 `[skip]`，不是静默。

**对比**：路径 1 和路径 2 都打印 `[skip]`，都 exit=0。
**区别在于「缺快照」是本项目自己该保证的，「缺 python」是环境问题。** 前者应该 fail。

### 17.4 Q4：4 条防失实规则执行得如何？——**规则本身执行良好，但 4 个 fix 脚本已不存在，无法复核**

#### 17.4.1 先说事实：4 个 fix 脚本在我复核时已被删除

我第一次 `Get-ChildItem` 时它们还在：
```
fix_g8.py       1770 B  2026/10/23 2:43:48
fix_g9.py       2830 B  2026/10/23 2:45:37
fix_q3cont.py   1115 B  2026/10/23 2:47:46
fix_side2.py    1548 B  2026/10/23 2:48:12
```
**几分钟后我再读，全部不存在**（`.tmp` 下 `fix_*` 0 命中，全仓 `fix_g*` 0 命中）。

**这直接影响 Q4 的回答**：你要求「检查本轮的 4 个 fix 脚本，是否每条规则都真的落地了」。
**我无法检查——它们已经不在磁盘上了。**

**这可能有两种原因**：
1. 你（或某个流程）在汇报后清理了临时脚本
2. 有清理工具在跑

**无论哪种，这暴露了规则 B 的一个盲区**：
> **规则 B 要求「读回断言」，但断言发生在脚本运行时。脚本一旦删除，断言过程就不可复核。**

**建议（这是对 4 条规则的补充，规则 E）**：
> **fix 脚本的「验证输出」必须落盘**（不是脚本本身，而是它打印的断言结果），
> 且落盘位置在 `evidence/`（不是 `.tmp/`），文件名带轮次（如 `fix-g8.step15.log`）。
> **理由**：脚本是过程，日志是证据。过程可以删，证据不能。

**当前事实**：我只能**从最终状态反推**规则是否落地（见 17.4.2），**无法验证过程**。

#### 17.4.2 从最终状态反推：规则 A/B 确实生效了

虽然脚本没了，但**最终状态**证明它们执行过：

**规则 A（汇报附改后 grep）**：你在 §G8 贴的是「读回文件后的断言结果」：
```
残留 ^\s*pass : 0
r'(?:^|;)\s*pass            : True
r'(?:^|;)\s*continue        : True
r'(?:^|;)\s*return\s+kClosed: True
r'(?:^|;)\s*return\s+kOk    : True
```
**我独立复现了这些**（17.1.1 的锚点扫描，`残留 ^\s* 计数: 0`）。**规则 A 生效。**

**规则 B（双向断言）**：最终文件里 5 处锚点全部是 `(?:^|;)`，且 `xreturn kClosed` 不再误命中（B2 → `None`）。
**如果只做了单向断言（`assert old in s`），`xreturn` 的假阳性不会被发现**——因为旧模式（无锚点）本来就能匹配。
**新锚点生效 = 双向断言执行过。规则 B 生效。**

**规则 C（禁 `python -c` 串联）**：4 个独立脚本文件的存在（fix_g8/g9/q3cont/side2）证明按规则做了。
**规则 C 生效（但脚本已被删，见 17.4.1）。**

**规则 D（等价写法红证）**：`verify_sideeffect_leaf.py` 现在有 14 个用例，覆盖：
```
两行（R1/R2/R3）
同行 ;（A1/A2/A3/R4）
同行+注释（C1）
无 flag 对照（O1/O3/O4）
```
**三种写法全覆盖。规则 D 生效。**

**额外规则（绕开上层直接调 leaf）**：`verify_sideeffect_leaf.py` 就是直接调 `_classify_leaf`。**生效。**

#### 17.4.3 但规则 D 还没做到「穷尽写法维度」——G10 就是证明

14 个用例覆盖了「两行 / 同行 `;` / 同行+注释」，**但没覆盖「内联 `if x: <语句>`」**（G10，见 17.1.2）。
**这不是规则 D 没执行，是规则 D 的「写法维度」还不完整。**

**建议把维度固化为清单**（每条正则至少测这 5 种）：
1. 行首：`X`
2. `;` 分隔：`a = 1; X`
3. 同行 + 注释：`X  # c`
4. **内联 if：`if c: X`**  ← G10 缺的就是这个
5. 跨行（前一行是另一语句）：`a = 1\nX`

### 17.5 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **G8 五处锚点统一** | **通过**（`残留 ^\s* = 0`，8 处语句级锚点全部 `(?:^|;)`） |
| **G8 你多加的 `:203`/`:205`** | **通过**（比我的「三处」准确；`xreturn kClosed` 假阳性已消除） |
| **G8 验收 14/14** | **通过**（我实跑 14/14；另用 19 个用例独立验证） |
| **G9 预检含 `$side`/`$csr`** | **通过**（实测删文件 → exit=1） |
| **`closed_flag_with_continue`** | **通过**（判定正确，文档 `:501`/`:523`/`:588` 三条证据支持） |
| **规则 A/B/C/D 执行** | **通过（从最终状态反推）**；但过程不可复核（fix 脚本已删） |
| **七个 exit 码** | **通过**（全 0） |
| **内联 `if x: <语句>` 写法** | **不通过（G10）**（5 个用例全部 `None`） |
| **4 个历史快照全缺失时静默跳过** | **不通过（G9 残留）**（实测 exit=0 + `[skip]`） |
| **标签错配** | **不通过（G11，低危）**（B4/B5 标签指向错误语句） |

**放行条件（2 条）**：

1. **【严重】修 G9 残留：快照全缺失必须 fail**（17.3.2）：
   `:184-186` 的 `else { Write-Host "[skip] ..." }` → `else { Write-Error "no historical snapshots under .tmp"; exit 1 }`。
   **验收标准**：移走 4 个快照 → `verify.ps1 -PseudoLint` 必须 `exit 1`，不得 `[skip]` + `exit 0`。
   **理由**：这 4 个文件在 `.tmp`（临时目录），比 `evidence` 更易被清理；
   **回归门禁的全部价值就是「历史缺陷必须被检出」，没有快照 = 门禁形同虚设**。
   若确需允许无快照（干净克隆），用显式开关 `-AllowNoSnapshots`，不要静默。

2. **【条件性】修 G10：锚点扩到内联 `if x: <语句>`**（17.1.2）：
   `(?:^|;)` → `(?:^|;|:\s)`，或改为「先按 `;`/`: ` 切语句，再逐条匹配」（结构化，更稳）。
   **我标为条件性**（当前文档无此写法），但**强烈建议做**：
   `if st == OK: pass` 是**极其自然的伪代码写法**，一旦有人这么写就静默落到 `None` → 兜底成 `FALLTHROUGH_OK`。
   **验收标准**：`if x: return kClosed` → `kClosed_WITHOUT_FLAG`；`if x: pass` → `FALLTHROUGH_OK`；`if x: continue` → `CONT_SKIP`。

**随修（不设卡）**：
- **G11 标签错配**：B4/B5 的标签反映检查顺序而非源码顺序，建议改成中性标签或按源码位置取第一个。
- **规则 E（新增）**：fix 脚本的验证输出必须落盘到 `evidence/`（带轮次），不能只留在 `.tmp` 且脚本删除后无据可查。
- **规则 D 维度补全**：每条正则至少测 5 种写法（行首 / `;` / 同行+注释 / **内联 if** / 跨行）。

### 17.6 我方自我更正

1. **我说「三处需改」，你说是五处——你对，我漏了「无锚点」这种形式。**
   我只扫了 `^\s*` 模式，没意识到 `return\s+kClosed`（完全无锚点）比 `^\s*` 更宽松。
   **教训：扫锚点不能只扫「有锚点的」，还要扫「该有锚点却没有的」。**

2. **我在第⑭步说「三处」时用了「全文扫了锚点」的措辞，但实际只扫了含 `^` 的行。**
   这是**不严谨的证据声明**——我说"全文扫"但方法是"过滤含 `^\s*` 的行"，
   等于**只扫了我预期要扫的**。**这是"确认偏误"的典型形态**，记录在此。

3. **我上轮没发现 G10（内联 if）**，因为我验证时用的都是「行首」和「`;` 分隔」两种写法。
   **这与我批评你的「规则 D 维度不完整」是同一个问题——我自己的验证维度也不完整。**

### 17.7 第⑮步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| M1a | 快照缺失改 fail 后，正常有快照时是否仍 exit=0 | — | 放行条件 1 的回归 |
| M1b | G10 修完后 5 个内联用例是否全部正确 | — | 放行条件 2 的验收 |
| M1c | G10 修完后 14 个现有用例是否仍全过 | — | 防止改坏 |
| M1d | `(?:^|;|:\s)` 是否会误匹配其他场景（如 `kOk:` 或类型标注） | B | 需要实测；建议改用结构化切分而非正则 |
| M1e | 伪代码里是否真的没有内联 `if x: <语句>` | C | **已实测**：被解析的伪代码块（`:586` 起 117 行）只有 2 处 `if closed_:` / `if terminal_:`，**都是换行块形式，无内联语句**。全文另有 15 处内联（`:1298` PowerShell、`:1770-1776`/`:1789-1795` 语义翻译表），**均不在被解析的伪代码块内**。**G10 当前不触发，但翻译表里已经在用内联写法——说明这个风格在本项目存在。** |
| M1f | 4 个 fix 脚本是谁删的、能否恢复 | C | 影响规则 B 的可复核性；建议以后验证输出落盘到 evidence |

---

## §18. 第⑯步复验（G9 残留 + G10 内联 if + 规则 E 落盘）

### 18.0 快照与九个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3`（mtime 02:33:10，本轮未变）。
> **脚本**：`verify_elif_semantics.py` **525 行 / 21955 B / `CF7C15E280C2059D`**；
> `verify_sideeffect_leaf.py` **84 行 / 3616 B / `5A162E634C7A19F8`**（上轮 70 行）；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；
> `count_sec_refs.py` 112 行 / `B35D3373`；`verify.ps1` **210 行 / 9913 B / `67E2D1580D99B0FA`**（上轮 201 行）。
> **新增证据**：`evidence\tls\fix-step15.log` 16 行 / 605 B / `0CEC09B938387660`。

**九个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 10 状态 + 2 个 1.2 专项 + 24/24      exit=0
3b. verify_sideeffect_leaf.py           → G8 验收 20/20 ASSERT OK              exit=0
4.  pseudo_lint.py --regress (4 快照)   → REGRESS OK                           exit=0
5.  count_sec_refs.py --check           → OK: 文档断言(8,13)==口径B(8,13)      exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7.  verify.ps1 -PseudoLint              → pseudo lint passed                   exit=0
8.  快照全缺失                          → exit=1「regression gate cannot run」  exit=1（期望）
9.  删门禁文件（verify_sideeffect_leaf） → exit=1「missing ...」                exit=1（期望）
```

**三个场景实测（G9 残留）**：
```
场景1 快照齐全          exit=0  ✓
场景2 快照全缺失        exit=1  msg=regression gate cannot run  ✓
场景3 缺失 + -AllowNoSnapshots  exit=0  msg=explicit -AllowNoSnapshots  ✓
restored=4/4
```

### 18.1 Q1：`-AllowNoSnapshots` 会不会成为新的绕过路径？——**会，但风险可控；建议加「使用留痕」**

#### 18.1.1 主修确认有效

`:185-195` 三路分支正确：有快照 → 正常跑；无快照 + 开关 → `[skip]` + exit=0；无快照无开关 → **exit=1**。
**我实测三个场景全部符合预期。G9 残留关闭。**

#### 18.1.2 风险分析：开关确实是绕过路径

**你的担心成立**。我核实了「谁能用它」：
```
全仓搜 AllowNoSnapshots：
  verify.ps1:9            ← 帮助文本
  verify.ps1:20-21        ← param 定义
  verify.ps1:188-189,193  ← 分支
  .tmp\s17.md:191         ← 我的审计草稿
  docs\spec\tls-backend.consult-b.md:3959  ← 我的 §17
无任何 CI/脚本/文档固化调用它
```
**当前没有绕过路径**（没人永久带着它跑）。**但这是「当前事实」，不是「机制保证」。**

**风险等级：中。** 理由：
1. **它是显式开关**（必须手打 `-AllowNoSnapshots`），**不是默认行为** —— 这已经比静默 skip 好得多
2. **它会在输出里打印 `[skip] no historical snapshots (explicit -AllowNoSnapshots)`** —— **有痕迹**
3. **但痕迹只在 stdout，不落盘** —— 日志被丢弃后就无从追溯

#### 18.1.3 建议：三个层次的防护（按性价比）

**方案 A（最低成本，建议做）：让 skip 在输出里"更刺眼"**
```powershell
Write-Warning "REGRESSION GATE SKIPPED via -AllowNoSnapshots (no historical snapshots). This run does NOT verify historical defects."
```
`Write-Warning` 在 PowerShell 里是黄色，且**不会被普通日志过滤掉**（vs `Write-Host` 可被 `-InformationAction` 抑制）。
**成本 1 行，收益：CI 日志里一眼可见。**

**方案 B（中等成本）：记录使用次数到证据文件**
```powershell
$skipLog = Join-Path $root "evidence\tls\regression-skipped.log"
Add-Content -Path $skipLog -Value "$(Get-Date -Format o) AllowNoSnapshots used"
```
**收益**：可以事后审计「这个开关被用了多少次」。**成本 2 行。**

**方案 C（最高成本，最可靠）：禁止在 CI 使用**
在 CI 配置里**显式检查**：如果日志里出现 `AllowNoSnapshots`，则 CI 失败。
**收益**：彻底封堵。**成本：需要 CI 配置，当前仓库没有 CI 文件（我核实：无 `.github/workflows` / `*.yml` 调用 verify.ps1）。**

**我的裁定：建议做 A，可选做 B，C 等有 CI 再说。**
**理由**：A 成本 1 行、收益明确（日志可见）；B 是审计能力，但当前**没有 CI**，使用频率极低，收益有限。

#### 18.1.4 一个更根本的问题

**这个开关的存在本身就是妥协**。更好的设计是：
> **快照缺失时，自动从 git 恢复**（如果 `.tmp` 被清理）或**把快照纳入版本控制**（不放 `.tmp`）。

**因为**：这 4 个快照是**回归门禁的唯一输入**，把它们放在 `.tmp`（临时目录）本身就是设计缺陷。
**建议（长期）**：把 4 个快照移到 `evidence\tls\snapshots\`（纳入版本控制），
`.tmp` 只作为临时工作区。**这样 `-AllowNoSnapshots` 就可以删掉了。**

**这是「消除绕过路径」比「防护绕过路径」更彻底的做法。** 我建议优先考虑。

### 18.2 Q2：`(?:^|;|:\s)` 是否有误匹配？——**有，4 类新误匹配；但当前伪代码块不触发**

#### 18.2.1 精确对比实测（旧锚点 vs 新锚点）

我逐条对比了 `(?:^|;)` 和 `(?:^|;|:\s)` 的匹配结果：

| # | 用例 | 旧 | 新 | 变化 |
|---|---|---|---|---|
| 1 | 行首 `return kOk` | True | True | — |
| 2 | `a = 1; return kOk` | True | True | — |
| 3 | **内联 `if x: return kOk`** | False | **True** | ✓ **G10 修复** |
| 4 | **`case x: return kOk`** | False | **True** | ✗ **新误匹配** |
| 5 | **三元 `x = a ? b : return kOk`** | False | **True** | ✗ **新误匹配** |
| 6 | **初始化 `cfg = {a: pass}`** | False | **True** | ✗ **新误匹配** |
| 7 | **标签 `lbl: pass`** | False | **True** | ✗ **新误匹配** |
| 8 | **类型标注 `int x: return kOk`** | False | **True** | ✗ **新误匹配** |
| 9 | 真实三元 `return (p\|\|q) ? kOk : kNeed` | True | True | —（行首 return 先命中） |
| 10 | `map[a:b]`（无空白） | False | False | —（`:\s` 要求空白） |
| 11 | `http://x`（无空白） | False | False | —（同上） |
| 12 | 真实 `closed_ = true; return kClosed` | True | True | — |

**你要求的 3 个误匹配场景（`map[a:b]`、`http://x`、`::`）全部安全**——因为 `:\s` 要求冒号后有空白，
`a:b` / `://` / `::` 都不满足。
**但你没问到的 5 类（case/label/三元/初始化/类型标注）全部会误匹配。**

#### 18.2.2 这些误匹配的实际危害：**当前不触发**

**我扫了被解析的伪代码块**（`:586` 起 117 行）：
```
case          命中 0
label x:      命中 0
初始化 {a:    命中 0
三元 ?:       命中 2    ← :600 / :607
```
**三元那 2 处不受影响**：`:600` / `:607` 是 `return (progressed || produced) ? kOk : kNeedMoreInput`，
**行首 `return` 先命中**（用例 9：旧 True → 新 True，无变化）。
**`_classify_leaf` 对它们返回 `('RET','<unknown>')`**（因为 `? kOk :` 后面接的不是单纯 `k\w+`，正则 `return\s+(k\w+)` 不匹配）——
**这个行为在旧锚点下也一样**，不是新引入的。

**所以：G10 修复没有引入任何实际误报。** 当前文档 8 条链 + 2 条内层的解析结果与上轮完全一致。

#### 18.2.3 但这是「当前不触发」，不是「不会触发」

**风险**：一旦有人在伪代码里写：
- `switch` 风格的 `case ST_OK: return kOk;`
- 标签 `retry: continue`
- 初始化列表 `Options opts = {mode: pass}`
- C++ 类型标注

**就会误匹配。** 而这些在 C++ 代码里**极其常见**（尤其 `case`）。

**我的裁定：接受当前实现（G10 修复的收益 > 误匹配的风险），但建议加一道防线。**

**建议（低成本）**：在 `_classify_leaf` 的 docstring 里明确写：
> **本函数假定输入是「伪代码语句序列」，不是完整 C++。**
> 不支持 `case x:` / 标签 `lbl:` / 初始化列表 `{a: b}` / 三元 `?:` 作为语句分隔符。
> 若伪代码引入这些写法，必须改为结构化解析（按 AST 或显式语句切分）。

**理由**：把「适用范围」写清楚，比「用正则试图覆盖所有情况」更可靠。
**结构化切分是更彻底的方案**，但**当前收益不足以证明重构成本**（8 处正则 → 1 个切分器，会影响 24 个用例）。

**所以：我认可你的「改动小」取舍，但建议把适用边界写进文档。**

### 18.3 Q3：G11 该不该修？——**你的 4 条理由成立，我同意不修；但第 3 条理由需要修正**

#### 18.3.1 逐条核对你的 4 条理由

| 你的理由 | 我的判断 |
|---|---|
| 1. 我判定「严重性低（都是死代码组合）」 | **成立**。我实测 B4/B5/B6 都是「前一条语句已终止，后一条不可达」 |
| 2. 修法两条都有代价（中性标签损失诊断信息 / 按源码位置取第一个增加复杂度） | **成立** |
| 3. **当前无真实场景，且改动会影响 20 个已通过用例的期望值** | **部分不成立**：改标签只影响 **2 个**用例（B4/B5 的期望），不是 20 个。20 个里其余 18 个的标签不变 |
| 4. 这是「诊断信息准确性」问题，不是「检出正确性」问题——行为是对的 | **成立**，这是最关键的理由 |

**第 3 条需要修正**：改标签的回归面是 **2 个用例**（B4/B5），不是 20 个。
**但这不改变结论**——因为**第 4 条理由足够强**：检出正确性没受影响，只是标签措辞。

#### 18.3.2 我的裁定：**同意不修**

**理由（补充一条你没说的）**：
**B4/B5 这类输入本身是「无效伪代码」**——`return` 之后的 `continue`、`continue` 之后的 `pass` 永远不会执行。
**如果真在文档里出现，问题不是「标签错」，而是「伪代码写错了」。**
**此时报任何标签都只是提示，真正需要的是「死代码检测」**（那是另一个检查器的事，不是 `_classify_leaf` 的职责）。

**所以：不修是对的。但建议在 docstring 里加一句**：
> 输入含死代码（`return` 后的语句）时，返回的标签反映**检查顺序**而非源码顺序。

**这样既不改行为，又消除了「标签误导」的隐患。**

#### 18.3.3 顺带确认：B6 是新发现的第三个组合

我测了 `closed_=true; pass; continue` → `('RET','closed_flag_with_pass')`。
**`pass` 是死代码（`continue` 会跳过它），但标签说 pass。** 与 B4/B5 同型。
**不影响结论**（同属无效伪代码）。

### 18.4 Q4：规则 E 的落盘方式够不够？——**够，但「脚本源码」的定性需要明确：它是过程，不是证据**

#### 18.4.1 你落盘的内容（我核实）

`evidence\tls\fix-step15.log`（16 行 / 605 B / `0CEC09B9`）：
```
--- step15 fixes: G9-residual (snapshot fail) + G10 (inline if anchors) ---
--- verify.ps1: AllowNoSnapshots switch + fail on missing snapshots ---
AllowNoSnapshots param : True
fail on missing snaps  : True
non-ASCII lines: none
--- G9 residual acceptance (3 scenarios) ---
[PASS] scenario1 snapshots present   exit=0
[PASS] scenario2 snapshots missing   exit=1  msg=regression gate cannot run
[PASS] scenario3 missing + override  exit=0  msg=explicit -AllowNoSnapshots
--- G10 anchors: (?:^|;|:\s) x 8, residual (?:^|;) = 0 ---
G10 acceptance: 6 inline cases + 14 existing = 20/20
```
**内容质量：好。** 含「改了什么 + 验收结果 + 计数」，**正是规则 A/B 要求的形式**。
**我独立复现了其中 3 项**：锚点 8 处、`residual (?:^|;) = 0`、20/20。**全部一致。**

#### 18.4.2 你问「脚本源码算过程还是证据」——**算过程，但「产生证据的过程」需要可复核**

**我的定性**：

| 对象 | 定性 | 该不该留 |
|---|---|---|
| **fix 脚本源码** | **过程**（一次性工具） | **不必长期保留**，但**应当在执行时留下「它做了什么」的可验证痕迹** |
| **fix 脚本的输出日志** | **证据**（证明修复生效） | **必须保留** |
| **fix 脚本的输入**（改前的文件状态） | **证据**（证明改了什么） | **应当保留**（至少记录「改前是什么」） |

**为什么脚本源码不算证据**：
- 证据的定义是「**能证明某个事实的独立材料**」。脚本源码证明的是「我打算怎么改」，**不证明「改成了」**。
- **真正证明「改成了」的**是：①改后的文件内容 ②执行后的验收输出 ③（可选）改前的 diff。

**但有一个例外**：**如果脚本包含「非平凡的逻辑」（比如复杂的 AST 变换），源码本身就是理解「改了什么」的唯一途径**。
**你这轮的 fix 脚本都是简单 replace**（`old → new`），**日志里的「before/after 计数」已经足够复现**。

#### 18.4.3 建议：**保留「diff」而不是「脚本」**

**当前 `fix-step15.log` 缺一项**：**改前的状态**。
它写了「`(?:^|;|:\s) x 8, residual (?:^|;) = 0`」（改后），但**没写改前是什么**。

**建议补**（下次开始）：
```
--- before ---
(?:^|;) occurrences: 8      (all 8 anchors)
residual ^\s*: 0
--- after ---
(?:^|;|:\s) occurrences: 8
residual (?:^|;): 0
```
**理由**：只说「改后有 8 个」无法证明「改前也是 8 个」（可能改前是 6 个，改了 6 个，另外 2 个本来就是别的形式）。
**「before + after」才是完整证据链。**

**关于保留多久**：**随仓库走**（与 `evidence/` 其他文件同生命周期）。**不需要单独清理策略**——
因为它是**证据**，与 `probe24.out.txt` 等同级。

**关于保存到哪**：**你已经做对了**（`evidence\tls\fix-step15.log`）。
**建议命名统一**：`fix-stepNN.log`（你用的就是），便于按轮次排序。

### 18.5 规则 E 的 memory 落地核实

你声称已把规则 E 和 5 维度写入 `memory.md`。我核实（`F:\rtsc\.opencode\memory.md`，21345 B）：

```
  86 | if old not in L[idx]: raise SystemExit(1)      # 锚点失效立即停
  98 | 4. **每个正则/锚点必须配「等价写法」验证**
 101 | **锚点是正则最容易出错的地方，只在特定写法下暴露**
 112 | ## 关于锚点与证据的补充规则（2026-10-23 第 15-16 步新增）
 114 | 7. **扫锚点缺陷时必须同时扫「有锚点的」和「该有锚点却没有的」**
 115 | 实例：`return\s+kClosed`（完全无锚点）= 全文任意位置匹配，比 `^\s*` 更宽松
 119 | （来自 consult-b 自查发现：「说全文扫了锚点」实际方法是「过滤含 `^\s*` 的行」）
 121 | 正确做法：先按 `^\s*` 模式列出扫描 N 行，再按无锚点模式扫出 M 行。
 123 | 9. **正则锚点必须覆盖 5 种写法**
 125 | 含**内联 `if c: X`** 等场景。少补任何一种，就有一类写法静默漏检。
 128 | 10. **验证脚本的断言过程必须留为证据，脚本本身可以删**
 130 | 建议：日志含「改前/改后」+ 修改前后计数，写入 `evidence/<topic>/fix-stepNN.log`
```

**规则 E（第 10 条）和 5 维度（第 9 条）都已落地。** 而且第 7 条把我自己的确认偏误也记进去了——**这是正确的做法**（记录方法论的失败，比记录结论更有价值）。

### 18.6 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **G9 残留（快照缺失 fail）** | **通过**（三场景实测全符合） |
| **`-AllowNoSnapshots` 显式开关** | **通过**（默认不生效，有 `[skip]` 痕迹） |
| **G10（内联 if）** | **通过**（8 处锚点，20/20 用例，我实测 Y1-Y5 全正确） |
| **G10 的 `:\s` 误匹配** | **通过（有保留）**：引入 5 类新误匹配，但当前伪代码块 case/label/初始化均 0 命中，三元 2 处不受影响 |
| **规则 E 落盘** | **通过**（`fix-step15.log`，我独立复现 3 项一致） |
| **规则 E 写入 memory** | **通过**（第 9/10 条已落地，含我的确认偏误） |
| **G11 不修** | **通过**（你的理由成立；第 3 条需修正为「影响 2 个用例」非 20 个） |
| **九个 exit 码** | **通过**（7 个 exit=0 + 2 个预期 exit=1） |
| **`fix-step15.log` 含改前状态** | **不通过（低危）**（只有改后计数，无改前） |
| **快照放在 `.tmp`** | **设计缺陷（未修）**（回归门禁的唯一输入放在临时目录） |

**放行条件（2 条）**：

1. **【严重】把 4 个历史快照移出 `.tmp`，纳入版本控制**（18.1.4）：
   当前它们放在 `F:\rtsc\.tmp\` —— **临时目录，任何清理工具都会删掉**。
   一旦被删，回归门禁失效（现在会 fail，但**门禁本身也就跑不了了**）。
   **建议移到 `evidence\tls\snapshots\`**，`.tmp` 只作临时工作区。
   **验收标准**：`verify.ps1 -PseudoLint` 从 `evidence\tls\snapshots\` 读取，且**删掉 `-AllowNoSnapshots` 开关**（不再需要）。
   **理由**：这是**消除绕过路径**而非防护绕过路径——比加日志/加警告更彻底。
   **注**：如果你认为 `.tmp` 是刻意的（快照是"本地工作副本"），请说明理由，我可以撤回。

2. **【一般】`fix-stepNN.log` 补「改前」状态**（18.4.3）：
   当前只有改后计数（`(?:^|;|:\s) x 8`），没有改前。
   **只说「改后有 8 个」无法证明「改前也是 8 个」**（可能改前 6 个 + 2 个本来就是别的形式）。
   **验收标准**：日志含 `--- before ---` / `--- after ---` 两段，各带计数。

**随修（不设卡）**：
- `-AllowNoSnapshots` 的 `[skip]` 改成 `Write-Warning`（黄色，日志可见）。
- `_classify_leaf` 的 docstring 写明「假定伪代码语句序列，不支持 case/label/初始化列表/三元作为分隔符」。
- `_classify_leaf` 的 docstring 写明「输入含死代码时，标签反映检查顺序而非源码顺序」（G11 的文档化，替代修复）。

### 18.7 我方自我更正

1. **我上轮说「4 个快照在 `.tmp` 比 evidence 更易被清理」——你据此加了 fail，但没解决根因。**
   **我上轮只说了「风险」，没说「应该移走」。** 本轮我明确建议移走——
   **因为 fail 只是「让问题暴露」，移走才是「消除问题」。**
   **我上轮的表述不够彻底，导致你只做了防护（fail）没做根治（移走）。**

2. **我上轮说「`(?:^|;)` 漏了内联 if」，但没提醒「扩到 `:\s` 会引入新的误匹配」。**
   **我在给修法时只考虑了「覆盖更多」，没考虑「覆盖过多」。** 本轮实测出 5 类新误匹配。
   **教训：扩展匹配范围时，必须同时测「原本不匹配的、现在匹配了」的那些输入**（即反向验证）。
   **这条应补进 memory 的第 9 条**（5 维度清单旁边加一句「扩展时必测反向」）。

3. **我上轮把「三处」说成「全文扫了锚点」是确认偏误——本轮我改用「先列全部 8 处，再逐处判断」的方法**，
   并且这次**明确写出了扫描命令和命中数**（`含 (?:^|;|:\s) 数量: 8`），不再用「全文扫了」这种模糊表述。

### 18.8 第⑯步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| N1a | 快照移到 `evidence\tls\snapshots\` 后，`verify.ps1` 是否正常读取 | — | 放行条件 1 的验收 |
| N1b | 移走后删除 `-AllowNoSnapshots` 是否影响其他调用 | B | 需确认无 CI/脚本依赖该开关（我已搜：无） |
| N1c | `Write-Warning` 是否被 PowerShell 日志正常捕获 | C | 若做方案 A 需验证 |
| N1d | `:\s` 在**未来**伪代码引入 `case x:` 时是否误报 | B | 当前 0 命中；建议 docstring 写边界 |
| N1e | `fix-stepNN.log` 加 before/after 后是否可复现 | — | 放行条件 2 的验收 |

---

## §19. 第⑰步复验（快照纳入版本控制 + 开关删除 + before/after 日志）

### 19.0 快照与十一个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3`（mtime 02:33:10，本轮未变）。
> **脚本**：`verify_elif_semantics.py` **540 行 / 23116 B / `DC5F13922103F82B`**（上轮 525 行）；
> `verify_sideeffect_leaf.py` 84 行 / `5A162E63`（未变）；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；
> `count_sec_refs.py` 112 行 / `B35D3373`；`verify.ps1` **204 行 / 9592 B / `2CC7084A4EFD768F`**（上轮 210 行）。
> **新增**：`evidence\tls\fix-step16.log` 38 行 / 1852 B / `04E752DEB8952BE6`；
> **`evidence\tls\snapshots\`（4 个快照，已纳入版本控制）**。

**十一个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 10 状态 + 2 个 1.2 专项 + 24/24      exit=0
3b. verify_sideeffect_leaf.py           → G8 验收 20/20 ASSERT OK              exit=0
4.  pseudo_lint.py --regress (evidence 快照) → REGRESS OK                       exit=0
5.  count_sec_refs.py --check           → OK: 文档断言(8,13)==口径B(8,13)      exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7.  verify.ps1 -PseudoLint              → pseudo lint passed                   exit=0
8.  verify.ps1（默认，无 -PseudoLint）   → 12/12 tests passed                   exit=0
9.  场景1 正常（快照在 evidence）         → exit=0                              exit=0
10. 场景2 .tmp 清空（5 个副本移走）       → exit=0「pseudo lint passed」         exit=0  ← **根治生效**
11. 场景3 evidence 缺快照                → exit=1「missing snapshot ...」       exit=1（期望）
```

**场景 2 是本轮核心**：我把 `.tmp` 下 5 个快照副本（含 `step7.v3.md`）全部移走，
`verify.ps1 -PseudoLint` **仍然 exit=0 且 `pseudo lint passed`**。
**这证明门禁已不依赖 `.tmp`——「消除」而非「防护」。**

### 19.1 Q1：快照移出后是否还有遗漏？——**主迁移完整，但 `.tmp` 里还留着 5 个旧副本，建议删除**

#### 19.1.1 迁移核实

`evidence\tls\snapshots\` 4 个文件，sha 与你报的一致：
```
design-a.bak.md                92381 B  10B0F3BEC05A9A69
design-a.step7.snapshot.md    112779 B  AD392E0B669AB004
design-a.step7.v2.md          120397 B  66729EE085B00545
design-a.step8.base.md        135988 B  2EAF8060B19C151F
```
**`KNOWN` 表引用的 4 个全部到位。**

#### 19.1.2 但 `.tmp` 里仍有 5 个同名旧副本（G12）

我实测 `.tmp` 目录：
```
design-a.bak.md              92381 B
design-a.step7.snapshot.md  112779 B
design-a.step7.v2.md        120397 B
design-a.step7.v3.md        120397 B   ← 你说的"重复副本"
design-a.step8.base.md      135988 B
```

**问题**：这 5 个副本**现在是无用残留**，但它们制造了一个真实风险——
**「同名的两份文件，改哪一份？」**

- 如果未来有人误改 `.tmp` 里的副本（以为那是"当前用的"），`evidence` 里的不会变，**门禁照常通过，但改的东西白改了**。
- 反过来，如果有人按 `.tmp` 的旧版本对比，会得出错误结论。

**建议**：**删除 `.tmp` 下的这 5 个副本**（`evidence` 已是唯一权威源）。
**保留 `design-a.step7.v3.md` 吗？——不保留。** 理由：
1. 它与 `v2.md` **sha 完全相同**（`66729EE085B00545`），**不提供任何额外信息**
2. 它不在 `KNOWN` 表里，**不参与回归**
3. 留着只会让「哪个是权威」变模糊

**如果担心「未来可能要追溯 v3」**：`v3` 与 `v2` 字节相同，**追溯 `v2` 就等于追溯 `v3`**，不需要单独留。

#### 19.1.3 关于 `design-a.step7.v3.md` 的定性

你说「与 v2 同 sha，是重复副本，未纳入」。**这个判断正确。**
**但它出现在 `.tmp` 里说明它曾经被创建过**——可能是某次「另存为」的产物。
**建议**：删掉 `.tmp` 里的，**不要在 `evidence/snapshots/` 里保留**（保持 4 个，与 `KNOWN` 表一一对应）。

**理由**：`evidence/tls/snapshots/` 的语义应该是「**回归门禁的输入集**」，而 `KNOWN` 表有 4 条。
**多一个不在 `KNOWN` 里的文件，会让「这个目录里的文件都该被 regress」这个隐含契约失效。**

### 19.2 Q2：`evidence/tls/snapshots/` 是不是正确归属？——**基本正确，但我倾向 `evidence/tls/snapshots/` 优于 `docs/spec/history/`**

#### 19.2.1 三种候选的对比

| 位置 | 优点 | 缺点 |
|---|---|---|
| **`evidence/tls/snapshots/`**（当前） | 与使用它的脚本同域（`evidence/tls/pseudo_lint.py`）；「证据」语义准确——这些文件是**验证的输入**，不是「文档历史」 | `evidence` 目录通常是「产出物」，放输入略有混用 |
| `docs/spec/history/` | 语义清晰（历史文档副本）；与 `design-a.md` 同域 | **远离使用方**（脚本在 `evidence/tls/`）；容易被当成「参考文档」而随意修改 |
| `.tmp/`（原位置） | — | **临时目录，会被清理**（已证明是缺陷） |

#### 19.2.2 我的裁定：**保持 `evidence/tls/snapshots/`**

**三条理由**：

1. **「证据」的定义包含「验证的输入」**。这 4 个文件的作用是**证明检查器能抓到已知缺陷**——
   它们是**证据材料**（如同 `probe24.out.txt` 是实测输出）。放 `evidence/` 语义准确。

2. **就近原则**：`pseudo_lint.py --regress` 消费它们，两者同在 `evidence/tls/`。
   **如果放 `docs/spec/history/`，脚本就要跨目录读 `docs/`**——**验证器读文档目录，边界更模糊**
   （`docs/` 是「被审计对象」，`evidence/` 是「审计工具与证据」，**这个边界应该保持**）。

3. **`docs/spec/history/` 会诱导「修改历史文档」**。`docs/` 下的文件通常被认为「可以编辑」；
   而 `evidence/` 下的文件是「冻结的证据」。**这 4 个快照必须冻结**（它们是回归基线）。

**一个改进建议（不设卡）**：在 `evidence/tls/snapshots/` 加一个 `README.md`，写清：
```
本目录是 pseudo_lint.py --regress 的输入集，与 KNOWN 表（pseudo_lint.py:667）一一对应。
这 4 个文件是冻结的历史基线，禁止修改；新增基线需同时更新 KNOWN 表。
```

**理由**：目录语义靠文件本身说不清，**一个 README 能让「为什么在这、能不能改」一目了然**。

### 19.3 Q3：`fix-step16.log` 的 before 段是凭记忆写的，算不算「事后编造证据」？——**不算编造，但确实是「弱证据」；你的补救思路正确**

#### 19.3.1 先看实际内容

`fix-step16.log` 的 BEFORE 段：
```
--- BEFORE (step15 state) ---
snapshot location        : F:\rtsc\.tmp\  (scratch dir, any cleanup tool may wipe)
AllowNoSnapshots switch  : PRESENT (escape hatch)
missing snapshot behavior: exit 1 via Write-Error (gate could not run at all)
anchor pattern           : (?:^|;|:\s)  x 8
residual (?:^|;)         : 0
sideeffect cases         : 20/20
```

#### 19.3.2 判定：**不算「编造」，但属于「回忆性描述」，强度低于「实测快照」**

**区分三个概念**：

| 类型 | 定义 | 强度 |
|---|---|---|
| **编造（fabrication）** | 写出**从未发生**的事实 | 零（且是诚信问题） |
| **回忆性描述** | 写出**确实发生过、但没有当时记录**的事实 | 中（可被其他证据交叉验证） |
| **实测快照** | 改动**之前**落盘的状态记录 | 高（不可否认） |

**你的 BEFORE 段属于第二类。** 判断依据：

1. **每一项都可以被独立交叉验证**：
   - `snapshot location : F:\rtsc\.tmp\` → **我第⑯步实测过**（§18.1.2 的全仓搜索，确实在 `.tmp`）
   - `AllowNoSnapshots : PRESENT` → **我第⑯步实测过**（§18.1.2，`verify.ps1:20-21`）
   - `anchor pattern x 8` → **我第⑯步实测过**（§18.2.1，`含 (?:^|;|:\s) 数量: 8`）
   - `sideeffect cases 20/20` → **我第⑯步实测过**（§18.0，`G8 验收 20/20`）

2. **每一条都能在 `fix-step15.log` 或我的 §18 里找到对应记录**。
   **所以它不是「凭记忆」，而是「引用已有记录」**——只是把记录汇总到了新日志里。

**结论：不算编造。** 但**它是「转述」，不是「原始记录」**——
**如果 `fix-step15.log` 和我的 §18 都不存在，这段 BEFORE 就无法验证**。

#### 19.3.3 你的补救思路正确，但还可以更严

你想到的：「每次改动前先落盘 before 快照」。**这是正确做法。** 我补充两点：

**（1）before 快照必须是「机器生成」，不是「人写」**

```python
# 改动前
before = {
    'snapshot_dir': detect_snapshot_dir(),
    'allow_no_snapshots': 'AllowNoSnapshots' in read('verify.ps1'),
    'anchor_count': len(re.findall(r'\(\?:\^\|;\|:\\s\)', read('verify_elif_semantics.py'))),
    'sideeffect_cases': count_cases('verify_sideeffect_leaf.py'),
    'sha256': {f: sha256(f) for f in files},
}
json.dump(before, open('evidence/tls/state-before-stepNN.json','w'))
```
**理由**：**人写的 before 永远可能是「我以为改前是这样」**；
机器生成的 before 是**客观状态**。这与规则 A（汇报附 grep 输出）同理。

**（2）before 快照应该是「可 diff 的结构化数据」，不是散文**

当前 BEFORE 段是散文（`snapshot location : ...`）。
**如果改成 JSON，就可以 `diff before.json after.json`**，**改动一目了然**。

**建议格式**：
```json
{
  "step": 16,
  "timestamp": "2026-10-23T03:10:39",
  "snapshot_dir": "F:\\rtsc\\.tmp",
  "allow_no_snapshots": true,
  "anchor_count": 8,
  "sideeffect_cases": 20,
  "files": {"verify.ps1": "2CC7084A...", "verify_elif_semantics.py": "DC5F1392..."}
}
```
**然后 AFTER 段用同样结构**。**两份 JSON 一 diff，改了什么清清楚楚。**

#### 19.3.4 一个更根本的问题

**为什么 before 需要「回忆」？** 因为**改动是「一次性动作」，没有中间状态**。
**但如果你先落盘 before、再改动、再落盘 after**，就永远不需要回忆。

**这正是你的思路，我只是把它形式化。** 建议写进 memory 作为规则 F：
> **改动前必须机器生成 before 状态（结构化），改动后生成 after 状态；两者 diff 即为证据。**

### 19.4 Q4：还有没有别的「临时目录依赖」？——**有，但都不在 `-PseudoLint` 门禁链上；风险分级如下**

#### 19.4.1 我扫了全仓的 `.tmp` 引用

```
verify.ps1:24-26        $env:TEMP = .tmp; New-Item -Force     ← 设置临时目录（正常）
evidence/capabilities/accept_consult_b.py:4   $env:TEMP=.tmp  ← 环境设置（正常）
evidence/capabilities/verify_caps.py:3        open('.tmp\bcgr.txt')  ← **硬依赖输入文件**
evidence/capabilities/mutation_test.py:26     TMPD=.tmp       ← 写入变异副本（正常，用完删）
evidence/capabilities/red_f06_f38_synonym.py:17 MUT=.tmp\_syn_mut.md ← 同上
evidence/tls/pseudo_lint_redtest.py:16        TMPD=.tmp       ← 生成变异副本（正常）
evidence/doc/doc_lint.py:129                  ".tmp" in path → skip  ← 主动排除（正常）
.tmp/check_acceptance.py, .tmp/gen_caps_full.py, .tmp/gen_dumps.py  ← 脚本本身在 .tmp
```

#### 19.4.2 风险分级

| 项 | 是否在 `-PseudoLint` 门禁链 | 风险 | 说明 |
|---|---|---|---|
| **`verify_caps.py` 的 `.tmp\bcgr.txt`** | **否** | **中** | **硬依赖**：文件缺失时 `open()` 直接抛 `FileNotFoundError`。**不会静默通过**（这是好的），但**无法运行** |
| `pseudo_lint_redtest.py` 的 `TMPD` | 是 | **低** | 只是**写**变异副本（`:16` 定义，用完即弃）；`TMPD` 不存在时会 `FileNotFoundError`，**不静默** |
| `mutation_test.py` / `red_f06_f38_synonym.py` | 否 | 低 | 同上，只写不读 |
| `doc_lint.py:129` 的 `.tmp` 排除 | 是 | **无** | **主动排除** `.tmp` 路径不检查（防止把临时文件当文档引用）——这是**正确设计** |
| `.tmp\check_acceptance.py` / `gen_caps_full.py` / `gen_dumps.py` | 否 | 低 | **脚本本身在 `.tmp`**，会被清理。但它们是一次性生成工具，**不是门禁** |
| `tlsprobe/`（探针源码+exe） | 否 | **中** | 探针二进制在 `.tmp`，**被清理后无法复现实测**。但 `probe24.out.txt` 已复制到 `evidence/`（见 §16.5） |
| `my24.txt` | 否 | 低 | 我的复跑输出，已在 `evidence/tls/probe24.rerun-consult-b.txt` 留档 |

#### 19.4.3 裁定

**只有 2 项需要关注**：

**(1) `verify_caps.py` 的 `.tmp\bcgr.txt`（中风险）**
- **不在 `-PseudoLint` 链上**，所以**不影响当前门禁**
- **但它是一个真实的「临时目录依赖」**：如果 `.tmp` 被清理，`verify_caps.py` 就跑不了
- **好消息**：它**不静默**（`open()` 抛异常），符合我们「宁可失败不可静默」的原则
- **建议（不设卡）**：把 `bcgr.txt` 也移到 `evidence/capabilities/`（与 `verify_caps.py` 同域），
  或让脚本在文件缺失时给出**明确错误信息**（而不是裸 `FileNotFoundError`）

**(2) `tlsprobe/`（中风险）**
- 探针源码 + exe 在 `.tmp\tlsprobe\`
- **`probe24` 的输出已留档**（`evidence/tls/probe24.out.txt` + `rerun-consult-b.txt`）
- **但源码和 exe 没有**——如果将来要复跑其他探针，`.tmp` 被清理就没了
- **建议（不设卡）**：把 `tlsprobe/*.cpp` 移到 `evidence/tls/probes/`（源码是**证据的一部分**，能证明实测怎么做的）

**其余项目：无风险或低风险**，因为它们「只写不读」或「主动排除」。

### 19.5 随修项复核

| 项 | 你说 | 我核实 |
|---|---|---|
| **快照移到 `evidence/tls/snapshots/`** | 4 个 | **已到位**，sha 全部一致 |
| **`verify.ps1` 读新路径** | 是 | **`:181`** `Join-Path $root "evidence\tls\snapshots\$sn"` |
| **逐文件缺失即 exit 1** | 是 | **`:182-185`** `if (-not (Test-Path $sp)) { Write-Error "missing snapshot $sp"; exit 1 }` |
| **`-AllowNoSnapshots` 删除** | 是 | **`AllowNoSnapshots` 命中 0**，`param()` 里已无该开关 |
| **`[skip]` 改 `Write-Warning`** | 2 处 | **`Write-Warning` 命中 2**，`[skip]` 命中 **0** |
| **`_classify_leaf` docstring 写边界** | 是 | 我核实 `verify_elif_semantics.py` 从 525→540 行（+15 行），docstring 已扩 |
| **docstring 写死代码标签含义** | 是 | 同上（G11 文档化替代） |
| **`fix-step16.log` before/after** | 是 | **已到位**（38 行，结构完整） |

**8 项全部落地。**

### 19.6 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **快照纳入版本控制（`evidence/tls/snapshots/`）** | **通过**（4 个，sha 一致） |
| **`.tmp` 清空后门禁仍工作（场景2）** | **通过**（我实测 exit=0 + `pseudo lint passed`）**根治生效** |
| **`-AllowNoSnapshots` 删除** | **通过**（0 命中） |
| **逐文件缺失即 fail** | **通过**（`:182-185`，场景3 实测 exit=1） |
| **`[skip]` → `Write-Warning`** | **通过**（2 处改，0 残留） |
| **docstring 边界 + 死代码说明** | **通过**（+15 行） |
| **`fix-step16.log` before/after** | **通过**（结构完整，且每项可交叉验证） |
| **十一个 exit 码** | **通过**（9 个 exit=0 + 2 个预期 exit=1） |
| **`.tmp` 残留 5 个同名副本** | **不通过（G12）**（会制造「改哪份」的歧义） |
| **`fix-step16.log` 的 before 是回忆性描述** | **通过但有保留**（不算编造，但强度低于机器生成） |

**放行条件（2 条）**：

1. **【一般】删除 `.tmp` 下的 5 个快照副本**（19.1.2）：
   `design-a.bak.md` / `step7.snapshot.md` / `step7.v2.md` / **`step7.v3.md`** / `step8.base.md`。
   **`v3` 与 `v2` sha 完全相同（`66729EE0`），不提供额外信息，且不在 `KNOWN` 表里。**
   **验收标准**：`.tmp` 下 `design-a.*.md` 命中 0；`verify.ps1 -PseudoLint` 仍 exit=0。
   **理由**：同名双份会让「改哪一份」产生歧义——**改错的那份不会让门禁失败，但改动白费**。
   这是**比「文件缺失」更隐蔽的问题**（缺失会 fail，改错份不会）。

2. **【一般】before/after 改为机器生成的结构化数据**（19.3.3）：
   当前 BEFORE 段是人写的散文。**建议改为 JSON**（`evidence/tls/state-before-stepNN.json` + `state-after-stepNN.json`），
   两项 `diff` 即为证据。**验收标准**：新日志的 before 由脚本读取文件生成，不是手写。

**随修（不设卡）**：
- `evidence/tls/snapshots/README.md` 说明「本目录是 regress 输入集，与 KNOWN 表一一对应，禁止修改」。
- `verify_caps.py` 的 `.tmp\bcgr.txt` 移到 `evidence/capabilities/`（或给明确错误信息）。
- `tlsprobe/*.cpp` 移到 `evidence/tls/probes/`（源码是实测证据的一部分）。

### 19.7 我方自我更正

1. **我第⑯步只说了「`.tmp` 更易被清理」这个风险，没说「应该移走」这个解法——你上轮照做了一半（加 fail），本轮才根治。**
   这轮证明：**「暴露问题」（fail）和「消除问题」（移走）是两个不同层次的修复，我给建议时必须说清是哪一层。**
   **我第⑯步的表述不够彻底，这条已在 §18.7 记录，本轮再次确认。**

2. **我在 §18.7 说「扩展匹配范围时必须测反向」——本轮你没有扩展匹配范围，所以该规则未受检验。**
   但我注意到：**`fix-step16.log` 的 BEFORE 段恰恰是「反向验证」的缺失**——
   它记录了「改前是什么」，但**是回忆的**。**这与我批评 G10 的「没测不该匹配的」是同一类问题：
   都缺少「改动前的客观记录」。** 我把这条并入规则 F。

3. **我上轮建议「加 `Write-Warning`」时没想到「`Write-Warning` 在 `verify.ps1` 里已有 2 处」**——
   本轮核实发现你改的正是那 2 处 python 缺失分支。**这说明我的建议是准确的，但我没有预判「它会被用在哪」。**

### 19.8 第⑰步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| P1a | 删除 `.tmp` 5 个副本后，是否有脚本仍引用它们 | — | 我已知 `verify.ps1` 用新路径；需确认无其他引用（放行条件 1 验收） |
| P1b | before/after JSON 的 diff 是否可读 | — | 放行条件 2 验收 |
| P1c | `snapshots/README.md` 是否影响 doc_lint（被当作文档检查） | C | 需实测 |
| P1d | `verify_caps.py` 的 `bcgr.txt` 移到 evidence 后是否正常 | B | 不在当前门禁链，低优先 |
| P1e | `tlsprobe/*.cpp` 移到 `evidence/tls/probes/` 是否影响探针编译 | B | 需改编译脚本路径 |

---

## §20. 第⑱步复验（G12 清零 + state_snapshot + README + probes）

### 20.0 快照与十三个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3`（mtime 02:33:10，连续三轮未变）。
> **脚本**：`verify_elif_semantics.py` 540 行 / `DC5F1392`（未变）；
> `verify_sideeffect_leaf.py` 84 行 / `5A162E63`（未变）；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；
> `count_sec_refs.py` 112 行 / `B35D3373`；
> **`verify.ps1` 210 行 / 9968 B / `8136601B359ECE49`**（上轮 204 行）；
> **`state_snapshot.py` 122 行 / 3901 B / `B1B1FCA950651049`（新增）**；
> `snapshots\README.md` 43 行 / 1985 B / `34C13E3E`；`probes\README.md` 27 行 / 1308 B / `5D641FF0`。

**十三个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 10 状态 + 2 个 1.2 专项 + 24/24      exit=0
3b. verify_sideeffect_leaf.py           → G8 验收 20/20 ASSERT OK              exit=0
4.  pseudo_lint.py --regress            → REGRESS OK                           exit=0
5.  count_sec_refs.py --check           → OK: (8,13)==(8,13)                   exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7.  state_snapshot.py --step ... --phase after → wrote state-after-*.json      exit=0
8.  verify.ps1 -PseudoLint              → pseudo lint passed                   exit=0
9.  verify.ps1（默认）                   → 12/12 tests passed                   exit=0
10. 场景1 正常                           → exit=0                              exit=0
11. 场景2 .tmp 副本数=0，门禁照跑         → exit=0                              exit=0
12. 场景3 evidence 缺快照                → exit=1「missing snapshot ...」       exit=1（期望）
13. 删 state_snapshot.py                 → exit=1「missing ...」                exit=1（期望）
```

**场景 13 是新验证**：第 6 道（state_snapshot）**也纳入了 `:153` 的预检列表**，
删除它 → `exit=1` 而不是静默跳过。**G9 的模式被正确延续到了新增门禁。**

### 20.1 Q1：`state_snapshot.py` 的 metrics 够用吗？——**8 个指标全部准确，但「统计文本出现次数」不等于「验证行为」**

#### 20.1.1 8 个指标我逐项独立核算，全部一致

| 指标 | 脚本值 | 我的独立核算 | 一致 |
|---|---|---|---|
| `tmp_design_a_copies` | 0 | 0 | ✓ |
| `anchor_triple_count` | 9 | 9 | ✓ |
| `anchor_semicolon_only_residual` | 0 | 0 | ✓ |
| `allow_no_snapshots_mentions` | 0 | 0 | ✓ |
| `skip_bracket_mentions` | 0 | 0 | ✓ |
| `write_warning_mentions` | 2 | 2 | ✓ |
| `known_table_entries` | 4 | 4 | ✓ |
| `snapshot_dir_referenced` | 1 | 1 | ✓ |

**8/8 一致。** 你修的两个坑（`known_table_entries` 引号位置、`count()` 缺 `re.M`）确实修好了——
我核实 `:676-679` 的 4 条全部正确识别，`^` 锚点生效。

#### 20.1.2 但 `anchor_triple_count = 9` 与实际代码的 8 处有偏差（G13）

**我逐行核对了这 9 处**：
```
 196  DOC   | 语句分隔符识别为 行首 / ; / 内联 if 的 ": "（即 `(?:^|;|:\s)`）……  ← docstring！
 218  CODE  | re.search(r'(?:^|;|:\s)\s*return\s+kClosed', ...)
 220  CODE  | re.search(r'(?:^|;|:\s)\s*return\s+kOk', ...)
 222  CODE  | re.search(r'(?:^|;|:\s)\s*pass\b', ...)
 224  CODE  | re.search(r'(?:^|;|:\s)\s*continue\b', ...)
 230  CODE  | re.search(r'(?:^|;|:\s)\s*return\s+(k\w+)', ...)
 233  CODE  | re.search(r'(?:^|;|:\s)\s*return\b', ...)
 235  CODE  | re.search(r'(?:^|;|:\s)\s*continue\b', ...)
 237  CODE  | re.search(r'(?:^|;|:\s)\s*pass\b', ...)
→ 代码 8 处 + docstring 1 处 = 9
```

**验证这个偏差是真实的**：我把 docstring 里的模式改成 `三锚点` 三个字（代码不动），
指标立刻从 9 变 8 —— **说明这 1 个差额确实是 docstring 贡献的**。

**影响**：
- **不影响任何门禁判定**（state_snapshot 只记录不判失败）
- **但会让「状态轨迹」失真**：如果某轮只改了 docstring 的措辞，`anchor_triple_count` 会从 9 变 8，
  **看起来像"少了一个锚点"**，实际代码没变。**这是"文本统计"与"代码结构"的固有差距。**

**建议（低成本）**：把统计范围限定到「非注释/非 docstring 行」：
```python
def count_code(path, pattern):
    t = io.open(path, encoding='utf-8', errors='replace').read()
    # 去掉 docstring 和 # 注释
    t = re.sub(r'"""[\s\S]*?"""', '', t)
    t = re.sub(r"'''[\s\S]*?'''", '', t)
    lines = [l.split('#')[0] for l in t.split('\n')]
    return len(re.findall(pattern, '\n'.join(lines), re.M))
```
**验收标准**：`anchor_triple_count` 报 8（与代码实际处数一致），且改 docstring 措辞后不变。

#### 20.1.3 还应该纳入哪些指标？（你问的）

**我建议补 4 个（按优先级）**：

**（1）`gate_count`（门禁道数）——最重要**
```python
'gate_count': count_code(vps, r'& \$py \$'),
```
**理由**：这是**唯一能反映"门禁是否被删减"的指标**。
当前 `verify.ps1` 有 6 道（`:158/:162/:166/:188/:192/:196`）+ state_snapshot = 7 道。
**如果某轮不小心删了一道，其他指标全部不变，只有这个会变。**
**这是"门禁完整性"的唯一可观测信号。**

**（2）`doc_defect_total`（文档缺陷总数）**
从 `design-a.md` 抓 `21−1=20` 之类的算式结果。
**理由**：文档里 §2 有「缺陷总数 20 条」的断言，且它被 `count_sec_refs` 之外的逻辑引用过。
**如果这个数字漂移，说明文档内部不自洽。**

**（3）`exit_codes`（各门禁的退出码）**
```python
'exit_codes': {'pseudo_lint': 0, 'redtest': 0, ...}
```
**理由**：当前 state_snapshot **只记录源码状态，不记录"跑起来是否通过"**。
**这是最大的缺口**——源码全对但跑起来失败的情况，state_snapshot 看不出来。
**但实现有难度**（state_snapshot 要调用其他脚本）。**建议作为"下一层"**：
让 `verify.ps1` 在跑完每道门禁后，把 `$LASTEXITCODE` 汇总进 state JSON。

**（4）`regress_extra`（regress 的额外命中）**
**理由**：当前 regress 输出 `extra=[...]`，如果新增了未登记的缺陷，state 看不出。
**建议**：把 regress 的 `fail_ids` 和 `known` 也记进 state。

**优先级排序**：`gate_count`（必加）> `exit_codes`（架构改动）> `doc_defect_total` > `regress_extra`。

#### 20.1.4 一个更根本的观察

**`state_snapshot.py` 现在的定位是「源码指纹 + 文本模式计数」。**
**它不验证行为**——这是它和 `verify.ps1` 的分工：
- `verify.ps1` 验证**行为**（跑脚本、看 exit 码）
- `state_snapshot.py` 记录**结构**（文件 sha、模式出现次数）

**这个分工是对的**（各司其职）。**但要注意**：
> **结构正确 ≠ 行为正确**。`anchor_triple_count=8` 只说明「有 8 个地方写了这个正则」，
> **不说明「这 8 个正则都正确工作」**——后者靠 `verify_sideeffect_leaf.py` 的 20 个用例。

**建议在 `state_snapshot.py` 的 docstring 里明确这个边界**（避免后人误以为它是"全面验证"）：
> 本脚本只记录**结构指纹**（文件 sha / 文本模式计数），**不验证行为**。
> 行为验证由 `verify.ps1` 的各道门禁负责。两者互补，不可替代。

### 20.2 Q2：`--step gate` 每次覆盖，要不要保留历史？——**要保留，但用「追加式索引」而非「多份全量 JSON」**

#### 20.2.1 当前问题

`--step gate` 每次写 `state-after-stepgate.json`（同名覆盖）。
**后果**：只有最新状态，**没有历史轨迹**。

**这违背了 state_snapshot 的初衷**——你上轮说它的用途是「形成持续的状态轨迹」，
**但同名覆盖让"轨迹"退化成"快照"**。

#### 20.2.2 三种方案对比

| 方案 | 优点 | 缺点 |
|---|---|---|
| **A. 每次写新文件（时间戳命名）** | 完整历史 | 文件无限增长；`evidence/` 会被垃圾文件淹没 |
| **B. 只留最新（当前）** | 干净 | 无轨迹（违背初衷） |
| **C. 全量 JSON 只留最新 + 追加式索引**（推荐） | 有轨迹且文件数可控 | 需要两处写入 |

#### 20.2.3 推荐方案 C 的实现

```python
# 全量快照仍覆盖写（只留最新）
io.open(out, 'w', ...).write(json.dumps(state, ...))

# 追加一行到索引（永不覆盖）
idx = os.path.join(EVID, 'state-history.jsonl')
with io.open(idx, 'a', encoding='utf-8', newline='') as f:
    f.write(json.dumps({
        'step': a.step, 'phase': a.phase,
        'ts': datetime.now().isoformat(timespec='seconds'),
        'sha': {k: v['sha256'][:16] for k, v in state['files'].items() if v['sha256']},
        'metrics': state['metrics'],
    }, ensure_ascii=False, sort_keys=True) + '\n')
```

**优点**：
1. **JSONL 追加**——每行一条记录，永不覆盖，**天然是轨迹**
2. **每行是"摘要"**（sha 前 16 位 + metrics），**体积可控**（每行约 500B）
3. **`diff` 两行就能看出改了什么**——比 diff 两份全量 JSON 更直观
4. **全量 JSON 仍只留最新**（`evidence/` 不会膨胀）

**验收标准**：
- 跑两次 `--step gate`，`state-history.jsonl` 有 2 行
- 两行的 `metrics` 可直接 diff
- `state-after-stepgate.json` 仍只有 1 份（最新）

#### 20.2.4 关于「保留多久」

**随仓库走，不设清理策略**——理由：
- 每行 ~500B，跑 100 次才 50KB，**不构成负担**
- 它是**审计轨迹**，删了就不可恢复（与 `fix-stepNN.log` 同级）
- 如果确实需要归档，按年切分（`state-history-2026.jsonl`），**但不要删**

### 20.3 Q3：`probes/` 50 个 .cpp 该全部保留还是只留被引用的？——**全部保留，但加索引说明"哪个被引用"**

#### 20.3.1 实测数据

我扫了 50 个 `.cpp`：
```
被 design-a / consult-b 引用: 28
仅被 evidence 其他文件引用: 0
完全未被引用: 22
```
**未被引用的 22 个**：
```
link1.cpp, link2.cpp, matrix.cpp,
probe12, probe13, probe14, probe17, probe22, probe23, probe28,
probe30, probe31, probe32, probe33, probe36, probe38, probe43,
probe6, probe8, tpkt_tls, tpkt_tls2, tpkt_tls3
```

**你点名的 4 个早期探索**（用 `\biso\.cpp\b` 精确匹配复核）：
```
iso.cpp      → 未引用（design-a 0 次、consult-b 0 次）
link1.cpp    → 未引用
link2.cpp    → 未引用
matrix.cpp   → 未引用
```

**你的归类正确，`iso.cpp` 确实是"与结论无关"。**

**但我必须记录我自己的一个错误**：我第一次扫描时用了 `stem in doc`（子串匹配），
`iso` 命中的是 `poisoned` 里的 `iso`——于是误判 `iso.cpp` 被引用。
**用 `\biso\.cpp\b` 精确匹配后，0 命中。** 我在 20.3.4 初稿里写了"纠正你的归类"，那是错的，已撤回。
**这是"子串匹配 vs 精确匹配"的坑，与本项目反复出现的锚点问题是同一类。**

#### 20.3.2 我的裁定：**全部保留**

**三条理由**：

**（1）「未被引用」不等于「无价值」——它可能是"负证据"**
`link1.cpp` / `link2.cpp` 从名字看是**链接试验**（可能是验证库依赖的）。
**如果将来有人问「为什么不用 xxx 库」，这些探针就是答案。**
**删掉它们，就等于删掉了「我们试过、失败了」的记录。**

**（2）「探针源码」是方法证据，不是结论证据**
你 README 写得好：
> 探针的**输出**证明"实测结果是什么"，源码证明"实测是怎么做的"。

**但这条同样适用于"失败的探针"**——它们证明"我们试过这条路，走不通"。
**这类证据在技术选型争议时极其重要**（避免重复踩坑）。

**（3）成本极低**
50 个 `.cpp` 合计约 400KB（我粗算），**远小于一个二进制**。
**保留的成本几乎为零，删除的代价是不可恢复。**

#### 20.3.3 但建议加索引（低成本，高收益）

**建议加 `probes/INDEX.md`**：
```markdown
| 文件 | 被引用处 | 用途 | 结论 |
|---|---|---|---|
| probe24.cpp | design-a:91, consult-b:§13-§19 (58 次) | 服务端重协商 / NO_RENEGOTIATION | 1.2 支持、1.3 返回 0x90360 |
| probe20.cpp | design-a:..., consult-b:... | SecBuffer 下限 | nbuf<4 报 0x80090308 |
| ... | | | |
| link1.cpp | **未被引用** | 链接试验（推测） | 未采用 |
| link2.cpp | **未被引用** | 链接试验（推测） | 未采用 |
| matrix.cpp | **未被引用** | 组合矩阵（推测） | 未采用 |
```

**理由**：
1. **"未被引用"本身是信息**——它告诉后人"这些不是结论依据"
2. **索引让"哪个重要"一目了然**，不必逐个 grep
3. **成本约 20 分钟**（50 行表格）

**但注意**：`link1/link2/matrix` 的"用途"是**我推测的**（从文件名）。
**建议你按实际内容填**，不要照抄我的推测——**否则索引本身就成了"编造证据"**。

#### 20.3.4 关于 `iso.cpp` 的归类：**你的判断正确，我最初的"纠正"是错的**

你说「有些是早期探索（`iso.cpp`/`link1.cpp`/`link2.cpp`/`matrix.cpp`），与最终结论无关」。

**我用 `\biso\.cpp\b` 精确匹配复核：design-a 0 次、consult-b 0 次。`iso.cpp` 确实未被引用。**

**我最初误判的原因（必须记录）**：
我第一次扫描用的是 `stem in doc`（子串匹配），`iso` 这个子串命中了 `poisoned` 里的 `iso`：
```
design-a: 子串 'iso' 命中 2 处 → 都是 "poisoned"
consult-b: 子串 'iso' 命中 3 处 → 都是 "poisoned"
```
**于是误判 `iso.cpp` 被引用。** 用精确匹配后 0 命中。

**这与本项目反复出现的"锚点/匹配精度"问题是同一类**：
- 第⑪步：`'st' in cond` 子串匹配 → 漏检运算符
- 第⑮步：`^\s*` vs `(?:^|;)` 锚点不一致 → 同行写法漏检
- **本轮：`stem in doc` 子串匹配 → 误判引用**

**三次都是"匹配范围过宽或过窄"。** 我的 §20.7 自我更正需要再加一条。

### 20.4 Q4：`verify_caps.py` 的 `bcgr.txt` 拒绝移走，理由成立吗？——**基本成立，但「从官方文档重新获取」需要验证可行性**

#### 20.4.1 你的理由拆解

> 1. 这是能力交换阶段的一次性验收脚本，该阶段已收口
> 2. 若将来要重跑，`bcgr.txt` 可从官方文档重新获取

**理由 1 成立**：我核实 `verify_caps.py` **不在 `verify.ps1` 的调用链上**（`"verify_caps" in verify.ps1` → **False**）。
所以它**不影响任何门禁**，移不移都不改变当前质量。

**理由 2 需要验证**：`bcgr.txt` 是 1154865 B（1.1 MB），**是什么内容？**
如果它是**从官方 PDF/HTML 提取的文本**，那"重新获取"意味着**重新跑提取流程**——
**而提取流程本身可能没有记录**（这正是"证据链断裂"）。

**我实测了**：
```
bcgr.txt exists: True  1154865 B
```
**1.1 MB 的文本，不可能是手写的**，必然是提取产物。

#### 20.4.2 我的裁定：**理由 1 成立，理由 2 需要补充「可复现性」**

**接受不移走**，但**建议补一条说明**：

**在 `verify_caps.py` 的 docstring 里写清 `bcgr.txt` 的来源**：
```python
"""...
输入：F:\\rtsc\\.tmp\\bcgr.txt
  来源：<从哪个文档/URL 提取>，提取方法：<脚本名或手工步骤>
  该文件是能力交换阶段的一次性输入，已随阶段收口。
  若 .tmp 被清理，需按上述方法重新提取（提取脚本：<路径>）。
"""
```

**理由**：
- **如果"重新获取"的方法有记录**，那 `.tmp` 被清理确实不是问题（可复现）
- **如果没记录**，那"可从官方文档重新获取"就是**未经验证的假设**

**这是"证据链完整性"的要求，不是"必须移走"的要求。** 你说得对，移走不是唯一解；
**但"可重新获取"必须有据可查，否则等同于"不可恢复"。**

#### 20.4.3 一个更轻的替代方案

如果不想动 `verify_caps.py`，可以**只加一行注释**在 `evidence/capabilities/README.md`（若有）或新建：
```
bcgr.txt（.tmp，1.1MB）：能力交换阶段 verify_caps.py 的输入。
来源与提取方法：<填>。若 .tmp 被清理需重新提取。
```

**成本 3 行，收益：消除"不可恢复"的风险。**

### 20.5 随修项复核

| 项 | 你说 | 我核实 |
|---|---|---|
| **`.tmp` 5 个副本清零** | 0 | **实测 count=0** ✓ |
| **`step7.v3.md` 删除** | 是 | **`.tmp` 与 `evidence/snapshots/` 均无 v3** ✓ |
| **`evidence/snapshots/` 仍 4 个** | 是 | **实测 4 个 + README** ✓ |
| **`state_snapshot.py` 新增** | 122 行 | **实测 122 行 / 3901 B** ✓ |
| **8 个指标** | 见你列 | **我独立核算 8/8 一致** ✓ |
| **接入第 6 道门禁** | 是 | **实测场景 13：删它 → exit=1** ✓ |
| **`snapshots/README.md`** | 43 行 | **实测 43 行 / 1985 B** ✓ |
| **`probes/README.md`** | 27 行 | **实测 27 行 / 1308 B** ✓ |
| **50 个探针源码** | 复制到 evidence | **实测 51 个文件（50 .cpp + 1 README）** ✓ |
| **`bcgr.txt` 未动** | 是 | **确认仍在 `.tmp`，1.1MB** ✓ |

**10 项全部核实一致。**

### 20.6 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **G12（`.tmp` 副本清零）** | **通过**（count=0） |
| **`step7.v3.md` 删除** | **通过**（两处均无） |
| **`state_snapshot.py` 8 指标** | **通过**（我独立核算 8/8 一致） |
| **接入第 6 道 + 预检** | **通过**（删它 → exit=1） |
| **`snapshots/README.md`** | **通过** |
| **`probes/README.md` + 50 源码** | **通过**（51 文件） |
| **十三个 exit 码** | **通过**（11 个 exit=0 + 2 个预期 exit=1） |
| **`anchor_triple_count` 含 docstring** | **不通过（G13，低危）**（报 9，代码实际 8） |
| **`--step gate` 覆盖无轨迹** | **不通过（G14）**（违背"持续轨迹"初衷） |
| **`iso.cpp` 被误归为"早期探索"** | **事实纠正**（它实际被引用） |
| **`bcgr.txt` 的"可重新获取"未验证** | **不通过（低危）**（需补来源说明） |

**放行条件（3 条）**：

1. **【一般】`--step gate` 改为「全量覆盖 + 追加式 JSONL 索引」**（20.2.3）：
   当前同名覆盖让"轨迹"退化成"快照"，**违背 state_snapshot 的初衷**。
   **验收标准**：跑两次 `--step gate` → `state-history.jsonl` 有 2 行；全量 JSON 仍只 1 份。
   **理由**：这是本轮唯一"设计层面"的问题——**其余都是实现细节，这条是功能缺失**。

2. **【一般】`anchor_triple_count` 限定到代码行**（20.1.2，G13）：
   当前报 9（含 `:196` docstring 里的 1 处），代码实际 8 处。
   **验收标准**：指标报 8；改 docstring 措辞后指标不变。
   **理由**：会让状态轨迹失真——**只改 docstring 措辞，指标却变化，看起来像"少了一个锚点"**。

3. **【低】补 `bcgr.txt` 的来源说明**（20.4.2）：
   "可从官方文档重新获取"目前是**未经验证的假设**。
   **验收标准**：`verify_caps.py` docstring 或 `capabilities/README.md` 写明来源 + 提取方法。

**随修（不设卡）**：
- `state_snapshot.py` 加 `gate_count` 指标（门禁完整性唯一可观测信号）。
- `probes/INDEX.md`（50 行表格，标注"被引用/未被引用"）。
- `state_snapshot.py` docstring 写明「只记录结构指纹，不验证行为」。

### 20.7 我方自我更正

1. **我上轮说「`tlsprobe/*.cpp` 移到 `evidence/tls/probes/`」——你做了，但我没料到会有 50 个文件、22 个未被引用。**
   我当时只想到"源码是证据"，**没考虑"证据也要分类"**。
   **本轮我补上了分类建议（INDEX.md），这是上轮建议的遗漏。**

2. **你 Q3 把 `iso.cpp` 归为"早期探索、与结论无关"，但我实测它被引用（design-a + consult-b）。**
   **这条需要你确认**——**如果它确实被引用，那"早期探索"这个归类对它不成立**。
   **我提出这个纠正，但同时承认"被引用"不等于"重要"**（可能只是顺带提及）。

3. **我上轮没指出 `state_snapshot.py` 的「文本统计 vs 代码结构」这个根本局限**——
   因为我上轮只是在"建议做机器生成快照"，**没有预见"机器生成"也会有自己的失真**（docstring 计入）。
   **这印证了一条规律：每个新工具都会引入新的失真维度，需要下一轮审计才能发现。**

4. **本轮我在 Q3 犯了「子串匹配」的错误**：用 `stem in doc` 判 `iso.cpp` 是否被引用，
   `iso` 命中了 `poisoned`，于是误判它被引用、并据此"纠正"你的归类。
   **精确匹配（`\biso\.cpp\b`）后 0 命中，你的归类正确，我的纠正错了。**
   **这是本项目第三次同类问题**：第⑪步 `'st' in cond`（漏检运算符）、第⑮步 `^\s*` vs `(?:^|;)`（锚点不一致）、
   本轮 `stem in doc`（误判引用）。**三次都是"匹配范围过宽或过窄"。**
   **这条应写进 memory 作为规则 G**：任何"是否包含/是否引用"的判断，
   **必须用精确匹配（词边界 + 完整标识符），禁止子串 `in`。**

### 20.8 第⑱步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| Q1a | `state-history.jsonl` 追加后是否可正常 diff | — | 放行条件 1 验收 |
| Q1b | `anchor_triple_count` 改代码行统计后是否报 8 | — | 放行条件 2 验收 |
| Q1c | `gate_count` 指标是否能正确反映 7 道门禁 | B | 建议新增 |
| Q1d | `iso.cpp` 实际用途与引用上下文 | B | 需查 consult-b 引用处 |
| Q1e | `bcgr.txt` 的来源与提取方法是否可复现 | C | 放行条件 3 |
| Q1f | `probes/INDEX.md` 的"用途"列是否会被误填为推测 | C | 我已提醒不要照抄我的推测 |

---

## §21. 第⑲步复验（G13 代码行统计 + G14 JSONL 轨迹 + 自指污染 + 门禁退出码）

### 21.0 快照与十三个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3`（**连续四轮未变**）。
> **脚本**：`verify_elif_semantics.py` 540 行 / `DC5F1392`；`verify_sideeffect_leaf.py` 84 行 / `5A162E63`；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；`count_sec_refs.py` 112 行 / `B35D3373`；
> **`verify.ps1` 225 行 / 10780 B / `258811030B7A50CD`**（上轮 210 行）；
> **`state_snapshot.py` 288 行 / 10856 B / `B74DF751E0EFB539`**（上轮 122 行，+166 行）；
> **`verify_g13.py` 61 行 / 2153 B / `07CC14AF86A74C6E`（新增）**；
> **`diff_state.py` 59 行 / 1944 B / `365E44E6EEBACEFF`（新增）**；
> `probes\INDEX.md` 113 行 / 11368 B / `9D7B780E`；`capabilities\bcgr-source.md` 112 行 / 3487 B / `575B3CB4`；
> `fix-step18.log` 68 行 / 3912 B / `396AF3E0`；`fix-step18.diff.log` 30 行 / 2914 B / `23D412E5`。

**十三个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 24/24                                exit=0
3b. verify_sideeffect_leaf.py           → 20/20                                exit=0
4.  pseudo_lint.py --regress            → REGRESS OK                           exit=0
5.  count_sec_refs.py --check           → OK: (8,13)==(8,13)                   exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7.  verify_g13.py                       → RESULT=PASS                          exit=0
8.  verify.ps1 -PseudoLint              → pseudo lint passed                   exit=0
9.  verify.ps1（默认）                   → 12/12 tests passed                   exit=0
10. verify.ps1 -DocLint                 → doc lint passed                      exit=0
11. state-history.jsonl 行数             → 5（本次运行前）                      —
12. 删 verify_g13.py                    → exit=1「missing ...」                exit=1（期望）
13. 连续两次跑 → JSONL 追加              → before=5 after=6 追加=1             ✓
```

### 21.1 Q1：引用统计口径——**你的「只在设计文档算」正确；但你的 26/24 和我的 36/14 差在「是否要求 `.cpp` 后缀」**

#### 21.1.1 自指污染是真实的，而且比我想的更严重

我实测三种口径：

| 口径 | 引用 | 未引用 |
|---|---|---|
| **仅 design-a** | 13 | 37 |
| **design-a + design-b**（你的 26/24） | 26 | 24 |
| **design-a + design-b + consult-b**（我上轮 28/22） | **50** | **0** |

**含 consult-b 时是「引用 50 / 未引用 0」——100% 全覆盖，这本身就是自指污染的铁证。**
（我上轮报 28/22，是因为当时只扫了 `\bstem\b` 且脚本有别的过滤；本轮用 `stem\.cpp` 得 26/24，与你的完全一致。）

**根因（你说得对）**：`consult-b` 是**审计报告**，它必然讨论「哪些没被引用」，
所以那些文件名**必然出现**在报告里。**任何在审计报告上做的引用统计都是自指的。**

**你的修法正确**：只在设计文档（design-a / design-b）上算，consult-b 单独一列标注「audit 提及」。
**INDEX.md 的实际表格也这么做了**（第 6 列 `设计文档引用`、第 7 列 `audit 提及`）。**这是正确设计。**

#### 21.1.2 但 26/24 与 36/14 的差异需要澄清（G15）

我实测：
```
\bstem\b   → 引用 36 / 未引用 14
stem\.cpp  → 引用 26 / 未引用 24   ← 你的口径
```

**差 10 个的原因**：`\bstem\b` 匹配裸名（如 `probe24`），`stem\.cpp` 要求带 `.cpp` 后缀。

**哪个更正确？——我判定 `stem\.cpp` 更严格但也更准确**，理由：
1. **`probe24` 这种裸引用，可能指「探针编号」而不是「文件」**（如「probe24 实测」指的是那次实验，不是文件）
2. **但反过来**，如果文档写「见 probe24」，**它确实指向那个探针**，只是没写后缀

**我的裁定：两个口径都有意义，但 INDEX.md 应说明用的是哪个。**
**当前 INDEX.md 写「被设计文档引用（design-a / design-b） | 26」，没说明匹配方式。**
**建议补一句**：`匹配方式：文件全名 \`<stem>.cpp\`（不含裸编号引用）`。
**理由**：**口径不写清，读者会以为 26 就是「所有被引用的」**，而实际上裸引用（10 个）没算进去。

**这是"口径必须显式声明"的又一例**——与本项目 §12.5 的 `count_sec_refs` 六口径问题同型。

#### 21.1.3 关于「审计文档的提及不能当使用证据」

**你的规则补充完全正确，我建议再精确一层**：

> **统计「被引用」时，先问「这份文档会不会正好在讨论『没被引用』」。**
> **审计文档的提及数不能当使用证据。**

**我补充的精确化**：
- **不只审计文档**——**任何"元文档"都有这个问题**（changelog、review、retrospective、bug report）
- **判据不是"文档类型"，而是"文档是否以这些名字为讨论对象"**
- **可操作的做法**：**统计源限定为「消费方文档」**（design-a/design-b 是"用探针结论"的文档），
  排除「元文档」（consult-b 是"讨论探针"的文档）

**建议写进 memory 作为规则 G 的补充（规则 G'）**：
> 引用统计必须区分「消费方文档」（用结论）与「元文档」（讨论结论）。
> 只有消费方文档的提及才算使用证据；元文档的提及是自指的，不计入。

### 21.2 Q2：`state_snapshot` 把 `state_snapshot.py` 自己纳入 WATCH，是自指还是必要？——**是必要的，但需要隔离**

#### 21.2.1 事实核实

`WATCH` 列表（8 项）确实包含自己：
```
verify.ps1, pseudo_lint.py, pseudo_lint_redtest.py, verify_elif_semantics.py,
verify_sideeffect_leaf.py, count_sec_refs.py,
state_snapshot.py,          ← 自己
docs/spec/tls-backend.design-a.md
```

#### 21.2.2 我的判定：**必要，但会产生"必然变化噪音"，需要隔离**

**为什么必要**：
`state_snapshot.py` 是**门禁的一部分**（第 6 道 / 现在的 S7 前置）。
**如果它被改动（比如 metrics 逻辑变了），历史轨迹的可比性就断了。**
**记录它的 sha，等于记录"这份轨迹是用哪个版本的测量工具生成的"** ——
**这与科学实验记录"仪器型号"是同一性质。**

**为什么是噪音**：
- 它改自己时，`files['state_snapshot.py'].sha256` 必然变
- **即使只是改注释**（不影响测量语义），sha 也变
- **结果**：`diff_state` 会报 `CHANGED`，**但测量结果可能完全没变**

**这与 G13 是同一个问题的两面**：
- G13：**docstring 改动 → 指标变化**（已修：屏蔽 docstring）
- Q2：**工具自身改动 → 轨迹变化**（未修）

#### 21.2.3 建议：**分两个字段记录**

```json
"files": { ... },                    // 所有 WATCH 文件的 sha
"tool": {                            // 单独隔离测量工具自身
    "state_snapshot.py": {"sha256": "...", "semantic_version": 2}
}
```

**或者更简单**：在 `diff_state.py` 里**把 `state_snapshot.py` 的变更单独归类**：
```
~ TOOL CHANGED (measurement instrument): state_snapshot.py  abc -> def
  ⚠ 轨迹可比性降低：此变更前后记录可能不可直接比较
```

**理由**：**"工具变了"和"被测对象变了"是两个不同的事实，混在一起会掩盖后者。**

**成本**：`diff_state.py` 加 5 行分类逻辑。**收益**：轨迹的可解释性。**

**当前严重性：低。** 因为 `state_snapshot.py` 现在稳定了（本轮改完应该不会再动）。
**但如果不隔离，下次它改 metrics 时，diff 输出会分不清"是对象变了还是尺子变了"。**

### 21.3 Q3：`verify_g13.py` 用 `sys.path.insert` import `state_snapshot`，算循环论证吗？——**不算，因为存在独立判据**

#### 21.3.1 你的担心

> 好处是测的是**真实使用的那个函数**，不是复制一份。
> 坏处是「测的和用的是同一份代码」——**这算不算循环论证**？

#### 21.3.2 循环论证的严格定义

**循环论证** = 用结论本身证明结论（`A 真因为 A 真`）。

**判断标准**：**被测命题是否独立于验证手段。**

#### 21.3.3 本例分析：**不是循环论证**

**被测命题**：「`mask_noncode()` 能把 docstring 里的模式排除在代码计数之外」

**`verify_g13.py` 的验证方式**：
1. 用 `mask_noncode` 得到 `code=8, docstring_only=1`
2. **改 docstring 措辞**
3. 再算：`code=8`（不变）、`docstring_only=0`（变了）

**为什么这不是循环**：**第 2 步的「改 docstring」是独立操作**，它的效果可以被**独立预测**：
> 如果 mask 生效，docstring 里的 1 处被排除 → 改动 docstring 不影响 code 计数
> 如果 mask 没生效（旧实现），docstring 里的 1 处被计入 → 改动 docstring 会让 code 从 9 变 8

**两个预测不同，实测符合前者 → 判据是独立的。**

#### 21.3.4 但我做了**更强的独立验证**（不采信它的自测）

我**不复用 `mask_noncode`**，直接用 `ast.parse` 独立算出 docstring 行区间：
```
docstring 区间（行号）: [(1,19), (55,55), (69,69), (77,77), (113,124),
                        (143,148), (167,167), (176,176), (188,209), (243,251)]
:196 是否落在任一 docstring 区间: True
```

**结论**：`:196` 确实在 `(188,209)` 这个 docstring 区间内。
**这与 `mask_noncode` 的判定一致，但推导路径完全独立。**

**所以：不是循环论证，而且有独立判据支撑。**

#### 21.3.5 但你的担心指向一个真问题

**`sys.path.insert` + `import` 的风险不是循环论证，是「版本漂移」**：
- 如果 `state_snapshot.py` 被改成 `mask_noncode` 不再屏蔽 docstring
- `verify_g13.py` 会**立刻失败**（因为它断言 `code=8`）
- **这是好事**（快速失败）

**真正的风险是相反方向**：如果 `verify_g13.py` 的期望值（`code==8`）是**硬编码**的，
而 `state_snapshot.py` 改成**正确统计 9 个锚点**（比如设计文档真的新增了一个），
**`verify_g13.py` 会误报失败。**

**建议**：把 `code==8` 的硬编码改为「与独立 ast 计算的结果比对」：
```python
# 不硬编码 8，而是用独立 ast 判据
expected = count_with_independent_ast_parser(SRC, PAT)
chk('code count matches independent ast result', n_code_o == expected, ...)
```
**这样 `verify_g13` 测的是「两个独立实现的答案是否一致」，而不是「是否等于我记住的 8」。**
**这是「差分测试（differential testing）」模式，比硬编码期望值更强。**

**当前严重性：低**（文档没变，8 是对的）。**但建议改进。**

### 21.4 Q4：`[推定]` 占 88% 是不是问题？——**是问题，但问题不在 INDEX.md，在探针本身**

#### 21.4.1 我核实了你的分布，完全正确

我按表格第 3 列（用途等级）精确统计 50 行：
```
推定=44, 注释=4, 无=2     ← 与你的 4/44/2 完全一致
设计文档引用: 有=26, 无=24  ← 与你的 26/24 完全一致
```

**我需要记录一个我自己的错误**：我第一次统计时用 `"注释" in row` 做关键字匹配，
结果报「注释=48 / 推定=0」——因为**每一行都含「（无作者注释）」这句话**。
**改用按列切分（`split("|")[3]`）后，4/44/2 正确。**
**这是本项目第四次「匹配方式错误」**（子串 → 列切分）。

#### 21.4.2 `[推定] 88%` 意味着什么

**它意味着：44 个探针没有作者注释，用途是从 API 调用反推的。**

**这本身不是 INDEX.md 的缺陷**——INDEX.md 已经**诚实标注**了：
```
[推定]：无作者注释，用途由实际出现的 SSPI/BCrypt API 调用推定。
       **这是推断不是事实**——它说明「这个探针调了什么」，不说明「作者想验证什么」。
```

**但这个 88% 暴露了一个真实问题**：
> **探针集合的可理解性严重依赖"读者能从 API 调用猜出意图"。**

#### 21.4.3 这是问题吗？——**是，但「补注释」不是正确的补救方式**

**为什么是问题**：
- 半年后有人看 `probe13.cpp`，看到「调用 AcceptSecurityContext」，
  **不知道它验证的是什么假设**（是测 TLS1.3 支持？测 buffer 下限？测重协商？）
- **`[推定]` 只能告诉你"用了什么 API"，不能告诉你"想证明什么"**

**为什么「现在补注释」不是正确补救**：
1. **现在补的注释是"事后回忆"，不是"当时意图"**——这与 §19.3 讨论的"回忆性 before"是同一类问题
2. **探针是一次性的**，补注释的收益（未来可读性）与成本（回忆 44 个文件）不匹配
3. **更重要的**：**如果某个探针的意图已经不可考，那它作为"证据"的价值本身就降低了**

**正确的补救**：
- **对「被引用」的 26 个**：**设计文档已经写了它们的结论**（如「probe24：1.2 支持重协商、1.3 返回 0x90360」）。
  **INDEX.md 的"用途"列应该链接到设计文档的引用处**，而不是自己概括。**这样"用途"有据可查。**
- **对「未被引用」的 24 个**：**它们的作用是"负证据"**，INDEX.md 已说明。
  **不需要补注释**——因为**没有结论依赖它们**。

**建议（低成本）**：
```markdown
| 文件 | 字节 | 等级 | 用途 | 设计文档引用 | audit 提及 |
| `probe24.cpp` | ... | 注释 | 服务端重协商 / NO_RENEGOTIATION | design-a:91, design-b×N | 58 |
```
**把「用途」列改成「设计文档引用处」+「结论摘要（如有）」**，
**`[推定]` 的 API 列表降为辅助信息**。

**理由**：**「用途」的权威来源是设计文档（结论），不是 API 列表（手段）。**
**当前 INDEX.md 把手段当用途，是层级错位。**

#### 21.4.4 关于 `link1/link2` 归入 `[无]`

我核实了源码：
```
link1.cpp: 267 B, int main(){ SecPkgContext_CipherInfo c{}; printf("%zu\n", sizeof(c)); return 0; }
link2.cpp: 289 B, int main(){ SecPkgContext_ConnectionInfoEx e{}; (void)e; printf("ok %d\n", ...); }
```
**它们确实只有 `sizeof()` 打印**——**从 API 看是"测结构体大小"**。

**你说「没有任何可推断用途的 API」——严格说不准确**：
`SecPkgContext_CipherInfo` / `SecPkgContext_ConnectionInfoEx` **是可辨识的类型**，
**用途可以推定为「测这两个结构体的 sizeof」**。

**但你归入 `[无]` 是更保守的做法，我认可**——因为**「测 sizeof」本身不构成一个"验证假设"**
（它没说"为什么测这个大小"）。**保守优于猜测。**

**建议（可选）**：把 `[无]` 的说明补一句「**从 API 可看出调用了 X，但无法推断验证意图**」，
比完全留空更有信息量，且不构成猜测。

### 21.5 其他发现

#### 21.5.1 `gate_count = 7` 的修正过程值得记录

你说第一次统计全文件 `& $py $` 得 8（把 `doc_lint` 的调用也算进去了），改成限定 `if ($PseudoLint)` 块内得 7。

**这个修正本身证明了「文本统计 ≠ 语义计数」**——与 G13 同型。
**我核实了 `state-history.jsonl` 里的 `py_gate_invocations: 7`。** 正确。

#### 21.5.2 `bcgr.txt` 可重现性：**实测通过，这是本轮最扎实的证据**

```
python docx2txt.py bcgr.docx bcgr.regen.txt
orig   1154865  ca703a9f3395801c
regen  1154865  ca703a9f3395801c
IDENTICAL True
```

**我核实了 `bcgr-source.md`（112 行 / 3487 B）存在，且记录了提取方法。**
**「可从官方文档重新获取」从假设变成了事实。放行条件 3 关闭。**

**但我要指出一个边界**：这次重现用的是**同一个 `docx2txt.py`**。
**如果 `docx2txt.py` 本身消失，仍然不可重现。**
**建议**：`bcgr-source.md` 里记录 `docx2txt.py` 的来源（是 pip 包？还是自写脚本？）。

#### 21.5.3 `fix-step18.log` 的 BEFORE 段修正

你发现第一版把 `history file (JSONL): present` 写进 BEFORE，但那是**生成日志时的测量**，不是 step17 状态。
**已改为 `did not exist at step17 (created in step18)`。这个修正是对的**——
**正是 §19.3 讨论的「回忆性 before」问题，你自己抓到并修正了。**

**这是本轮最好的信号**：**规则 F（before 必须机器生成）已经被内化，你能自己发现违反。**

### 21.6 盖章裁定

**不盖章。**

| 门 | 状态 |
|---|---|
| **G13（anchor 限定代码行）** | **通过**（8 处，docstring 屏蔽生效；我用独立 ast 验证 `:196` 在 docstring 区间） |
| **G13 的 4 条验收** | **通过**（我实跑 RESULT=PASS，4 条全 PASS） |
| **G14（JSONL 追加轨迹）** | **通过**（实测连续两次跑 → 追加 1 行；全量 JSON 仍 1 份） |
| **`gate_count` = 7** | **通过**（限定 `if ($PseudoLint)` 块内，正确） |
| **门禁退出码入 state** | **通过**（`gate_exits` 7 项） |
| **`bcgr.txt` 可重现** | **通过**（逐字节 IDENTICAL） |
| **`probes/INDEX.md` 分布** | **通过**（4/44/2 和 26/24，我按列切分核实完全一致） |
| **自指污染识别** | **通过**（含 consult-b 时 50/0，铁证） |
| **`fix-step18.log` BEFORE 修正** | **通过**（自己发现并修正"回忆性 before"） |
| **十三个 exit 码** | **通过**（11 个 exit=0 + 2 个预期 exit=1） |
| **引用口径未声明** | **不通过（G15，低危）**（26 用的是 `stem\.cpp`，裸编号引用 10 个未算，未说明） |
| **`state_snapshot.py` 自指未隔离** | **不通过（低危）**（工具变更与对象变更混在一起） |
| **`verify_g13.py` 硬编码期望值 8** | **不通过（低危）**（建议改差分测试） |

**放行条件（2 条）**：

1. **【一般】`probes/INDEX.md` 声明引用匹配口径**（21.1.2，G15）：
   当前写「被设计文档引用 26」，但**没说匹配方式**。
   我实测 `\bstem\b` 得 36，`stem\.cpp` 得 26——**差 10 个是裸编号引用**。
   **验收标准**：表格加一行 `匹配方式：文件全名 \`<stem>.cpp\`（裸编号引用不计）`。
   **理由**：**口径不写清，读者会以为 26 就是「所有被引用的」**，而实际裸引用（10 个）没算。
   **这与 §12.5 `count_sec_refs` 的六口径问题同型——口径必须显式声明。**

2. **【一般】`INDEX.md` 的「用途」列层级错位**（21.4.3）：
   当前「用途」列填的是 **API 调用列表**（手段），而真正的「用途」是**设计文档里的结论**。
   **验收标准**：对 26 个被引用的探针，「用途」列改为「设计文档引用处 + 结论摘要」；
   API 列表降为辅助列或截断。
   **理由**：**「用途」的权威来源是结论，不是手段。** 88% 的 `[推定]` 本质是"只有手段没有结论"。

**随修（不设卡）**：
- `state_snapshot.py` 在 `diff_state.py` 里单独归类为「工具变更」（21.2.3）。
- `verify_g13.py` 把硬编码 `code==8` 改为「与独立 ast 计算比对」（21.3.5）。
- `bcgr-source.md` 补充 `docx2txt.py` 的来源（21.5.2）。
- `[无]` 的说明补「从 API 可看出调用了 X，但无法推断验证意图」（21.4.4）。

### 21.7 我方自我更正

1. **我上轮报「28/22」是错的，正确是 26/24（`stem\.cpp`）或 36/14（`\bstem\b`）。**
   我上轮用 `\bstem\b` 但脚本有别的过滤，得到 28/22——**两个数都对不上，说明我的扫描脚本本身有 bug。**
   **本轮我用两种明确的口径重算，得到 36/14 和 26/24，其中 26/24 与你的完全一致。**
   **教训：报数字时必须同时报"用什么方法算的"**——否则数字不可复核。

2. **我第一次核实 INDEX.md 的 4/44/2 时，用 `"注释" in row` 做关键字匹配，报「注释=48 / 推定=0」。**
   根因：**每行都含「（无作者注释）」这句话**，所以"注释"关键字全命中。
   **改用按列切分（`split("|")[3]`）后，4/44/2 正确。**
   **这是本项目第四次「匹配方式错误」**：
   - 第⑪步 `'st' in cond`（子串）
   - 第⑮步 `^\s*` vs `(?:^|;)`（锚点）
   - 第⑱步 `stem in doc`（子串）
   - **第⑲步 `"注释" in row`（子串，且命中的是否定表述）**
   **四次都是"用子串匹配代替结构化解析"。这条必须写进 memory，且我建议不只写"用精确匹配"，
   而是写"涉及表格/结构化数据时，必须按列/字段切分，禁止整行关键字匹配"。**

3. **我上轮说 `iso.cpp` 的归类"需要你确认"，本轮确认你的 `[无]` 归类正确**，
   但我同时指出 `link1/link2` 从 API 看是"测 sizeof"——**"无可推断 API"这个说法不准确**，
   更准确是"可看出调用什么，但无法推断验证意图"。**这是我的精确化，不是纠正。**

4. **我上轮建议"保留全部 50 个探针"是对的，但我当时没意识到「保留」会带来「索引必须标注证据等级」的需求。**
   你做了 `[注释]/[推定]/[无]` 三级——**这比我上轮的建议更完整。** 我认可。

### 21.8 第⑲步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| R1a | INDEX.md 加「匹配方式」声明后，26 是否仍准确 | — | 放行条件 1 验收 |
| R1b | 「用途」列改为「引用处+结论」后，是否覆盖 26 个 | — | 放行条件 2 验收 |
| R1c | `diff_state.py` 隔离工具变更后，diff 是否更可读 | C | 随修项 |
| R1d | `verify_g13.py` 改差分测试后，是否能发现"文档真的新增了锚点" | C | 随修项 |
| R1e | `docx2txt.py` 的来源（pip 包/自写）是否记录 | C | 21.5.2 的边界 |
| R1f | 审计文档自指污染是否影响其他统计（如 `count_sec_refs`） | B | **已实测**：`count_sec_refs.py:27` `DEFAULT_DOC = tls-backend.design-a.md`，**只读 design-a，不涉及 consult-b** → **无自指污染**。它的口径问题是"六种口径未声明"（§12.5 已处理），不是自指。 |

---

## §22. 第⑳步复验（G15 双口径 + 用途层级 + 三个解析器 bug + 收敛判据）

### 22.0 快照与十一个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3`，**mtime 02:33:10（本轮未变）**；
> `design-b.md` 566 行 / 45397 B / `3F7405AB`（mtime 22:51:05）。
> **脚本**：`verify_elif_semantics.py` 540 行 / `DC5F1392`；`verify_sideeffect_leaf.py` 84 行 / `5A162E63`；
> `pseudo_lint.py` 756 行 / `74625A83`；`pseudo_lint_redtest.py` 229 行 / `F193DB47`；`count_sec_refs.py` 112 行 / `B35D3373`；
> `verify.ps1` 225 行 / `25881103`；`state_snapshot.py` 288 行 / `B74DF751`；
> **`verify_g13.py` 185 行 / 6521 B / `7D0177DCA6502DD8`**（上轮 61 行，+124 行差分测试）；
> **`diff_state.py` 100 行 / 3705 B / `72B27E07C64FA9A3`**（上轮 59 行）；
> **`probes\INDEX.md` 133 行 / 12026 B / `78FDB3D41267A5B6`**（上轮 113 行）；
> **`capabilities\bcgr-source.md` 124 行 / 4190 B / `2BFF2C77579C3FF3`**（上轮 112 行）；
> **`gen_probe_index.py` 新增**（mtime 03:51:37）。
> `state-history.jsonl` **9 行**。

**十一个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 24/24                                exit=0
3b. verify_sideeffect_leaf.py           → 20/20                                exit=0
4.  pseudo_lint.py --regress            → REGRESS OK                           exit=0
5.  count_sec_refs.py --check           → OK: (8,13)==(8,13)                   exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7.  verify_g13.py                       → RESULT=PASS（7/7）                    exit=0
8.  verify.ps1 -PseudoLint              → pseudo lint passed                   exit=0
9.  verify.ps1 -DocLint                 → doc lint passed                      exit=0
10. verify.ps1（默认）                   → 12/12 tests passed                   exit=0
11. state-history.jsonl                 → 9 行                                 —
```

### 22.1 Q1：`probe` stem 假阳性——**建议保留 36 原样 + 文字说明；但你报的「22 次」是错的，实际 20 次**

#### 22.1.1 先纠正数字

你写：
> `design-a.md : \bprobe\b = 18 次，其中 \bprobe\.cpp\b 只 2 次`
> `design-b.md : \bprobe\b = 4 次，其中 \bprobe\.cpp\b 0 次`
> **→ 22 次全是假阳性**

**前两行的数字我核实全部正确**（18/2、4/0）。**但结论「22 次」算错了**：

```
design-a: 总 18，真引用 2，假阳性 16
design-b: 总  4，真引用 0，假阳性  4
合计假阳性 = 20        ← 不是 22
```

**22 是「总出现次数」（18+4），不是「假阳性次数」。** 真引用那 2 次不算假阳性。
**正确的表述是「22 次出现中有 20 次是假阳性」。**

#### 22.1.2 更严重的问题：`probe` 在口径 B 下被误算为「已引用」

我实测：
```
口径B 引用集是否含 'probe': True
口径B 引用数 = 36
剔除 probe 后 = 35 引用 / 15 未引用
```

**这意味着口径 B 的 36 里有 1 个是纯假阳性**——`probe.cpp` 之所以被算作"已引用"，
**完全是因为文档里写了 `schannel-probe.txt` / `schannel-spki-probe.txt`**（20 处，全是别的文件名）。

**这是"假阳性"的两种不同后果**：
- 对**统计数字**：虚高 1 个（36 vs 35）
- 对**集合成员**：`probe.cpp` 被错误列入"已引用"，而它实际**从未被任何文档按文件名引用**

**所以口径 B 的正确值是 35/15，不是 36/14。**（因为 `probe.cpp` 应归入"未引用"）

#### 22.1.3 你问的「保留 36 原样 + 文字说明」vs「改成 36（含 1 个 stem 假阳性）」——**都不够，应该改成 35/15**

**三个选项对比**：

| 选项 | 诚实度 | 问题 |
|---|---|---|
| 保留 36，文字说明 | 中 | **数字本身是错的**（`probe.cpp` 不该算已引用），说明文字救不了错数字 |
| 改成「36（含 1 个 stem 假阳性）」 | 中 | 仍把错的数字当主值，只是加了注 |
| **改成 35/15 + 说明** | **高** | **数字正确**，且说明为什么剔除了 `probe` |

**我裁定：改成 35/15，并在口径 B 的说明里写**：
> B（参考）：`\b<stem>\b` 裸编号也算 → **35 / 15**。
> 注：`probe.cpp` 的 stem `probe` 会命中 `schannel-probe.txt` / `schannel-spki-probe.txt`
> （20 处，均为其他文件名），故已从"已引用"中剔除，计入"未引用"。

**理由**：**口径的作用是给出可复算的数字。数字错了，说明再详细也是错的。**
「保留原样 + 说明」只适合**无法修正**的情况；这里**可以修正**。

#### 22.1.4 顺带确认：这是第三个假阳性来源，你的分类正确

```
1. 子串匹配（第⑱步）    → \b 词边界修
2. 自指污染（第⑲步）    → 只用消费方文档修
3. 单词/文件名碰撞（本轮）→ 要求扩展名修
```

**我认可这个三分法。** 但要注意：**第 3 类在口径 A 下不存在**（口径 A 要求 `.cpp` 后缀），
**只在口径 B 下出现**。**所以口径 B 本质上是"更宽松但有已知缺陷"的参考口径**——
它的价值是**展示差异**，不是**提供权威数字**。

**建议在 INDEX 里明确这一点**：
> 口径 B 仅用于说明"裸编号引用"的规模，**不作为统计依据**。

### 22.2 Q2：24 个「无结论」留空 + 调用列列 API，是否满足我的建议？——**基本满足，但你的数字错了：有结论的是 26 个不是 24 个**

#### 22.2.1 你的说法与实测不符

你说：
> ```
> [结论来源] design-b 探针表  24 个
> [结论来源] 作者注释          2 个
> [结论来源] 无               24 个
> ```

**前两行正确，但"24 个有权威结论"这个总结错了**——**24 + 2 = 26 个有结论**，只有 24 个无结论。

我按表格第 6 列（来源）精确统计（用 `re.split(r'(?<!\\)\|', row)` 按未转义管道切分，9 列表头）：
```
来源列分布: {'无': 24, 'design-b 探针表': 24, '作者注释': 2}   → 合计 50
用途列（第3列）: 非空 50，空 0
```

**所以：「有结论 26 个 / 无结论 24 个」。** 你报的「24 个有权威结论」少算了 2 个（作者注释的那 2 个：`probe44`、`tpkt_tls`）。

#### 22.2.2 这影响你的论断吗？

你在 §四说：
> **你的 §21 说「探针集合的可理解性严重依赖读者能从 API 猜出意图」——我现在有 24 个有权威结论了，不是靠猜。**

**实际是 26 个，比你说的多 2 个。结论方向不变（有结论的占多数），但数字要修正。**

#### 22.2.3 是否满足我的建议？

我 §21.4.4 的建议是：
> `[无]` 的说明补一句「从 API 可看出调用了 X，但无法推断验证意图」，比完全留空更有信息量，且不构成猜测。

**你的做法**：
- 用途列留空（不猜）✓
- 调用列如实列出 API（事实）✓
- 说明写明「能看出调用了哪些 API，但无法推断验证意图」✓

**满足。而且比我的建议更好**——我建议"在用途列写一句说明"，你改成**「用途列留空 + 调用列单列 + 表头说明」**，
**结构更清晰**（事实与推断分离在不同列）。

**但有一个细节要注意**：我实测「用途列（第3列）非空 50，空 0」——
**说明用途列其实没留空**，而是填了结论摘要（24 个无结论的可能填了「—」或空字符串但有内容）。
**这不算问题**（只要不是编造结论），但**与你说的"留空"表述不一致**。
**建议**：如果无结论的行确实填了「—」，那就在表头说明「— 表示无权威结论」。

### 22.3 Q3：`verify_g13` 的"独立实现"独立性够吗？——**不够。它和 `mask_noncode` 同源（都用 ast.walk + 同样的判断链）**

#### 22.3.1 我读了两个实现

**`state_snapshot.mask_noncode`（`:137-153`）**：
```python
for node in ast.walk(tree):
    if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)): continue
    body = getattr(node, 'body', None) or []
    if not body: continue
    first = body[0]
    if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)): continue
    v = first.value
    r0, c0 = v.lineno, _byte_col_to_char_col(lines[v.lineno-1], v.col_offset)
    ...
```

**`verify_g13.docstring_spans_independent`（`:47-82`）**：
```python
for node in ast.walk(tree):
    if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)): continue
    body = getattr(node, 'body', []) or []
    if not body: continue
    first = body[0]
    if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)): continue
    v = first.value
    c0 = len(raw[:offsets[v.lineno-1] + v.col_offset].decode('utf-8'))
    ...
```

**两段几乎逐行相同**：同样的 `ast.walk`、同样的四个 `isinstance` 检查、同样的 `body[0]` 判定、同样的 `Expr/Constant/str` 三元判断。

**唯一的差异**：
- `mask_noncode` 用 `_byte_col_to_char_col()`（按行建表）
- `docstring_spans_independent` 用 `len(raw[:offset+col].decode())`（按字节前缀解码）

**这两个差异都是"字节偏移换算"的实现细节，不构成"独立判据"。**

#### 22.3.2 所以：**独立性不够，但不是零**

**真正独立的部分**：`strip_hash_comments()`（`:94-`）——**字符状态机，不用 `tokenize`**。
这是真正不同的实现路径。

**不独立的部分**：`docstring_spans_independent()` ——**与 `mask_noncode` 同源**。

**后果**：如果 `ast` 对 docstring 的定义有误（比如某些语法结构下 `body[0]` 不是 docstring），
**两个实现会同时出错，差分测试发现不了。**

#### 22.3.3 需不需要我写第三个实现？——**不需要。但需要换一个"不同维度"的判据**

**理由**：写第三个 `ast` 实现也是同源（`ast` 是唯一的 Python 语法解析器）。
**真正的独立需要"不同维度的证据"**，比如：

**（1）行号锚定（最轻，我能立刻做）**
`:196` 是否在 docstring 里，可以用**纯文本**判断：
```
从 :188 开始是 `"""`，到 :209 结束是 `"""` → :196 在其中
```
**这不需要 AST，只需要"找三引号配对"。** 我已经在 §21.3.4 做过类似的（用 ast 算区间），
**但更独立的是：直接看 `:188` 和 `:209` 是否都是 `"""` 开头/结尾。**

**（2）变异测试（最强，但成本高）**
往 docstring 里**故意插入一个假锚点**，看 `mask_noncode` 是否仍然不计数。
如果计数没变 → 屏蔽生效（这是**行为证据**，不是**实现一致性证据**）。

**（3）人工核对（最可靠，不可自动化）**
`:196` 那一行肉眼可见是中文说明文字（「语句分隔符识别为 行首 / ; / 内联 if 的 ": "」），
**不是代码**。这是**语义判断**，任何解析器都不能替代。

**我的裁定**：
- **当前差分测试的价值**：能防"`mask_noncode` 被改坏"（回归保护）✓
- **当前差分测试的局限**：**不能证明"docstring 定义正确"**（同源）✗
- **建议补一条"行号锚定"判据**（成本 5 行）：断言 `:188` 和 `:209` 是三引号边界
- **不需要我写第三个实现**——**需要的是"不同维度的证据"，不是"更多同源代码"**

**这条可以推广为一般原则（规则 H）**：
> **差分测试的独立性，取决于两个实现是否用了"不同的信息源"，而不是"不同的代码写法"。**
> 同用 `ast` 的两个实现，写法再不同也是同源。

### 22.4 Q4：收敛判据——**这是本轮最重要的问题，我给你一个可机械判定的三段式判据**

#### 22.4.1 先确认你的观察是对的

```
design-a.md mtime = 2026-10-23 02:33:10
现在时刻         = 2026-10-23 03:58:11
静止时长         = 1.4 小时（跨 5 轮审计）
consult-b.md     = 5588 行 / 350983 B（审计报告已 35 万字节）
```

**`design-a.md` 静止 1.4 小时 / 5 轮未变，而工具链每轮都在改。这个循环确实需要终止判据。**

#### 22.4.2 循环的性质分析

**当前循环是什么**：
```
审计 → 发现工具缺陷 → 修工具 → 审计新工具 → 发现新工具的新缺陷 → ...
```

**这是一个"元层级无限上升"的循环**（审计工具的审计工具的审计…）。

**它为什么不会自然收敛**：**每修一个缺陷，工具就变复杂，复杂就引入新缺陷。**
证据：`state_snapshot.py` 从 122 行 → 288 行；`verify_g13.py` 从 61 行 → 185 行。

**它什么时候应该收敛**：**当"继续修"的边际收益 < 边际风险时。**

#### 22.4.3 我给出的三段式终止判据（可机械判定）

**判据 A（必要条件）：`design-a.md` 连续 N 轮不变，且所有门禁绿。**

```
N = 3（已满足：本轮是第 5 轮未变）
门禁：11 个 exit 码全 0（已满足）
```

**为什么 N=3**：一轮不变可能是"还没轮到改"；两轮可能是"改工具没触发"；
**三轮不变 + 门禁全绿 = 文档质量已稳定**。

**判据 B（充分条件）：新增缺陷的"严重级别"连续两轮下降。**

```
第⑱步：G13(低) G14(一般)          ← 一般
第⑲步：G15(低) 用途层级(一般)      ← 一般
第⑳步：口径数字错(低) 独立性(低)     ← 低
```

**如果第㉑步仍只有"低"级缺陷，且没有"阻断/严重"级 → 收敛。**

**为什么用"严重级别"而不是"数量"**：数量不收敛（每轮都有新发现），
但**级别会收敛**（从阻断 → 严重 → 一般 → 低 → 无）。

**判据 C（硬性停止）：任何一轮出现"工具改动导致门禁自身不可信"时立即停止。**

```
例：如果某轮为了让门禁通过而修改门禁的判定逻辑 → 立即停止，报告主代理
```

**理由**：这是"为了通过测试而改测试"的作弊模式。**必须硬停。**

#### 22.4.4 具体的终止动作（我建议现在执行）

**当前状态评估**：

| 判据 | 状态 |
|---|---|
| **A：design-a 连续 3 轮不变 + 门禁全绿** | ✅ **已满足**（5 轮不变，11 个 exit=0） |
| **B：新增缺陷级别连续两轮下降** | ✅ **已满足**（第⑱步一般 → 第⑲步一般 → 第⑳步低） |
| **C：无"改测试以通过"** | ✅ **未发生** |

**我的裁定：当前已满足收敛条件。建议第㉑步为「终审轮」，只做验收不做新修复。**

#### 22.4.5 终审轮应该做什么（明确清单）

**第㉑步（终审）只做三件事**：

1. **验收本轮 3 个放行条件**（口径 B 改 35/15、有结论数改 26、独立性补行号锚定）
2. **跑一次完整门禁 + 记录最终快照**（作为"交付基线"）
3. **输出「工具链终审报告」**：列出所有门禁、所有证据文件、所有已知局限

**明确不做的事**：
- **不再新增检查器**
- **不再重构已有检查器**（除非发现"阻断"级缺陷）
- **不再优化指标**（当前 8 个够用）

#### 22.4.6 如果第㉑步又发现新缺陷怎么办

**分两种情况**：

| 新缺陷级别 | 处理 |
|---|---|
| **阻断/严重** | 修，然后**再跑一轮终审**（回到第㉑步） |
| **一般/低** | **记录到「已知局限」清单，不修**，直接盖章 |

**理由**：**"已知局限"是工程的正常状态**。任何检查器都有局限，
**把它写清楚比无限修补更有价值**——因为读者能据此判断"这个门禁能保证什么、不能保证什么"。

#### 22.4.7 关于"我是否在拖延"

你的担心有道理。**我明确说：不是拖延，但确实到了该停的时候。**

**证据**：
- `design-a.md`（被审计对象）**已经 5 轮没动**
- 我们讨论的全部是**审计工具的元性质**（口径、自指、锚点、独立性）
- **这些讨论对 `design-a.md` 的质量已无增量贡献**

**继续下去的风险**：
- 工具链越来越复杂（`state_snapshot.py` 288 行、`verify_g13.py` 185 行）
- **复杂度本身成为新缺陷源**（本轮 G13/G14 都是复杂度引入的）
- 审计报告 35 万字节，**新读者已无法通读**

**所以：我建议明确终止。**

### 22.5 其他核实

#### 22.5.1 三个解析器 bug：全部修复，且"跳过"现在会打印

你列的三个 bug 我核实了逻辑：
- **bug 1**（正则漏路径）：`probe5` 在 design-b 表里写作 `.tmp/tlsprobe/probe5.cpp`，
  旧正则 `([A-Za-z0-9_]+\.cpp)` 匹配不到 `/`，故丢失。修法（允许路径 + `basename`）正确。
- **bug 2**（转义管道）：`1.2\|1.3` 被按 `|` 切分导致列数不对。
  修法 `re.split(r'(?<!\\)\|', row)` 正确。
- **bug 3**（`\bprobe\b`）：见 22.1。

**「跳过要打印」这个改进是最有价值的**——**静默跳过是这三个 bug 共同的特征**。
**这与本项目反复出现的主题一致：静默失败比显式失败危险得多。**

**但我要指出**：`probe5` / `probe9` / `probe16` 现在被正确解析了，
**这使"有结论"从 22 个变成 26 个（24 design-b + 2 作者注释）**。
**你报的"24 个"少算了 2 个作者注释的**（见 22.2.1）。

#### 22.5.2 `diff_state.py` 的 `INSTRUMENT NEW IN AFTER`

你说：
> **「不存在」不等于「未变」**——已改为 `INSTRUMENT NEW IN AFTER (no before record)`。

**这个修正完全正确**，而且它和 G13 是同一原则的两个面：
- G13：**「docstring 里的锚点」不等于「代码里的锚点」**
- 本轮：**「没有记录」不等于「记录了且没变」**

**这正是"三值逻辑"的必要性**：`是 / 否 / 未知`。
**把"未知"当成"否"是这类 bug 的共同根源。**
**建议写进 memory 作为规则 I**：
> 任何"是否变化"的判断必须区分三态：**变了 / 没变 / 无基线**。
> 把"无基线"当成"没变"会掩盖真实变化（如工具首次出现）。

#### 22.5.3 `bcgr-source.md` 补 `docx2txt.py` 来源

我核实 `bcgr-source.md` 从 112 行 → 124 行（+12 行）。
**你写「本项目自写的脚本，不是 pip 包」，依据是「位于 .tmp、只依赖标准库、全文约 2KB」。**

**这个推理成立**（`zipfile` + `xml.etree` + 正则 = 典型的自写 docx 提取器）。
**但有一个边界**：**「全文必须在这里留档」**——我核实 `bcgr-source.md` 是否真含全文。

**建议**：如果全文已贴，说明里应写明「全文见本文档第 N-M 行」，
**否则读者不知道去哪找。**

#### 22.5.4 `verify_g13` 的 7 条断言

我实跑 7/7 全 PASS。**第 3 条 `total = code + docstring`（8+1=9）是新增的，它保证"没有第三个桶"**——
这是好的（防止"漏统计"）。

**但它也暴露一个隐含假设**：**锚点只可能出现在 code 或 docstring 两处**。
**如果出现在 `#` 注释里呢？**
我实测：`mask_noncode` 把 `#` 注释从**两个缓冲都屏蔽**（`:118-126`），
所以**注释里的锚点会被完全忽略，不进任何桶**。
**这意味着：如果有人在注释里写了锚点，`total` 会小于"原始出现次数"，而断言 3 会失败。**
**当前文档无此情况**（注释里没有锚点），**但这是"测试的隐含假设"，建议在 docstring 写明。**

### 22.6 盖章裁定

**不盖章（但已满足收敛条件，建议下轮终审）。**

| 门 | 状态 |
|---|---|
| **G15 双口径并列** | **通过**（A=26/24，B=36/14，已声明匹配式） |
| **G15 的 B 口径数字** | **不通过（低危）**（`probe.cpp` 被误算已引用，应为 **35/15**） |
| **`probe` 假阳性识别** | **通过**（三分法正确），但**你报的"22 次"应为 20 次** |
| **用途层级修正** | **通过**（结论来源：design-b 24 + 注释 2 + 无 24） |
| **"24 个有权威结论"** | **不通过（低危）**（实际 **26** 个） |
| **三个解析器 bug** | **通过**（含"跳过打印"，这是最有价值的改进） |
| **`diff_state` INSTRUMENT NEW** | **通过**（三值逻辑修正正确） |
| **`bcgr-source.md` 补来源** | **通过** |
| **`verify_g13` 去硬编码** | **通过**（无硬编码，7/7 PASS） |
| **`verify_g13` 独立性** | **不通过（低危）**（与 `mask_noncode` 同用 `ast.walk` + 同判断链，同源） |
| **十一个 exit 码** | **通过**（全 0） |
| **收敛条件 A/B/C** | **全部满足** |

**放行条件（3 条，均为低危）**：

1. **【低】口径 B 数字改为 35/15**（22.1.3）：
   `probe.cpp` 的 stem `probe` 命中的是 `schannel-probe.txt`（20 处，全是别的文件名），
   **应把它从"已引用"剔除，计入"未引用"**。
   **验收标准**：口径 B 行改为 `35 / 15`，并注明剔除原因。
   **理由**：**口径的作用是给出可复算的数字。数字错了，说明再详细也是错的。**

2. **【低】「有结论」数字改为 26**（22.2.1）：
   实测来源分布 `design-b 探针表 24 + 作者注释 2 + 无 24 = 50`。
   **验收标准**：任何地方提到"24 个有权威结论"改为 **26**。

3. **【低】`verify_g13` 补"行号锚定"判据**（22.3.3）：
   当前两个实现同用 `ast`，**同源**，差分测试发现不了 `ast` 本身对 docstring 定义的错误。
   **验收标准**：加一条纯文本判据——断言 `:188` 与 `:209` 是三引号边界（不依赖 `ast`）。
   **不需要我写第三个实现**——需要的是**不同信息源**，不是更多同源代码。

**随修（不设卡）**：
- 规则 H：差分测试的独立性取决于"信息源不同"，不是"代码写法不同"。
- 规则 I：任何"是否变化"的判断必须区分三态（变了 / 没变 / 无基线）。
- `verify_g13` docstring 写明「锚点只可能在 code/docstring 两处，注释里的不计入」。
- `bcgr-source.md` 注明 `docx2txt.py` 全文在第 N-M 行。

### 22.7 终止判据（正式答复 Q4）

**我给出的终止判据是三条，且当前已全部满足**：

| 判据 | 定义 | 当前 |
|---|---|---|
| **A（必要）** | `design-a.md` 连续 **≥3 轮**不变 + 所有门禁 exit=0 | ✅ 5 轮不变，11 个 exit=0 |
| **B（充分）** | 新增缺陷**最高级别**连续两轮下降（阻断→严重→一般→低→无） | ✅ 一般 → 一般 → **低** |
| **C（硬停）** | 出现"为通过而改门禁判定"立即停止 | ✅ 未发生 |

**结论：已满足收敛。第㉑步应为「终审轮」，只做三件事**：
1. 验收本轮 3 个低危放行条件
2. 跑完整门禁 + 记录最终快照（交付基线）
3. 输出「工具链终审报告」（门禁清单 + 证据文件 + **已知局限清单**）

**明确不做**：不新增检查器、不重构（除非阻断级）、不优化指标。

**如果第㉑步又发现新缺陷**：
- **阻断/严重** → 修，再跑一轮终审
- **一般/低** → **记入「已知局限」，不修，直接盖章**

**理由：「已知局限」是工程的正常状态。把它写清楚比无限修补更有价值——
读者能据此判断"这个门禁能保证什么、不能保证什么"。**

### 22.8 我方自我更正

1. **我上轮报「28/22」是扫描脚本 bug；本轮又发现你报的「22 次假阳性」也是算错（实为 20 次）。**
   **双方都在"数字怎么算"上出错**——这印证了 §21.1 的教训：**报数字必须同时报算法**。
   我本轮的做法：先报 `\bprobe\b=18 / \bprobe\.cpp\b=2` 两个原始计数，再算差，**可复算**。

2. **我上轮说"`iso.cpp` 归类需你确认"，本轮核实 `probe.cpp` 才是真正被误算的那个**——
   `iso` 是子串碰撞（`poisoned`），`probe` 是**单词碰撞**（`schannel-probe.txt`）。
   **两者性质不同**：前者是"部分匹配"，后者是"完整单词但不同实体"。
   **我上轮只识别了前者，没预见后者。**

3. **我上轮建议"`[无]` 补一句说明"，你的做法（用途列留空 + 调用列单列）比我的更好**——
   **结构上分离了"事实"与"推断"**，比在同一格里混写更清晰。**我认可并采纳你的方案。**

4. **关于 Q3，我上轮说"不是循环论证"是对的，但我没检查"两个实现是否同源"。**
   **"不同写法"和"不同信息源"是两回事**——本轮才发现两个实现都用 `ast.walk` + 同一套判断链。
   **这是我上轮的疏漏：我验证了"有独立判据"，但没验证"判据的信息源是否独立"。**

### 22.9 第⑳步新增未验证项

| # | 内容 | 级别 | 说明 |
|---|---|---|---|
| S1a | 口径 B 改 35/15 后，与 INDEX 正文的 10 个差集是否仍一致 | — | 放行条件 1 验收 |
| S1b | "有结论 26 个"改完后，INDEX 统计表是否自洽 | — | 放行条件 2 验收 |
| S1c | 行号锚定判据是否真能不依赖 `ast` 判断 `:188/:209` | — | 放行条件 3 验收 |
| S1d | `bcgr-source.md` 是否真含 `docx2txt.py` 全文 | C | 22.5.3 |
| S1e | `verify_g13` 的断言 3（total=code+docstring）在注释含锚点时是否失败 | C | 22.5.4 的隐含假设 |
| S1f | 第㉑步终审报告应包含的"已知局限清单"内容 | — | 22.7 第 3 项 |

---

## §23. 第㉑步终审（裁决 + 已知局限清单 + 交付基线）

### 23.0 终审快照与十一个 exit 码

> **文档**：`design-a.md` **1893 行 / 153606 B**，SHA256 `CA7955D4DEAED6E3A5FC9AD77B0140D5CC0A6C6E52452E638DD094369715F13F`，
> **mtime 02:33:10（连续 6 轮未变）**。
> **脚本**：`pseudo_lint.py` 31547 B / `74625A83`；`pseudo_lint_redtest.py` 10141 B / `F193DB47`；
> `verify_elif_semantics.py` 23116 B / `DC5F1392`；`verify_sideeffect_leaf.py` 3616 B / `5A162E63`；
> `count_sec_refs.py` 3818 B / `B35D3373`；**`verify_g13.py` 8844 B / `B043D3A9`**（上轮 6521 B，+2323）；
> `state_snapshot.py` 10856 B / `B74DF751`；`diff_state.py` 3705 B / `72B27E07`；`verify.ps1` 10780 B / `25881103`。
> **`probes\INDEX.md`**、**`capabilities\bcgr-source.md` 126 行**（上轮 124）。
> `state-history.jsonl` **12 行**。

**十一个 exit 码，我自己跑出来的**：

```
1.  pseudo_lint.py --file design-a.md   → TOTAL fail=0 warn=0                  exit=0
2.  pseudo_lint_redtest.py              → 22/22 ASSERT OK                      exit=0
3.  verify_elif_semantics.py            → 24/24                                exit=0
3b. verify_sideeffect_leaf.py           → 20/20                                exit=0
4.  pseudo_lint.py --regress            → REGRESS OK                           exit=0
5.  count_sec_refs.py --check           → OK: (8,13)==(8,13)                   exit=0
6.  doc_lint.py --root F:\rtsc          → TOTAL fail=0 warn=0                  exit=0
7.  verify_g13.py                       → RESULT=PASS（**12/12**）              exit=0
8.  verify.ps1 -PseudoLint              → pseudo lint passed                   exit=0
9.  verify.ps1 -DocLint                 → doc lint passed                      exit=0
10. verify.ps1（默认）                   → 12/12 tests passed                   exit=0
11. state-history.jsonl                 → 12 行                                —
```

### 23.1 裁决 (1)：`probe.cpp` 算不算引用？——**你对，我错。撤回 35/15，接受 36/14**

#### 23.1.1 我核实了你贴的两处原文

```
design-a:37   ..."Unified Security Protocol Provider"不是**必须** `"CredSSP"`
              [READ:F:\rtsc\.tmp\tlsprobe\probe.cpp:61]。注意：项目内的权威证据...
design-a:955  ...`const_cast<SEC_WCHAR*>`；探测写到 `/W4` 可警告
              [READ:F:\rtsc\.tmp\tlsprobe\probe.cpp:61] | | `sprintf_s`...
```

**两处都是 `[READ:...probe.cpp:61]` 证据标记**，且都用于支撑 `UNISP_NAME_W` 的包名证据。

#### 23.1.2 我的错误性质

我在 §22.1.2 写：
> `probe.cpp` 之所以被算作"已引用"，**完全是因为**文档里写了 `schannel-probe.txt` / `schannel-spki-probe.txt`（20 处，全是别的文件名）。

**「完全是因为」是错的。** 正确事实是：
- **20 次**命中是 `schannel-probe.txt` / `schannel-spki-probe.txt`（假阳性）
- **2 次**命中是 `[READ:...probe.cpp:61]`（**真引用**）

**我犯的错是「把 20 次假阳性当成全部 22 次」**——正是你 §22.1.1 纠正我的那个错误，**我自己又犯了一遍**：
我在 §22.1.1 明确写了「22 次出现中有 20 次是假阳性」，**却在 §22.1.2 用"完全是因为"把 2 次真引用抹掉了**。

**这是同一段落内的自相矛盾。** 我必须记录：**我给出的"35/15"是从"20 次假阳性"错误推导到"集合应剔除"的跳跃**——
**计数假阳性 ≠ 集合该剔除**。前者是"这个 stem 多数命中是噪音"，后者是"这个文件没被引用"。**两者不等价。**

#### 23.1.3 裁决

**你对，我错。撤回「口径 B 改 35/15」这条放行条件。接受 36/14。**

**保留的部分**：`probe` stem 的 20 次假阳性是真实存在的，**说明文字应保留**（你已做）。
**但集合成员不能剔除**——因为 2 次真引用是充分的引用证据。

### 23.2 裁决 (2)：口径 A 漏了 10 个真引用？——**你对，这比我原判断更严重**

#### 23.2.1 我逐个核实了这 10 个

| 文件 | 证据形态 | 判定 |
|---|---|---|
| `probe10` | design-b:307 `[BASH:probe10/probe12/probe17/probe27/probe36]` | **真引用** |
| `probe12` | 同上（同组回归探针） | **真引用** |
| `probe17` | 同上 | **真引用** |
| `probe15` | design-b:113 `[BASH:probe15.exe → "target=wrong name, manual only ... OK"]` | **真引用** |
| `probe22` | design-b:436 `[BASH:probe22.exe → flight 1 (318 bytes)]` | **真引用** |
| `probe3` | design-b:173 `[BASH:probe3/probe6]`（close_notify 证据） | **真引用** |
| `probe31` | design-b:80 `[BASH:probe31.exe]`（版本矩阵） | **真引用** |
| `probe41` | design-a:1319 `consult-b \`probe41\` → 0x1302 TLS_AES_256_GCM_SHA384` | **真引用**（采信另一方） |
| `probe44` | design-a:541 `consult-b \`probe44\`（标 C 级）` | **真引用**（采信另一方） |
| `probe6` | design-b:152 `[BASH:probe6.exe → "ISC(+USE_SUPPLIED_CREDS) on established ctx -> 0x80090300"]` | **真引用** |

**8 个有 `[BASH:...]` 标记，2 个是 `consult-b probeNN` 采信。全部是真实证据。**

#### 23.2.2 所以口径 A 的定位要改

**我 §22.1.4 说**：「口径 B 本质是更宽松但有已知缺陷的参考口径」。
**你说**：「口径 A 不是最保守，而是漏了 10 个真引用」。

**你对。** 更准确的表述：

| 口径 | 集合正确性 | 计数正确性 | 应作为 |
|---|---|---|---|
| A（`<stem>.cpp`） | **漏 10 个真引用** | 26 正确（但含义是"显式写文件名的"） | 参考（"显式文件名引用"） |
| B（`\b<stem>\b`） | **正确（36）** | 36 正确（`probe` 的 20 次假阳性不影响集合，因为有 2 次真引用兜底） | 不作依据（计数语义混杂） |
| **C（你新增）** | **正确（36）** | **正确，且逐文件给理由** | **主口径** |

**关键洞察（我上轮没看到）**：
**「stem 有假阳性」不影响「集合成员判定」，只影响「提及次数统计」。**
因为判定集合只需要「至少一次真引用」，而假阳性再多也不改变"至少一次真"。

**这是我上轮的逻辑错误根源**：我把「计数噪音」和「集合成员」混为一谈。

#### 23.2.3 我核实了口径 C 的实现

INDEX 第 6 列（引用依据）实测抽样：
```
probe25.cpp | 引用依据 = 'cpp×1, exe×1, evtag×1'
probe26.cpp | 引用依据 = 'cpp×1, audit×2'
probe27.cpp | 引用依据 = 'cpp×2, exe×3, evtag×5, audit×1'
iso.cpp     | 引用依据 = '无'
link1.cpp   | 引用依据 = '无'
```
**逐文件给出具体理由，且区分了 `cpp`/`exe`/`evtag`/`audit` 四种形态。** 这比我上轮建议的"加一行匹配方式"强得多。

**裁定：口径 C 作为主口径，正确。**

### 23.3 裁决 (3)：`verify_g13` 12 条断言——**通过，且"新判据自己先错"这件事值得记录**

#### 23.3.1 我实跑 12/12

```
ast and text scan agree on the docstring region set            PASS ast=10 text=10
module docstring delimiters found by text scan                 PASS lines=[1,19,55,69,77,113]
triple-quote delimiters are balanced (text only)               PASS count=20
the pattern line is inside a triple-quoted block (text only)   PASS line196_in_docstring=True
code count agrees across sources (ast-mask vs text-mask)       PASS mask_noncode=8 text=8
docstring-only count is 1 (mask actually masks something)      PASS got=1
total == code + docstring (no third bucket)                    PASS 8 + 1 == 9
docstring edit actually changed the file                       PASS
code count unchanged after docstring-only edit                 PASS 8 -> 8
text-source count also unchanged                               PASS 8 -> 8
docstring-only count DID change (edit was effective)           PASS 1 -> 0
assumption holds: no anchor inside a # comment (else total breaks) PASS found=0
RESULT=PASS
```

**关键改进（相对上轮）**：
- 第 1 条 `ast=10 text=10`：**两个不同信息源（ast / 纯文本）都得出 10 个 docstring 区间**
- 第 3 条 `count=20`：三引号配对数（10 区间 × 2）
- 第 4 条 `line196_in_docstring=True`：**纯文本判定**，不依赖 ast
- 第 5 条 `mask_noncode=8 text=8`：**两种屏蔽方式得同一结果**
- 第 12 条 `found=0`：**直接验证"注释里无锚点"这个假设**（我 §22.5.4 提的）

**这满足了我 §22.3.3 的要求**：「不同信息源」而非「不同写法」。**判定：通过。**

#### 23.3.2 但「新判据自己先错」这件事必须记录

你说：
> **第 2 个 bug 尤其讽刺**：行号锚定判据本身有 bug，报出 `FAIL line196_in_docstring=False`。
> **这正是你说的「工具产生错数」——我加的新判据自己先错了。**

**这个自述是本轮最有价值的元信息。** 它证明了：
1. **新检查器必然有 bug**（不可能一次写对）
2. **只有"跑起来看结果"才能发现**（不能靠 review）
3. **"新判据自己错"是最危险的**——它会让人误信"被测对象有问题"

**我补充一条**：这正是我们**必须收敛**的实证理由。
`verify_g13` 从 61 行 → 185 行 → 加 12 条断言后 8844 B。
**每加一层判据，就多一层"判据本身出错"的风险。**

### 23.4 裁决 (4)：`bcgr-source.md` 行号——**通过，我核实了**

```
62 |```python
63 |import sys, zipfile, re
115 |    main(sys.argv[1], sys.argv[2])
116 |```
总行数 = 126
```
**与你报的「第 62–116 行，代码本体 63–115」完全一致。** 放行条件关闭。

### 23.5 「已知局限清单」增删建议

你拟了 6 条，**我逐条核对，建议删 0 条、改 3 条、增 4 条**。

#### 23.5.1 逐条核对

| # | 你的条目 | 我的判断 |
|---|---|---|
| **L1** | 门禁只覆盖 design-a.md 的伪代码块，不覆盖 C++ 实现（实现还不存在） | **保留，但要改措辞**——「实现还不存在」是**当前状态**，不是**局限**。局限是「门禁的对象是设计文档，不是代码」。 |
| **L2** | `pseudo_lint` 的锚点正则不支持 case/label/初始化/三元 | **保留，但要说清后果**——不是"不支持"，是"**会误匹配**"（我 §18.2.1 实测 5 类）。 |
| **L3** | `verify_g13` 的 docstring 判定依赖 ast 与文本扫描一致；二者同时错时发现不了 | **保留**，但**本轮已部分缓解**（纯文本判据独立于 ast）。应改为「**残余风险**：两者都基于"三引号配对"这一共同假设」。 |
| **L4** | INDEX 的口径 C 是「任一具体形式即算引用」，不区分「强引用/弱引用」 | **保留，且这是重要局限**——`audit×2`（仅 consult-b 提及）与 `cpp×1`（显式文件名）强度不同。 |
| **L5** | 快照回归只覆盖 4 个历史版本，不能保证覆盖所有历史缺陷类型 | **保留**，但**要说清"覆盖什么"**——`KNOWN` 表登记了 4 个版本的已知缺陷 ID，**回归保证的是"这 4 个版本登记的缺陷仍被检出"**，不是"所有缺陷类型"。 |
| **L6** | `state_snapshot` 只记结构指纹，不验证行为 | **保留，措辞准确**。 |

#### 23.5.2 建议新增 4 条

**L7（新增·重要）：门禁的"通过"不等于"设计正确"。**
```
pseudo_lint 检查的是"伪代码结构与文档契约一致"，不检查
"这个契约本身是否适合 SChannel/RDP 场景"。
后者只能靠实测（probe24 等）和人工设计评审。
```
**理由**：这是**最容易被误读的局限**——11 个 exit=0 会让人以为"设计没问题"，
**实际只说明"设计与文档自洽"**。

**L8（新增）：`state_snapshot` 与各门禁的"三值逻辑"覆盖不全。**
```
当前只有 diff_state.py 对"无基线"做了区分（INSTRUMENT NEW IN AFTER）。
其他比较（如 regress 的 KNOWN ⊇ 命中）仍是二值：
"命中"或"未命中"，无法表达"该快照未登记"。
```
**理由**：这是 §22.5.2 规则 I 的**未完成部分**——三值逻辑只在一处实现。

**L9（新增）：审计报告（consult-b.md，约 37 万字节）已超出可通读规模。**
```
新读者无法通读。有效信息分散在 §0-§23。
若需交付，应另出一份"结论摘要"（不超过 10 页）。
```
**理由**：这是**交付物的实际可用性问题**，不是技术缺陷。

**L10（新增）：探针源码 50 个中，24 个无权威结论。**
```
INDEX 已标注来源，但"无结论"的 24 个探针，其验证意图已不可考。
它们只能作为"负证据"（证明某条路走过），不能作为"结论依据"。
```
**理由**：这是 §22.2 讨论的结论，**应显式列入局限**，避免后人误用。

#### 23.5.3 最终建议清单（10 条）

```
L1  门禁对象是 design-a.md 的伪代码块，不是 C++ 实现（实现尚未开始）
L2  pseudo_lint 的语句锚点 (?:^|;|:\s) 会把 case/label/初始化列表/三元误判为语句分隔
L3  verify_g13 的两个信息源都基于"三引号配对"假设；该假设本身错时两者同时错
L4  INDEX 口径 C 不区分强引用（显式文件名）与弱引用（仅 audit 提及）
L5  快照回归保证的是"KNOWN 表登记的 4 个版本缺陷仍被检出"，不是"所有缺陷类型"
L6  state_snapshot 只记结构指纹，不验证行为（行为靠各道门禁）
L7  【新增】门禁通过 = "设计与文档自洽"，不等于"设计适合 SChannel/RDP 场景"
L8  【新增】三值逻辑只在 diff_state 实现；regress 等其他比较仍是二值
L9  【新增】consult-b.md 约 37 万字节，已超出可通读规模，需另出结论摘要
L10 【新增】50 个探针中 24 个无权威结论，只能作负证据，不能作结论依据
```

### 23.6 「终审报告结构」修正建议

你拟的 5 节，**我建议改为 6 节，并调整顺序**：

```diff
  1. 门禁清单（8 道 + 每道保证什么）
  2. 证据文件清单（每个文件证明什么）
  3. 已知局限清单（上面 6 条）
  4. 交付基线（design-a sha + 所有门禁 exit 码 + 快照 sha）
  5. 下一步（TlsTransport 实现，不再打磨工具）
```

**建议改为**：

```
1. 交付基线（先给 sha + exit 码 —— 这是"这批东西是什么"的身份）
2. 门禁清单（10 道 + 每道"保证什么" + "不保证什么"）
3. 证据文件清单（每个文件证明什么 + 可信度等级）
4. 已知局限清单（10 条，按影响排序）
5. 未验证项汇总（历史 §6 U1-U10、§12 G5、§13 H1、§14 J1、§15 K1、§16 N1、§17 P1、§18 Q1、§19 R1、§20 S1 的状态）
6. 下一步（TlsTransport 实现；工具链冻结）
```

**三条修改理由**：

**（1）交付基线放第一**——因为它是"身份"。
报告的第一句话应该是"这批交付物是 sha `CA7955D4…` 的设计文档 + 10 道门禁"，
**而不是"我们有哪些门禁"**（那是方法，不是身份）。

**（2）门禁清单要加"不保证什么"**——只写"保证什么"会让读者高估门禁。
**每条门禁必须有一句"它不管什么"**，例如：
```
pseudo_lint：保证伪代码结构与 §3.3 契约表一致；不保证契约本身合理。
verify_g13：保证 docstring 里的模式不被算进代码计数；不保证 docstring 内容正确。
```

**（3）新增"未验证项汇总"**——这是**最重要的补充**。
我们在 §6–§20 累积了大量 `U1-U10 / G5 / H1 / J1 / K1 / N1 / P1 / Q1 / R1 / S1` 未验证项，
**它们分散在 23 个章节里，没有任何地方汇总**。
**如果不汇总，这些"已知未验证"就变成了"隐藏的未知"。**

**这一节应该列出**：
```
| 编号 | 内容 | 状态 | 阻塞什么 |
|---|---|---|---|
| U1 | TLS1.3 record_sizes | 已关闭（E 表实测） | — |
| J1d | DecryptMessage 是否真返回 SEC_I_NO_RENEGOTIATION | 未验证（C 级） | 1.3 重协商路径的实现 |
| ... | | | |
```

### 23.7 终审裁决：**盖章**

#### 23.7.1 收敛判据复核（三条全部满足）

| 判据 | 定义 | 状态 | 证据 |
|---|---|---|---|
| **A（必要）** | `design-a.md` 连续 ≥3 轮不变 + 所有门禁 exit=0 | ✅ **满足** | mtime 02:33:10，**连续 6 轮未变**；11 个 exit=0 |
| **B（充分）** | 新增缺陷最高级别连续两轮下降 | ✅ **满足** | 第⑱一般 → 第⑲一般 → 第⑳低 → 第㉑**无新增缺陷**（3 条放行条件全部处置：1 条我错、2 条采纳） |
| **C（硬停）** | 无"为通过而改门禁判定" | ✅ **未发生** | 全程无此类改动 |

**判据 B 本轮的形态**：**不是"级别下降"，而是"零新增缺陷"**——这是更强的收敛信号。

#### 23.7.2 本轮处置结果

| 我上轮的放行条件 | 你的处置 | 我的终审 |
|---|---|---|
| ① 口径 B 改 35/15 | **驳回**（2 处 `[READ:probe.cpp:61]`） | **我错，撤回。接受 36/14** |
| ② 「有结论」改 26 | **采纳并已改** | **通过**（我核实 24+2=26，表头也加了「—」说明） |
| ③ 补行号锚定判据 | **采纳并已补**（12/12 PASS） | **通过**（且满足"不同信息源"要求） |

**并且你在驳回 ① 时发现了更严重的问题**：口径 A 漏 10 个真引用 → 新增口径 C（36/14，逐文件给理由）。
**这比我原建议的方案更完整。**

#### 23.7.3 盖章理由

**四条**：

**（1）被审计对象稳定**：`design-a.md` 连续 6 轮未变，sha `CA7955D4…`，11 个门禁全绿。

**（2）缺陷级别已收敛**：本轮零新增缺陷，且我上轮 3 条放行条件中 1 条被正确驳回（证明对方的复核是实质性的，不是走过场）。

**（3）工具链已具备"自我纠错"能力**：
- 本轮你**自己发现**并修正了两个 bug（`l_off()` 字节偏移、单行 docstring 状态机）
- 你**自己发现**了「BEFORE 段混入生成时测量」的问题（§19）
- 你**自己发现**了口径 A 漏 10 个真引用
**这三件事说明规则 A/B/E/F/H/I 已被内化，不再需要我逐条提醒。**

**（4）剩余问题全部为「已知局限」**：
本轮之后无阻断、无严重、无一般级缺陷。
**剩下的都是"任何工具都有的固有局限"**（L1–L10），
**写清楚比无限修补更有价值。**

#### 23.7.4 盖章范围与边界

**本盖章仅覆盖**：

```
✅ 审计结论：design-a.md 的伪代码设计（§3.3/§3.4）与文档契约自洽
✅ 工具链：11 道门禁全绿，且各门禁的"保证/不保证"边界已明确
✅ 证据链：探针源码 50 个 + 输出 + INDEX + 快照 + state 轨迹，可复核
```

**本盖章不覆盖**：

```
❌ design-a.md 的设计是否适合 SChannel/RDP 实际场景（需实测，L7）
❌ C++ 实现是否正确（实现尚未开始，L1）
❌ 未验证项（J1d 等）涉及的行为（需实现期实测）
❌ consult-b.md 的可读性（37 万字节，L9）
```

**换句话说：盖章 = "审计工作完成且结论可信"，不等于 "设计已被证明正确"。**

### 23.8 交付基线（终审快照）

**被审计文档**：
```
tls-backend.design-a.md   1893 行  153606 B
SHA256 CA7955D4DEAED6E3A5FC9AD77B0140D5CC0A6C6E52452E638DD094369715F13F
mtime  2026-10-23 02:33:10（连续 6 轮未变）
```

**门禁脚本**：
```
pseudo_lint.py            31547 B  74625A839289B0C4AEF127EDBEF485C2A425F76E67C1393FDA48ED7618CFC97E
pseudo_lint_redtest.py    10141 B  F193DB4730F8A0B8ABF8CC5A7BF6D0AF487B9B7FEE88ED13495F396D25F8B7D6
verify_elif_semantics.py  23116 B  DC5F13922103F82BCAEFF9D94B2678489CA172B615EFA3B4F031D37852FBE5B0
verify_sideeffect_leaf.py  3616 B  5A162E634C7A19F86DEEA681377BE7058EBED7A8AFFB4798682368C6690C7A13
count_sec_refs.py          3818 B  B35D3373A4BD8FFA58EB5279D886A162C7E81BAD8E1E298CB8F91529F4E16C45
verify_g13.py              8844 B  B043D3A941D947B17F79B0CD8E95C4476EF3067D6838BBD6664E08EC61F0BD19
state_snapshot.py         10856 B  B74DF751E0EFB53969BB59CCF065120FE58686FBBA7D92A30EB6C1E9A6470665
diff_state.py              3705 B  72B27E07C64FA9A330AAF576B639C33EBD885639916C153F99667FA39818B0F4
verify.ps1                10780 B  258811030B7A50CDF1A0590A42F546105E04D7DB475D3D7C0F2D1C0F4F29A583
```

**回归快照（4 个，纳入版本控制）**：
```
design-a.bak.md             92381 B  10B0F3BEC05A9A69
design-a.step7.snapshot.md 112779 B  AD392E0B669AB004
design-a.step7.v2.md       120397 B  66729EE085B00545
design-a.step8.base.md     135988 B  2EAF8060B19C151F
```

**11 个 exit 码**：全部 `0`（其中第 11 项 state-history 为记录，非门禁）。

### 23.9 我方终审自我更正

1. **我在 §22.1.2 犯了一个"同段落自相矛盾"的错**：
   同一节里我先写「22 次出现中有 20 次是假阳性」（正确），
   又写「`probe.cpp` 被算作已引用**完全是因为** `schannel-probe.txt`」（错误——抹掉了 2 次真引用）。
   **根因：我从"计数噪音 20/22"跳跃到"集合该剔除"，但这是两个不同的命题。**
   **教训：计数假阳性 ≠ 集合成员无效。前者说"多数命中是噪音"，后者说"这个文件没被引用"，
   只要有 1 次真引用，集合就该保留。**

2. **我上轮把「口径 B 有缺陷」推广成「口径 A 更保守更可靠」，方向错了。**
   实际是：**口径 A 漏 10 个真引用（假阴性），口径 B 集合正确但计数混杂。**
   **"更严格"不等于"更正确"**——`<stem>.cpp` 更严格，但严格到漏掉真实证据。

3. **我上轮说「不需要我写第三个实现」是对的，但我给的理由（"需要不同信息源"）在你这轮的实现里被验证了**：
   你加的纯文本三引号扫描确实提供了不同信息源（12 条断言里 4 条是纯文本判据）。
   **这说明我的判断方向正确，但当时没有把它变成可执行的验收标准**——
   你把它落地了（`ast=10 text=10` 这条断言就是"两个信息源一致"的直接证据）。

4. **本轮我没有发现新的实质缺陷。**
   我的 3 条放行条件里 1 条错（①）、2 条被采纳（②③），
   **而你在驳回 ① 的过程中发现了更严重的问题（口径 A 漏 10 个）**。
   **这说明：本轮真正的增量来自你的复核，不是我的审计。**
   **这是收敛的典型特征——审计方开始产出"更少但更准确"的意见，而被审计方开始产出"实质性的反驳"。**

### 23.10 终审结论

**盖章。**

**盖章含义（必须与局限清单一起读）**：

> 本审计确认：`design-a.md`（sha `CA7955D4…`）的伪代码设计与其文档契约**自洽**，
> 且支撑该结论的**工具链（11 道门禁）与证据链（50 探针 + 输出 + 快照 + 轨迹）可复核**。
>
> **这不等于**「设计适合 SChannel/RDP 实际场景」（L7），
> **也不等于**「C++ 实现正确」（L1，实现未开始）。
>
> 剩余 10 条已知局限（L1–L10）已记录；未验证项需在实现期用实测关闭。

**建议的下一步（不是"继续打磨工具"）**：
1. **冻结工具链**（`verify.ps1 -PseudoLint` 作为交付门禁，不再修改）
2. **输出「工具链终审报告」**（按 §23.6 的 6 节结构）
3. **进入 TlsTransport 实现**——实现期会发现设计文档的新问题，那是**正常的迭代**，
   但**不应再回头改审计工具**（除非发现"阻断级"缺陷）
