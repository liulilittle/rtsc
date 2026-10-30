# RD Gateway RDGSP — 阶段 2 握手/通道接线证据

目标：`C:\Windows\System32\mstscax.dll`
SHA-256：`d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05`
取证：REA / Ghidra 12.1.4 `procedure_pseudo_code`，只读。
本文只覆盖**阶段 2**（握手状态机 + 双通道请求构造 + 101 升级），阶段 1 的协议层见 `gateway-rdgsp-design.md`。

---

## 1. IN 通道请求构造 — `FUN_1801bc14c`

反编译（92 行）关键片段：

```c
int FUN_1801bc14c(longlong param_1, longlong *param_2, longlong *param_3)
{
  ...
  uVar1 = *(undefined2 *)(param_1 + 0x6a6);          // IN 通道端口
  ...
  uVar2 = (**(*param_2 + 0x30))(param_2, &local_res8, param_1 + 0x28c, uVar1);
  if (iVar3 == 0) {
    uVar5 = (**(*local_res8 + 0x18))(
        local_res8, param_3,
        L"RDG_IN_DATA",              // ← HTTP 方法硬编码
        param_1 + 0xe14,             // ← 预构造的 URL
        -(ulonglong)(param_1 != 0) & param_1 + 8U,
        *(int *)(param_1 + 0x6a8) != 0,   // ← 是否 HTTPS
        0xffffffffffffffff);
```

**结论**：
- IN 通道 HTTP 方法 **硬编码 `RDG_IN_DATA`**，无分支。
- `param_1 + 0x6a6` = IN 通道端口，`param_1 + 0x28c` = 网关主机，`param_1 + 0xe14` = 预构造 URL。
- `*(int *)(param_1 + 0x6a8)` 是 HTTPS 开关（非 0 = https）。

## 2. OUT 通道请求构造 — `FUN_1801bc3c4`

反编译（99 行）关键片段：

```c
int FUN_1801bc3c4(longlong param_1, longlong *param_2, longlong *param_3)
{
  ...
  uVar4 = (**(*param_2 + 0x30))(param_2, plVar1, param_1 + 0x28c,
                                *(undefined2 *)(param_1 + 0x6a4));  // OUT 端口
  if (iVar2 == 0) {
    iVar2 = *(int *)(param_1 + 0x1440);      // ← 传输模式选择子
    if (iVar2 == 0) {
LAB_1801bc48d:
      pwVar3 = L"GET";                       // 模式 0 → GET
    }
    else if (iVar2 == 1) {
      pwVar3 = L"RDG_OUT_DATA";              // 模式 1 → RDG_OUT_DATA
    }
    else {
      if (iVar2 != 2) goto LAB_1801bc48d;    // 其它 → 回退 GET
      pwVar3 = L"POST";                      // 模式 2 → POST
    }
    uVar4 = (**(*plVar1 + 0x18))(*plVar1, param_3, pwVar3, param_1 + 0xe14, ...);
```

**结论（`*(param_1 + 0x1440)` 是 OUT 通道的传输模式选择子）**：

| 值 | HTTP 方法 | 备注 |
|---|---|---|
| 0 | `GET` | 也是所有未知值的回退（`LAB_1801bc48d`） |
| 1 | `RDG_OUT_DATA` | 标准 RDGSP 双通道模式 |
| 2 | `POST` | |
| 其它 | `GET`（`goto LAB_1801bc48d`） | |

注意：`0x1440` 同时被 `FUN_1801c3818` 用作 `if (*(int *)(param_1 + 0x1440) != 2) { *(param_1 + 0xd24) = 9; } else { *(param_1 + 0xd24) = 0xf; }` 的判据（阶段 1 已记录）。

## 3. URL 构造 — `FUN_1801bd574`

反编译（90 行）关键片段：

```c
int FUN_1801bd574(longlong param_1, longlong param_2, undefined8 param_3,
                  ushort param_4, wchar_t *param_5)
{
  lVar4 = param_1 + 0x28c;                 // 网关主机
  pwVar5 = L"https";
  uVar1 = (uint)param_4;                   // 端口
  if (param_5 == 0) {
    pwVar6 = L"/remoteDesktopGateway/";    // 默认路径
    if (*(int *)(param_1 + 0x6a8) == 0) {
      pwVar5 = L"http";                    // 0x6a8 == 0 → 明文 http
    }
    uVar2 = StringCchPrintf(param_2, 0x30c, L"%s://%s:%hu%s",
                            pwVar5, lVar4, uVar1, L"/remoteDesktopGateway/");
    ...
    // 第二段：写入 param_1 + 0xe14（即请求模板里用的 URL 缓冲）
    uVar2 = StringCchPrintf(param_1 + 0xe14, 0x30c, &DAT_1806b9a4c,
                            param_5, lVar4, uVar1, pwVar6);
```

**结论**：
- URL 格式 **`%s://%s:%hu%s`**（scheme / host / port / path）。
- scheme = `https`，仅当 `*(param_1 + 0x6a8) == 0` 时降为 `http`。
- 默认路径 `/remoteDesktopGateway/`。
- `param_5` 非空时用自定义路径（`&DAT_1806b9a4c` 格式）。
- **重要**：`http` 明文模式是出厂内建能力（`0x6a8 == 0`），可用于本地桩测试，无需伪造 TLS。

## 4. 响应处理与 101 升级 — `FUN_1801bfd60`（779 行）

关键片段：

```c
  // :147  认证状态推进
  else if (*(int *)(param_1 + 0xd20) == 1) {
      *(undefined4 *)(param_1 + 0xd20) = 2;
      goto LAB_1801bffa0;
  }
  ...
  if (bVar2) {
    iVar5 = (int)local_4a8;                 // 状态码
    ...
    if ((int)local_4a8 == 0x65) {           // :158  ← 101 Switching Protocols
      if (local_4b8 != 0) {                 // :159  ← local_4b8 = 该响应属于 IN 通道
        uVar16 = FUN_1801bdd8c(lVar1, param_4, 0x65);
        // :163
        L"Server returned switch protocols for IN channel. errorCode=0x%x", 0x65);
        ...
        goto LAB_1801c0336;                 // 失败路径
      }
      // :177  OUT 通道：接受升级
      *(longlong **)(param_1 + 0xdf0) = param_5;   // 升级后的流对象
      if (param_5 == 0) goto LAB_1801c0f4b;
      (**(*param_5))(param_5);
      (**(*(*(param_1 + 0xdf0)) + 0x18))();
      *(undefined4 *)(param_1 + 0xd20) = 4;        // 认证/隧道类型 = 4
      *(undefined4 *)(param_1 + 0xd24) = 1;        // ← OUT 通道状态 = 1（Upgraded）
      *(undefined4 *)(param_1 + 0xd1c) = 0xb;      // 阶段 = 0xb（ready/reading）
      *(undefined4 *)(param_1 + 0xd38) = 0;        // ← 重试计数清零
      FUN_1801bdc9c(lVar1, 0, 3, 2);               // notify(0, 3, 2)
      ...
    }
    else if ((int)local_4a8 == 200) {              // :192  正常 200
```

**结论**：
1. **101 升级只对 OUT 通道有效**。IN 通道收到 101 → 报错 `Server returned switch protocols for IN channel`（`0x1806cf530`）并走失败路径。
2. OUT 升级成功后状态：`0xd20 = 4`（隧道类型）、`0xd24 = 1`（OUT=Upgraded）、`0xd1c = 0xb`（阶段）、`0xd38 = 0`（重试计数清零）。
3. 状态码取自 `local_4a8`，是**数值**比较（`== 0x65` / `== 200`）—— 这印证阶段 1 的自我纠错：不能用字符串是否存在来判定 101 支持。
4. 升级后的 RDP 字节流通过 `param_1 + 0xdf0` 的流对象读写，**不再经过 chunked 封装**。

## 5. 认证状态机（`0xd20` 隧道/认证类型）

来自 `FUN_1801bfd60` 与阶段 1 的 `FUN_1801c3818` 交叉观察：

| `0xd20` 值 | 含义 | 证据 |
|---|---|---|
| 1 | 初始/待认证 | `FUN_1801bfd60:147` `== 1` → 置 2 |
| 2 | 认证中（401 已收到，正在回应） | `FUN_1801bfd60:148` |
| 4 | 已升级（101 完成） | `FUN_1801bfd60:181` |
| 8 / 0x10 / 0x40 / 0x80 | 原生 / SMARTCARD / claims / CONNID | `FUN_1801c3818:97-118` 的状态分发 + 证据串 |

`0xd24`（OUT 通道状态）：`1` = Upgraded；`0xb` = ready/reading；`0x9`/`0xf` = init（由 `0x1440 != 2` 区分）；`0xc` = reading；`0xd`/`0xe` = closing/closed。

`0xd1c`（阶段）：`0xb` = ready；`0x10` = 特定等待态（`FUN_1801bfd60:194`）。

`0xd38` = IN 通道重试计数（101 成功时清零，`FUN_1801bfd60:184`）。

## 6. 401 处理与重试上限

证据串（阶段 1 已记录）：
- `CAAHttpClientRawTransport::ProcessResponse401 CurrentRetryCount=%d is larger than MaxRetryCount=%d`（`0x1806d29d0`）
- `CAAHttpClientRawTransport::ProcessResponse307`（`0x1806d2d10`）

**结论**：401 有显式重试上限（`MaxRetryCount`），不是无限重试。具体上限数值 UNVERIFIED（需读 ProcessResponse401 的立即数）。

## 7. 对阶段 2 实现的直接约束

| 约束 | 依据 |
|---|---|
| IN 通道方法固定 `RDG_IN_DATA` | §1 `FUN_1801bc14c` 硬编码 |
| OUT 通道方法由模式选择：0/其它→`GET`、1→`RDG_OUT_DATA`、2→`POST` | §2 `FUN_1801bc3c4` |
| URL = `scheme://host:port/remoteDesktopGateway/` | §3 `FUN_1801bd574` |
| `http` 明文模式内建（`0x6a8 == 0`），可作桩测试路径 | §3 |
| **101 只允许 OUT 通道；IN 收到 101 必须报错** | §4 `:159-170` |
| 升级后走裸字节流，不经 chunked | §4 `:177-186` |
| 401 重试必须有上限 | §6 |
| 状态码按数值判定，不得按文本匹配 | §4 `:158/:192` |

## 8. UNVERIFIED（阶段 2 需继续取证或标注）

- `MaxRetryCount` 的具体数值。
- 401 的 `WWW-Authenticate` 具体 scheme 优先级（NTLM vs Negotiate）。
- 双通道是否复用同一 TCP 连接（静态证据不足；`SendHttpRequest`/`IoReadDataAsync` 共用 `+0xdf8` 槽，但双 request 句柄并存）。
- OUT 响应体的 chunked 与否（仅 IN 有 `transfer-encoding` 证据）。
- `0x1440` 各模式的外部配置入口（哪个 RDP 文件/属性驱动）。
- 升级后 `param_1 + 0xdf0` 流对象的帧格式（是否 WebSocket 帧）。

## 9. 复现命令

```
REA open_binary C:\Windows\System32\mstscax.dll
REA procedure_pseudo_code 0x1801bc14c   # IN 通道请求
REA procedure_pseudo_code 0x1801bc3c4   # OUT 通道请求（0x1440 选择）
REA procedure_pseudo_code 0x1801bd574   # URL 构造
REA procedure_pseudo_code 0x1801bfd60   # 响应处理 + 101 分支
REA procedure_pseudo_code 0x1801c3818   # 头部构造（阶段 1 已用）
REA procedure_pseudo_code 0x1801bdd8c   # 状态码 → HRESULT
```
