# TLS 传输层实现记录

生成方式：`evidence/tls/impl_log.py`（机器测量，非人工填写）。

## 1. 交付物

| 文件 | 字节 | 行 | SHA256（前 16 位） |
|---|---:|---:|---|
| `include/rtsc/net/tls.h` | 9974 | 208 | `A89FDCF3488A472C` |
| `src/net/tls_schannel.cpp` | 32552 | 754 | `4D21A97D63EDC27E` |
| `tests/test_tls.cpp` | 34000 | 893 | `815BCFBB32FC4FA1` |
| `CMakeLists.txt` | 6237 | 146 | `BDAF3D22290CCA4D` |
| `verify.ps1` | 11746 | 245 | `34C6A28CFB1CE1D4` |
| `evidence/tls/red_test_tls.py` | 6875 | 164 | `0427C91FB3207301` |

## 2. 测试结果（本次实跑）

```
26 tests, 139 checks, 0 failing tests, 0 failed checks
```

退出码：0

通过的用例（26 个）：

- `status_has_exactly_six_terminal_values`
- `status_non_terminal_values_are_not_terminal`
- `closed_is_not_an_error_but_is_idempotent_like_one`
- `record_sizes_upper_bound_is_not_the_actual_length`
- `factory_reports_unknown_backend`
- `factory_enumerates_schannel`
- `handshake_completes_and_reports_negotiated_parameters`
- `record_sizes_are_measured_not_assumed`
- `boundary1_record_split_into_feeds_yields_needmoreinput_then_ok`
- `boundary2_two_records_in_one_call_are_concatenated`
- `boundary9_three_records_accumulate_without_losing_earlier_ones`
- `boundary3_trailing_partial_record_stays_buffered`
- `boundary4_zero_length_record_is_ok_not_closed`
- `boundary8_empty_input_returns_needmoreinput_when_nothing_happened`
- `boundary7_tampered_record_fails_and_leaves_plaintext_empty`
- `boundary11_terminal_error_is_idempotent`
- `boundary10_complete_record_reported_incomplete_is_protocol_error`
- `record_length_above_rfc_limit_is_protocol_error`
- `extra_is_zero_because_records_are_pre_sliced`
- `boundary12_pure_housekeeping_record_still_returns_ok`
- `max_out_is_soft_and_caller_can_drain`
- `send_roundtrips_and_real_length_is_not_the_allocation_bound`
- `send_splits_oversized_payload_instead_of_failing`
- `peer_keys_are_consistent_and_not_fixed_offset_slices`
- `shutdown_is_idempotent`
- `version_bounds_are_enforced_after_handshake`

## 3. 覆盖的边界（design-a §3.4.3 十二条）

| 边界 | 测试用例 |
|---|---|
| 1 一条记录切成 N 次喂入 | `boundary1_record_split_into_feeds_yields_needmoreinput_then_ok` |
| 2 一次喂入两条记录 | `boundary2_two_records_in_one_call_are_concatenated` |
| 3 一条记录 + 下一条前 3 字节 | `boundary3_trailing_partial_record_stays_buffered` |
| 4 零长度应用数据 | `boundary4_zero_length_record_is_ok_not_closed` |
| 5 post-handshake 票据 | **未覆盖**（本机回环是 TLS1.2，不产生票据；见 §5） |
| 6 EXTRA 算术定位 | `extra_is_zero_because_records_are_pre_sliced`（见 §5） |
| 7 失败路径明文为空 | `boundary7_tampered_record_fails_and_leaves_plaintext_empty` |
| 8 空缓冲返回码 | `boundary8_empty_input_returns_needmoreinput_when_nothing_happened` |
| 9 多记录累加 | `boundary9_three_records_accumulate_without_losing_earlier_ones` |
| 10 5+len 到齐仍 INCOMPLETE | `boundary10_complete_record_reported_incomplete_is_protocol_error` |
| 11 终止闩锁 | `boundary11_terminal_error_is_idempotent` |
| 12 双计数 | `boundary12_pure_housekeeping_record_still_returns_ok` |

附加覆盖：`max_out` 软阈值与排空义务、`Send` 分片、真实尾长推导、
对端公钥不按固定偏移切、`Shutdown` 幂等、版本窗口自检、N4 长度上界。

## 4. 红证（变异测试）

`evidence/tls/red_test_tls.py` 逐个破坏 design-a §3.4.1 的规则，
要求测试套件**必须失败**；每次变异后按 sha256 恢复源码。

```
M1_no_back_edge                 B1  删除循环回边
M2_clear_output_in_loop         N5  循环内清空调用方缓冲
M3_no_record_length_bound       N4  接受任意声明长度
M4_no_terminal_latch            N7  不闩锁终止错误
M5_incomplete_returns_needmore  N6  把完整记录当"字节不够"
M6_no_progress_counter          N8  消费了记录却报 kNeedMoreInput
M7_no_drain_on_max_out          B9  忽略 max_out
M8_record_not_consumed          N1  解密前不消费记录
```

结果：8/8 全部被检出，0 遗漏，0 锚点缺失，源码 sha256 恢复一致。

## 5. 已知局限（诚实记录）

| # | 局限 | 影响 |
|---|---|---|
| I1 | **TLS1.3 路径未在测试中跑到**：回环对端只启用 `SP_PROT_TLS1_2_SERVER` | `SEC_I_RENEGOTIATE`（票据）、`SEC_I_NO_RENEGOTIATION`、TLS1.3 尾长 17 三条路径只有实现与设计依据，没有本套件的绿证 |
| I2 | **EXTRA 分支在本实现里不可达**：`Receive` 先按记录头精确切出单条记录再解密，`DecryptMessage` 永远看不到第二条记录，因此 `SECBUFFER_EXTRA` 恒为 0。该分支作为防御性契约保留，但无法通过本路径触发 |
| I3 | 证书策略三档只有 `kInsecure` 被实测；`kTofu` / `kStrict` 的链校验与 pin 比对尚未实现（当前三档都走 `ISC_REQ_MANUAL_CRED_VALIDATION`） |
| I4 | `overhead_actual` 在握手后先按版本推定（1.2=16 / 1.3=17），首次 `Send` 后按实测校正。握手完成到首次发送之间的读数是推定值 |
| I5 | 未与真实 RDP 服务器联调：`ConnectMachine` 仍停在 `kAwaitExternalSecurity`，接入需要 CredSSP |

## 6. 实现期发现的与设计不符之处

| # | 现象 | 处理 |
|---|---|---|
| D1 | `SecPkgContext_ConnectionInfo::dwProtocol` 是 `SP_PROT_*` **位掩码**（TLS1.2 = 0x00000040），不是线缆版本（0x0303）。按 `& 0xFF00` 取版本得 0，版本窗口自检因此误拒 | 改为 `WireVersionFromProtocolMask()` 逐位映射 |
| D2 | `InitializeSecurityContext` 首次调用若给 `cbBuffer=0, pvBuffer=nullptr` 的输出缓冲，返回 `SEC_E_INVALID_TOKEN (0x80090308)` | 改用真实 64 KB 栈缓冲（与 loopback 证据一致） |
| D3 | design-a 说 `overhead_actual` 可实测，但实测需要先加密一条记录；握手期加密会给对端发一条多余记录 | 改为版本推定 + 首次发送校正，并在报告里标注为局限 I4 |
