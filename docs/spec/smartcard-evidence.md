# 智能卡虚拟通道证据（smartcard-evidence）

依据优先级：[MS-RDPESC] 官方规范 > FreeRDP `channels/rdpdr/client/smartcard_*`
交叉核对 > 本项目测试。

## 1. SCARD_IOCTL_ISVALIDCONTEXT（批134，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.3 `SCARD_IOCTL_ISVALIDCONTEXT`（IOCTL 0x0009001C）：
  检查先前由 `SCARD_IOCTL_ESTABLISHCONTEXT` 建立的上下文是否仍有效；
  `Context_Call.Context` 必须存在于 rgSCardContextList 且通信通道仍在。
- 请求结构：[MS-RDPESC] 2.2.2.2 `Context_Call`（`REDIR_SCARDCONTEXT Context`），
  与 `SCARD_IOCTL_RELEASECONTEXT` 相同。
- 返回结构：[MS-RDPESC] 2.2.3.3 `Long_Return`（仅 `ReturnCode`）。
  成功为 SCARD_S_SUCCESS，否则为智能卡错误或 Winerror.h 返回码。

**当前实现缺口**：`ScardIoctl::kIsValidContext` 已在枚举与名称表中，但
`IsSupportedScardIoctl` 拒绝它，`rdpdr_client` 也没有分派分支；服务器调用会
得到 STATUS_UNSUCCESSFUL 而不是 Long_Return。

**本批改动**：
- `proto/smartcard.cpp`：`IsSupportedScardIoctl` 接受 kIsValidContext；
  `ParseScardCall` 复用 `ParseContextCall`；`EncodeScardReturn` 复用
  Long_Return 分支。
- `smartcard::ISmartCardBackend` 新增 `IsValidContext`；Win32 后端动态解析
  `SCardIsValidContext`，Null 后端返回 SCARD_E_INVALID_HANDLE。
- `rdpdr_client` 新增 kIsValidContext 分派。

**验收**：proto 解析/编码用例、通道分派用例（成功与失败返回码）；
变异 M48（删除分派分支）必须转红。

## 2. SCARD_IOCTL_GETATTRIB（批135，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.38 `SCARD_IOCTL_GETATTRIB`（IOCTL 0x000900D8）。
- 请求：[MS-RDPESC] 2.2.2.21 `GetAttrib_Call`
  `{ REDIR_SCARDHANDLE hCard; unsigned long dwAttrId; long fpbAttrIsNULL;
     unsigned long cbAttrLen; }`。
- 返回：[MS-RDPESC] 2.2.3.12 `GetAttrib_Return`
  `{ long ReturnCode; [range(0,65536)] unsigned long cbAttrLen;
     [unique][size_is(cbAttrLen)] byte *pbAttr; }`。
- 语义：
  - `fpbAttrIsNULL=TRUE`：只返回长度（pbAttr 为 NULL）。
  - `fpbAttrIsNULL=FALSE` 且 `cbAttrLen=0`：调用成功，cbAttrLen=数据长度，
    pbAttr 为 NULL。
  - 数据长度超过 `cbAttrLen`：ReturnCode=SCARD_E_INSUFFICIENT_BUFFER
    (0x80100008)。
  - `cbAttrLen=0xFFFFFFFF`（SCARD_AUTOALLOCATE）：任意长度都可返回。

**当前实现缺口**：枚举未包含 GETATTRIB，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kGetAttrib、GetAttrib_Call 解析、GetAttrib_Return 编码
  （Result + cbAttrLen + [unique] pbAttr）。
- `ISmartCardBackend` 新增 `GetAttrib`；Win32 后端动态解析 `SCardGetAttrib`；
  Null 后端返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派：长度探测（NULL/0 容量）返回长度 + NULL；
  超容量返回 SCARD_E_INSUFFICIENT_BUFFER；否则返回数据。

**验收**：proto 解析/编码、通道成功/长度探测/超容量/失败码；变异 M49
（忽略 fpbAttrIsNULL 仍返回数据）必须转红。
## 3. SCARD_IOCTL_SETATTRIB（批136，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.39 `SCARD_IOCTL_SETATTRIB`（IOCTL 0x000900DC）。
- 请求：[MS-RDPESC] 2.2.2.22 `SetAttrib_Call`
  `{ REDIR_SCARDHANDLE hCard; unsigned long dwAttrId;
     [range(0,65536)] unsigned long cbAttrLen;
     [size_is(cbAttrLen)] const byte* pbAttr; }`。
- 返回：[MS-RDPESC] 2.2.3.3 `Long_Return`（仅 ReturnCode）。

**交叉依据**（FreeRDP `libfreerdp/utils/smartcard_pack.c`
`smartcard_unpack_set_attrib_call`）：读取 handles、dwAttrId、cbAttrLen、
pbAttr 指针与 NDR 数组；NDR 数组长度必须与 cbAttrLen 一致（FreeRDP 3.20.1
修复的堆越界正是长度不一致导致）。本项目按“NDR Length 必须等于 cbAttrLen”
拒绝畸形输入。

**当前实现缺口**：枚举未包含 SETATTRIB，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kSetAttrib、SetAttrib_Call 解析（长度一致性校验）、
  Long_Return 编码。
- `ISmartCardBackend` 新增 `SetAttrib`；Win32 后端动态解析 `SCardSetAttrib`；
  Null 后端返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/长度不一致拒绝/返回编码、通道成功与失败；变异 M50
（删除 SETATTRIB 分派）必须转红。
## 4. SCARD_IOCTL_LOCATECARDSA（批137，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.21 `SCARD_IOCTL_LOCATECARDSA`（IOCTL 0x00090098）。
- 请求：[MS-RDPESC] 2.2.2.9 `LocateCardsA_Call`
  `{ REDIR_SCARDCONTEXT Context; [range(0,65536)] unsigned long cBytes;
     [size_is(cBytes)] const byte* mszCards;
     [range(0,10)] unsigned long cReaders;
     [size_is(cReaders)] ReaderStateA* rgReaderStates; }`。
  `mszCards` 是 ANSI 多字符串（卡名，须已在 Smart Cards for Windows 注册）。
- 返回：[MS-RDPESC] 2.2.3.5 `LocateCards_Return`
  `{ long ReturnCode; [range(0,10)] unsigned long cReaders;
     [size_is(cReaders)] ReaderState_Return* rgReaderStates; }`，
  与 `GetStatusChange_Return` 同构。

**交叉依据**（FreeRDP `libfreerdp/utils/smartcard_pack.c`
`smartcard_unpack_locate_cards_a_call`，2026-11-07 下载核对）：
- 线上结构**只有 REDIR_SCARDCONTEXT**，没有 hCard（FreeRDP 的 IDL 声明
  `Handles_Call` 与实现不符，实现只解 context）。
- `cBytes` 上限 65536；`cReaders` 上限 10；`mszCards` 的 NDR 长度必须等于
  `cBytes`（`smartcard_ndr_read_ex` 的 NDR_PTR_SIMPLE 分支强制 `len == min`）。
- `rgReaderStates` 的数组 MaxCount 必须等于 `cReaders`；每个元素的
  `szReader` 是 NDR_PTR_FULL 字符串，空指针元素被忽略。
- 返回编码：`ReturnCode != 0` 时 `cReaders` 写 0、指针写 NULL
  （`smartcard_pack_locate_cards_return`）。

**当前实现缺口**：枚举未包含 LOCATECARDSA，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kLocateCardsA、LocateCardsA_Call 解析（复用
  ReaderStateA 数组解析）、LocateCards_Return 编码（与 GetStatusChange 共用）。
- `ISmartCardBackend` 新增 `LocateCards`；Win32 后端动态解析
  `SCardLocateCardsA`；Null 后端返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/长度不一致拒绝/上限拒绝/返回编码；通道成功与失败；
变异 M51（删除 LOCATECARDS 分派）必须转红。
## 5. SCARD_IOCTL_READCACHEA（批138，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.42 `SCARD_IOCTL_READCACHEA`（IOCTL 0x000900F0）。
- 请求：[MS-RDPESC] 2.2.2.25 `ReadCacheA_Call`
  `{ [string] char* szLookupName; ReadCache_Common Common; }`；
  `ReadCache_Common`（2.2.1.9）
  `{ REDIR_SCARDCONTEXT Context; UUID* CardIdentifier;
     unsigned long FreshnessCounter; long fPbDataIsNULL;
     unsigned long cbDataLen; }`。
  `fPbDataIsNULL=1` 表示只要长度；`cbDataLen` 此时必须忽略；
  `cbDataLen=0xFFFFFFFF` 表示 SCARD_AUTOALLOCATE。
- 返回：[MS-RDPESC] 2.2.3.1 `ReadCache_Return`
  `{ long ReturnCode; [range(0,65536)] unsigned long cbDataLen;
     [unique] [size_is(cbDataLen)] byte* pbData; }`。

**交叉依据**（FreeRDP `smartcard_unpack_read_cache_a_call` /
`smartcard_pack_read_cache_return`，2026-11-07 核对）：
- 线上顺序是 **szLookupName 指针在最前**，随后 Context、CardIdentifier 指针、
  FreshnessCounter、fPbDataIsNULL、cbDataLen；referent 顺序同指针顺序。
- UUID referent 是 16 字节定长（NDR_PTR_FIXED），无长度前缀。
- 返回：`ReturnCode != 0` 时 cbDataLen 写 0、指针写 NULL；cbDataLen > 65536
  视为编码失败。

**当前实现缺口**：枚举未包含 READCACHEA，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kReadCacheA、ReadCacheA_Call 解析（UUID 16 字节）、
  ReadCache_Return 编码（长度探测/数据/失败三态）。
- `ISmartCardBackend` 新增 `ReadCache`；Win32 后端动态解析
  `SCardReadCacheA`（含 SCARD_AUTOALLOCATE）；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/空指针拒绝/精确返回字节/探测/失败；通道成功、探测、
失败；变异 M52（删除 READCACHE 分派）必须转红。
## 6. SCARD_IOCTL_WRITECACHEA（批139，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.44 `SCARD_IOCTL_WRITECACHEA`（IOCTL 0x000900F8）。
- 请求：[MS-RDPESC] 2.2.2.27 `WriteCacheA_Call`
  `{ [string] char* szLookupName; WriteCache_Common Common; }`；
  `WriteCache_Common`（2.2.1.10）
  `{ REDIR_SCARDCONTEXT Context; UUID* CardIdentifier;
     unsigned long FreshnessCounter;
     [range(0,65536)] unsigned long cbDataLen;
     [unique] [size_is(cbDataLen)] byte* pbData; }`。
- 返回：[MS-RDPESC] 2.2.3.3 `Long_Return`（仅 ReturnCode）。

**交叉依据**（FreeRDP `smartcard_unpack_write_cache_a_call`，2026-11-07 核对）：
- 线上顺序：szLookupName 指针、Context、CardIdentifier 指针、
  FreshnessCounter、cbDataLen、pbData 指针；referent 顺序同指针顺序。
- cbDataLen 上限 65536；pbData 的 NDR 长度必须等于 cbDataLen；
  pbData 是 [unique]，空指针合法（cbDataLen 必须为 0）。

**当前实现缺口**：枚举未包含 WRITECACHEA，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kWriteCacheA、WriteCacheA_Call 解析（UUID 16 字节、
  pbData 长度一致性）、Long_Return 编码。
- `ISmartCardBackend` 新增 `WriteCache`；Win32 后端动态解析
  `SCardWriteCacheA`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/空指针拒绝/上限拒绝/长度不一致拒绝/空数据；通道成功与
失败；变异 M53（删除 WRITECACHE 分派）必须转红。
## 7. SCARD_IOCTL_GETREADERICON（批140，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.47 `SCARD_IOCTL_GETREADERICON`（IOCTL 0x00090104）。
- 请求：[MS-RDPESC] 2.2.2.31 `GetReaderIcon_Call`
  `{ REDIR_SCARDCONTEXT Context; [string] wchar_t* szReaderName; }`。
- 返回：[MS-RDPESC] 2.2.3.14 `GetReaderIcon_Return`
  `{ long ReturnCode; [range(0,4194304)] unsigned long cbDataLen;
     [unique, size_is(cbDataLen)] byte* pbData; }`。

**交叉依据**（FreeRDP `smartcard_unpack_get_reader_icon_call` /
`smartcard_pack_get_reader_icon_return` / `smartcard_GetReaderIcon_Call`，
2026-11-07 核对）：
- 请求线上：Context、szReaderName 指针、context referent、WCHAR [string]
  referent；WCHAR 的 Length/Offset/ActualCount 以**字符**为单位，数据为
  UTF-16LE，按 4 字节对齐。
- 客户端调用 `SCardGetReaderIconW` 时用 SCARD_AUTOALLOCATE，成功后用
  SCardFreeMemory 释放。
- 返回：ReturnCode != 0 时 cbDataLen 写 0、指针写 NULL；cbDataLen 上限
  4194304。

**当前实现缺口**：枚举未包含 GETREADERICON，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kGetReaderIcon、GetReaderIcon_Call 解析
  （WCHAR [string]）、GetReaderIcon_Return 编码（上限 4 MiB）。
- `ISmartCardBackend` 新增 `GetReaderIcon`；Win32 后端动态解析
  `SCardGetReaderIconW`（SCARD_AUTOALLOCATE + SCardFreeMemory）；
  Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/空指针拒绝/缺失 NUL 拒绝/精确返回字节/失败/超限；
通道成功与失败；变异 M54（删除 GETREADERICON 分派）必须转红。
## 8. SCARD_IOCTL_GETDEVICETYPEID（批141，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.48 `SCARD_IOCTL_GETDEVICETYPEID`（IOCTL 0x00090108）。
- 请求：[MS-RDPESC] 2.2.2.32 `GetDeviceTypeId_Call`
  `{ REDIR_SCARDCONTEXT Context; [string] wchar_t* szReaderName; }`。
- 返回：[MS-RDPESC] 2.2.3.15 `GetDeviceTypeId_Return`
  `{ long ReturnCode; unsigned long dwDeviceId; }`。

**交叉依据**（FreeRDP `smartcard_unpack_get_device_type_id_call` /
`smartcard_pack_device_type_id_return` / `smartcard_GetDeviceTypeId_Call`，
2026-11-07 核对）：
- 请求线上与 GetReaderIcon_Call 同构（Context + WCHAR [string]），
  没有 hCard。
- 返回**无论成功失败都写 dwDeviceId**（失败时为 0）。
- Win32 调用 `SCardGetDeviceTypeIdW`。

**当前实现缺口**：枚举未包含 GETDEVICETYPEID，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kGetDeviceTypeId、GetDeviceTypeId_Call 解析
  （复用 GetReaderIcon 的 Context+WCHAR 路径）、GetDeviceTypeId_Return 编码。
- `ISmartCardBackend` 新增 `GetDeviceTypeId`；Win32 后端动态解析
  `SCardGetDeviceTypeIdW`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/返回字节（成功与失败都含 dwDeviceId）；通道成功与失败；
变异 M55（删除 GETDEVICETYPEID 分派）必须转红。
## 9. SCARD_IOCTL_GETTRANSMITCOUNT（批142，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.41 `SCARD_IOCTL_GETTRANSMITCOUNT`（IOCTL 0x00090100）。
- 请求：[MS-RDPESC] 2.2.2.29 `GetTransmitCount_Call`
  `{ REDIR_SCARDHANDLE hCard; }`（REDIR_SCARDHANDLE 2.2.1.2 内含
  REDIR_SCARDCONTEXT）。
- 返回：[MS-RDPESC] 2.2.3.13 `GetTransmitCount_Return`
  `{ long ReturnCode; unsigned long cTransmitCount; }`。

**交叉依据**（FreeRDP `smartcard_pack_get_transmit_count_return` /
`smartcard_GetTransmitCount_Call`，2026-11-07 核对）：
- 返回**无论成功失败都写 cTransmitCount**（失败时为 0）。
- Win32 调用 `SCardGetTransmitCount(hCard, &count)`，参数是卡句柄。

**文档更正（同批）**：
- 3.1.4 的编号是**章节号**，不是 IOCTL 表的 Function number。此前第 5-8 节
  误把 Function number（60/62/65/66）写成章节号，已更正为
  3.1.4.42 / 3.1.4.44 / 3.1.4.47 / 3.1.4.48；GetDeviceTypeId_Return 的
  章节号更正为 2.2.3.15。

**当前实现缺口**：枚举未包含 GETTRANSMITCOUNT，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kGetTransmitCount、GetTransmitCount_Call 解析
  （REDIR_SCARDHANDLE）、GetTransmitCount_Return 编码。
- `ISmartCardBackend` 新增 `GetTransmitCount`；Win32 后端动态解析
  `SCardGetTransmitCount`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/返回字节（成功与失败都含 cTransmitCount）；通道成功与
失败；变异 M56（删除 GETTRANSMITCOUNT 分派）必须转红。
## 10. SCARD_IOCTL_LOCATECARDSBYATRA（批143，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.25 `SCARD_IOCTL_LOCATECARDSBYATRA`（IOCTL 0x000900E8）。
- 请求：[MS-RDPESC] 2.2.2.23 `LocateCardsByATRA_Call`
  `{ REDIR_SCARDCONTEXT Context; [range(0,1000)] unsigned long cAtrs;
     [size_is(cAtrs)] LocateCards_ATRMask* rgAtrMasks;
     [range(0,10)] unsigned long cReaders;
     [size_is(cReaders)] ReaderStateA* rgReaderStates; }`。
- `LocateCards_ATRMask`（2.2.1.6）
  `{ [range(0,36)] unsigned long cbAtr; byte rgbAtr[36]; byte rgbMask[36]; }`。
- 返回：[MS-RDPESC] 2.2.3.5 `LocateCards_Return`（与 GetStatusChange 同构）。

**交叉依据**（FreeRDP `smartcard_unpack_locate_cards_by_atr_a_call` /
`smartcard_ndr_read_atrmask`，2026-11-07 核对）：
- 线上顺序：Context、cAtrs、rgAtrMasks 指针、cReaders、rgReaderStates 指针；
  referent 顺序：context、ATR mask 数组、ReaderStateA 数组。
- cAtrs 上限 1000；cReaders 上限 10；mask 数组的 NDR Length 是**元素个数**
  （必须等于 cAtrs），每个元素 76 字节（4+36+36）。
- cbAtr > 36 必须拒绝（越界读）；掩码指针与 cAtrs 必须同时为零或同时非零。

**当前实现缺口**：枚举未包含 LOCATECARDSBYATRA，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kLocateCardsByAtrA、LocateCardsByAtrA_Call 解析
  （ATR mask 数组 + 复用 ReaderStateA 数组）、LocateCards_Return 编码复用。
- `ISmartCardBackend` 新增 `LocateCardsByAtr`；Win32 后端动态解析
  `SCardLocateCardsByATRA`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/上限拒绝/cbAtr 越界拒绝/数组计数不一致拒绝/指针计数
不一致拒绝；通道成功与失败；变异 M57（删除分派）必须转红。
## 11. SCARD_IOCTL_ACCESSSTARTEDEVENT（批144，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.4 `SCARD_IOCTL_ACCESSSTARTEDEVENT`（IOCTL 0x000900E0）。
- 请求：[MS-RDPESC] 2.2.2.30 `ScardAccessStartedEvent_Call` **不是 NDR
  结构**，只是 4 字节未初始化缓冲区（内容 SHOULD 随机、接收方 MUST 忽略）。
- 返回：[MS-RDPESC] 2.2.3.3 `Long_Return`（3.1.4.4 正文明确
  “sets Long_Return.ReturnCode to SCARD_S_SUCCESS ... otherwise ...”）。

**交叉依据**（FreeRDP `smartcard_AccessStartedEvent_Call`，2026-11-07 核对）：
- FreeRDP 调用 `SCardAccessStartedEvent` 并缓存句柄，但**不写输出缓冲区**
  （dispatcher 对本 IOCTL 跳过 8 字节对齐），与规范 3.1.4.4 的 Long_Return
  不一致；本项目以规范为准，返回 NDR 包装的 Long_Return。
- 服务未运行时返回 SCARD_E_NO_SERVICE。

**当前实现缺口**：枚举未包含 ACCESSSTARTEDEVENT，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kAccessStartedEvent；`ParseScardCall` 特判 4 字节
  裸载荷（长度必须恰好 4，内容忽略）；Long_Return 编码。
- `ISmartCardBackend` 新增 `AccessStartedEvent`；Win32 后端动态解析
  `SCardAccessStartedEvent`/`SCardReleaseStartedEvent`（取到句柄后立即释放，
  1:1 配对）；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 4 字节解析/长度拒绝/返回字节；通道成功与失败；变异 M58
（删除分派）必须转红。
## 12. SCARD_IOCTL_CANCEL（批145，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.27 `SCARD_IOCTL_CANCEL`（IOCTL 0x000900A8）。
- 请求：[MS-RDPESC] 2.2.2.2 `Context_Call`（仅 REDIR_SCARDCONTEXT）。
- 返回：[MS-RDPESC] 2.2.3.3 `Long_Return`（仅 ReturnCode）。

**交叉依据**（FreeRDP `smartcard_Cancel_Call`，2026-11-07 核对）：
- 调用 `SCardCancel(hContext)`，返回 Long_Return；无额外字段。

**当前实现缺口**：枚举未包含 CANCEL，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kCancel，复用 `ParseContextCall` 与 Long_Return 编码。
- `ISmartCardBackend` 新增 `Cancel`；Win32 后端动态解析 `SCardCancel`；
  Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/返回字节；通道成功与失败；变异 M59（删除 CANCEL 分派）
必须转红。
## 13. SCARD_IOCTL_STATE（批146，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.40 `SCARD_IOCTL_STATE`（IOCTL 0x000900C4）。
- 请求：[MS-RDPESC] 2.2.2.17 `State_Call`
  `{ REDIR_SCARDHANDLE hCard; long fpbAtrIsNULL;
     unsigned long cbAtrLen; }`。
- 返回：[MS-RDPESC] 2.2.3.9 `State_Return`
  `{ long ReturnCode; unsigned long dwState; unsigned long dwProtocol;
     [range(0,36)] unsigned long cbAtrLen;
     [unique] [size_is(cbAtrLen)] byte* rgAtr; }`。
- 语义（2.2.2.17 正文）：fpbAtrIsNULL=1 → 只回长度；fpbAtrIsNULL=0 且
  cbAtrLen=0 → 调用必须成功、回长度 + NULL；数据超 cbAtrLen →
  SCARD_E_INSUFFICIENT_BUFFER；cbAtrLen=0xFFFFFFFF → SCARD_AUTOALLOCATE。

**交叉依据**（FreeRDP `smartcard_unpack_state_call` /
`smartcard_pack_state_return`，2026-11-07 核对）：
- 线上顺序：REDIR_SCARDHANDLE、fpbAtrIsNULL、cbAtrLen；referent 顺序：
  context、handle。
- 返回失败时 cbAtrLen 写 0、指针写 NULL。
- FreeRDP 的 State 处理忽略调用方的 fpbAtrIsNULL/cbAtrLen、总是回 ATR；
  本项目按规范实现三态（探测/空容量/超容量）。

**当前实现缺口**：枚举未包含 STATE，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kState、State_Call 解析（REDIR_SCARDHANDLE +
  fpbAtrIsNULL + cbAtrLen）、State_Return 编码（三态、cbAtrLen≤36）。
- `ISmartCardBackend` 新增 `State`；Win32 后端动态解析 `SCardState`；
  Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派（探测/空容量/超容量/数据）。

**验收**：proto 解析/返回字节（数据/探测/失败）；通道成功、探测、空容量、
超容量、失败；变异 M60（删除 STATE 分派）必须转红。
## 14. SCARD_IOCTL_RECONNECT（批147，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.36 `SCARD_IOCTL_RECONNECT`（IOCTL 0x000900B4）。
- 请求：[MS-RDPESC] 2.2.2.15 `Reconnect_Call`
  `{ REDIR_SCARDHANDLE hCard; unsigned long dwShareMode;
     unsigned long dwPreferredProtocols; unsigned long dwInitialization; }`。
- 返回：[MS-RDPESC] 2.2.3.7 `Reconnect_Return`
  `{ long ReturnCode; unsigned long dwActiveProtocol; }`。

**交叉依据**（FreeRDP `smartcard_unpack_reconnect_call` /
`smartcard_pack_reconnect_return` / `smartcard_Reconnect_Call`，
2026-11-07 核对）：
- 线上顺序：REDIR_SCARDHANDLE、dwShareMode、dwPreferredProtocols、
  dwInitialization；referent 顺序：context、handle。
- 返回**无论成功失败都写 dwActiveProtocol**（失败时为 0）。
- Win32 调用 `SCardReconnect(hCard, share, preferred, init, &active)`。

**当前实现缺口**：枚举未包含 RECONNECT，proto/后端/rdpdr 均无对应路径。

**本批改动**：
- `proto/smartcard`：新增 kReconnect、Reconnect_Call 解析
  （REDIR_SCARDHANDLE + 三个 DWORD）、Reconnect_Return 编码。
- `ISmartCardBackend` 新增 `Reconnect`；Win32 后端动态解析 `SCardReconnect`；
  Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 解析/返回字节（成功与失败都含 dwActiveProtocol）；通道成功
与失败；变异 M61（删除 RECONNECT 分派）必须转红。
## 15. SCARD_IOCTL_LISTREADERSW（批148，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.8 `SCARD_IOCTL_LISTREADERSW`（IOCTL 0x0009002C）。
- 请求：[MS-RDPESC] 2.2.2.7 `ListReadersW_Call`，与 2.2.2.6
  `ListReadersA_Call` 同构（Context_Call：Context、mszGroups、cBytes、
  fmszReadersIsNULL、cchReaders）。
- 返回：[MS-RDPESC] 2.2.3.3 `ListReadersW_Return`：ReturnCode、cBytes、
  mszReaders；mszReaders 是宽字符多字符串（UTF-16LE），cBytes 为字节数且
  必须为偶数。

**交叉依据**（FreeRDP `smartcard_unpack_list_readers_call(..., unicode)` /
`smartcard_pack_list_readers_return(..., unicode)`，2026-11-07 核对）：
- unicode 时 cBytes 必须为偶数，否则 SCARD_E_INVALID_PARAMETER。
- 返回失败时 cBytes 置 0 且指针为 NULL。
- Win32 调用 `SCardListReadersW(hContext, LPCWSTR filter, ...)`，cch 为字符数。

**本批改动**：
- `ISmartCardBackend` 新增 `ListReadersW`（groups/readers 均为 UTF-16LE
  多字符串字节）；Win32 后端调用 `SCardListReadersW`；Null 返回
  SCARD_E_NO_SERVICE。
- proto：kListReadersW 复用 ListReaders_Call 解析；返回编码校验偶数长度与
  双 NUL 结尾。
- `rdpdr_client` 新增分派。

**验收**：proto 解析（宽字符 group）、返回字节、奇数长度拒绝；通道成功；
变异 M62（删除 LISTREADERSW 分派）必须转红。
## 16. SCARD_IOCTL_CONNECTW（批149，2026-11-07）

**规范依据**（Microsoft Learn 目录，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.29 `SCARD_IOCTL_CONNECTW`（IOCTL 0x000900B0）。
- 请求：[MS-RDPESC] 2.2.2.14 `ConnectW_Call`：szReader 指针、Context、
  dwShareMode、dwPreferredProtocols；referent 顺序：szReader（WCHAR
  [string]）、Context。
- 返回：[MS-RDPESC] 2.2.3.8 `Connect_Return`（与 ConnectA 共用）：
  ReturnCode、hContext、hCard、dwActiveProtocol。

**交叉依据**（FreeRDP `smartcard_unpack_connect_w_call` /
`smartcard_pack_connect_return`，2026-11-07 核对）：
- 与 ConnectA_Call 唯一差异是 szReader 用 `smartcard_ndr_read_w`
  （宽字符 [string]）。
- 返回结构完全共用；失败时 hCard 为空、dwActiveProtocol 为 0。
- Win32 调用 `SCardConnectW(hContext, LPCWSTR szReader, ...)`。

**本批改动**：
- `ISmartCardBackend` 新增 `ConnectW`（reader 为 UTF-16LE [string] 字节）；
  Win32 后端动态解析 `SCardConnectW`；Null 返回 SCARD_E_NO_SERVICE。
- proto：新增 `ParseConnectW`（复用 Connect_Common 字段 + 宽字符 referent）；
  返回编码复用 ConnectA。
- `rdpdr_client` 新增分派。

**验收**：proto 解析（宽字符 reader）、返回字节复用；通道成功；变异 M63
（删除 CONNECTW 分派）必须转红。
## 17. SCARD_IOCTL_STATUSW（批150，2026-11-07）

**规范依据**（Microsoft Learn 目录，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.34 `SCARD_IOCTL_STATUSW`（IOCTL 0x000900CC）。
- 请求：[MS-RDPESC] 2.2.2.18 `Status_Call`（与 StatusA 共用）：
  hCard、fmszReaderNamesIsNULL、cchReaderLen、cbAtrLen。
- 返回：[MS-RDPESC] 2.2.3.10 `Status_Return`：ReturnCode、cBytes、
  mszReaderNames 指针、dwState、dwProtocol、pbAtr[32]、cbAtrLen；
  StatusW 的 mszReaderNames 为 UTF-16LE，cBytes 为字节数。

**交叉依据**（FreeRDP `smartcard_unpack_status_call` /
`smartcard_pack_status_return(..., unicode)`，2026-11-07 核对）：
- 调用结构 A/W 完全相同；返回失败时 cBytes 置 0、指针 NULL。
- cBytes > 65536 拒绝；cbAtrLen > 32 拒绝。
- Win32 调用 `SCardStatusW(hCard, LPWSTR, &cch, ...)`，cch 为字符数。

**本批改动**：
- `ISmartCardBackend` 新增 `StatusW`（reader_names 为 UTF-16LE 多字符串）；
  Win32 后端动态解析 `SCardStatusW`；Null 返回 SCARD_E_NO_SERVICE。
- proto：kStatusW 复用 Status_Call 解析；返回编码新增宽字符校验。
- `rdpdr_client` 新增分派。

**验收**：proto 解析、返回字节（宽字符 + 2 字节填充）；通道成功；变异 M64
（删除 STATUSW 分派）必须转红。
## 18. SCARD_IOCTL_GETSTATUSCHANGEW（批151，2026-11-07）

**规范依据**（Microsoft Learn 目录，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.24 `SCARD_IOCTL_GETSTATUSCHANGEW`（IOCTL 0x000900A4）。
- 请求：[MS-RDPESC] 2.2.2.12 `GetStatusChangeW_Call`：Context、TimeOut、
  ReaderStates 数组（ReaderStateW：szReader、dwCurrentState、dwEventState、
  cbAtr、rgbAtr[36]）；szReader 为 UTF-16LE。
- 返回：[MS-RDPESC] 2.2.3.5 `GetStatusChange_Return`（与 A 共用）：
  cReaders + ReaderState_Return 数组（不含 reader 名）。

**交叉依据**（FreeRDP `smartcard_unpack_get_status_change_w_call` /
`smartcard_pack_get_status_change_return`，2026-11-07 核对）：
- 调用与 A 唯一差异是 reader 名用 `smartcard_ndr_read_w`；返回完全共用。
- Win32 调用 `SCardGetStatusChangeW`（szReader 为 LPCWSTR）。

**本批改动**：
- proto：新增 `ScardReaderStateW`/`reader_states_w` 与
  `ReadReaderStateArrayW`；`ParseGetStatusChangeW`。
- `ISmartCardBackend` 新增 `GetStatusChangeW`；Win32 后端抽出
  `WaitForStatusChange` 轮询助手（A/W 共用）；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派；返回编码复用 A 分支。

**验收**：proto 宽字符 reader 解析；通道成功（event_state/atr 回填）；
变异 M65（删除 GETSTATUSCHANGEW 分派）必须转红。
## 19. SCARD_IOCTL_LOCATECARDSW（批152，2026-11-07）

**规范依据**（Microsoft Learn，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.22 `SCARD_IOCTL_LOCATECARDSW`（IOCTL 0x0009009C）。
- 请求：[MS-RDPESC] 2.2.2.10 `LocateCardsW_Call`：
  `{ REDIR_SCARDCONTEXT Context; [range(0,65536)] unsigned long cBytes;
     [size_is(cBytes)] const byte* mszCards;
     [range(0,10)] unsigned long cReaders;
     [size_is(cReaders)] ReaderStateW* rgReaderStates; }`。
  mszCards 是 Unicode 多字符串，cBytes 为字节数；ReaderStateW 的 szReader
  为 UTF-16LE。
- 返回：[MS-RDPESC] 2.2.3.5 `LocateCards_Return`（与 GetStatusChange 共用，
  不含名字）。

**交叉依据**（FreeRDP `smartcard_unpack_locate_cards_w_call`，2026-11-07
核对）：
- 线上顺序：Context、cBytes、mszCards 指针、cReaders、rgReaderStates 指针；
  referent 顺序：Context、mszCards、ReaderStateW 数组（各自 reader 名）。
- **已知分歧**：FreeRDP 用 `smartcard_ndr_read_fixed_string_w(..., cBytes,
  NDR_PTR_SIMPLE)`（elementSize=2），即 Length==cBytes 且读 2*cBytes 字节；
  这与其自身 IDL（byte* + size_is(cBytes)）矛盾，疑为 FreeRDP 缺陷。
  本实现按规范 IDL：Length==cBytes、读 cBytes 字节，并校验 UTF-16LE
  偶数长度与双 NUL。未真机验证，列入 discover。

**本批改动**：
- proto：新增 kLocateCardsW、`ParseLocateCardsW`（复用
  `ReadReaderStateArrayW`）；返回编码复用 A 分支。
- `ISmartCardBackend` 新增 `LocateCardsW`；Win32 后端动态解析
  `SCardLocateCardsW`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 宽字符解析；通道成功；变异 M66（删除 LOCATECARDSW 分派）
必须转红。
## 20. SCARD_IOCTL_READCACHEW（批153，2026-11-07）

**规范依据**（Microsoft Learn 目录，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.43 `SCARD_IOCTL_READCACHEW`（IOCTL 0x000900F4）。
- 请求：[MS-RDPESC] 2.2.2.26 `ReadCacheW_Call`：与 ReadCacheA_Call 同构，
  仅 szLookupName 为 WCHAR [string]；其余为 ReadCache_Common
  {Context、UUID* CardIdentifier、FreshnessCounter、fPbDataIsNull、
  cbDataLen}。
- 返回：[MS-RDPESC] 2.2.3.1 `ReadCache_Return`（与 A 共用）：
  ReturnCode、cbDataLen、pbData。

**交叉依据**（FreeRDP `smartcard_unpack_read_cache_w_call`，2026-11-07
核对）：
- 与 A 唯一差异是 `smartcard_ndr_read_w`（宽字符 full string）；返回共用。
- Win32 调用 `SCardReadCacheW(hContext, &uuid, freshness, LPCWSTR, ...)`。

**本批改动**：
- proto：新增 kReadCacheW、`ParseReadCacheW`（宽字符 lookup name）。
- `ISmartCardBackend` 新增 `ReadCacheW`；Win32 后端动态解析
  `SCardReadCacheW`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派；返回编码复用 A 分支。

**验收**：proto 宽字符解析；通道成功（数据回填）；变异 M67（删除
READCACHEW 分派）必须转红。
## 21. SCARD_IOCTL_WRITECACHEW（批154，2026-11-07）

**规范依据**（Microsoft Learn 目录，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.45 `SCARD_IOCTL_WRITECACHEW`（IOCTL 0x000900FC）。
- 请求：[MS-RDPESC] 2.2.2.28 `WriteCacheW_Call`：与 WriteCacheA_Call
  同构，仅 szLookupName 为 WCHAR [string]；其余为 WriteCache_Common
  {Context、UUID* CardIdentifier、FreshnessCounter、cbDataLen、
  [unique] pbData}。
- 返回：[MS-RDPESC] 2.2.3.3 `Long_Return`（与 A 共用）。

**交叉依据**（FreeRDP `smartcard_unpack_write_cache_w_call`，2026-11-07
核对）：
- 与 A 唯一差异是 `smartcard_ndr_read_w`（宽字符 full string）；返回共用。
- Win32 调用 `SCardWriteCacheW(hContext, &uuid, freshness, LPCWSTR, ...)`。

**本批改动**：
- proto：新增 kWriteCacheW、`ParseWriteCacheW`（宽字符 lookup name）。
- `ISmartCardBackend` 新增 `WriteCacheW`；Win32 后端动态解析
  `SCardWriteCacheW`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派；返回编码复用 A 分支（Long_Return）。

**验收**：proto 宽字符解析；通道成功（后端收到宽名字与数据）；变异 M68
（删除 WRITECACHEW 分派）必须转红。
## 22. SCARD_IOCTL_LISTREADERGROUPSW（批155，2026-11-07）

**规范依据**（Microsoft Learn 目录，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.6 `SCARD_IOCTL_LISTREADERGROUPSW`（IOCTL 0x00090024）。
- 请求：[MS-RDPESC] 2.2.2.3 `ListReaderGroups_Call`（与 A 共用）：
  Context、fmszGroupsIsNULL、cchGroups。
- 返回：[MS-RDPESC] 2.2.3.4 `ListReaderGroups_Return`（与
  ListReaders_Return 共用）：ReturnCode、cBytes、mszGroups；W 时 mszGroups
  为 UTF-16LE 多字符串，cBytes 为字节数且必须为偶数。

**交叉依据**（FreeRDP `smartcard_unpack_list_reader_groups_call` /
`smartcard_pack_list_reader_groups_return(..., unicode)`，2026-11-07 核对）：
- 调用 A/W 完全相同；unicode 返回 cBytes 必须为偶数，失败时 cBytes=0、
  指针 NULL。
- Win32 调用 `SCardListReaderGroupsW(hContext, LPWSTR, &cch)`。

**本批改动**：
- `ISmartCardBackend` 新增 `ListReaderGroupsW`；Win32 后端动态解析
  `SCardListReaderGroupsW`；Null 返回 SCARD_E_NO_SERVICE。
- proto：kListReaderGroupsW 复用 ListReaderGroups_Call 解析；返回编码并入
  kListReadersW 的宽字符分支。
- `rdpdr_client` 新增分派。

**验收**：proto 返回字节（宽字符 + 填充）、奇数长度拒绝；通道成功与失败；
变异 M69（删除 LISTREADERGROUPSW 分派）必须转红。
## 23. SCARD_IOCTL_LOCATECARDSBYATRW（批156，2026-11-07）

**规范依据**（Microsoft Learn 目录，2026-11-07 复核）：
- [MS-RDPESC] 3.1.4.26 `SCARD_IOCTL_LOCATECARDSBYATRW`（IOCTL 0x000900EC）。
- 请求：[MS-RDPESC] 2.2.2.24 `LocateCardsByATRW_Call`：Context、cAtrs、
  rgAtrMasks（LocateCards_ATRMask 数组，ATR/mask 为字节数组）、cReaders、
  rgReaderStates（ReaderStateW，reader 名为 UTF-16LE）。
- 返回：[MS-RDPESC] 2.2.3.5 `LocateCards_Return`（与 A 共用，不含名字）。

**交叉依据**（FreeRDP `smartcard_unpack_locate_cards_by_atr_w_call`，
2026-11-07 核对）：
- 与 A 唯一差异是 rgReaderStates 的 reader 名用宽字符；ATR mask 数组
  完全相同（cbAtr ≤ 36、固定 36 字节数组）。
- Win32 调用 `SCardLocateCardsByATRW`（LPSCARD_READERSTATEW）。

**本批改动**：
- proto：新增 kLocateCardsByAtrW、`ParseLocateCardsByAtrW`（ATR mask 复用
  A 的解析 + `ReadReaderStateArrayW`）；返回编码复用 A 分支。
- `ISmartCardBackend` 新增 `LocateCardsByAtrW`；Win32 后端动态解析
  `SCardLocateCardsByATRW`；Null 返回 SCARD_E_NO_SERVICE。
- `rdpdr_client` 新增分派。

**验收**：proto 宽字符 reader 解析；通道成功；变异 M70（删除
LOCATECARDSBYATRW 分派）必须转红。
## 24. 待审计三问的结论（批157，2026-11-07）

### Q1 OutputBufferLength=0 是否豁免 STATUS_BUFFER_TOO_SMALL

**结论：不豁免，当前实现正确。**
- [MS-RDPESC] 3.2.5.1：输出缓冲长度 SHOULD 为 2048 字节，正常不会出现 0。
- [MS-RDPESC] 3.2.5.2：IOStatus 为 STATUS_BUFFER_TOO_SMALL 时，服务端
  SHOULD 以双倍缓冲重发。
- FreeRDP `smartcard_call.c`（`smartcard_call.c:2384`）对
  `outputBufferLength > operation->outputBufferLength` 一律回
  STATUS_BUFFER_TOO_SMALL，无 0 豁免。
- 本实现 `src/channel/rdpdr_client.cpp` 的 `SendScardCompletion` 同样无豁免。

### Q2 GetStatusChange 超时回填 reader_states 是否符合 2.2.3.5

**结论：回填正确，但编码器此前在超时时丢弃状态，属缺陷，已修复。**
- [MS-RDPESC] 2.2.3.5 的结构对 ReturnCode 无分支；FreeRDP
  `smartcard_pack_get_status_change_return` 仅在
  `ReturnCode != 0 && != SCARD_E_TIMEOUT` 时把 cReaders 置 0。
- 修复：`src/proto/smartcard.cpp` 的 reader-states 编码分支改为
  `keep = ok || return_code == kScardETimeout`；新增
  `kScardETimeout = 0x8010000A`（`include/rtsc/proto/smartcard.h`）。
- 测试：`smartcard_get_status_change_return_keeps_states_on_timeout`、
  `smartcard_get_status_change_return_drops_states_on_other_failure`、
  通道 `smartcard_get_status_change_timeout_keeps_states`。
- 变异 M71（去掉超时豁免）→ 2 个测试红；恢复后全绿。

### Q3 kStatusChangeStepMs=1000 是否最多阻塞 UI 1 秒

**结论：不是 1 秒；是完整的请求超时（可能是 INFINITE），UI 会被冻结。**
- `src/smartcard/backend_win32.cpp` 的 `WaitForStatusChange` 在
  `rc == SCARD_E_TIMEOUT` 且未到总超时时继续循环；`dwTimeOut=INFINITE`
  时永不退出，直到读卡器状态变化。
- `tools/rtsc_gui/main.cpp` 在 UI 线程的 `client.Pump()` 内同步调用
  `rdpdr.OnChannelData` → 智能卡后端，因此该循环直接阻塞 UI 线程。
- 1 秒步长只限制单次 WinSCard 调用，不限制整个循环。
- 正确修复需要智能卡 IOCTL 异步完成（工作线程 + 按 CompletionId 回包），
  属架构改动；已记入 plan 的后续项，本批不改。

**本批验收**：M71 红绿证；C0 零错误零警告；影响面 ctest 6/6。
## 25. SCARD_IOCTL 执行与发送解耦（批158，2026-11-07）

**目的**：为智能卡 IOCTL 异步化（Q3 后续）做无行为变更的前置重构，并把
OutputBufferLength 的边界语义用测试钉死。

**改动**：
- `RdpdrClient::OnSmartCardControl` 拆为：
  - `BuildSmartCardCompletion(req) -> ScardCompletion`：解析、调用后端、编码
    *_Return、比较 OutputBufferLength；不触碰传输层，可在工作线程运行。
  - `OnSmartCardControl`：记录 IOCTL 名、计数、调用 Build 并发送。
- `SendScardCompletion(completion)` 只负责把已算好的 status/output 写出。
- 拒绝语义不变：解析失败/不可编码返回 → STATUS_UNSUCCESSFUL + 空输出；
  编码后超 OutputBufferLength → STATUS_BUFFER_TOO_SMALL + 空输出。

**边界语义**（[MS-RDPESC] 3.2.5.2 + FreeRDP smartcard_call.c）：
- 比较必须是 `encoded.size() > output_limit`；相等即成功。
- 新增测试 `smartcard_output_buffer_exact_fit_succeeds`（EstablishContext
  返回 40 字节，OutputBufferLength=40 → STATUS_SUCCESS）。
- 变异 M72（`>` 改 `>=`）→ 该测试红；恢复后全绿。

**验收**：C0 零错误零警告；影响面 ctest 6/6；smartcard 126/348、
smartcard_channel 43/504、rdpdr 62/899。
## 26. 智能卡 IOCTL 异步执行（批159，2026-11-07）

**目的**：消除 Q3 的 UI 阻塞。GetStatusChange 可能等待完整请求超时（甚至
INFINITE），同步在 GUI 事件循环里执行会冻结界面。

**设计**：
- `SetAsyncSmartCard(true)`：启动工作线程；`OnSmartCardControl` 只把请求
  入队并返回，不触碰传输层。
- 工作线程循环：取请求 → `BuildSmartCardCompletion`（解析、后端调用、编码、
  限长）→ 完成项入 `scard_done_`。
- `PollSmartCard()`：在传输线程（GUI 事件循环）排空完成队列，计数并写出
  DR_CONTROL_RSP。
- `SetAsyncSmartCard(false)`/析构：置停止标志、唤醒、join；队列中已入队的
  请求仍会执行，join 后 `PollSmartCard()` 排空。join 可能阻塞到当前后端调用
  返回——这是关停代价，不会丢请求。
- 同步模式（默认）行为不变：`OnSmartCardControl` 内联执行并立即发送。

**并发约束（D11/D12/D19）**：
- 单锁 `scard_mutex_`，无嵌套加锁；发送与后端调用都在锁外。
- `scard_async_` 仅由传输线程读写；`SetAsyncSmartCard`/`PollSmartCard` 必须
  在传输线程调用。
- 队列为 UI→worker、完成队列为 worker→UI，均在锁内交换。
- 后端必须比 handler 长寿（析构 join 时仍在用）；GUI 接线时必须保证。

**测试**（`tests/test_smartcard_channel.cpp`）：
- `smartcard_async_poll_delivers_completion`：异步模式下请求入队，轮询后
  收到 CompletionId=9 的成功响应。
- `smartcard_async_rejects_malformed_call`：畸形调用异步返回
  STATUS_UNSUCCESSFUL、空输出、reject 计数 +1。
- `smartcard_sync_mode_resumes_after_async`：关闭异步后同步路径恢复。
- 变异 M73（PollSmartCard 不写回）→ 2 tests / 2 checks 红；恢复后全绿。

**验收**：C0 零错误零警告；影响面 ctest 6/6；smartcard 126/348、
smartcard_channel 46/519、rdpdr 62/899。

**未完成**：rtsc_gui 尚未开启异步模式与轮询（下一批接线）。
## 27. GUI 接线与跨会话过期响应丢弃（批160，2026-11-07）

**GUI 接线**（`tools/rtsc_gui/main.cpp`）：
- `scard_backend` 声明移到 `RdpdrClient` 之前：析构顺序反转后 backend 比
  handler 长寿，异步 worker 在 `~RdpdrClient` join 时仍可安全调用后端。
- `EnableSmartCard` 成功后调用 `SetAsyncSmartCard(true)`。
- 事件循环在 `cliprdr.Poll(...)` 之后调用 `rdpdr.PollSmartCard()`，把工作
  线程完成的 SCARD_IOCTL 写回服务器。

**跨会话过期响应（D18）**：
- `ScardCompletion`/`ScardJob` 携带 `generation`；`Reset()`（自动重连替换
  传输）递增 `scard_generation_` 并清空队列与完成队列。
- `PollSmartCard()` 丢弃 `generation` 不匹配的完成项：旧会话的在途调用
  即使在新会话建立后返回，也不会写到新传输上。
- 新增测试 `smartcard_async_drops_completions_after_reset`：FakeBackend 在
  EstablishContext 内阻塞，测试等待其进入后调用 `Reset()`，再放行；
  轮询后断言没有任何 DR_CONTROL_RSP 发出。
- 变异 M74（删除 generation 检查）→ 1 test / 1 check 红；恢复后全绿。

**验收**：C0 零错误零警告；影响面 ctest 6/6；smartcard 126/348、
smartcard_channel 47/521、rdpdr 62/899。

**未验证**：GUI 异步路径未真机/交互式验证；join 仍可能阻塞到后端调用返回。