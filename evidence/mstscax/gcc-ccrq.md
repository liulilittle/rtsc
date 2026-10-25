# GCC Conference Create Request 模板 — 二进制取证（mstscax.dll 10.0.26100.8875）

取证对象：`C:\Windows\System32\mstscax.dll`
SHA256：`d73c76d65721043cc96484e3483bdd1aab4357a8bfa924465adc572ced0eda05`
工具：REA 6.7.0 + Ghidra 12.1.4（provider `ghidra`）

## 1. 定位链

| 步骤 | 工具调用 | 结果 |
|---|---|---|
| 常量扫描 | `tools/scan_constants.py` | `.rdata` 文件偏移 `0x6C3330` 命中 `00 08 00 10 00 01 C0 00` |
| 虚拟地址 | 文件偏移 + image base（`.rdata` RVA 0x66F000 @ file 0x66F000，1:1） | `0x1806C3330` |
| 交叉引用 | `search_bytes("00 08 00 10 00 01 C0 00")` → 1 命中 | `0x1806c3330`（`.rdata`，无 procedure） |
| 引用点 | `xrefs(0x1806C3330)` | `["0x180161eda"]` |
| 所属函数 | `inspect_address_context(0x180161EDA)` | `FUN_180161ce0`，`0x180161ce0`–`0x180162069`（906 B） |
| 上游 | `analyze_function(0x180161ce0).callers` | `FUN_18015d974`（`0x18015d974`–`0x18015e08f`，1820 B） |

## 2. 关键汇编（`FUN_180161ce0`，输出缓冲构造段）

```
0x180161e40: MOV RAX, qword ptr [RSP + 0x100]      ; RAX = out_len 指针
0x180161e48: CMP dword ptr [RAX], EDI              ; 容量 vs 需求(uVar7)
0x180161e4a: JNC 0x180161e8b                       ; 容量足够
0x180161e4c: ...                                   ; 不足 → 日志 0x3e
0x180161e81: MOV EDI, 0x80004005                   ; E_FAIL
0x180161e86: JMP 0x180162059

0x180161e8b: MOV RCX, qword ptr [RSP + 0xf8]       ; RCX = out_buf
0x180161e93: XOR EDI, EDI
0x180161e95: MOV dword ptr [RAX], EDI              ; *out_len = 0
0x180161e97: MOV EAX, dword ptr [0x1806c3338]      ; ★ 常量 A = 4 字节
0x180161e9d: MOV dword ptr [RCX], EAX              ; out[0..3]
0x180161e9f: MOVZX EAX, word ptr [0x1806c333c]     ; ★ 常量 B = 2 字节
0x180161ea6: MOV word ptr [RCX + 0x4], AX          ; out[4..5]
0x180161eaa: MOV AL, byte ptr [0x1806c333e]        ; ★ 常量 C = 1 字节
0x180161eb0: MOV byte ptr [RCX + 0x6], AL          ; out[6]
0x180161eb3: ADD RCX, 0x7                          ; RCX = out+7（外层长度位置）

0x180161eb7: CMP ESI, EDX                          ; ESI = uVar1（外层长度）, EDX = 0x80
0x180161eb9: JC 0x180161ed3                        ; < 0x80 → 单字节
0x180161ebb: CMP ESI, 0xffff
0x180161ec1: JA 0x180161fde                        ; > 0xFFFF → E_FAIL
0x180161ec7: MOV EAX, ESI
0x180161ec9: SHR EAX, 0x8
0x180161ecc: OR AL, DL                             ; | 0x80
0x180161ece: MOV byte ptr [RCX], AL                ; 长形式首字节 0x81
0x180161ed0: INC RCX
0x180161ed3: MOV byte ptr [RCX], SIL               ; 长度低字节
0x180161ed6: LEA RSI, [RCX + 0xe]                  ; RSI = 数据区起点

0x180161eda: MOV RAX, qword ptr [0x1806c3330]      ; ★ 常量 D = 8 字节
0x180161ee1: MOV qword ptr [RCX + 0x1], RAX        ; 紧跟长度字段
0x180161ee5: MOV dword ptr [RCX + 0x9], 0x61637544 ; ★ "Duca"（LE: 44 75 63 61）
0x180161eec: CMP EBP, EDX                          ; EBP = uVar3（userData 内容长度）
0x180161eee: JNC 0x180161ef6
0x180161ef0: MOV byte ptr [RCX + 0xd], BPL         ; 短形式 userData 长度
0x180161ef4: JMP 0x180161f06
0x180161ef6: MOV EAX, EBP
0x180161ef8: SHR EAX, 0x8
0x180161efb: OR AL, DL                             ; | 0x80
0x180161efd: MOV byte ptr [RCX + 0xd], AL
0x180161f00: MOV byte ptr [RSI], BPL
0x180161f03: INC RSI
0x180161f06: MOV EBX, dword ptr [RSP + 0x80]       ; 块 1 长度
0x180161f0d: MOV RCX, RSI                          ; 目标 = 块数据区
0x180161f10: MOV RDX, qword ptr [RSP + 0x78]       ; 块 1 指针
0x180161f15: MOV R8D, EBX
0x180161f18: CALL 0x18066b6a6                      ; memcpy
```

## 3. 常量取值（`read_bytes` 实测）

| 标签 | 虚拟地址 | 字节 | 含义 |
|---|---|---|---|
| A | `0x1806c3338` | `00 05 00 14` | T.124 `Key::object` 头 + OID 前段 |
| B | `0x1806c333c` | `7C 00` | OID 尾段（`0x7C`=124）+ 版本 `0` |
| C | `0x1806c333e` | `01` | OID 末段 `1` |
| D | `0x1806c3330` | `00 08 00 10 00 01 C0 00` | ConnectGCCPDU/CCrq/ConferenceName/TerminationMethod/UserData 头 + H.221 长度 |
| — | 立即数 | `0x61637544` | ASCII `"Duca"`（LE） |

注：常量 D 的 8 字节在内存中**连续**，但汇编是 `MOV qword ptr [RCX+1], RAX` 一次性写入；`0x1806c3330` 的 `xrefs` 只有 `0x180161eda` 一处，说明它是**专用模板常量**，不被其他函数复用。

## 4. 反编译伪码（Ghidra，原文）

```c
undefined4
FUN_180161ce0(undefined8 param_1, void *param_2, uint param_3, void *param_4, uint param_5,
              void *param_6, uint param_7, void *param_8, uint param_9,
              void *param_10, uint param_11, void *param_12, uint param_13)
{
  uint  uVar1, uVar3, uVar7;
  byte *pbVar4, *pbVar6;
  undefined4 *in_stack_00000090;   // out_buf
  uint       *in_stack_00000098;   // out_len (in: capacity, out: written)

  uVar3 = param_3 + param_5;
  if ((param_3 <= uVar3) && (param_5 <= uVar3)) {
    uVar1 = uVar3 + param_7;
    if ((uVar3 <= uVar1) && (param_7 <= uVar1)) {
      uVar3 = uVar1 + param_9;
      if ((uVar1 <= uVar3) && (param_9 <= uVar3)) {
        uVar1 = uVar3 + param_11;
        if ((uVar3 <= uVar1) &&
            (((param_11 <= uVar1 && (uVar3 = uVar1 + param_13, uVar1 <= uVar3)) &&
              (param_13 <= uVar3)))) {

          uVar1 = (0xe - (uint)(uVar3 < 0x80)) + uVar3;   // 13+uVar3 或 14+uVar3
          /* …日志 0x3c… */
          uVar7 = (9 - (uint)(uVar1 < 0x80)) + uVar1;     // 8+uVar1 或 9+uVar1
          /* …日志 0x3d… */

          if (*in_stack_00000098 < uVar7) { /* 日志 0x3e */ return 0x80004005; }

          *in_stack_00000098 = 0;
          *in_stack_00000090 = 0x14000500;                // out[0..3] = 00 05 00 14
          *(undefined2 *)(in_stack_00000090 + 1) = 0x7c;  // out[4..5] = 7C 00
          *(undefined1 *)((longlong)in_stack_00000090 + 6) = 1;  // out[6] = 01
          pbVar4 = (byte *)((longlong)in_stack_00000090 + 7);

          if (0x7f < uVar1) {
            if (0xffff < uVar1) { /* 日志 0x3f */ return 0x80004005; }
            *pbVar4 = (byte)(uVar1 >> 8) | 0x80;          // 0x81
            pbVar4 = (byte *)(in_stack_00000090 + 2);     // → out+8
          }
          *pbVar4 = (byte)uVar1;
          pbVar6 = pbVar4 + 0xe;

          pbVar4[1] = 0;        pbVar4[2] = 8;      pbVar4[3] = 0;
          pbVar4[4] = 0x10;     pbVar4[5] = 0;      pbVar4[6] = 1;
          pbVar4[7] = 0xc0;     pbVar4[8] = 0;
          pbVar4[9] = 0x44;  pbVar4[10] = 0x75; pbVar4[0xb] = 99; pbVar4[0xc] = 0x61;

          if (uVar3 < 0x80) {
            pbVar4[0xd] = (byte)uVar3;
          } else {
            pbVar4[0xd] = (byte)(uVar3 >> 8) | 0x80;
            *pbVar6 = (byte)uVar3;
            pbVar6 = pbVar4 + 0xf;
          }

          memcpy(pbVar6, param_2,  param_3);  pbVar6 += param_3;
          if ((param_5  != 0) && (param_4  != 0)) { memcpy(pbVar6, param_4,  param_5);  pbVar6 += param_5;  }
          if ((param_7  != 0) && (param_6  != 0)) { memcpy(pbVar6, param_6,  param_7);  pbVar6 += param_7;  }
          if ((param_9  != 0) && (param_8  != 0)) { memcpy(pbVar6, param_8,  param_9);  pbVar6 += param_9;  }
          if ((param_11 != 0) && (param_10 != 0)) { memcpy(pbVar6, param_10, param_11); pbVar6 += param_11; }
          if ((param_13 != 0) && (param_12 != 0)) { memcpy(pbVar6, param_12, param_13); }

          *in_stack_00000098 = uVar7;
          return 0;
        }
      }
    }
  }
  /* …日志 0x3b… */
  return 0x80070057;   // E_INVALIDARG
}
```

## 5. 长度恒等式（自洽性证明）

设 6 块总长 `S = Σ len_i`（代码逐段做无符号溢出校验，任一溢出返回 `E_INVALIDARG`）。

- 外层长度（`connectPDU` 内容）：`L1 = (S < 0x80 ? 13 : 14) + S`
  - 短形式：`8`（常量 D）+ `4`（"Duca"）+ `1`（userData 长度）+ `S` = `13 + S`
  - 长形式：`8` + `4` + `2` + `S` = `14 + S`
- `userData` OCTET STRING 内容长度：`L2 = (L1 < 0x80 ? 8 : 9) + L1`
  - 短形式：`7`（t124Identifier）+ `1`（外层长度）+ `L1` = `8 + L1`
  - 长形式：`7` + `2` + `L1` = `9 + L1`

**代入规范 416 字节向量**：`S = 284`（=216+12+12+44）→ `L1 = 14 + 284 = 298 = 0x12A`（线上 `81 2A` ✓）→ `L2 = 9 + 298 = 307 = 0x133`（线上 `04 82 01 33` ✓）。

## 6. 输出字节布局（与 `docs/spec/mcs-connect.md` §4.2 逐字节一致）

`userData` OCTET STRING 内容相对偏移：

| 偏移 | 短形式（S<0x80） | 长形式（S≥0x80） | 内容 |
|---|---|---|---|
| 0..6 | `00 05 00 14 7C 00 01` | 同 | 常量 A+B+C（T.124 `Key::object`，OID 0.0.20.124.0.1） |
| 7 | `L1`（1 B） | `81 L1`（2 B） | 外层长度（`connectPDU`） |
| 8 / 9 | `00 08 00 10 00 01 C0 00` | 同（起点后移 1） | 常量 D |
| 16 / 17 | `44 75 63 61` | 同 | `"Duca"` |
| 20 / 21 | `S`（1 B） | `81 S`（2 B） | userData 内容长度 |
| 21 / 23 | 6 块拼接 | 同 | CS_CORE… |

## 7. 调用者实参（`FUN_18015d974` @ `0x18015dd54`）

```
FUN_180161ce0(out_buf, blk1_ptr, blk1_len, blk2_ptr, blk2_len, blk3_ptr, blk3_len,
              blk4_ptr, blk4_len, blk5_ptr, blk5_len, blk6_ptr, blk6_len)
```

- `out_buf` = 栈上 `local_1038[4096]`；`out_len` 初值 `0x1000`。
- 6 组 `(len, ptr)` 位于对象 `param_1` 的偏移 `+0x108/+0x110`、`+0x118/+0x120`、`+0x128/+0x130`、`+0x138/+0x140`、`+0x148/+0x150`、`+0x158/+0x160`（步长 16 B）。
- `blk1` 的 `(len, ptr)` 读取**不受** `ExtendedGccUserDataSupported` 门控；`blk2..blk6` 的 **len** 在 `local_1068[0] == 0` 时被置 0（即不发送）。**未验证**该门控对应的确切块类型语义（属实现细节，非协议契约）。
- 失败日志字符串：`"NC_PrepareMcsUserData failed!"`（本函数即 `NC_PrepareMcsUserData` 的模板拼装子过程）。

## 8. 服务端方向（Connect Response）的二进制证据

`search_bytes("2A 14 76 0A")` → **0 命中**；`search_bytes("4D 63 44 6E")`（"McDn"）→ 1 命中：
`0x18015f086` @ `.text`，所属 `FUN_18015eecc`（`0x18015eecc`–`0x1801603c3`，5368 B）。

**推论**：`mstscax.dll` 只实现**客户端**方向，服务端模板（`14 76 0A …` + `"McDn"`）不存在于本模块——`2A 14 76 0A` 来自 [MS-RDPBCGR] 4.1.4 服务端 dump，不是本客户端的常量。故：
- 客户端 CCRQ 模板：`00 05 00 14 7C 00 01` + `00 08 00 10 00 01 C0 00` + `"Duca"`（**已二进制确认**）
- 服务端 CCRSP 模板：`00 05 00 14 7C 00 01` + `14 76 0A 01 01 00 01 C0 00` + `"McDn"`（**仅规范确认**，本模块无此常量）

## 9. CS_CORE 构造点（交叉验证字段偏移）

`search_bytes("03 C0", mask="FF FF")` 命中 `0x18013ed24` @ `FUN_18013eaf4`（`0x18013eaf4`–`0x18013f6d5`，3042 B）。

伪码关键行 → 字段偏移换算（`hMem` 为 `undefined4*`）：

| 伪码 | 字节偏移 | 规范字段 | 规范 §5.2 表偏移 | 一致 |
|---|---|---|---|---|
| `*hMem = 0xeac001` | 0..3 | type=0xC001, length=0x00EA=**234** | 0 | ✓ |
| `hMem[1] = 0x80011` | 4..7 | `version` = 0x00080011（RDP 10.1） | 4 | ✓ |
| `*(u16*)(hMem + 2) = *(u16*)(p2+0x204)` | 8 | `desktopWidth` | 8 | ✓ |
| `*(u16*)((longlong)hMem + 10)` | 10 | `desktopHeight` | 10 | ✓ |
| `hMem[3] = 0xca01` | 12 | `colorDepth` = 0xCA01 | 12 | ✓ |
| `hMem[0x21] = 0xca00` | 132 | `postBeta2ColorDepth` | 132 | ✓ |
| `hMem[0x23] = 4` | 140 | `highColorDepth` | 140 | ✓ |
| `*(u16*)((longlong)hMem + 0x8e) = 0xf` | 142 | `supportedColorDepths` = 0xF | 142 | ✓ |
| `*(u16*)(hMem + 0x24) = 0xd` (+OR 0x40/0x20/0x80/0x700/0x800) | 144 | `earlyCapabilityFlags` | 144 | ✓ |
| `hMem[0x36]` | 216 | `desktopPhysicalWidth` | 216 | ✓ |
| `hMem[0x37]` | 220 | `desktopPhysicalHeight` | 220 | ✓ |
| `*(short*)(hMem + 0x38)` | 224 | `desktopOrientation` | 224 | ✓ |
| `*(u32*)((longlong)hMem + 0xe2)` | 226 | `desktopScaleFactor` | 226 | ✓ |
| `*(u32*)((longlong)hMem + 0xe6)` | 230 | `deviceScaleFactor` | 230 | ✓ |

结论：**块长 234 = 4 + 212 + 18**，覆盖到 `deviceScaleFactor` 末尾；`docs/spec/mcs-connect.md` §5.2 的全部字段偏移与本二进制**逐项一致**。规范 §9 的 416 B dump 块长 216（止于 `serverSelectedProtocol`）属较早版本取值，两者不冲突。

`desktopOrientation` 取值白名单（伪码）：`0 / 0x5A(90) / 0xB4(180) / 0x10E(270)`，其他一律置 0。

## 10. 块顺序（规范 416 B dump 实测）

`c001`(216) → `c004`(12) → `c002`(12) → `c003`(44)，总计 284。

注意：**mstsc 把 CS_CLUSTER 放在 CS_SECURITY 之前**（非 `CORE/SEC/NET/CLUSTER` 的自然顺序）。客户端侧规范允许任意顺序（S2），但字节级复刻必须保持此顺序。
