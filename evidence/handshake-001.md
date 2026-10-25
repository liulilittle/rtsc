# 真实握手取证 #001

目标：192.168.1.7:3389（用户提供的本地 RDP 服务器）
工具：F:\rtsc\build\msvc\rtsc_probe.exe --connect 192.168.1.7 3389 tester
时间：2026-10-22 13:54

## 发送（客户端 CRQ，44 字节）

```
03 00 00 2C   TPKT length=44
27            X.224 LI=0x27=39
E0            CRQ
00 00         dst-ref=0
00 00         src-ref=0
00            class=0
43 6F 6F 6B 69 65 3A 20 6D 73 74 73 68 61 73 68 3D 74 65 73 74 65 72 0D 0A
              "Cookie: mstshash=tester\r\n"（27 字节）
01 00 08 00   RDP_NEG_REQ type=1 flags=0 length=8
0B 00 00 00   requestedProtocols = 0x0B = SSL|HYBRID|HYBRID_EX
```

长度校验：4 + 7 + 27 + 8 = 46？实测 44 字节。
核对：cookie 字符串 "Cookie: mstshash=tester" 长度 23，+CRLF=25；4+7+25+8=44。
（上表按 16 字节行显示共 44 字节，LI=0x27=39 = 44-4-1。自洽。）

## 接收（服务端 CCF，19 字节）

```
03 00 00 13   TPKT length=19
0E            X.224 LI=14
D0            CC (Connection Confirm)
00 00         dst-ref=0
12 34         src-ref=0x1234   ← 与规范 2.2.1.2 强制值一致
00            class/options=0
02            RDP_NEG_RSP type=2
0F            flags=0x0F = EXTENDED_CLIENT_DATA_SUPPORTED(0x01)
                          | DYNVC_GFX_PROTOCOL_SUPPORTED(0x02)
                          | NEGRSP_FLAG_RESERVED(0x04)
                          | RESTRICTED_ADMIN_MODE_SUPPORTED(0x08)
08 00         length=8
08 00 00 00   selectedProtocol=0x08 = PROTOCOL_HYBRID_EX
```

## 结论（观察）

1. 真实 Windows 服务端 CCF 与规范 2.2.1.2 完全一致（src-ref=0x1234、LI=14、总长 19）。
2. 该服务器要求 CredSSP（HYBRID_EX 意味着 CredSSP + Early User Authorization Result PDU），
   因此下一阶段必须实现 TLS + CredSSP/NLA 才能继续 MCS 层。
3. 服务端声明 EXTENDED_CLIENT_DATA_SUPPORTED 与 DYNVC_GFX_PROTOCOL_SUPPORTED，
   后续 GCC Client Core Data 需支持扩展客户端数据块，图形走 EGFX 管线。
4. flags 中 0x04 为保留位且被置位——证明客户端必须忽略未知/保留位（规范 2.2.1.2.1 明示）。

## 复现命令

```
F:\rtsc\build\msvc\rtsc_probe.exe --connect 192.168.1.7 3389 <cookie>
```
