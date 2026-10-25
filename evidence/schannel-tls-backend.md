# SChannel TLS 后端可行性实测（2026-10-22）

## 结论

Windows 自带的 SChannel **可以**完成对 `192.168.1.7:3389` 的 TLS 1.2 客户端握手，
并且**可以**导出 CredSSP pubKeyAuth 所需的 SubjectPublicKeyInfo DER。
因此 TLS 层在 Windows 上可以做到**零第三方依赖**。

## 探针 1：TLS 握手（`F:\rtsc\.tmp\schprobe\main.cpp`）

复现命令：

```powershell
$env:TEMP='F:\rtsc\.tmp'; $env:TMP='F:\rtsc\.tmp'
$vs='C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat'
cmd /c "call `"$vs`" >nul 2>&1 && cd /d F:\rtsc\.tmp\schprobe && cl /nologo /W4 /EHsc /std:c++20 /utf-8 main.cpp /Fe:schprobe.exe /link ws2_32.lib secur32.lib crypt32.lib && schprobe.exe"
```

输出（完整见 `schannel-probe.txt`）：

```
TCP connected to 192.168.1.7:3389
X.224 CC (19 bytes): 03 00 00 13 0e d0 00 00 12 34 00 02 0f 08 00 08 00 00 00
selectedProtocol = 0x08
AcquireCredentialsHandle OK
ClientHello (147 bytes): 16 03 03 00 8e 01 00 00 8a 03 03 ...
round 1: received 846 bytes
  ISC -> 0x00090312
round 2: received 51 bytes
  ISC -> 0x00000000
TLS handshake complete after 2 rounds
protocol=0x00000800 cipher=0x00006610 bits=256
stream sizes: header=13 trailer=16 maxmsg=16384
server cert subject: (present)
cert cbCertEncoded = 742
```

关键读数：

| 项 | 值 | 含义 |
|---|---|---|
| `selectedProtocol` | `0x08` | 服务器强制 `PROTOCOL_HYBRID_EX`，与既有握手取证一致 |
| `protocol` | `0x00000800` | `SP_PROT_TLS1_2`（不是 TLS 1.3） |
| `cipher` | `0x00006610` | `CALG_AES_256` + `CALG_ECDH` = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 |
| `header` | 13 | TLS 记录头 5 + GCM 显式 nonce 8 |
| `trailer` | 16 | GCM 认证标签 |
| `maxmsg` | 16384 | 单条记录最大应用数据 |

注意 `round 1` 返回 `0x00090312` = `SEC_I_CONTINUE_NEEDED`，`round 2` 返回 `0x00000000` =
`SEC_E_OK`。服务器把 `ServerHello`+`Certificate`+`ServerKeyExchange`+`ServerHelloDone` 合并在
一个 846 字节 TCP 段里发出，`ClientKeyExchange`+`ChangeCipherSpec`+`Finished` 之后 51 字节
`ChangeCipherSpec`+`Finished` 就完成握手——**两轮**，无重协商。

## 探针 2：SPKI 导出（`F:\rtsc\.tmp\schprobe\spki.cpp`）

输出（完整见 `schannel-spki-probe.txt`）：

```
public key bit length = 2160, unused bits = 0
SubjectPublicKeyInfo DER (294 bytes): 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 ce b5 bf 3f ...
SPKI found in certificate at offset 134
SPKI verbatim-in-cert = YES
SHA256(SPKI) (32 bytes): 78 b5 f2 6b 09 41 d4 fd 97 89 00 25 30 f1 eb 31 95 80 b0 6a 95 3e ef 63 62 ef 02 05 91 00 0f 3a
```

关键结论：

1. `CryptEncodeObjectEx(X509_PUBLIC_KEY_INFO)` 直接作用于
   `cert->pCertInfo->SubjectPublicKeyInfo`，产出 **294 字节** DER，
   与证书 DER 中偏移 134 处**逐字节相同**。
2. 这意味着**不需要自己写 ASN.1 解析器**来取 SPKI——Windows 上 crypt32 已给出规范 DER。
3. **踩过的坑**：第一次尝试把整张证书当作 `X509_PUBLIC_KEY_INFO` 传给
   `CryptDecodeObjectEx`，返回 `0xC0000005`（访问违例，`GetLastError` 打印成
   `3221225477`）。正确做法是**不 decode**，直接用 `pCertInfo` 里已解析好的字段。

## 对 `security-layer.md` §8 的影响

§8 现推荐 OpenSSL 3.x，理由之一是"跨平台唯一解"。本实测证明：

- Windows 侧 **SChannel 零依赖可用**，且已对真实服务器跑通；
- §8.2 写"① vcpkg：`vcpkg install openssl`"——**本机无 vcpkg**；
- §8.2 写"③ 源码 + `perl Configure VC-WIN64A`"——**本机无 perl**；
- 因此 §8 的三条 Windows 集成路径在当前环境下**全部不可用**。

Linux 侧仍需 OpenSSL（或其它），所以正确形态是**后端抽象**：Windows 用 SChannel，
Linux 用 OpenSSL，接口一致。这正是 `tls-backend.design-a/b.md` 要审计的内容。

## 未验证

- 未验证 TLS 1.3（服务器选的是 1.2）。
- 未验证 `SEC_I_RENEGOTIATE` / `SEC_I_CONTEXT_EXPIRED` 路径（本次握手未触发）。
- 未验证 Linux 侧任何后端。
- 未验证 SChannel 在 FIPS 模式下的行为。
