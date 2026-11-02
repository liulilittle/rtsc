# 输入几何：主代理侧独立探针证据（2026-11-02）

本文件只记录**主代理自己跑出的原始输出**与**环境限制**，不提出设计方案（设计由审计
`input-geometry-design-M.md` / `-N.md` 负责，实现由执行角色落地）。目的是让审计结论里
每一条"真机实测"都能被指认来源，并明确哪些结论**只有一方证据**。

复跑脚本位于 `%TEMP%\opencode\`（未入库）：`gdi_probe.ps1`、`decode_probe5.ps1`。

---

## 1. GDI `StretchBlt(COLORONCOLOR)` 采样相位（已复现，结论明确）

方法与 `src/server/desktop_gdi.cpp:205-206` 的生产路径一致：
`SetStretchBltMode(memory, COLORONCOLOR)` + `StretchBlt`，源为一个 1px 高的 32bpp DIB，
每个像素的值编码其 x 索引；读取目标 DIB 还原"每个目标列取了源图哪一列"。

三类候选各自与实测比较（`center` = `floor(((2x+1)*cap)/(2*fb))`、
`endpoint` = `round(x*(cap-1)/(fb-1))`、`leftedge` = `floor(x*cap/fb)`）：

```text
src=2560 dst=1280  center=0/1280   endpoint=640/1280  leftedge=1280/1280
src=1920 dst=1280  center=0/1280   endpoint=0/1280    leftedge=640/1280
src=1280 dst=1280  center=0/1280   endpoint=0/1280    leftedge=0/1280
src=640  dst=1280  center=0/1280   endpoint=0/1280    leftedge=0/1280
src=1280 dst=2560  center=0/2560   endpoint=0/2560    leftedge=0/2560
src=3200 dst=1280  center=0/1280   endpoint=428/1280  leftedge=1280/1280
src=1920 dst=1920  center=0/1920   endpoint=0/1920    leftedge=0/1920
```

结论（7/7 组）：

- **中心采样 `floor(((2x+1)*cap)/(2*fb))` 在每一组上都是 0 失配**，包括下采样
  2560→1280、3200→1280 与 1:1。
- 端点锚定 `round(x*(cap-1)/(fb-1))` 在 2560→1280 上错 640/1280（50%）、
  3200→1280 上错 428/1280。
- 左端点缩放 `floor(x*cap/fb)` 在所有下采样组上 100% 错。

因此**捕获路径的像素来源**是中心采样，不是端点锚定。这与 `input-geometry-design-N.md`
§2 的 21 组结论一致（方向与数值一致）。

> 连带作废：主代理第 846 轮曾以端点锚定为 oracle 得出"新公式 mean=0/max=0"，
> 该 oracle 在**下采样**路径上不成立。见 `.opencode/discover.md` 第 28 例。

---

## 2. DPI 语境（已复现，结论明确）

在未声明 DPI 感知的进程里，`SM_*VIRTUALSCREEN` 返回的是**虚拟化后**的尺寸；
`GetDeviceCaps(DESKTOPHORZRES/DESKTOPVERTRES)` 返回真实物理像素：

```text
awareness 未设置: SM_CXVIRTUALSCREEN=2048x1152  DESKTOPHORZRES=2560x1440
set PMv2 返回 True: SM_CXVIRTUALSCREEN=2560x1440  DESKTOPHORZRES=2560x1440
```

本机真实分辨率为 2560x1440，系统 DPI 120（默认缩放到 2048x1152）。

`src/server/desktop_gdi.cpp:63-65` 把 `SetProcessDpiAwarenessContext` 的返回值
丢弃（`(void)`），所以一旦该调用失败（例如 manifest 已固定、或先前调用已设置过），
`SM_*` 会静默返回 2048x1152，而真实桌面是 2560x1440 —— 此时 `desktop` 矩形与
`capture` 矩形都会偏小，注入落点按错误范围归一化。

与 `input-geometry-design-N.md` §4.3 结论一致（方向与数值一致）。

---

## 3. 解码公式 `floor(n*extent/65536)`（**未复现**，仅 N 单方证据）

本会话**无法驱动光标**：`SendInput(MOVE|ABSOLUTE|VIRTUALDESK)` 返回 1（成功），
但 `GetCursorPos` 读数完全不变：

```text
n=0     sent=1 pos=2366
n=1     sent=1 pos=2366
n=1000  sent=1 pos=2366
n=16384 sent=1 pos=2366
n=32768 sent=1 pos=2366
n=65535 sent=1 pos=2366
```

排查过程（记录以免重犯）：

- 第一次尝试 `SendInput` 返回 0、`GetLastError()=87`（ERROR_INVALID_PARAMETER）。
  原因是我自己把 `INPUT` 结构多写了一个 `long pad`，`sizeof(INPUT)=48`；修正为
  联合体后 `sizeof=40`，`SendInput` 开始返回 1。
- 修正后仍然不动，且 `OpenInputDesktop` 返回非 0 句柄。

判断：该会话运行在**非交互桌面**（或会话隔离子系统）上，注入被静默丢弃。
因此：

- `input-geometry-design-N.md` §1.2 的"x 向 4179 点 / y 向 685 点全 0 失配"
  **在主代理侧为 UNVERIFIED（未验证）**，不构成第二方证据。
- 该结论目前**只有 N 单方证据**。在真机验收清单里必须保留为需要用户复验的项目。

---

## 4. 编码方案三者的全像素往返（纯算术，可复跑，已复现）

对 `w ∈ {1280,1920,2560,3200,3840,2048}` 枚举全部 `x ∈ [0,w-1]`，
以 `land(n) = floor(n*w/65536)` 为解码，统计 `land(encode(x)) != x` 的个数：

| w | 纯 `ceil(x*65536/w)` | 混合式（`x>=w-1` 时 65535，否则 ceil） | 现行 `round(x*65535/(w-1))` |
|---|---|---|---|
| 1280 | 0 | 0 | 3 |
| 1920 | 0 | 0 | 7 |
| 2048 | 0 | 0 | 0 |
| 2560 | 0 | 0 | 8 |
| 3200 | 0 | 0 | 20 |
| 3840 | 0 | 0 | 28 |

末像素 `x=w-1` 的编码值与落点：

```text
pure-ceil  w=1280 n=65485 land=1279 | w=1920 n=65502 land=1919 | w=2560 n=65511 land=2559
hybrid     w=1280 n=65535 land=1279 | w=1920 n=65535 land=1919 | w=2560 n=65535 land=2559
old        w=1280 n=65535 land=1279 | w=1920 n=65535 land=1919 | w=2560 n=65535 land=2559
```

要点：纯 ceil 与混合式在**落点**上完全等价（末像素都落在 `w-1`），差别只在 wire 值。
混合式把末像素钉在 65535，与 [MS-W32] 对 `MOUSEINPUT` 的原文
（"coordinate (65535,65535) maps onto the lower-right corner"）一致，且与
`tests/test_desktop_input.cpp:272-279` 的既有断言语义一致。

---

## 5. 与现有测试的关系（核对结果，纠正一处第三方论证）

`tests/test_desktop_input.cpp:272-279` 的用例是 **`ev.x = 1920`、几何 `1920x1080`**，
即 value 等于 extent（超出最后一个像素），不是 `extent-1`。

现行 `NormalizeAxis` 有前置夹取 `if (value >= extent-1) return 65535;`
（`src/server/desktop_input_map.cpp:25`）。因为该夹取先执行：

- 三种编码方案对 `(1920,1080)@1920x1080` **都返回 65535**，该用例在三种方案下都通过。
- 因此"纯 ceil 会打断 `:272-279` 的既有断言"这一说法**在本仓库当前代码上不成立**：
  只要保留既有的 `value >= extent-1` 夹取，纯 ceil 同样给 65535。
- 混合式相对纯 ceil 的真正价值不是"避免改动断言"，而是**让末像素的 wire 值回到
  65535**（文档端点语义），且不引入任何往返失配。

结论：混合式可以采纳，但采纳理由应写"对齐文档端点语义 + 零往返失配"，
不应写"否则会打断既有测试"。

---

## 6. 本文件未覆盖的内容

- 负原点多屏布局、非矩形拼接空洞、显示器缝穿越：本会话只有单屏，无法验证。
- `--monitor N` 的注入端到端落点：受第 3 节限制，无法验证。
- 以上均保持 UNVERIFIED，需用户在有真实交互桌面的机器上按
  `docs/spec/input-injection-real-machine-checklist.md` 执行。

---

## 7. 用**真实库**复现跨屏缺陷（主代理亲测，非引用他人）

探针 `%TEMP%\opencode\probe_real.cpp` 链接仓库产物
`build/Release/rtsc_server_desktop_input_map.lib`，直接调用线上函数 `TranslateInput`，
再用 OS 的解码语义 `floor(n*extent/65536)`（VIRTUALDESK 按虚拟桌面 3200x1024）还原落点：

```text
场景：--monitor 1（第二块屏，origin 1920,0），捕获 1280x1024，虚拟桌面 3200x1024，
      客户端 framebuffer 1280x1024，客户端点 (640,512)
wire n=(32793,32800) landing=(1601,512)
expected landing=(2560,512)  (monitor1 origin 1920 + 640)
[RED] cross-monitor
```

结论：**跨屏缺陷用真实产物可复现**，落点在第一块屏 `x=1601`，应在第二块屏 `x=2560`，
偏 **959 px**。这与审计 M §13.1 的红证数值一致（`n=(32793,32800)`、`(1601,512)`）。

编译命令（可复跑）：

```text
call "<VS>\VC\Auxiliary\Build\vcvars64.bat"
cl /nologo /std:c++20 /EHsc /MD /W4 /I F:\rtsc\include probe_real.cpp ^
   /Fe:probe_real.exe F:\rtsc\build\Release\rtsc_server_desktop_input_map.lib
```

> 注意：编译该探针时 `InputEvent` 定义在 `rtsc/server/server.h`，
> 只包含 `desktop_input_map.h` 会报 `C2065: ev 未声明`。
---

## 8. `DesktopSource` 扩接口的破坏面（主代理核验，支持"默认实现"决定）

设计 M §5 主张给 `DesktopSource` 加 `virtual DesktopGeometry Geometry() const` 时**必须带默认实现**
（而非纯虚），理由是"否则所有实现点都要改"。我核实了实现点数量：

```text
src/server/desktop_gdi.cpp:146                GdiDesktopSourceImpl
src/server/server.cpp:2705                    TestPatternSource（默认源）
tests/test_server.cpp:1691                    FailingAfterSource
tests/test_server.cpp:2632                    ScriptedSource
tests/test_server.cpp:3421                    BlockingFirstCaptureSource
tests/test_server_multisession.cpp:150        RecordingSource
```

共 **6 处**实现。若改为纯虚：

- 这 6 处全部编译失败，需要逐一实现（其中 5 处是测试替身，实现值为"未知几何"）
- 且每个测试替身都要写一份"返回 unknown"的样板代码

⇒ **默认实现（返回 capture/desktop 全 0、`mapped=false`、`pixels_are_physical=false`）是正确选择**：
生产实现只覆盖 GDI 一处，测试替身零改动，且默认值本身是 fail-closed（不产出移动），
不会让未覆盖的替身静默产出错误坐标。