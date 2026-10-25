import io

proc = """

## 第231轮：用户要求「音频必须全部实现（远程放音乐）+ 压缩 + 全部功能」→ 派音频子代理

- **用户要求**：远程桌面**音频必须全部实现**（远程放音乐）、**压缩**、**全部功能**。
- **现状**：rdpsnd 只有**结构层**（`channel/rdpsnd.h`：SNDPROLOG + 13 SNDC_* + Wave2），**无通道处理器、无音频输出**；
  压缩（RDP6/NSCodec）已实现（需复核）。
- **[task:general] 新开子代理** 实现 **rdpsnd 通道处理器 + Windows 音频输出（WASAPI 或 waveOut）**：
  - 解 `SNDC_WAVE`(Wave2 format+samples) → 播放；`SNDC_WAVECONFIRM`/`SNDC_CLOSE`/`SNDC_SETVOLUME`/`SNDC_SETPITCH`/`SNDC_TRAINING`；
  - Windows 音频输出（WASAPI 优先，waveOut 备选）；线程安全；
  - 注册 chan 1006（rdpsnd）；测试（解析 + mock 音频后端断言 PCM）；真机验证能听到远程声音。
- **性能**：非阻塞 I/O（SO_RCVTIMEO 已落盘）；渲染最近邻缩放；RLE 线性。
- 在途：音频实现；未响应修复（ses_e8c9ac69，忙）。
"""
io.open('.opencode/process.md', 'a', encoding='utf-8').write(proc)
print('ok')
