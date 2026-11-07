# Display Control 证据（[MS-RDPEDISP]）

## 批186：主屏原点与 caps 面积饱和（2026-11-07）

**事实来源**（learn.microsoft.com 原文）：
- 2.2.2.2.1 DISPLAYCONTROL_MONITOR_LAYOUT：坐标相对主屏左上角，主屏左上角
  恒为 (0,0)；Width 200..8192 且不得为奇数；Height 200..8192；
  PhysicalWidth/Height 超出 10..10000 时服务器忽略；Orientation 非
  0/90/180/270 时忽略。
- 2.2.2.1 DISPLAYCONTROL_CAPS_PDU：最大面积为
  MaxNumMonitors x MaxMonitorAreaFactorA x MaxMonitorAreaFactorB。
- 3.2.5.1：服务器仅在字段合法、无重叠、每块屏至少与另一块相邻（边或角）
  时才应用布局。

**实现**：
- `src/proto/display_control.cpp`：`DisplayControlMonitorValid` 拒绝非原点
  的 PRIMARY 屏；`DisplayControlLayoutWithinCaps` 的面积上限改为饱和乘法
  （三因子乘积超 64 位时取 UINT64_MAX，不再回绕）。
- 删除“至多一个主屏”的独立计数：该规则由原点规则 + 不重叠规则蕴含，
  变异 M103 存活证明其不可隔离（见 discover 例96）。

**证据**：`tests/test_display_control.cpp` 新增
`disp_layout_primary_must_be_at_origin_and_unique`、
`disp_caps_area_bound_saturates`；`tests/test_display_control_client.cpp`
新增 `display_control_rejects_off_origin_primary`。display_control 15/70、
display_control_client 13/80 全绿；影响面 5/5。变异 M101（删原点检查）红
5+3 checks、M102（面积不回绕）红 1 check，恢复后全绿。

**未验证**：真实服务器对非原点主屏/超大 caps 的处理；caps 长度大于 20 的
前向兼容字段未解析。