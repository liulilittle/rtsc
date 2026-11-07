// Display Control virtual channel wire format ([MS-RDPEDISP]).

#include "rtsc/proto/display_control.h"

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {
namespace {

constexpr size_t kHeaderSize = 8;
constexpr size_t kCapsBodySize = 12;      // MaxNumMonitors + factors A/B
constexpr size_t kLayoutFixedSize = 8;    // MonitorLayoutSize + NumMonitors
constexpr size_t kCapsPduSize = kHeaderSize + kCapsBodySize;
constexpr uint32_t kMinMonitorDimension = 200;
constexpr uint32_t kMaxMonitorDimension = 8192;

}  // namespace

bool ParseDisplayControlCaps(const uint8_t* data, size_t size,
                             DisplayControlCaps& out) {
    if (data == nullptr || size < kCapsPduSize) return false;
    ByteReader r(data, size);
    uint32_t type = 0;
    uint32_t length = 0;
    if (!r.u32le(type) || !r.u32le(length)) return false;
    if (type != static_cast<uint32_t>(DisplayControlType::kCaps)) return false;
    // Length includes the 8-byte header. A length below the fixed body is
    // malformed; one above the received buffer is truncated.
    if (length < kCapsPduSize || length > size) return false;
    DisplayControlCaps caps;
    if (!r.u32le(caps.max_num_monitors) ||
        !r.u32le(caps.max_monitor_area_factor_a) ||
        !r.u32le(caps.max_monitor_area_factor_b)) {
        return false;
    }
    out = caps;
    return true;
}

bool DisplayControlMonitorValid(const DisplayControlMonitor& m) {
    if (m.width < kMinMonitorDimension || m.width > kMaxMonitorDimension) {
        return false;
    }
    // Width MUST NOT be odd ([MS-RDPEDISP] 2.2.2.2.1).
    if ((m.width & 1u) != 0) return false;
    if (m.height < kMinMonitorDimension || m.height > kMaxMonitorDimension) {
        return false;
    }
    if (m.orientation != 0 && m.orientation != 90 && m.orientation != 180 &&
        m.orientation != 270) {
        return false;
    }
    if (m.desktop_scale_factor < 100 || m.desktop_scale_factor > 500) {
        return false;
    }
    if (m.device_scale_factor != 100 && m.device_scale_factor != 140 &&
        m.device_scale_factor != 180) {
        return false;
    }
    // The primary monitor is the coordinate origin: its upper-left corner is
    // always (0, 0) ([MS-RDPEDISP] 2.2.2.2.1).
    if ((m.flags & kDisplayControlMonitorPrimary) != 0 &&
        (m.left != 0 || m.top != 0)) {
        return false;
    }
    return true;
}

bool MakePrimaryMonitorFromViewport(uint32_t width, uint32_t height,
                                    DisplayControlMonitor& out) {
    if (height < kMinMonitorDimension || height > kMaxMonitorDimension) {
        return false;
    }
    // The wire rule is "width MUST NOT be odd"; rounding down keeps the request
    // close to the local window instead of failing a resize by one pixel.
    const uint32_t even_width = width & ~1u;
    if (even_width < kMinMonitorDimension || even_width > kMaxMonitorDimension) {
        return false;
    }
    DisplayControlMonitor monitor;
    monitor.flags = kDisplayControlMonitorPrimary;
    monitor.width = even_width;
    monitor.height = height;
    out = monitor;
    return true;
}

std::vector<uint8_t> EncodeDisplayControlMonitorLayout(
    const std::vector<DisplayControlMonitor>& monitors) {
    if (monitors.empty()) return {};
    if (monitors.size() > 0xFFFFFFFFu / kDisplayControlMonitorLayoutSize) {
        return {};
    }
    // Reject layouts the server would only ignore: overlapping monitors, or a
    // monitor that touches no other monitor ([MS-RDPEDISP] 3.2.5.1).
    if (!DisplayControlLayoutValid(monitors)) return {};
    const uint64_t layout_bytes =
        static_cast<uint64_t>(monitors.size()) * kDisplayControlMonitorLayoutSize;
    const uint64_t total = kHeaderSize + kLayoutFixedSize + layout_bytes;
    if (total > 0xFFFFFFFFu) return {};

    ByteWriter w;
    w.u32le(static_cast<uint32_t>(DisplayControlType::kMonitorLayout));
    w.u32le(static_cast<uint32_t>(total));
    w.u32le(kDisplayControlMonitorLayoutSize);
    w.u32le(static_cast<uint32_t>(monitors.size()));
    for (const DisplayControlMonitor& m : monitors) {
        w.u32le(m.flags);
        w.u32le(static_cast<uint32_t>(m.left));
        w.u32le(static_cast<uint32_t>(m.top));
        w.u32le(m.width);
        w.u32le(m.height);
        w.u32le(m.physical_width);
        w.u32le(m.physical_height);
        w.u32le(m.orientation);
        w.u32le(m.desktop_scale_factor);
        w.u32le(m.device_scale_factor);
    }
    return w.take();
}

bool DisplayControlLayoutValid(
    const std::vector<DisplayControlMonitor>& monitors) {
    if (monitors.empty()) return false;
    for (const DisplayControlMonitor& m : monitors) {
        if (!DisplayControlMonitorValid(m)) return false;
    }
    // A second primary monitor is already impossible here: the primary is
    // pinned to (0, 0) and two monitors at the origin overlap.
    if (monitors.size() == 1) return true;

    const auto left = [](const DisplayControlMonitor& m) {
        return static_cast<int64_t>(m.left);
    };
    const auto top = [](const DisplayControlMonitor& m) {
        return static_cast<int64_t>(m.top);
    };
    const auto right = [](const DisplayControlMonitor& m) {
        return static_cast<int64_t>(m.left) + static_cast<int64_t>(m.width);
    };
    const auto bottom = [](const DisplayControlMonitor& m) {
        return static_cast<int64_t>(m.top) + static_cast<int64_t>(m.height);
    };

    for (size_t i = 0; i < monitors.size(); ++i) {
        bool adjacent = false;
        for (size_t j = 0; j < monitors.size(); ++j) {
            if (i == j) continue;
            // Strict interior intersection: touching edges/corners is not an
            // overlap ([MS-RDPEDISP] 3.2.5.1).
            if (left(monitors[i]) < right(monitors[j]) &&
                left(monitors[j]) < right(monitors[i]) &&
                top(monitors[i]) < bottom(monitors[j]) &&
                top(monitors[j]) < bottom(monitors[i])) {
                return false;
            }
            if (left(monitors[i]) <= right(monitors[j]) &&
                left(monitors[j]) <= right(monitors[i]) &&
                top(monitors[i]) <= bottom(monitors[j]) &&
                top(monitors[j]) <= bottom(monitors[i])) {
                adjacent = true;
            }
        }
        if (!adjacent) return false;
    }
    return true;
}

bool DisplayControlLayoutWithinCaps(
    const std::vector<DisplayControlMonitor>& monitors,
    const DisplayControlCaps& caps) {
    if (monitors.empty()) return false;
    if (caps.max_num_monitors == 0 || caps.max_monitor_area_factor_a == 0 ||
        caps.max_monitor_area_factor_b == 0) {
        return false;
    }
    if (monitors.size() > caps.max_num_monitors) return false;
    // MaxNumMonitors * FactorA * FactorB can exceed 64 bits for the largest
    // server-stated caps; saturate instead of wrapping to a small bound that
    // would reject a legal layout.
    const uint64_t kMaxU64 = ~static_cast<uint64_t>(0);
    uint64_t max_area = 1;
    const uint64_t factors[3] = {caps.max_num_monitors,
                                 caps.max_monitor_area_factor_a,
                                 caps.max_monitor_area_factor_b};
    for (const uint64_t factor : factors) {
        if (max_area > kMaxU64 / factor) {
            max_area = kMaxU64;
            break;
        }
        max_area *= factor;
    }
    uint64_t total_area = 0;
    for (const DisplayControlMonitor& m : monitors) {
        if (!DisplayControlMonitorValid(m)) return false;
        const uint64_t area =
            static_cast<uint64_t>(m.width) * static_cast<uint64_t>(m.height);
        if (total_area + area < total_area) return false;  // overflow
        total_area += area;
    }
    return total_area <= max_area;
}

}  // namespace rtsc::proto
