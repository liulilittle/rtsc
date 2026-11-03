// Application of the DstBlt / OpaqueRect / ScrBlt primary drawing orders
// ([MS-RDPEGDI] 2.2.2.2.1.1.2) to a ui::Surface.
//
// This layer keeps rtsc::proto free of any UI dependency: the orders are
// decoded by rtsc::proto (Parse* / OrderBodyState) and applied here.

#pragma once

#include "rtsc/proto/orders.h"
#include "rtsc/ui/surface.h"

namespace rtsc::render {

// Applies a parsed order to a surface. All three clip to the surface: pixels
// outside it are never written, and a zero or negative width/height is a no-op.
// DstBlt uses S = P = 0 (the spec requires the result not to depend on them);
// OpaqueRect fills opaque RGB (palette mode is out of scope for now);
// ScrBlt snapshots the source rectangle first so overlapping self-copies do
// not smear.
void ApplyDstBlt(rtsc::ui::Surface& surface,
                 const rtsc::proto::DstBltOrder& order);
void ApplyOpaqueRect(rtsc::ui::Surface& surface,
                     const rtsc::proto::OpaqueRectOrder& order);
void ApplyScrBlt(rtsc::ui::Surface& surface,
                 const rtsc::proto::ScrBltOrder& order);

// Result of applying a PatBlt.
enum class PatBltResult {
    kApplied,      // pixels were drawn
    kNoOp,         // BS_NULL or zero/negative size: nothing drawn
    kUnsupported,  // unimplemented brush (e.g. a cache miss): nothing drawn
};

// Read-only view of the brush cache, so a PatBlt can resolve a TS_CACHED_BRUSH
// brush without rtsc_render depending on the order engine. The order engine
// adapts its cache to this interface.
class BrushCacheView {
 public:
    virtual ~BrushCacheView() = default;
    // Returns the cached brushData bytes (wire order) for `index`, or nullptr
    // when the entry is not populated. `format` receives the cached
    // iBitmapFormat and `length` the brushData byte count, so the caller can
    // classify the brush form ([MS-RDPEGDI] 2.2.2.2.1.2.7.1).
    virtual const uint8_t* Lookup(uint8_t index, uint8_t& format,
                                  uint8_t& length) const = 0;
};

// Applies a parsed PatBlt to a surface with no brush cache: a TS_CACHED_BRUSH
// brush is always kUnsupported (there is no cache to resolve it against).
// BS_SOLID uses P = ForeColor and S = 0; BS_NULL draws nothing; BS_HATCHED
// uses the six built-in GDI hatch patterns (HS_HORIZONTAL..HS_DIAGCROSS);
// BS_PATTERN uses the inline 8x8 BrushExtra pattern. Only an unhandled style
// reports kUnsupported.
PatBltResult ApplyPatBlt(rtsc::ui::Surface& surface,
                         const rtsc::proto::PatBltOrder& order);

// Applies a parsed PatBlt, resolving TS_CACHED_BRUSH (BrushStyle high bit set)
// through `cache`: BrushHatch is the cache index and BrushStyle & 0x0F is the
// color depth, which must match the cached brush's iBitmapFormat. A cached
// brush is decoded into an 8x8 pattern and composited with the ROP3 (S = 0):
// BMF_1BPP is monochrome (bit 0 = ForeColor, bit 1 = BackColor, matching the
// hatch/pattern polarity); BMF_8BPP is unsupported (it needs the color-table
// context, which is not plumbed here); 16/24/32BPP brushes are decoded either
// as COMPRESSED_COLOR_BRUSH (16 + 4*bpp_bytes bytes) or uncompressed
// (64*bpp_bytes bytes). A cache miss, a depth mismatch, a form that matches no
// defined encoding, or a color depth that needs a palette is kUnsupported
// rather than drawn wrong.
PatBltResult ApplyPatBlt(rtsc::ui::Surface& surface,
                         const rtsc::proto::PatBltOrder& order,
                         const BrushCacheView& cache);

}  // namespace rtsc::render
