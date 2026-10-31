// Direction-B file-list backend: Win32 CF_HDROP -> FileListProvider.
//
// Tests the DropFileList provider and the CreateDropFileListFromBytes factory
// against byte blobs built with the real shellapi.h DROPFILES layout, and
// against real temporary files/directories for the filesystem-backed parts.

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "rtsc/clipboard/drop_files.h"
#include "test_framework.h"
#include "test_main.h"

namespace {

using rtsc::clipboard::CreateDropFileListFromBytes;
using rtsc::clipboard::DropFileList;

// Appends `s` as a null-terminated UTF-16LE string to `b`.
void AppendWide(std::vector<uint8_t>& b, const std::u16string& s) {
    for (char16_t c : s) {
        b.push_back(static_cast<uint8_t>(c & 0xFF));
        b.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
    b.push_back(0);
    b.push_back(0);
}

// Builds a CF_HDROP blob: a 20-byte DROPFILES header (pFiles=20, fWide=1)
// followed by null-terminated UTF-16LE names. When `double_null` is true a
// final empty string is appended, the layout Windows produces.
std::vector<uint8_t> MakeHdropWide(const std::vector<std::u16string>& names,
                                   bool double_null = true) {
    std::vector<uint8_t> b(20, 0);
    b[0] = 20;   // pFiles: file table starts right after the header.
    b[16] = 1;   // fWide: UTF-16LE table.
    for (const auto& n : names) AppendWide(b, n);
    if (double_null) {
        b.push_back(0);
        b.push_back(0);
    }
    return b;
}

// ANSI variant (fWide stays 0): null-terminated bytes, list double-null.
std::vector<uint8_t> MakeHdropAnsi(const std::vector<std::string>& names) {
    std::vector<uint8_t> b(20, 0);
    b[0] = 20;
    for (const auto& n : names) {
        b.insert(b.end(), n.begin(), n.end());
        b.push_back(0);
    }
    b.push_back(0);
    return b;
}

// Fails the case and bails out when `ok` is false (the test framework has no
// fatal assertion, and dereferencing a null provider would crash the process).
bool NeedProvider(bool ok) {
    if (!ok) {
        ::rtsc::test::report_failure(__FILE__, __LINE__,
                                     "expected a non-null provider");
    }
    return ok;
}

std::filesystem::path MakeTempPath(const std::string& tag) {
    static std::atomic<uint64_t> counter{0};
    std::error_code ec;
    std::filesystem::path base = std::filesystem::temp_directory_path(ec);
    if (ec) base = std::filesystem::path(".");
    return base / ("rtsc_drop_" + tag + "_" +
                   std::to_string(counter.fetch_add(1)));
}

// RAII: removes the backed file/directory when the case ends.
struct TempScope {
    std::filesystem::path p;
    ~TempScope() {
        std::error_code ec;
        std::filesystem::remove_all(p, ec);
    }
};

std::filesystem::path MakeTempFile(const std::vector<uint8_t>& content) {
    const std::filesystem::path p = MakeTempPath("file");
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!content.empty()) {
        f.write(reinterpret_cast<const char*>(content.data()),
                static_cast<std::streamsize>(content.size()));
    }
    f.close();
    CHECK(f.good() || content.empty());
    return p;
}

// Creates a real temp file with an explicit file name, so the basename under
// test is controllable (including CJK and space characters).
std::filesystem::path MakeTempFileNamed(const std::u16string& name,
                                        const std::vector<uint8_t>& content) {
    std::error_code ec;
    const std::filesystem::path base = std::filesystem::temp_directory_path(ec);
    const std::filesystem::path p =
        (ec ? std::filesystem::path(".") : base) / std::filesystem::path(name);
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!content.empty()) {
        f.write(reinterpret_cast<const char*>(content.data()),
                static_cast<std::streamsize>(content.size()));
    }
    f.close();
    CHECK(f.good() || content.empty());
    return p;
}

std::filesystem::path MakeTempDir() {
    const std::filesystem::path p = MakeTempPath("dir");
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    CHECK(!ec);
    return p;
}

const std::vector<uint8_t> kTen = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

}  // namespace

// ---- parsing --------------------------------------------------------------

RTSC_TEST(drop_files_parses_single_file) {
    const std::filesystem::path file = MakeTempFileNamed(u"a.txt", kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(1));
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK(info.name == u"a.txt");
}

RTSC_TEST(drop_files_parses_multiple_files_order) {
    const std::filesystem::path f1 = MakeTempFileNamed(u"1.txt", kTen);
    const std::filesystem::path f2 = MakeTempFileNamed(u"2.txt", kTen);
    const std::filesystem::path f3 = MakeTempFileNamed(u"3.txt", kTen);
    TempScope guard3{f3};
    TempScope guard2{f2};
    TempScope guard1{f1};
    auto p = CreateDropFileListFromBytes(
        MakeHdropWide({f1.u16string(), f2.u16string(), f3.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(3));
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK(info.name == u"1.txt");
    CHECK(p->file_info(1, info));
    CHECK(info.name == u"2.txt");
    CHECK(p->file_info(2, info));
    CHECK(info.name == u"3.txt");
}

RTSC_TEST(drop_files_parses_cjk_and_space_names) {
    const std::filesystem::path f1 = MakeTempFileNamed(u"报告 2024.txt", kTen);
    const std::filesystem::path f2 = MakeTempFileNamed(u"my file.txt", kTen);
    TempScope guard2{f2};
    TempScope guard1{f1};
    auto p =
        CreateDropFileListFromBytes(MakeHdropWide({f1.u16string(), f2.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(2));
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK(info.name == u"报告 2024.txt");
    CHECK(p->file_info(1, info));
    CHECK(info.name == u"my file.txt");
}

RTSC_TEST(drop_files_parses_name_without_directory_part) {
    // A separator-free (relative) name still parses to a one-file list.
    auto p =
        CreateDropFileListFromBytes(MakeHdropWide({u"rtsc_no_such_bare_9f31.txt"}));
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(1));
    // D-B1: the CWD-relative path does not exist, so file_info must fail
    // instead of fabricating a zero-length file for the peer.
    rtsc::clipboard::FileInfo info;
    CHECK_EQ(p->file_info(0, info), false);
}

RTSC_TEST(drop_files_basename_strips_trailing_separator) {
    // A directory path that ends with a separator (Explorer usually strips it,
    // but be tolerant): the basename must drop the trailing separator. Use the
    // platform separator so the stat below sees a directory on POSIX too.
    const std::filesystem::path dir = MakeTempDir();
    TempScope guard{dir};
    const char16_t sep = static_cast<char16_t>(
        std::filesystem::path::preferred_separator);
    const std::u16string with_trailing = dir.u16string() + sep;
    auto p = CreateDropFileListFromBytes(MakeHdropWide({with_trailing}));
    if (!NeedProvider(p != nullptr)) return;
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK_EQ(info.is_directory, true);
    CHECK(info.name == dir.filename().u16string());
}

RTSC_TEST(drop_files_file_count_zero_one_many) {
    auto none = CreateDropFileListFromBytes(MakeHdropWide({}));
    if (!NeedProvider(none != nullptr)) return;
    CHECK_EQ(none->file_count(), static_cast<uint32_t>(0));

    auto one = CreateDropFileListFromBytes(MakeHdropWide({u"C:\\x\\a"}));
    if (!NeedProvider(one != nullptr)) return;
    CHECK_EQ(one->file_count(), static_cast<uint32_t>(1));

    auto many =
        CreateDropFileListFromBytes(MakeHdropWide({u"C:\\x\\a", u"C:\\x\\b", u"C:\\x\\c"}));
    if (!NeedProvider(many != nullptr)) return;
    CHECK_EQ(many->file_count(), static_cast<uint32_t>(3));
}

// ---- invalid input --------------------------------------------------------

RTSC_TEST(drop_files_factory_rejects_empty_vector) {
    CHECK(CreateDropFileListFromBytes({}) == nullptr);
}

RTSC_TEST(drop_files_factory_rejects_short_header) {
    std::vector<uint8_t> bytes(19, 0);
    bytes[16] = 1;
    CHECK(CreateDropFileListFromBytes(bytes) == nullptr);
}

RTSC_TEST(drop_files_factory_rejects_pfiles_below_header) {
    std::vector<uint8_t> bytes(20, 0);
    bytes[0] = 4;  // pFiles < sizeof(DROPFILES).
    bytes[16] = 1;
    CHECK(CreateDropFileListFromBytes(bytes) == nullptr);
}

// Probe: pFiles pointing outside the buffer must be rejected, never read.
RTSC_TEST(drop_files_factory_rejects_pfiles_out_of_bounds) {
    std::vector<uint8_t> bytes(20, 0);
    bytes[0] = 0xFF;
    bytes[1] = 0xFF;
    bytes[2] = 0x7F;  // pFiles = 0x7FFFFF, far beyond the buffer.
    bytes[3] = 0x00;
    bytes[16] = 1;
    CHECK(CreateDropFileListFromBytes(bytes) == nullptr);
}

// A pFiles value that points exactly at EOF is an empty table, not a crash.
RTSC_TEST(drop_files_pfiles_at_eof_is_empty_provider) {
    auto bytes = MakeHdropWide({u"C:\\x\\a.txt"});
    const uint32_t n = static_cast<uint32_t>(bytes.size());
    bytes[0] = static_cast<uint8_t>(n & 0xFF);
    bytes[1] = static_cast<uint8_t>((n >> 8) & 0xFF);
    bytes[2] = static_cast<uint8_t>((n >> 16) & 0xFF);
    bytes[3] = static_cast<uint8_t>((n >> 24) & 0xFF);
    auto p = CreateDropFileListFromBytes(bytes);
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(0));
}

// Probe: fWide==0 (ANSI table) is unsupported in v1 and must be refused.
RTSC_TEST(drop_files_factory_rejects_ansi_fwide_zero) {
    const auto bytes = MakeHdropAnsi({"C:\\folder\\a.txt"});
    CHECK(CreateDropFileListFromBytes(bytes) == nullptr);
}

// The table ends after the last name's own terminator without a trailing
// empty string; accept it.
RTSC_TEST(drop_files_accepts_single_null_terminator) {
    const std::filesystem::path f1 = MakeTempFileNamed(u"n1.txt", kTen);
    const std::filesystem::path f2 = MakeTempFileNamed(u"n2.txt", kTen);
    TempScope guard2{f2};
    TempScope guard1{f1};
    const auto bytes = MakeHdropWide({f1.u16string(), f2.u16string()}, false);
    auto p = CreateDropFileListFromBytes(bytes);
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(2));
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK(info.name == f1.filename().u16string());
    CHECK(p->file_info(1, info));
    CHECK(info.name == f2.filename().u16string());
}

// Probe: a name truncated mid-string (no terminator) must not be produced and
// must not crash or read past the buffer; prior names survive.
RTSC_TEST(drop_files_truncated_filename_keeps_prior_names) {
    const std::filesystem::path f1 = MakeTempFileNamed(u"p1.txt", kTen);
    const std::filesystem::path f2 = MakeTempFileNamed(u"p2.txt", kTen);
    TempScope guard2{f2};
    TempScope guard1{f1};
    const auto bytes =
        MakeHdropWide({f1.u16string(), f2.u16string(), u"C:\\c\\3.txt"});
    auto truncated = bytes;
    // Remove the final 6 bytes: the trailing double-null plus 4 bytes of the
    // last name's terminator-carrying tail, leaving that name unterminated.
    truncated.resize(truncated.size() - 6);
    auto p = CreateDropFileListFromBytes(truncated);
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(2));
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK(info.name == f1.filename().u16string());
    CHECK(p->file_info(1, info));
    CHECK(info.name == f2.filename().u16string());
}

// An empty (but well-formed) table is a legal zero-file provider.
RTSC_TEST(drop_files_empty_table_is_valid_zero_file_provider) {
    auto p = CreateDropFileListFromBytes(MakeHdropWide({}));
    if (!NeedProvider(p != nullptr)) return;
    CHECK_EQ(p->file_count(), static_cast<uint32_t>(0));
    rtsc::clipboard::FileInfo info;
    CHECK_EQ(p->file_info(0, info), false);
    std::vector<uint8_t> out;
    CHECK_EQ(p->read_range(0, 0, 1, out), false);
}

// ---- file_info ------------------------------------------------------------

RTSC_TEST(drop_files_file_info_reports_size) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK_EQ(info.is_directory, false);
    CHECK_EQ(info.size, static_cast<uint64_t>(10));
    CHECK(info.name == file.filename().u16string());
}

RTSC_TEST(drop_files_file_info_detects_directory) {
    const std::filesystem::path dir = MakeTempDir();
    TempScope guard{dir};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({dir.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK_EQ(info.is_directory, true);
    CHECK_EQ(info.size, static_cast<uint64_t>(0));
}

// D-B1: a file that no longer exists must fail file_info (never a forged
// zero-length size) so the channel's SIZE answer fails instead.
RTSC_TEST(drop_files_file_info_missing_file_false) {
    const std::u16string missing =
        u"C:\\rtsc_definitely_missing_9f31\\gone.txt";
    auto p = CreateDropFileListFromBytes(MakeHdropWide({missing}));
    if (!NeedProvider(p != nullptr)) return;
    rtsc::clipboard::FileInfo info;
    CHECK_EQ(p->file_info(0, info), false);
}

RTSC_TEST(drop_files_file_info_bad_index_false) {
    auto p = CreateDropFileListFromBytes(MakeHdropWide({u"C:\\x\\a.txt"}));
    if (!NeedProvider(p != nullptr)) return;
    rtsc::clipboard::FileInfo info;
    CHECK_EQ(p->file_info(1, info), false);
}

// ---- read_range -----------------------------------------------------------

RTSC_TEST(drop_files_read_range_from_start_partial) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK(p->read_range(0, 0, 4, out));
    CHECK_BYTES(out, 0, 1, 2, 3);
}

RTSC_TEST(drop_files_read_range_middle) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK(p->read_range(0, 3, 3, out));
    CHECK_BYTES(out, 3, 4, 5);
}

RTSC_TEST(drop_files_read_range_exact_to_eof) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK(p->read_range(0, 7, 3, out));
    CHECK_BYTES(out, 7, 8, 9);
}

// Probe: asking for more than the remaining bytes must be truncated, never
// over-sold.
RTSC_TEST(drop_files_read_range_count_overshoot_truncates) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK(p->read_range(0, 4, 100, out));
    CHECK_BYTES(out, 4, 5, 6, 7, 8, 9);
}

RTSC_TEST(drop_files_read_range_offset_beyond_eof_false) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK_EQ(p->read_range(0, 30, 1, out), false);
}

RTSC_TEST(drop_files_read_range_offset_is_eof_empty_ok) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK(p->read_range(0, 10, 3, out));
    CHECK_EQ(out.size(), static_cast<size_t>(0));
}

RTSC_TEST(drop_files_read_range_appends_to_out) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    out.push_back(0xAA);
    out.push_back(0xBB);
    CHECK(p->read_range(0, 0, 2, out));
    CHECK_BYTES(out, 0xAA, 0xBB, 0, 1);
}

RTSC_TEST(drop_files_read_range_bad_index_false) {
    auto p = CreateDropFileListFromBytes(MakeHdropWide({u"C:\\x\\a.txt"}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK_EQ(p->read_range(5, 0, 1, out), false);
}

RTSC_TEST(drop_files_read_range_missing_file_false) {
    auto p = CreateDropFileListFromBytes(
        MakeHdropWide({u"C:\\rtsc_missing_9f31\\nope.bin"}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK_EQ(p->read_range(0, 0, 4, out), false);
}

RTSC_TEST(drop_files_read_range_directory_false) {
    const std::filesystem::path dir = MakeTempDir();
    TempScope guard{dir};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({dir.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    std::vector<uint8_t> out;
    CHECK_EQ(p->read_range(0, 0, 1, out), false);
}

// The full Serve path for one real file: size then a full range.
RTSC_TEST(drop_files_serves_real_file_end_to_end) {
    const std::filesystem::path file = MakeTempFile(kTen);
    TempScope guard{file};
    auto p = CreateDropFileListFromBytes(MakeHdropWide({file.u16string()}));
    if (!NeedProvider(p != nullptr)) return;
    rtsc::clipboard::FileInfo info;
    CHECK(p->file_info(0, info));
    CHECK_EQ(info.size, static_cast<uint64_t>(10));
    std::vector<uint8_t> out;
    CHECK(p->read_range(0, 0, static_cast<uint32_t>(info.size), out));
    CHECK_BYTES(out, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
}

int main() { return rtsc::test::run_all("rtsc_clipboard_tests"); }