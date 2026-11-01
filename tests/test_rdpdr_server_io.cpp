// Route-A RDPDR asynchronous I/O engine ([MS-RDPEFS] 2.2.1.4 / 2.2.1.5).
//
// The server issues an IRP (DR_DEVICE_IOREQUEST) toward the client's shared
// drive, registers the request in an outstanding table keyed by completion id,
// keeps pumping the channel while the completion is in flight, and dispatches
// the matching DR_DEVICE_IOCOMPLETION back to the caller's callback. This suite
// drives the RdpdrServer against the in-tree RdpdrClient over real wire
// encoding (the same back-to-back Pair harness the e2e suite uses), then
// exercises the state machine the live channel cannot reach: completion-id
// matching, unknown / duplicate completion rejection, the outstanding limit,
// timeout reaping and teardown failure of pending IRPs.
//
// Mutations that must turn these red:
//   1. dropping the outstanding completion-id match ("fire the first entry")
//      -> the completion-id and unknown-completion cases fail;
//   2. dropping timeout reaping in Poll() -> the timeout case fails;
//   3. dropping the kMaxOutstanding gate -> the limit case fails.

#include "rtsc/channel/rdpdr_client.h"
#include "rtsc/channel/rdpdr_server.h"
#include "rtsc/rdpdr/file_system.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "rtsc/proto/channel.h"
#include "rtsc/proto/rdpdr.h"
#include "test_framework.h"
#include "test_main.h"

namespace proto = rtsc::proto;
using rtsc::channel::RdpdrClient;
using rtsc::channel::RdpdrServer;
using rtsc::rdpdr::HostFileSystem;
using rtsc::rdpdr::IFileSystem;

namespace {

constexpr uint32_t kDeviceId = 7;
// GENERIC_READ | GENERIC_WRITE ([MS-SMB2] DesiredAccess).
constexpr uint32_t kGenericReadWrite = 0xC0000000u;
// FILE_OPEN_IF ([MS-SMB2] 2.2.13 create disposition) with write access.
constexpr uint32_t kFileOpenIf = 0x00000003;
// NTSTATUS for ``timeout waiting for a Device Io Completion``, defined
// client-side as a local constant ([MS-ERREF] STATUS_IO_TIMEOUT).
constexpr uint32_t kStatusIoTimeout = 0xC00000B5;

struct Pair {
    std::vector<std::vector<uint8_t>> server_to_client;
    std::vector<std::vector<uint8_t>> client_to_server;
    std::unique_ptr<RdpdrServer> server;
    std::unique_ptr<RdpdrClient> client;
};

void InitPair(Pair& p, IFileSystem* fs,
              std::vector<RdpdrClient::Device> devices) {
    p.server = std::make_unique<RdpdrServer>(
        [&p](const std::vector<uint8_t>& chunk) {
            p.server_to_client.push_back(chunk);
        });
    p.client = std::make_unique<RdpdrClient>(
        fs, std::move(devices), "RTSC-IO",
        [&p](const std::vector<uint8_t>& chunk) {
            p.client_to_server.push_back(chunk);
        });
}

std::filesystem::path MakeTempDir(const char* tag) {
    static unsigned counter = 0;
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
        ("rtsc_rdpdr_io_" + std::string(tag) + "_" +
         std::to_string(++counter));
    std::filesystem::create_directories(dir);
    return dir;
}

void PumpPair(Pair& p, int max_rounds = 8) {
    for (int i = 0; i < max_rounds; ++i) {
        if (p.server_to_client.empty() && p.client_to_server.empty()) return;
        const auto sc = std::move(p.server_to_client);
        const auto cs = std::move(p.client_to_server);
        for (const auto& chunk : sc) {
            p.client->OnChannelData(chunk.data(), chunk.size());
        }
        for (const auto& chunk : cs) {
            p.server->OnChannelData(chunk.data(), chunk.size());
        }
    }
}

// Runs the full initialization exchange until both sides reach READY.
void Handshake(Pair& p) {
    p.server->Start();
    PumpPair(p);
    CHECK(p.server->phase() == RdpdrServer::Phase::kReady);
    CHECK(p.client->phase() == RdpdrClient::Phase::kReady);
}

uint32_t U32At(const std::vector<uint8_t>& v, size_t off) {
    return static_cast<uint32_t>(v[off]) |
           (static_cast<uint32_t>(v[off + 1]) << 8) |
           (static_cast<uint32_t>(v[off + 2]) << 16) |
           (static_cast<uint32_t>(v[off + 3]) << 24);
}

std::vector<uint8_t> ReadWholeFileContent(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    in.seekg(0, std::ios::end);
    const size_t n = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> out(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(out.data()),
                static_cast<std::streamsize>(n));
    }
    return out;
}

// Feeds a fabricated DR_DEVICE_IOCOMPLETION to the server: `completion_id` /
// `io_status` plus a Create-style tail (file_id + information).
void FeedFakeCreateCompletion(RdpdrServer& server, uint32_t device_id,
                              uint32_t completion_id, uint32_t io_status,
                              uint32_t file_id) {
    proto::RdpdrDeviceIoCompletion completion;
    completion.device_id = device_id;
    completion.completion_id = completion_id;
    completion.io_status = io_status;
    proto::ByteWriter w;
    const std::vector<uint8_t> completion_bytes = completion.encode();
    w.bytes(completion_bytes.data(), completion_bytes.size());
    w.u32le(file_id);
    w.u8(0);  // Information
    const std::vector<uint8_t> pdu =
        proto::BuildRdpdrPdu(proto::kPakidCoreDeviceIocompletion, w.take());
    for (const auto& chunk : proto::FragmentChannelMessage(pdu)) {
        server.OnChannelData(chunk.data(), chunk.size());
    }
}

// Scans the newest IOREQUEST chunk the server queued (newest first) and returns
// its rdpdr body (after the RDPDR_HEADER) plus the parsed request header.
bool CaptureIoRequest(Pair& p, proto::RdpdrDeviceIoRequest& request,
                      std::vector<uint8_t>& body) {
    for (auto it = p.server_to_client.rbegin(); it != p.server_to_client.rend();
         ++it) {
        if (it->size() < proto::ChannelPduHeader::kSize +
                             proto::RdpdrHeader::kSize) {
            continue;
        }
        proto::RdpdrPdu pdu;
        if (proto::RdpdrPdu::parse(it->data() + proto::ChannelPduHeader::kSize,
                                   it->size() - proto::ChannelPduHeader::kSize,
                                   pdu) != proto::Status::Ok) {
            continue;
        }
        if (pdu.header.packet_id != proto::kPakidCoreDeviceIorequest) continue;
        body = pdu.data;
        return proto::RdpdrDeviceIoRequest::parse(pdu.data, request) ==
               proto::Status::Ok;
    }
    return false;
}

}  // namespace

// R1: the server issues DR_CREATE_REQ toward a shared drive, the client
// answers with a matching DR_CREATE_RSP completion, and the outstanding-table
// dispatch delivers io_status = STATUS_SUCCESS plus the assigned file id to the
// registered callback (completion-id matching works).
RTSC_TEST(rdpdr_server_io_create_roundtrip_receives_file_id) {
    const std::filesystem::path dir = MakeTempDir("create");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    uint32_t fstatus = 0xFFFFFFFF;
    std::vector<uint8_t> fdata;
    bool fired = false;
    const uint32_t cid = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\io.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            fstatus = st;
            fdata = data;
            fired = true;
        });
    CHECK(cid != 0);
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));

    PumpPair(p);
    CHECK(fired);
    CHECK_EQ(fstatus, static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(fdata.size(), static_cast<size_t>(4));
    const uint32_t file_id = fdata.empty() ? 0 : U32At(fdata, 0);
    CHECK(file_id != 0);
    CHECK(std::filesystem::exists(dir / "io.txt"));
    CHECK_EQ(p.client->create_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->unknown_completion_count(), static_cast<unsigned>(0));

    std::filesystem::remove_all(dir, ec);
}

// R2: Read / Write / Close round-trip over the same handle: the write payload
// reaches the client's file system, the read echoes it back, and Close
// completes with STATUS_SUCCESS.
RTSC_TEST(rdpdr_server_io_read_write_close_roundtrip) {
    const std::filesystem::path dir = MakeTempDir("rwc");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    uint32_t fid = 0;
    bool created = false;
    p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\data.bin", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            created = true;
            if (st == proto::kStatusSuccess && data.size() == 4) {
                fid = U32At(data, 0);
            }
        });
    PumpPair(p);
    CHECK(created);
    CHECK(fid != 0);
    if (fid == 0) {
        std::filesystem::remove_all(dir, ec);
        return;
    }

    const std::vector<uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};
    bool wrote = false;
    uint32_t wstatus = 0xFFFFFFFF;
    const uint32_t wcid = p.server->WriteFile(
        kDeviceId, fid, 0, payload,
        [&](uint32_t st, const std::vector<uint8_t>&) {
            wrote = true;
            wstatus = st;
        });
    CHECK(wcid != 0);
    PumpPair(p);
    CHECK(wrote);
    CHECK_EQ(wstatus, static_cast<uint32_t>(proto::kStatusSuccess));

    // Read the payload back through the same (still open) handle: it proves the
    // write reached the client's file system without depending on OS buffering.
    bool read = false;
    uint32_t rstatus = 0xFFFFFFFF;
    std::vector<uint8_t> rdata;
    const uint32_t rcid = p.server->ReadFile(
        kDeviceId, fid, 0, static_cast<uint32_t>(payload.size()),
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            read = true;
            rstatus = st;
            rdata = data;
        });
    CHECK(rcid != 0);
    PumpPair(p);
    CHECK(read);
    CHECK_EQ(rstatus, static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(rdata == payload);

    bool closed = false;
    uint32_t cstatus = 0xFFFFFFFF;
    const uint32_t ccid = p.server->CloseFile(
        kDeviceId, fid, [&](uint32_t st, const std::vector<uint8_t>&) {
            closed = true;
            cstatus = st;
        });
    CHECK(ccid != 0);
    PumpPair(p);
    CHECK(closed);
    CHECK_EQ(cstatus, static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK_EQ(p.client->close_count(), static_cast<unsigned>(1));
    // After CloseFile the client released the handle, flushing the stream: the
    // write is now durably visible on disk.
    CHECK(ReadWholeFileContent(dir / "data.bin") == payload);

    std::filesystem::remove_all(dir, ec);
}

// R3: QueryDirectory round-trip. The server opens the shared root as a
// directory handle and enumerates one entry (the file created inside the share
// before the query), receiving STATUS_SUCCESS plus the encoded directory
// record bytes.
RTSC_TEST(rdpdr_server_io_query_directory_roundtrip) {
    const std::filesystem::path dir = MakeTempDir("qdir");
    std::error_code ec;
    {
        std::ofstream out(dir / "entry.txt", std::ios::binary);
        out.put('x');
    }
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    uint32_t fid = 0;
    bool created = false;
    p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            created = true;
            if (st == proto::kStatusSuccess && data.size() == 4) {
                fid = U32At(data, 0);
            }
        });
    PumpPair(p);
    CHECK(created);
    CHECK(fid != 0);
    if (fid == 0) {
        std::filesystem::remove_all(dir, ec);
        return;
    }

    bool queried = false;
    uint32_t qstatus = 0xFFFFFFFF;
    std::vector<uint8_t> qdata;
    const uint32_t qcid = p.server->QueryDirectory(
        kDeviceId, fid, 0x0C /* FileNamesInformation */, true,
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            queried = true;
            qstatus = st;
            qdata = data;
        });
    CHECK(qcid != 0);
    PumpPair(p);
    CHECK(queried);
    CHECK_EQ(qstatus, static_cast<uint32_t>(proto::kStatusSuccess));
    CHECK(!qdata.empty());

    std::filesystem::remove_all(dir, ec);
}

// R4a: a completion whose id belongs to a *later* request must never be
// dispatched to an earlier one. Two creates stay outstanding; the completion
// for the second one must wake exactly the second callback. A "fire the first
// entry" implementation would wake the first callback and go red here.
RTSC_TEST(rdpdr_server_io_completion_id_mismatch_not_dispatched) {
    const std::filesystem::path dir = MakeTempDir("mismatch");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    unsigned a_fires = 0;
    unsigned b_fires = 0;
    std::vector<uint8_t> b_data;
    const uint32_t a_cid = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            ++a_fires;
            (void)st;
            (void)data;
        });
    const uint32_t b_cid = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\b.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            ++b_fires;
            b_data = data;
            (void)st;
        });
    CHECK(a_cid != 0);
    CHECK(b_cid != 0);
    CHECK(a_cid != b_cid);
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(2));

    // A fabricated completion for B (id = b_cid) with a marker file id.
    FeedFakeCreateCompletion(*p.server, kDeviceId, b_cid,
                             proto::kStatusSuccess, 0x77);
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));
    CHECK_EQ(a_fires, static_cast<unsigned>(0));
    CHECK_EQ(b_fires, static_cast<unsigned>(1));
    CHECK(b_data.size() == 4 && (!b_data.empty() && U32At(b_data, 0) == 0x77));

    std::filesystem::remove_all(dir, ec);
}

// R4b: a completion id with no outstanding entry is discarded and counted, and
// no pending request is woken. A "fire the first entry" implementation would
// wake the sole outstanding create and go red.
RTSC_TEST(rdpdr_server_io_unknown_completion_id_discarded) {
    const std::filesystem::path dir = MakeTempDir("unknown");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    unsigned fires = 0;
    p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>&) {
            ++fires;
            (void)st;
        });
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));

    FeedFakeCreateCompletion(*p.server, kDeviceId, 12345,
                             proto::kStatusSuccess, 0x55);
    CHECK(fires == 0);
    CHECK_EQ(p.server->unknown_completion_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));

    std::filesystem::remove_all(dir, ec);
}

// R4c: replaying an already-completed id (same bytes, second arrival) is a
// duplicate completion: discarded and counted, and the callback fires exactly
// once.
RTSC_TEST(rdpdr_server_io_duplicate_completion_discarded) {
    const std::filesystem::path dir = MakeTempDir("dup");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    unsigned fires = 0;
    const uint32_t cid = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>&) {
            ++fires;
            (void)st;
        });
    CHECK(cid != 0);
    PumpPair(p);
    CHECK_EQ(fires, static_cast<unsigned>(1));
    CHECK_EQ(p.server->unknown_completion_count(), static_cast<unsigned>(0));

    FeedFakeCreateCompletion(*p.server, kDeviceId, cid,
                             proto::kStatusSuccess, 0x22);
    CHECK_EQ(fires, static_cast<unsigned>(1));
    CHECK_EQ(p.server->unknown_completion_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(0));

    std::filesystem::remove_all(dir, ec);
}

// R5: the outstanding table is capped at kMaxOutstanding; the request right
// past the cap is refused (completion id 0 = failure) and not transmitted.
RTSC_TEST(rdpdr_server_io_outstanding_limit_rejects_extra) {
    const std::filesystem::path dir = MakeTempDir("limit");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    for (size_t i = 0; i < RdpdrServer::kMaxOutstanding; ++i) {
        const uint32_t cid = p.server->CreateFile(
            kDeviceId, "\\tsclient\\C\\file_lim.txt", kGenericReadWrite,
            kFileOpenIf, [](uint32_t st, const std::vector<uint8_t>&) {
                (void)st;
            });
        CHECK(cid != 0);
    }
    CHECK_EQ(p.server->outstanding_count(), RdpdrServer::kMaxOutstanding);

    const uint32_t refused = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\file_lim.txt", kGenericReadWrite,
        kFileOpenIf, [](uint32_t st, const std::vector<uint8_t>&) { (void)st; });
    CHECK_EQ(refused, static_cast<uint32_t>(0));
    CHECK_EQ(p.server->outstanding_count(), RdpdrServer::kMaxOutstanding);

    std::filesystem::remove_all(dir, ec);
}

// R6: Poll(now) reaps an IRP whose deadline has passed, fails its callback
// with STATUS_IO_TIMEOUT and drops it from the table.
RTSC_TEST(rdpdr_server_io_timeout_reaps_expired_irp) {
    const std::filesystem::path dir = MakeTempDir("timeout");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    unsigned fires = 0;
    uint32_t status = 0;
    const std::vector<uint8_t> empty;
    p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>& data) {
            ++fires;
            status = st;
            (void)data;
        });
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));

    p.server->Poll(std::chrono::steady_clock::now() +
                   std::chrono::seconds(31));
    CHECK_EQ(fires, static_cast<unsigned>(1));
    CHECK_EQ(status, kStatusIoTimeout);
    CHECK_EQ(p.server->device_io_timeout_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(0));

    std::filesystem::remove_all(dir, ec);
}

// R7: destroying the handler while IRPs are in flight fails every outstanding
// callback and clears the table (the session died under their feet). Two IRPs
// are in flight and the first callback throws: the per-entry isolation must
// still fail the second one (a "fail the first, then give up" mutation has to
// turn this red -- with a single IRP that mutation is indistinguishable).
RTSC_TEST(rdpdr_server_io_destructor_fails_outstanding) {
    const std::filesystem::path dir = MakeTempDir("teardown");
    std::error_code ec;
    unsigned fires = 0;
    unsigned threw = 0;
    uint32_t status1 = 0;
    uint32_t status2 = 0;
    {
        HostFileSystem fs;
        Pair p;
        InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
        Handshake(p);
        p.server->CreateFile(
            kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
            [&](uint32_t st, const std::vector<uint8_t>&) {
                ++fires;
                status1 = st;
                // The first pending callback belongs to the embedder and may
                // throw; that must not skip the remaining pending IRPs.
                ++threw;
                throw std::runtime_error("embedder callback failed");
            });
        p.server->CreateFile(
            kDeviceId, "\\tsclient\\C\\b.txt", kGenericReadWrite, kFileOpenIf,
            [&](uint32_t st, const std::vector<uint8_t>&) {
                ++fires;
                status2 = st;
            });
        CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(2));
        // Pair (and the RdpdrServer) goes out of scope here.
    }
    CHECK_EQ(threw, static_cast<unsigned>(1));
    CHECK_EQ(fires, static_cast<unsigned>(2));
    CHECK_EQ(status1, static_cast<uint32_t>(proto::kStatusUnsuccessful));
    CHECK_EQ(status2, static_cast<uint32_t>(proto::kStatusUnsuccessful));

    std::filesystem::remove_all(dir, ec);
}

// R8: before the handshake reached READY the engine refuses to issue IRPs:
// every active call returns 0 and nothing is sent.
RTSC_TEST(rdpdr_server_io_not_ready_returns_zero) {
    const std::filesystem::path dir = MakeTempDir("preready");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    CHECK(p.server->phase() == RdpdrServer::Phase::kIdle);

    const uint32_t cid = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
        [](uint32_t st, const std::vector<uint8_t>&) { (void)st; });
    CHECK_EQ(cid, static_cast<uint32_t>(0));
    const uint32_t rcid = p.server->ReadFile(
        kDeviceId, 1, 0, 1, [](uint32_t st, const std::vector<uint8_t>&) {
            (void)st;
        });
    CHECK_EQ(rcid, static_cast<uint32_t>(0));
    const uint32_t ccid = p.server->CloseFile(
        kDeviceId, 1, [](uint32_t st, const std::vector<uint8_t>&) {
            (void)st;
        });
    CHECK_EQ(ccid, static_cast<uint32_t>(0));
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(0));
    CHECK(p.server_to_client.empty());

    std::filesystem::remove_all(dir, ec);
}

// R9: the timeout callback may re-enter the engine (a natural retry pattern).
// Poll() must finish its scan before firing callbacks, so the re-entered IRP
// is registered cleanly instead of being reaped (or crashing) inside the same
// sweep.
RTSC_TEST(rdpdr_server_io_timeout_callback_can_reenter_create) {
    const std::filesystem::path dir = MakeTempDir("reenter");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    unsigned timeout_fires = 0;
    uint32_t retry_cid = 0;
    bool retried_ok = false;
    const uint32_t first = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>&) {
            ++timeout_fires;
            if (retry_cid == 0) {
                retry_cid = p.server->CreateFile(
                    kDeviceId, "\\tsclient\\C\\retry.txt", kGenericReadWrite,
                    kFileOpenIf,
                    [](uint32_t st2, const std::vector<uint8_t>&) { (void)st2; });
                retried_ok = (retry_cid != 0);
            }
            (void)st;
        });
    CHECK(first != 0);
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));

    p.server->Poll(std::chrono::steady_clock::now() + std::chrono::seconds(31));
    CHECK_EQ(timeout_fires, static_cast<unsigned>(1));
    CHECK(retried_ok);
    CHECK(retry_cid != 0);
    CHECK(retry_cid != first);
    // Only the re-entered IRP survives; the reaping pass must not touch it.
    CHECK_EQ(p.server->device_io_timeout_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));

    std::filesystem::remove_all(dir, ec);
}

// R10 (K2): a completion whose device id does not match the pending IRP is
// discarded like an unknown completion id; the wrong device must never wake the
// registered callback.
RTSC_TEST(rdpdr_server_io_completion_device_id_mismatch_discarded) {
    const std::filesystem::path dir = MakeTempDir("devmismatch");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    unsigned fires = 0;
    const uint32_t cid = p.server->CreateFile(
        kDeviceId, "\\tsclient\\C\\a.txt", kGenericReadWrite, kFileOpenIf,
        [&](uint32_t st, const std::vector<uint8_t>&) {
            ++fires;
            (void)st;
        });
    CHECK(cid != 0);

    // Correct completion id, wrong device id.
    FeedFakeCreateCompletion(*p.server, kDeviceId + 999, cid,
                             proto::kStatusSuccess, 0x55);
    CHECK_EQ(fires, static_cast<unsigned>(0));
    CHECK_EQ(p.server->unknown_completion_count(), static_cast<unsigned>(1));
    CHECK_EQ(p.server->outstanding_count(), static_cast<size_t>(1));

    std::filesystem::remove_all(dir, ec);
}

// R11 (K3): the wire layout of every issued IOREQUEST matches [MS-RDPEFS]
// 2.2.1.4.x / 2.2.3.3.4, including the paddings a real peer requires. DR_READ_REQ
// is DeviceIoRequest(20) + Length(4) + Offset(8) + Padding(20) and DR_WRITE_REQ
// carries its own 20-byte padding before the data, both all-zero.
RTSC_TEST(rdpdr_server_io_wire_layout_matches_ms_rdpefs) {
    const std::filesystem::path dir = MakeTempDir("wire");
    std::error_code ec;
    HostFileSystem fs;
    Pair p;
    InitPair(p, &fs, {{kDeviceId, "C:", dir.string()}});
    Handshake(p);

    // DR_READ_REQ (2.2.1.4.3): Length(4) + Offset(8) + Padding(20) = 32-byte
    // tail after the DeviceIoRequest.
    p.server_to_client.clear();
    p.server->ReadFile(kDeviceId, 1, 0x0102030405060708ULL, 64,
                       [](uint32_t st, const std::vector<uint8_t>&) { (void)st; });
    {
        proto::RdpdrDeviceIoRequest req;
        std::vector<uint8_t> body;
        CHECK(CaptureIoRequest(p, req, body));
        CHECK_EQ(req.major_function, static_cast<uint32_t>(proto::kIrpMjRead));
        CHECK_EQ(body.size(), static_cast<size_t>(52));
        if (body.size() != 52) return;
        {
            proto::ByteReader r(body.data() + 20, body.size() - 20);
            uint32_t length = 0;
            CHECK(r.u32le(length));
            CHECK_EQ(length, static_cast<uint32_t>(64));
            uint32_t lo = 0, hi = 0;
            CHECK(r.u32le(lo));
            CHECK(r.u32le(hi));
            const uint64_t offset =
                static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
            CHECK_EQ(offset, 0x0102030405060708ULL);
            CHECK_EQ(r.remaining(), static_cast<size_t>(20));
            bool all_zero = true;
            for (size_t i = 0; i < 20; ++i) {
                uint8_t b = 0xFF;
                if (!r.u8(b) || b != 0) all_zero = false;
            }
            CHECK(all_zero);
        }
    }

    // DR_WRITE_REQ (2.2.1.4.4): Length(4) + Offset(8) + Padding(20) + Data.
    p.server_to_client.clear();
    p.server->WriteFile(kDeviceId, 1, 7, {1, 2, 3},
                        [](uint32_t st, const std::vector<uint8_t>&) { (void)st; });
    {
        proto::RdpdrDeviceIoRequest req;
        std::vector<uint8_t> body;
        CHECK(CaptureIoRequest(p, req, body));
        CHECK_EQ(body.size(), static_cast<size_t>(55));
        if (body.size() != 55) return;
        {
            bool all_zero = true;
            for (size_t i = 20 + 4 + 8; i < 20 + 4 + 8 + 20; ++i) {
                if (body[i] != 0) all_zero = false;
            }
            CHECK(all_zero);
            CHECK(body[20 + 4 + 8 + 20] == 1);
            CHECK(body[20 + 4 + 8 + 21] == 2);
            CHECK(body[20 + 4 + 8 + 22] == 3);
        }
    }

    // DR_CLOSE_REQ (2.2.1.4.2): bare DeviceIoRequest, no payload.
    p.server_to_client.clear();
    p.server->CloseFile(kDeviceId, 1,
                        [](uint32_t st, const std::vector<uint8_t>&) { (void)st; });
    {
        proto::RdpdrDeviceIoRequest req;
        std::vector<uint8_t> body;
        CHECK(CaptureIoRequest(p, req, body));
        CHECK_EQ(body.size(), static_cast<size_t>(20));
    }

    // DR_CREATE_REQ (2.2.1.4.1): 32-byte fixed tail + Path, no padding.
    p.server_to_client.clear();
    const std::string create_path = "\\tsclient\\C\\io.txt";
    p.server->CreateFile(kDeviceId, create_path, kGenericReadWrite, kFileOpenIf,
                         [](uint32_t st, const std::vector<uint8_t>&) { (void)st; });
    {
        proto::RdpdrDeviceIoRequest req;
        std::vector<uint8_t> body;
        CHECK(CaptureIoRequest(p, req, body));
        const size_t expect = 52 + proto::RdpdrEncodeUtf16(create_path).size();
        CHECK_EQ(body.size(), expect);
    }

    // DR_DRIVE_QUERY_DIRECTORY_REQ (2.2.3.3.4): FsInformationClass(4) +
    // InitialQuery(1) + PathLength(4) + Padding(23) + Path.
    p.server_to_client.clear();
    p.server->QueryDirectory(kDeviceId, 1, 0x0C, true,
                             [](uint32_t st, const std::vector<uint8_t>&) { (void)st; });
    {
        proto::RdpdrDeviceIoRequest req;
        std::vector<uint8_t> body;
        CHECK(CaptureIoRequest(p, req, body));
        const size_t expect = 52 + proto::RdpdrEncodeUtf16("*").size();
        CHECK_EQ(body.size(), expect);
        bool all_zero = true;
        for (size_t i = 20 + 4 + 1 + 4; i < 20 + 4 + 1 + 4 + 23; ++i) {
            if (body[i] != 0) all_zero = false;
        }
        CHECK(all_zero);
    }

    std::filesystem::remove_all(dir, ec);
}

int main() { return rtsc::test::run_all("rtsc_rdpdr_server_io_tests"); }