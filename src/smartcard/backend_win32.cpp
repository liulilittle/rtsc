// Win32 smart card backend ([MS-RDPESC] 3.1.4) over winscard.dll.
//
// The DLL is loaded with LoadLibraryW at first use and every entry point is
// resolved with GetProcAddress, so:
//   * rtsc_gui has no link-time dependency on winscard.lib,
//   * a host where the Smart Card service (or the DLL) is missing still runs
//     and answers every SCARD_IOCTL with SCARD_E_NO_SERVICE.
//
// Handles crossing the wire are the backend's own opaque 8-byte ids, never the
// native SCARDCONTEXT/SCARDHANDLE. [MS-RDPESC] 2.2.1.1 says pbContext is
// implementation-specific and MUST NOT be interpreted by the server, and the
// FreeRDP reference emits the native ULONG_PTR; using our own id keeps the
// native value out of the untrusted stream and survives the server echoing a
// context/handle back verbatim. The id is validated against the live map, so a
// forged id is rejected with SCARD_E_INVALID_HANDLE instead of dereferencing a
// stale native handle.

#include "rtsc/smartcard/backend.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace rtsc::smartcard {

#if defined(_WIN32)

namespace {

// WinSCard signatures, spelled out so the DLL can be bound dynamically. They
// mirror winscard.h (Windows SDK 10.0.26100). SCARDCONTEXT and SCARDHANDLE are
// ULONG_PTR (winscard.h: typedef ULONG_PTR SCARDCONTEXT / SCARDHANDLE).
using SCARDCONTEXT = ULONG_PTR;
using SCARDHANDLE = ULONG_PTR;
using LPSCARD_IO_REQUEST = struct ScardIoRequestNative*;
using LPCSCARD_IO_REQUEST = const struct ScardIoRequestNative*;

// winsmcrd.h: typedef struct _SCARD_IO_REQUEST { DWORD dwProtocol;
// DWORD cbPciLength; } SCARD_IO_REQUEST. The extra bytes follow it.
struct ScardIoRequestNative {
    DWORD dwProtocol;
    DWORD cbPciLength;
};

// winscard.h SCARD_READERSTATEA. rgbAtr is 36 bytes; the struct has 8-byte
// alignment on x64 because pvUserData is a pointer, so the array is followed
// by 4 bytes of padding.
struct ScardReaderStateNative {
    LPCSTR szReader;
    LPVOID pvUserData;
    DWORD dwCurrentState;
    DWORD dwEventState;
    DWORD cbAtr;
    BYTE rgbAtr[36];
};

using FnEstablishContext = LONG(WINAPI*)(DWORD, LPCVOID, LPCVOID,
                                          SCARDCONTEXT*);
using FnReleaseContext = LONG(WINAPI*)(SCARDCONTEXT);
using FnListReaderGroupsA = LONG(WINAPI*)(SCARDCONTEXT, LPSTR, LPDWORD);
using FnListReadersA = LONG(WINAPI*)(SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD);
using FnGetStatusChangeA = LONG(WINAPI*)(SCARDCONTEXT, DWORD,
                                          ScardReaderStateNative*, DWORD);
using FnConnectA = LONG(WINAPI*)(SCARDCONTEXT, LPCSTR, DWORD, DWORD,
                                 SCARDHANDLE*, LPDWORD);
using FnDisconnect = LONG(WINAPI*)(SCARDHANDLE, DWORD);
using FnBeginTransaction = LONG(WINAPI*)(SCARDHANDLE);
using FnEndTransaction = LONG(WINAPI*)(SCARDHANDLE, DWORD);
using FnStatusA = LONG(WINAPI*)(SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD,
                                 LPBYTE, LPDWORD);
using FnTransmit = LONG(WINAPI*)(SCARDHANDLE, LPCSCARD_IO_REQUEST,
                                  const BYTE*, DWORD, LPSCARD_IO_REQUEST, LPBYTE,
                                  LPDWORD);
using FnControl = LONG(WINAPI*)(SCARDHANDLE, DWORD, LPCVOID, DWORD, LPVOID,
                                 DWORD, LPDWORD);
using FnFreeMemory = LONG(WINAPI*)(SCARDCONTEXT, LPCVOID);

// SCARD_AUTOALLOCATE (winscard.h): pass a pointer-to-pointer and let the
// service allocate the (double-NUL terminated) multistring.
constexpr DWORD kScardAutoAllocate = static_cast<DWORD>(-1);
constexpr DWORD kInfinite = 0xFFFFFFFF;
// FreeRDP smartcard_call.c caps a single GetStatusChange wait to 1 s so it can
// service concurrent IRPs; a longer dwTimeOut is polled in 1 s steps.
constexpr DWORD kStatusChangeStepMs = 1000;
// Status_Return.pbAtr is 32 bytes ([MS-RDPESC] 2.2.3.10).
constexpr size_t kStatusAtrBytes = 32;

struct WinScardApi {
    HMODULE module = nullptr;
    FnEstablishContext establish_context = nullptr;
    FnReleaseContext release_context = nullptr;
    FnListReaderGroupsA list_reader_groups = nullptr;
    FnListReadersA list_readers = nullptr;
    FnGetStatusChangeA get_status_change = nullptr;
    FnConnectA connect = nullptr;
    FnDisconnect disconnect = nullptr;
    FnBeginTransaction begin_transaction = nullptr;
    FnEndTransaction end_transaction = nullptr;
    FnStatusA status = nullptr;
    FnTransmit transmit = nullptr;
    FnControl control = nullptr;
    FnFreeMemory free_memory = nullptr;

    bool Load() {
        if (module != nullptr) return true;
        module = ::LoadLibraryW(L"winscard.dll");
        if (module == nullptr) return false;
        establish_context = reinterpret_cast<FnEstablishContext>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardEstablishContext")));
        release_context = reinterpret_cast<FnReleaseContext>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardReleaseContext")));
        list_reader_groups = reinterpret_cast<FnListReaderGroupsA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardListReaderGroupsA")));
        list_readers = reinterpret_cast<FnListReadersA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardListReadersA")));
        get_status_change = reinterpret_cast<FnGetStatusChangeA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardGetStatusChangeA")));
        connect = reinterpret_cast<FnConnectA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardConnectA")));
        disconnect = reinterpret_cast<FnDisconnect>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardDisconnect")));
        begin_transaction = reinterpret_cast<FnBeginTransaction>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardBeginTransaction")));
        end_transaction = reinterpret_cast<FnEndTransaction>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardEndTransaction")));
        status = reinterpret_cast<FnStatusA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardStatusA")));
        transmit = reinterpret_cast<FnTransmit>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardTransmit")));
        control = reinterpret_cast<FnControl>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardControl")));
        free_memory = reinterpret_cast<FnFreeMemory>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardFreeMemory")));
        return establish_context != nullptr && release_context != nullptr &&
               list_reader_groups != nullptr && list_readers != nullptr &&
               get_status_change != nullptr && connect != nullptr &&
               disconnect != nullptr && begin_transaction != nullptr &&
               end_transaction != nullptr && status != nullptr &&
               transmit != nullptr && control != nullptr &&
               free_memory != nullptr;
    }
};

WinScardApi& Api() {
    static WinScardApi api;
    static std::once_flag once;
    std::call_once(once, [] { api.Load(); });
    return api;
}

// The wire id: an 8-byte little-endian value. [MS-RDPESC] 2.2.1.1 allows 0..16
// bytes; 8 always fits and matches a 64-bit handle in size.
std::vector<uint8_t> EncodeId(uint64_t id) {
    std::vector<uint8_t> out(8);
    for (int i = 0; i < 8; ++i) {
        out[static_cast<size_t>(i)] = static_cast<uint8_t>((id >> (8 * i)) & 0xFF);
    }
    return out;
}

bool DecodeId(const std::vector<uint8_t>& bytes, uint64_t& id) {
    if (bytes.empty() || bytes.size() > 8) return false;
    id = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        id |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    }
    return true;
}

class WinSmartCardBackend final : public ISmartCardBackend {
 public:
    WinSmartCardBackend() : api_(Api()), available_(api_.module != nullptr) {}

    bool available() const override { return available_; }

    uint32_t EstablishContext(uint32_t scope,
                              std::vector<uint8_t>& context) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        const LONG rc = api_.establish_context(scope, nullptr, nullptr, &native);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        const uint64_t id = NextId();
        {
            std::lock_guard<std::mutex> lock(mu_);
            contexts_[id] = native;
        }
        context = EncodeId(id);
        return kScardSuccess;
    }

    uint32_t ReleaseContext(const std::vector<uint8_t>& context) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            const auto it = FindContextLocked(context, native);
            if (it == contexts_.end()) return kScardEInvalidHandle;
            contexts_.erase(it);
        }
        return static_cast<uint32_t>(api_.release_context(native));
    }

    uint32_t ListReaderGroups(const std::vector<uint8_t>& context,
                              std::vector<uint8_t>& groups) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        LPSTR raw = nullptr;
        DWORD cch = kScardAutoAllocate;
        const LONG rc = api_.list_reader_groups(native, reinterpret_cast<LPSTR>(&raw),
                                                &cch);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        const std::vector<uint8_t> copy = CopyMultiString(raw, cch);
        if (raw != nullptr) api_.free_memory(native, raw);
        groups = copy;
        return kScardSuccess;
    }

    uint32_t ListReaders(const std::vector<uint8_t>& context,
                         const std::vector<uint8_t>& groups,
                         std::vector<uint8_t>& readers) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        // An empty group filter is a NULL LPCSTR, i.e. "every reader"
        // (winscard.h SCardListReadersA _In_opt_ mszGroups).
        const char* filter = groups.empty()
                                 ? nullptr
                                 : reinterpret_cast<const char*>(groups.data());
        LPSTR raw = nullptr;
        DWORD cch = kScardAutoAllocate;
        const LONG rc =
            api_.list_readers(native, filter, reinterpret_cast<LPSTR>(&raw), &cch);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        const std::vector<uint8_t> copy = CopyMultiString(raw, cch);
        if (raw != nullptr) api_.free_memory(native, raw);
        readers = copy;
        return kScardSuccess;
    }

    uint32_t GetStatusChange(const std::vector<uint8_t>& context,
                             uint32_t timeout_ms,
                             std::vector<ScardReaderState>& states) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        // Reader names must outlive the call: szReader points into `names`.
        std::vector<std::string> names;
        names.reserve(states.size());
        for (const auto& st : states) names.push_back(st.reader);

        std::vector<ScardReaderStateNative> native_states(states.size());
        for (size_t i = 0; i < states.size(); ++i) {
            native_states[i].szReader = names[i].c_str();
            native_states[i].pvUserData = nullptr;
            native_states[i].dwCurrentState = states[i].current_state;
            native_states[i].dwEventState = 0;
            native_states[i].cbAtr = 0;
            std::memset(native_states[i].rgbAtr, 0, sizeof(native_states[i].rgbAtr));
        }

        // Long waits are polled in 1 s steps exactly like FreeRDP
        // smartcard_call.c: smartcard_status_change_step, so a cancelled
        // session is not stuck inside one huge WinSCard call.
        const DWORD total = timeout_ms;
        DWORD waited = 0;
        LONG rc = kScardSuccess;
        for (;;) {
            DWORD step = 0;
            if (total == kInfinite) {
                step = kStatusChangeStepMs;
            } else if (waited >= total) {
                step = 0;
            } else {
                step = std::min<DWORD>(total - waited, kStatusChangeStepMs);
            }
            rc = api_.get_status_change(
                native, step, native_states.empty() ? nullptr : native_states.data(),
                static_cast<DWORD>(native_states.size()));
            if (rc != static_cast<LONG>(kScardETimeout)) break;
            if (total != kInfinite) {
                waited += step;
                if (waited >= total) break;
            }
        }
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);

        for (size_t i = 0; i < states.size(); ++i) {
            states[i].event_state = native_states[i].dwEventState;
            const size_t atr_len =
                std::min<size_t>(native_states[i].cbAtr,
                                 sizeof(native_states[i].rgbAtr));
            states[i].atr.assign(native_states[i].rgbAtr,
                                 native_states[i].rgbAtr + atr_len);
        }
        return kScardSuccess;
    }

    uint32_t Connect(const std::vector<uint8_t>& context,
                     const std::string& reader, uint32_t share_mode,
                     uint32_t preferred_protocols,
                     std::vector<uint8_t>& handle,
                     uint32_t& active_protocol) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        // [MS-RDPESC] 3.1.4.28 (FreeRDP smartcard_ConnectA_Call): a zero
        // preferred protocol means "any" unless the caller asked for direct
        // access, in which case the value is passed through untouched.
        uint32_t protocols = preferred_protocols;
        if (protocols == kScardProtocolUndefined && share_mode != kScardShareDirect) {
            protocols = kScardProtocolT0 | kScardProtocolT1;
        }
        SCARDHANDLE card = 0;
        DWORD active = kScardProtocolUndefined;
        const LONG rc =
            api_.connect(native, reader.c_str(), share_mode, protocols, &card, &active);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        const uint64_t id = NextId();
        {
            std::lock_guard<std::mutex> lock(mu_);
            handles_[id] = card;
        }
        handle = EncodeId(id);
        active_protocol = active;
        return kScardSuccess;
    }

    uint32_t Disconnect(const std::vector<uint8_t>& context,
                        const std::vector<uint8_t>& handle,
                        uint32_t disposition) override {
        SCARDHANDLE card = 0;
        uint32_t rc = TakeHandle(context, handle, card);
        if (rc != kScardSuccess) return rc;
        return static_cast<uint32_t>(api_.disconnect(card, disposition));
    }

    uint32_t BeginTransaction(const std::vector<uint8_t>& context,
                              const std::vector<uint8_t>& handle) override {
        SCARDHANDLE card = 0;
        const uint32_t rc = LookupHandle(context, handle, card);
        if (rc != kScardSuccess) return rc;
        return static_cast<uint32_t>(api_.begin_transaction(card));
    }

    uint32_t EndTransaction(const std::vector<uint8_t>& context,
                            const std::vector<uint8_t>& handle,
                            uint32_t disposition) override {
        SCARDHANDLE card = 0;
        const uint32_t rc = LookupHandle(context, handle, card);
        if (rc != kScardSuccess) return rc;
        return static_cast<uint32_t>(api_.end_transaction(card, disposition));
    }

    uint32_t Status(const std::vector<uint8_t>& context,
                    const std::vector<uint8_t>& handle,
                    std::vector<uint8_t>& reader_names, uint32_t& state,
                    uint32_t& protocol, std::vector<uint8_t>& atr) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;

        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            FindContextLocked(context, native);
        }

        LPSTR names = nullptr;
        DWORD cch = kScardAutoAllocate;
        BYTE atr_buf[kStatusAtrBytes] = {0};
        DWORD atr_len = static_cast<DWORD>(sizeof(atr_buf));
        DWORD native_state = 0;
        DWORD native_protocol = 0;
        const LONG rc = api_.status(
            card, reinterpret_cast<LPSTR>(&names), &cch, &native_state,
            &native_protocol, atr_buf, &atr_len);
        std::vector<uint8_t> names_copy;
        if (rc == kScardSuccess) names_copy = CopyMultiString(names, cch);
        if (names != nullptr && native != 0) api_.free_memory(native, names);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        reader_names = std::move(names_copy);
        state = native_state;
        protocol = native_protocol;
        atr.assign(atr_buf, atr_buf + std::min<size_t>(atr_len, sizeof(atr_buf)));
        return kScardSuccess;
    }

    uint32_t Transmit(const std::vector<uint8_t>& context,
                      const std::vector<uint8_t>& handle,
                      const ScardPci& send_pci, const std::vector<uint8_t>& send,
                      bool wants_recv_pci, uint32_t recv_capacity, ScardPci& recv_pci,
                      std::vector<uint8_t>& recv) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;

        // ScardIoRequestNative + the extra bytes, which WinSCard reads from
        // cbPciLength onward.
        std::vector<uint8_t> send_pci_storage(sizeof(ScardIoRequestNative) +
                                              send_pci.extra.size(), 0);
        auto* send_req = reinterpret_cast<ScardIoRequestNative*>(
            send_pci_storage.data());
        send_req->dwProtocol = send_pci.protocol;
        send_req->cbPciLength = static_cast<DWORD>(send_pci_storage.size());
        if (!send_pci.extra.empty()) {
            std::memcpy(send_pci_storage.data() + sizeof(ScardIoRequestNative),
                        send_pci.extra.data(), send_pci.extra.size());
        }

        // The recv PCI buffer must be at least sizeof(SCARD_IO_REQUEST) plus
        // room for the extra bytes the card returns. FreeRDP passes the
        // server's pioRecvPci straight through; we size it for the same
        // kScardMaxExtraBytes bound the wire format allows.
        constexpr size_t kMaxRecvPciExtra = 1024;
        std::vector<uint8_t> recv_pci_storage(
            sizeof(ScardIoRequestNative) + kMaxRecvPciExtra, 0);
        auto* recv_req = reinterpret_cast<ScardIoRequestNative*>(
            recv_pci_storage.data());
        recv_req->dwProtocol = kScardProtocolUndefined;
        recv_req->cbPciLength = static_cast<DWORD>(recv_pci_storage.size());

        std::vector<uint8_t> recv_buffer;
        const size_t capacity = std::min<size_t>(recv_capacity, 66560);
        recv_buffer.resize(capacity);
        DWORD recv_len = static_cast<DWORD>(capacity);
        const LONG rc = api_.transmit(
            card, send_req, send.empty() ? nullptr : send.data(),
            static_cast<DWORD>(send.size()), wants_recv_pci ? recv_req : nullptr,
            recv_buffer.empty() ? nullptr : recv_buffer.data(), &recv_len);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        recv.assign(recv_buffer.begin(),
                    recv_buffer.begin() +
                        std::min<size_t>(recv_len, recv_buffer.size()));
        if (wants_recv_pci) {
            recv_pci.protocol = recv_req->dwProtocol;
            if (recv_req->cbPciLength > sizeof(ScardIoRequestNative)) {
                size_t extra = recv_req->cbPciLength - sizeof(ScardIoRequestNative);
                extra = std::min<size_t>(extra, kMaxRecvPciExtra);
                recv_pci.extra.assign(
                    recv_pci_storage.begin() + sizeof(ScardIoRequestNative),
                    recv_pci_storage.begin() + sizeof(ScardIoRequestNative) + extra);
            } else {
                recv_pci.extra.clear();
            }
        }
        return kScardSuccess;
    }

    uint32_t Control(const std::vector<uint8_t>& context,
                     const std::vector<uint8_t>& handle, uint32_t control_code,
                     const std::vector<uint8_t>& in, uint32_t out_capacity,
                     std::vector<uint8_t>& out) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;

        std::vector<uint8_t> buffer(std::min<size_t>(out_capacity, 66560));
        DWORD returned = 0;
        const LONG rc = api_.control(
            card, control_code, in.empty() ? nullptr : in.data(),
            static_cast<DWORD>(in.size()),
            buffer.empty() ? nullptr : buffer.data(),
            static_cast<DWORD>(buffer.size()), &returned);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        out.assign(buffer.begin(),
                   buffer.begin() + std::min<size_t>(returned, buffer.size()));
        return kScardSuccess;
    }

 private:
    uint64_t NextId() {
        std::lock_guard<std::mutex> lock(mu_);
        return ++next_id_;
    }

    using ContextMap = std::map<uint64_t, SCARDCONTEXT>;
    using HandleMap = std::map<uint64_t, SCARDHANDLE>;

    ContextMap::iterator FindContextLocked(const std::vector<uint8_t>& context,
                                           SCARDCONTEXT& native) {
        uint64_t id = 0;
        if (!DecodeId(context, id)) return contexts_.end();
        const auto it = contexts_.find(id);
        if (it != contexts_.end()) native = it->second;
        return it;
    }

    uint32_t LookupHandle(const std::vector<uint8_t>& context,
                          const std::vector<uint8_t>& handle,
                          SCARDHANDLE& card) {
        if (!available_) return kScardENoService;
        uint64_t id = 0;
        if (!DecodeId(handle, id)) return kScardEInvalidHandle;
        std::lock_guard<std::mutex> lock(mu_);
        SCARDCONTEXT context_native = 0;
        if (FindContextLocked(context, context_native) == contexts_.end()) {
            return kScardEInvalidHandle;
        }
        const auto it = handles_.find(id);
        if (it == handles_.end()) return kScardEInvalidHandle;
        card = it->second;
        return kScardSuccess;
    }

    uint32_t TakeHandle(const std::vector<uint8_t>& context,
                        const std::vector<uint8_t>& handle, SCARDHANDLE& card) {
        const uint32_t rc = LookupHandle(context, handle, card);
        if (rc != kScardSuccess) return rc;
        uint64_t id = 0;
        DecodeId(handle, id);
        std::lock_guard<std::mutex> lock(mu_);
        handles_.erase(id);
        return kScardSuccess;
    }

    // Copies a WinSCard multistring. With SCARD_AUTOALLOCATE `cch` is the byte
    // count including the final double NUL; when it is 0 the buffer is empty.
    static std::vector<uint8_t> CopyMultiString(const char* raw, DWORD cch) {
        if (raw == nullptr || cch == 0) return {};
        return std::vector<uint8_t>(raw, raw + cch);
    }

    WinScardApi& api_;
    bool available_;
    std::mutex mu_;
    uint64_t next_id_ = 0;
    ContextMap contexts_;
    HandleMap handles_;
};

}  // namespace

std::unique_ptr<ISmartCardBackend> MakeSmartCardBackend() {
    auto backend = std::make_unique<WinSmartCardBackend>();
    if (!backend->available()) return MakeNullSmartCardBackend();
    return backend;
}

#else  // !defined(_WIN32)

std::unique_ptr<ISmartCardBackend> MakeSmartCardBackend() {
    return MakeNullSmartCardBackend();
}

#endif

}  // namespace rtsc::smartcard
