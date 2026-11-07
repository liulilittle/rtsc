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

struct ScardReaderStateNativeW {
    LPCWSTR szReader;
    LPVOID pvUserData;
    DWORD dwCurrentState;
    DWORD dwEventState;
    DWORD cbAtr;
    BYTE rgbAtr[36];
};

// GUID/UUID in-memory layout (guiddef.h): Data1/Data2/Data3 little-endian,
// Data4[8]. NDR serializes a UUID in exactly this byte order.
struct ScardAtrMaskNative {
    DWORD cbAtr;
    BYTE rgbAtr[36];
    BYTE rgbMask[36];
};

struct UuidNative {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

using FnEstablishContext = LONG(WINAPI*)(DWORD, LPCVOID, LPCVOID,
                                          SCARDCONTEXT*);
using FnReleaseContext = LONG(WINAPI*)(SCARDCONTEXT);
using FnIsValidContext = LONG(WINAPI*)(SCARDCONTEXT);
using FnListReaderGroupsA = LONG(WINAPI*)(SCARDCONTEXT, LPSTR, LPDWORD);
using FnListReaderGroupsW = LONG(WINAPI*)(SCARDCONTEXT, LPWSTR, LPDWORD);
    using FnListReadersA = LONG(WINAPI*)(SCARDCONTEXT, LPCSTR, LPSTR, LPDWORD);
    using FnListReadersW = LONG(WINAPI*)(SCARDCONTEXT, LPCWSTR, LPWSTR,
                                         LPDWORD);
    using FnListReadersW = LONG(WINAPI*)(SCARDCONTEXT, LPCWSTR, LPWSTR, LPDWORD);
using FnGetStatusChangeA = LONG(WINAPI*)(SCARDCONTEXT, DWORD,
                                         ScardReaderStateNative*, DWORD);
using FnGetStatusChangeW = LONG(WINAPI*)(SCARDCONTEXT, DWORD,
                                         ScardReaderStateNativeW*, DWORD);
using FnLocateCardsA = LONG(WINAPI*)(SCARDCONTEXT, LPCSTR,
                                     ScardReaderStateNative*, DWORD);
using FnLocateCardsW = LONG(WINAPI*)(SCARDCONTEXT, LPCWSTR,
                                     ScardReaderStateNativeW*, DWORD);
using FnLocateCardsByATRA = LONG(WINAPI*)(SCARDCONTEXT, ScardAtrMaskNative*,
                                         DWORD, ScardReaderStateNative*, DWORD);
using FnLocateCardsByATRW = LONG(WINAPI*)(SCARDCONTEXT, ScardAtrMaskNative*,
                                         DWORD, ScardReaderStateNativeW*, DWORD);
    using FnConnectA = LONG(WINAPI*)(SCARDCONTEXT, LPCSTR, DWORD, DWORD,
                                     SCARDHANDLE*, LPDWORD);
    using FnConnectW = LONG(WINAPI*)(SCARDCONTEXT, LPCWSTR, DWORD, DWORD,
                                     SCARDHANDLE*, LPDWORD);
using FnDisconnect = LONG(WINAPI*)(SCARDHANDLE, DWORD);
using FnBeginTransaction = LONG(WINAPI*)(SCARDHANDLE);
using FnEndTransaction = LONG(WINAPI*)(SCARDHANDLE, DWORD);
    using FnStatusA = LONG(WINAPI*)(SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD,
                                     LPBYTE, LPDWORD);
    using FnStatusW = LONG(WINAPI*)(SCARDHANDLE, LPWSTR, LPDWORD, LPDWORD,
                                     LPDWORD, LPBYTE, LPDWORD);
using FnTransmit = LONG(WINAPI*)(SCARDHANDLE, LPCSCARD_IO_REQUEST,
                                  const BYTE*, DWORD, LPSCARD_IO_REQUEST, LPBYTE,
                                  LPDWORD);
using FnControl = LONG(WINAPI*)(SCARDHANDLE, DWORD, LPCVOID, DWORD, LPVOID,
                                 DWORD, LPDWORD);
using FnGetAttrib = LONG(WINAPI*)(SCARDHANDLE, DWORD, LPBYTE, LPDWORD);
using FnSetAttrib = LONG(WINAPI*)(SCARDHANDLE, DWORD, const BYTE*, DWORD);
using FnReadCacheA = LONG(WINAPI*)(SCARDCONTEXT, const UuidNative*, DWORD,
                                 LPCSTR, LPBYTE, LPDWORD);
using FnReadCacheW = LONG(WINAPI*)(SCARDCONTEXT, const UuidNative*, DWORD,
                                 LPCWSTR, LPBYTE, LPDWORD);
using FnWriteCacheA = LONG(WINAPI*)(SCARDCONTEXT, const UuidNative*, DWORD,
                                  LPCSTR, const BYTE*, DWORD);
using FnWriteCacheW = LONG(WINAPI*)(SCARDCONTEXT, const UuidNative*, DWORD,
                                  LPCWSTR, const BYTE*, DWORD);
using FnGetReaderIconW = LONG(WINAPI*)(SCARDCONTEXT, LPCWSTR, LPBYTE,
                                      LPDWORD);
using FnGetDeviceTypeIdW = LONG(WINAPI*)(SCARDCONTEXT, LPCWSTR, LPDWORD);
using FnGetTransmitCount = LONG(WINAPI*)(SCARDHANDLE, LPDWORD);
using FnAccessStartedEvent = HANDLE(WINAPI*)(void);
using FnReleaseStartedEvent = void(WINAPI*)(void);
using FnCancel = LONG(WINAPI*)(SCARDCONTEXT);
using FnState = LONG(WINAPI*)(SCARDHANDLE, LPDWORD, LPDWORD, LPBYTE,
                             LPDWORD);
using FnReconnect = LONG(WINAPI*)(SCARDHANDLE, DWORD, DWORD, DWORD,
                                 LPDWORD);
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
// ReadCache_Return.cbDataLen is [range(0,65536)] ([MS-RDPESC] 2.2.3.1).
constexpr size_t kScardMaxCacheBytes = 65536;

struct WinScardApi {
    HMODULE module = nullptr;
    FnEstablishContext establish_context = nullptr;
    FnReleaseContext release_context = nullptr;
    FnIsValidContext is_valid_context = nullptr;
    FnListReaderGroupsA list_reader_groups = nullptr;
    FnListReaderGroupsW list_reader_groups_w = nullptr;
    FnListReadersA list_readers = nullptr;
    FnListReadersW list_readers_w = nullptr;
    FnGetStatusChangeA get_status_change = nullptr;
    FnGetStatusChangeW get_status_change_w = nullptr;
    FnLocateCardsA locate_cards = nullptr;
    FnLocateCardsW locate_cards_w = nullptr;
    FnLocateCardsByATRA locate_cards_by_atr = nullptr;
    FnLocateCardsByATRW locate_cards_by_atr_w = nullptr;
    FnConnectA connect = nullptr;
    FnConnectW connect_w = nullptr;
    FnDisconnect disconnect = nullptr;
    FnBeginTransaction begin_transaction = nullptr;
    FnEndTransaction end_transaction = nullptr;
    FnStatusA status = nullptr;
    FnStatusW status_w = nullptr;
    FnTransmit transmit = nullptr;
    FnControl control = nullptr;
    FnGetAttrib get_attrib = nullptr;
    FnSetAttrib set_attrib = nullptr;
    FnReadCacheA read_cache = nullptr;
    FnReadCacheW read_cache_w = nullptr;
    FnWriteCacheA write_cache = nullptr;
    FnWriteCacheW write_cache_w = nullptr;
    FnGetReaderIconW get_reader_icon = nullptr;
    FnGetDeviceTypeIdW get_device_type_id = nullptr;
    FnGetTransmitCount get_transmit_count = nullptr;
    FnAccessStartedEvent access_started_event = nullptr;
    FnReleaseStartedEvent release_started_event = nullptr;
    FnCancel cancel = nullptr;
    FnState state = nullptr;
    FnReconnect reconnect = nullptr;
    FnFreeMemory free_memory = nullptr;

    bool Load() {
        if (module != nullptr) return true;
        module = ::LoadLibraryW(L"winscard.dll");
        if (module == nullptr) return false;
        establish_context = reinterpret_cast<FnEstablishContext>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardEstablishContext")));
        release_context = reinterpret_cast<FnReleaseContext>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardReleaseContext")));
        is_valid_context = reinterpret_cast<FnIsValidContext>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardIsValidContext")));
        list_reader_groups = reinterpret_cast<FnListReaderGroupsA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardListReaderGroupsA")));
        list_reader_groups_w = reinterpret_cast<FnListReaderGroupsW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardListReaderGroupsW")));
        list_readers = reinterpret_cast<FnListReadersA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardListReadersA")));
        list_readers_w = reinterpret_cast<FnListReadersW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardListReadersW")));
        get_status_change = reinterpret_cast<FnGetStatusChangeA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardGetStatusChangeA")));
        get_status_change_w = reinterpret_cast<FnGetStatusChangeW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardGetStatusChangeW")));
        locate_cards = reinterpret_cast<FnLocateCardsA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardLocateCardsA")));
        locate_cards_w = reinterpret_cast<FnLocateCardsW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardLocateCardsW")));
        locate_cards_by_atr = reinterpret_cast<FnLocateCardsByATRA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardLocateCardsByATRA")));
        locate_cards_by_atr_w = reinterpret_cast<FnLocateCardsByATRW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardLocateCardsByATRW")));
        connect = reinterpret_cast<FnConnectA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardConnectA")));
        connect_w = reinterpret_cast<FnConnectW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardConnectW")));
        disconnect = reinterpret_cast<FnDisconnect>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardDisconnect")));
        begin_transaction = reinterpret_cast<FnBeginTransaction>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardBeginTransaction")));
        end_transaction = reinterpret_cast<FnEndTransaction>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardEndTransaction")));
        status = reinterpret_cast<FnStatusA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardStatusA")));
        status_w = reinterpret_cast<FnStatusW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardStatusW")));
        transmit = reinterpret_cast<FnTransmit>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardTransmit")));
        control = reinterpret_cast<FnControl>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardControl")));
        get_attrib = reinterpret_cast<FnGetAttrib>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardGetAttrib")));
        set_attrib = reinterpret_cast<FnSetAttrib>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardSetAttrib")));
        read_cache = reinterpret_cast<FnReadCacheA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardReadCacheA")));
        read_cache_w = reinterpret_cast<FnReadCacheW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardReadCacheW")));
        write_cache = reinterpret_cast<FnWriteCacheA>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardWriteCacheA")));
        write_cache_w = reinterpret_cast<FnWriteCacheW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardWriteCacheW")));
        get_reader_icon = reinterpret_cast<FnGetReaderIconW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardGetReaderIconW")));
        get_device_type_id = reinterpret_cast<FnGetDeviceTypeIdW>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardGetDeviceTypeIdW")));
        get_transmit_count = reinterpret_cast<FnGetTransmitCount>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardGetTransmitCount")));
        access_started_event = reinterpret_cast<FnAccessStartedEvent>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardAccessStartedEvent")));
        release_started_event = reinterpret_cast<FnReleaseStartedEvent>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardReleaseStartedEvent")));
        cancel = reinterpret_cast<FnCancel>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardCancel")));
        state = reinterpret_cast<FnState>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardState")));
        reconnect = reinterpret_cast<FnReconnect>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardReconnect")));
        free_memory = reinterpret_cast<FnFreeMemory>(
            reinterpret_cast<void*>(::GetProcAddress(module, "SCardFreeMemory")));
        return establish_context != nullptr && release_context != nullptr &&
               is_valid_context != nullptr &&
               list_reader_groups != nullptr &&
               list_reader_groups_w != nullptr && list_readers != nullptr &&
               list_readers_w != nullptr &&
               get_status_change != nullptr &&
               get_status_change_w != nullptr && locate_cards != nullptr &&
               locate_cards_w != nullptr &&
               locate_cards_by_atr != nullptr &&
               locate_cards_by_atr_w != nullptr &&
               connect != nullptr && connect_w != nullptr &&
               disconnect != nullptr && begin_transaction != nullptr &&
               end_transaction != nullptr && status != nullptr &&
               status_w != nullptr &&
               transmit != nullptr && control != nullptr &&
               get_attrib != nullptr && set_attrib != nullptr &&
               read_cache != nullptr && read_cache_w != nullptr &&
               write_cache != nullptr && write_cache_w != nullptr &&
               get_reader_icon != nullptr &&
               get_device_type_id != nullptr &&
               get_transmit_count != nullptr &&
               access_started_event != nullptr &&
               release_started_event != nullptr && cancel != nullptr &&
               state != nullptr && reconnect != nullptr &&
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

    uint32_t IsValidContext(const std::vector<uint8_t>& context) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        return static_cast<uint32_t>(api_.is_valid_context(native));
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

    uint32_t ListReaderGroupsW(const std::vector<uint8_t>& context,
                               std::vector<uint8_t>& groups) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        LPWSTR raw = nullptr;
        DWORD cch = kScardAutoAllocate;
        const LONG rc = api_.list_reader_groups_w(
            native, reinterpret_cast<LPWSTR>(&raw), &cch);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        const std::vector<uint8_t> copy = CopyMultiStringW(raw, cch);
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

    uint32_t ListReadersW(const std::vector<uint8_t>& context,
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
        const wchar_t* filter =
            groups.empty()
                ? nullptr
                : reinterpret_cast<const wchar_t*>(groups.data());
        LPWSTR raw = nullptr;
        DWORD cch = kScardAutoAllocate;
        const LONG rc = api_.list_readers_w(
            native, filter, reinterpret_cast<LPWSTR>(&raw), &cch);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        readers = CopyMultiStringW(raw, cch);
        if (raw != nullptr) api_.free_memory(native, raw);
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
        const LONG rc = WaitForStatusChange(native, timeout_ms, native_states,
                                           api_.get_status_change);
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

    uint32_t GetStatusChangeW(const std::vector<uint8_t>& context,
                              uint32_t timeout_ms,
                              std::vector<ScardReaderStateW>& states) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        // The u16string data is already UTF-16LE; wchar_t is 16-bit on Windows.
        std::vector<ScardReaderStateNativeW> native_states(states.size());
        for (size_t i = 0; i < states.size(); ++i) {
            native_states[i].szReader =
                reinterpret_cast<const wchar_t*>(states[i].reader.c_str());
            native_states[i].pvUserData = nullptr;
            native_states[i].dwCurrentState = states[i].current_state;
            native_states[i].dwEventState = 0;
            native_states[i].cbAtr = 0;
            std::memset(native_states[i].rgbAtr, 0,
                        sizeof(native_states[i].rgbAtr));
        }
        const LONG rc = WaitForStatusChange(native, timeout_ms, native_states,
                                           api_.get_status_change_w);
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

    uint32_t LocateCards(const std::vector<uint8_t>& context,
                         const std::vector<uint8_t>& cards,
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

        const LONG rc = api_.locate_cards(
            native,
            cards.empty() ? nullptr : reinterpret_cast<LPCSTR>(cards.data()),
            native_states.empty() ? nullptr : native_states.data(),
            static_cast<DWORD>(native_states.size()));
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

    uint32_t LocateCardsW(const std::vector<uint8_t>& context,
                          const std::vector<uint8_t>& cards,
                          std::vector<ScardReaderStateW>& states) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        std::vector<ScardReaderStateNativeW> native_states(states.size());
        for (size_t i = 0; i < states.size(); ++i) {
            native_states[i].szReader =
                reinterpret_cast<const wchar_t*>(states[i].reader.c_str());
            native_states[i].pvUserData = nullptr;
            native_states[i].dwCurrentState = states[i].current_state;
            native_states[i].dwEventState = 0;
            native_states[i].cbAtr = 0;
            std::memset(native_states[i].rgbAtr, 0,
                        sizeof(native_states[i].rgbAtr));
        }
        const LONG rc = api_.locate_cards_w(
            native,
            cards.empty() ? nullptr
                          : reinterpret_cast<LPCWSTR>(cards.data()),
            native_states.empty() ? nullptr : native_states.data(),
            static_cast<DWORD>(native_states.size()));
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

    uint32_t LocateCardsByAtr(const std::vector<uint8_t>& context,
                              const std::vector<ScardAtrMask>& masks,
                              std::vector<ScardReaderState>& states) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        std::vector<ScardAtrMaskNative> native_masks(masks.size());
        for (size_t i = 0; i < masks.size(); ++i) {
            if (masks[i].atr.size() > 36 ||
                masks[i].atr.size() != masks[i].mask.size()) {
                return kScardEInvalidParameter;
            }
            native_masks[i].cbAtr = static_cast<DWORD>(masks[i].atr.size());
            std::memset(native_masks[i].rgbAtr, 0,
                        sizeof(native_masks[i].rgbAtr));
            std::memset(native_masks[i].rgbMask, 0,
                        sizeof(native_masks[i].rgbMask));
            if (!masks[i].atr.empty()) {
                std::memcpy(native_masks[i].rgbAtr, masks[i].atr.data(),
                            masks[i].atr.size());
                std::memcpy(native_masks[i].rgbMask, masks[i].mask.data(),
                            masks[i].mask.size());
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

        const LONG rc = api_.locate_cards_by_atr(
            native, native_masks.empty() ? nullptr : native_masks.data(),
            static_cast<DWORD>(native_masks.size()),
            native_states.empty() ? nullptr : native_states.data(),
            static_cast<DWORD>(native_states.size()));
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

    uint32_t LocateCardsByAtrW(
        const std::vector<uint8_t>& context,
        const std::vector<ScardAtrMask>& masks,
        std::vector<ScardReaderStateW>& states) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        std::vector<ScardAtrMaskNative> native_masks(masks.size());
        for (size_t i = 0; i < masks.size(); ++i) {
            if (masks[i].atr.size() > 36 ||
                masks[i].atr.size() != masks[i].mask.size()) {
                return kScardEInvalidParameter;
            }
            native_masks[i].cbAtr = static_cast<DWORD>(masks[i].atr.size());
            std::memset(native_masks[i].rgbAtr, 0,
                        sizeof(native_masks[i].rgbAtr));
            std::memset(native_masks[i].rgbMask, 0,
                        sizeof(native_masks[i].rgbMask));
            if (!masks[i].atr.empty()) {
                std::memcpy(native_masks[i].rgbAtr, masks[i].atr.data(),
                            masks[i].atr.size());
                std::memcpy(native_masks[i].rgbMask, masks[i].mask.data(),
                            masks[i].mask.size());
            }
        }
        std::vector<ScardReaderStateNativeW> native_states(states.size());
        for (size_t i = 0; i < states.size(); ++i) {
            native_states[i].szReader =
                reinterpret_cast<const wchar_t*>(states[i].reader.c_str());
            native_states[i].pvUserData = nullptr;
            native_states[i].dwCurrentState = states[i].current_state;
            native_states[i].dwEventState = 0;
            native_states[i].cbAtr = 0;
            std::memset(native_states[i].rgbAtr, 0,
                        sizeof(native_states[i].rgbAtr));
        }
        const LONG rc = api_.locate_cards_by_atr_w(
            native, native_masks.empty() ? nullptr : native_masks.data(),
            static_cast<DWORD>(native_masks.size()),
            native_states.empty() ? nullptr : native_states.data(),
            static_cast<DWORD>(native_states.size()));
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

    uint32_t ConnectW(const std::vector<uint8_t>& context,
                      const std::u16string& reader, uint32_t share_mode,
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
        uint32_t protocols = preferred_protocols;
        if (protocols == kScardProtocolUndefined &&
            share_mode != kScardShareDirect) {
            protocols = kScardProtocolT0 | kScardProtocolT1;
        }
        const wchar_t* name =
            reinterpret_cast<const wchar_t*>(reader.c_str());
        SCARDHANDLE card = 0;
        DWORD active = kScardProtocolUndefined;
        const LONG rc = api_.connect_w(native, name, share_mode, protocols,
                                       &card, &active);
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

    uint32_t StatusW(const std::vector<uint8_t>& context,
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

        LPWSTR names = nullptr;
        DWORD cch = kScardAutoAllocate;
        BYTE atr_buf[kStatusAtrBytes] = {0};
        DWORD atr_len = static_cast<DWORD>(sizeof(atr_buf));
        DWORD native_state = 0;
        DWORD native_protocol = 0;
        const LONG rc = api_.status_w(
            card, reinterpret_cast<LPWSTR>(&names), &cch, &native_state,
            &native_protocol, atr_buf, &atr_len);
        std::vector<uint8_t> names_copy;
        if (rc == kScardSuccess) names_copy = CopyMultiStringW(names, cch);
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

    uint32_t GetAttrib(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& handle, uint32_t attr_id,
                       bool attr_is_null, uint32_t capacity,
                       std::vector<uint8_t>& attr,
                       uint32_t& attr_length) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;

        DWORD length = 0;
        LONG rc = api_.get_attrib(card, attr_id, nullptr, &length);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        attr_length = length;
        if (attr_is_null || capacity == 0) {
            attr.clear();
            return kScardSuccess;
        }
        if (capacity != kScardAutoAllocate && length > capacity) {
            attr.clear();
            return kScardEInsufficientBuffer;
        }
        std::vector<uint8_t> buffer(length);
        DWORD got = length;
        rc = api_.get_attrib(card, attr_id,
                             buffer.empty() ? nullptr : buffer.data(), &got);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        buffer.resize(std::min<size_t>(got, buffer.size()));
        attr = std::move(buffer);
        attr_length = static_cast<uint32_t>(attr.size());
        return kScardSuccess;
    }

    uint32_t SetAttrib(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& handle, uint32_t attr_id,
                       const std::vector<uint8_t>& attr) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;
        const LONG rc = api_.set_attrib(
            card, attr_id, attr.empty() ? nullptr : attr.data(),
            static_cast<DWORD>(attr.size()));
        return static_cast<uint32_t>(rc);
    }

    uint32_t ReadCache(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& card_id,
                       uint32_t freshness, const std::string& lookup_name,
                       bool length_only, uint32_t capacity,
                       std::vector<uint8_t>& data,
                       uint32_t& data_length) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        if (card_id.size() != sizeof(UuidNative)) {
            return kScardEInvalidParameter;
        }
        UuidNative uuid;
        std::memcpy(&uuid, card_id.data(), sizeof(uuid));
        const char* name = lookup_name.c_str();

        // The length probe uses SCARD_AUTOALLOCATE instead of a NULL buffer so
        // the service reports the exact size regardless of how it treats a
        // NULL Data pointer ([MS-RDPESC] 2.2.1.9 allows cbDataLen = 0xFFFFFFFF).
        if (length_only || capacity == kScardAutoAllocate) {
            BYTE* raw = nullptr;
            DWORD len = kScardAutoAllocate;
            const LONG rc = api_.read_cache(
                native, &uuid, freshness, name,
                reinterpret_cast<LPBYTE>(&raw), &len);
            if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
            data_length = len;
            if (!length_only && raw != nullptr && len <= kScardMaxCacheBytes) {
                data.assign(raw, raw + len);
            }
            if (raw != nullptr) api_.free_memory(native, raw);
            if (!length_only && len > kScardMaxCacheBytes) {
                return kScardEInsufficientBuffer;
            }
            return kScardSuccess;
        }

        const size_t alloc = std::min<size_t>(capacity, kScardMaxCacheBytes);
        std::vector<uint8_t> buffer(alloc);
        DWORD len = static_cast<DWORD>(alloc);
        const LONG rc = api_.read_cache(
            native, &uuid, freshness, name,
            buffer.empty() ? nullptr : buffer.data(), &len);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        if (len > buffer.size()) return kScardEInsufficientBuffer;
        buffer.resize(len);
        data = std::move(buffer);
        data_length = len;
        return kScardSuccess;
    }

    uint32_t ReadCacheW(const std::vector<uint8_t>& context,
                        const std::vector<uint8_t>& card_id,
                        uint32_t freshness, const std::u16string& lookup_name,
                        bool length_only, uint32_t capacity,
                        std::vector<uint8_t>& data,
                        uint32_t& data_length) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        if (card_id.size() != sizeof(UuidNative)) {
            return kScardEInvalidParameter;
        }
        UuidNative uuid;
        std::memcpy(&uuid, card_id.data(), sizeof(uuid));
        const wchar_t* name =
            reinterpret_cast<const wchar_t*>(lookup_name.c_str());

        if (length_only || capacity == kScardAutoAllocate) {
            BYTE* raw = nullptr;
            DWORD len = kScardAutoAllocate;
            const LONG rc = api_.read_cache_w(
                native, &uuid, freshness, name,
                reinterpret_cast<LPBYTE>(&raw), &len);
            if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
            data_length = len;
            if (!length_only && raw != nullptr && len <= kScardMaxCacheBytes) {
                data.assign(raw, raw + len);
            }
            if (raw != nullptr) api_.free_memory(native, raw);
            if (!length_only && len > kScardMaxCacheBytes) {
                return kScardEInsufficientBuffer;
            }
            return kScardSuccess;
        }

        const size_t alloc = std::min<size_t>(capacity, kScardMaxCacheBytes);
        std::vector<uint8_t> buffer(alloc);
        DWORD len = static_cast<DWORD>(alloc);
        const LONG rc = api_.read_cache_w(
            native, &uuid, freshness, name,
            buffer.empty() ? nullptr : buffer.data(), &len);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        if (len > buffer.size()) return kScardEInsufficientBuffer;
        buffer.resize(len);
        data = std::move(buffer);
        data_length = len;
        return kScardSuccess;
    }

    uint32_t WriteCache(const std::vector<uint8_t>& context,
                        const std::vector<uint8_t>& card_id,
                        uint32_t freshness, const std::string& lookup_name,
                        const std::vector<uint8_t>& data) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        if (card_id.size() != sizeof(UuidNative)) {
            return kScardEInvalidParameter;
        }
        UuidNative uuid;
        std::memcpy(&uuid, card_id.data(), sizeof(uuid));
        const LONG rc = api_.write_cache(
            native, &uuid, freshness, lookup_name.c_str(),
            data.empty() ? nullptr : data.data(),
            static_cast<DWORD>(data.size()));
        return static_cast<uint32_t>(rc);
    }

    uint32_t WriteCacheW(const std::vector<uint8_t>& context,
                         const std::vector<uint8_t>& card_id,
                         uint32_t freshness, const std::u16string& lookup_name,
                         const std::vector<uint8_t>& data) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        if (card_id.size() != sizeof(UuidNative)) {
            return kScardEInvalidParameter;
        }
        UuidNative uuid;
        std::memcpy(&uuid, card_id.data(), sizeof(uuid));
        const wchar_t* name =
            reinterpret_cast<const wchar_t*>(lookup_name.c_str());
        const LONG rc = api_.write_cache_w(
            native, &uuid, freshness, name,
            data.empty() ? nullptr : data.data(),
            static_cast<DWORD>(data.size()));
        return static_cast<uint32_t>(rc);
    }

    uint32_t GetReaderIcon(const std::vector<uint8_t>& context,
                           const std::u16string& reader_name,
                           std::vector<uint8_t>& icon,
                           uint32_t& icon_length) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        std::wstring name;
        name.reserve(reader_name.size());
        for (char16_t ch : reader_name) name.push_back(static_cast<wchar_t>(ch));

        // FreeRDP smartcard_GetReaderIcon_Call: SCARD_AUTOALLOCATE + free.
        BYTE* raw = nullptr;
        DWORD len = kScardAutoAllocate;
        const LONG rc = api_.get_reader_icon(
            native, name.c_str(), reinterpret_cast<LPBYTE>(&raw), &len);
        if (rc != kScardSuccess) {
            if (raw != nullptr) api_.free_memory(native, raw);
            return static_cast<uint32_t>(rc);
        }
        icon_length = len;
        if (raw != nullptr) {
            icon.assign(raw, raw + len);
            api_.free_memory(native, raw);
        }
        return kScardSuccess;
    }

    uint32_t GetDeviceTypeId(const std::vector<uint8_t>& context,
                             const std::u16string& reader_name,
                             uint32_t& device_type_id) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        std::wstring name;
        name.reserve(reader_name.size());
        for (char16_t ch : reader_name) name.push_back(static_cast<wchar_t>(ch));
        DWORD id = 0;
        const LONG rc = api_.get_device_type_id(native, name.c_str(), &id);
        if (rc == kScardSuccess) device_type_id = id;
        return static_cast<uint32_t>(rc);
    }

    uint32_t GetTransmitCount(const std::vector<uint8_t>& context,
                              const std::vector<uint8_t>& handle,
                              uint32_t& transmit_count) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;
        DWORD count = 0;
        const LONG rc = api_.get_transmit_count(card, &count);
        if (rc == kScardSuccess) transmit_count = count;
        return static_cast<uint32_t>(rc);
    }

    uint32_t AccessStartedEvent() override {
        if (!available_) return kScardENoService;
        HANDLE event = api_.access_started_event();
        if (event == nullptr) return kScardENoService;
        // 1:1 pairing: the handle is only a local liveness probe.
        api_.release_started_event();
        return kScardSuccess;
    }

    uint32_t Cancel(const std::vector<uint8_t>& context) override {
        if (!available_) return kScardENoService;
        SCARDCONTEXT native = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (FindContextLocked(context, native) == contexts_.end()) {
                return kScardEInvalidHandle;
            }
        }
        return static_cast<uint32_t>(api_.cancel(native));
    }

    uint32_t State(const std::vector<uint8_t>& context,
                   const std::vector<uint8_t>& handle, uint32_t& state,
                   uint32_t& protocol, std::vector<uint8_t>& atr) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;
        DWORD native_state = 0;
        DWORD native_protocol = 0;
        BYTE buffer[36] = {};
        DWORD length = sizeof(buffer);
        const LONG rc = api_.state(card, &native_state, &native_protocol,
                                   buffer, &length);
        if (rc != kScardSuccess) return static_cast<uint32_t>(rc);
        if (length > sizeof(buffer)) return kScardEInsufficientBuffer;
        state = native_state;
        protocol = native_protocol;
        atr.assign(buffer, buffer + length);
        return kScardSuccess;
    }

    uint32_t Reconnect(const std::vector<uint8_t>& context,
                       const std::vector<uint8_t>& handle,
                       uint32_t share_mode, uint32_t preferred_protocols,
                       uint32_t initialization,
                       uint32_t& active_protocol) override {
        if (!available_) return kScardENoService;
        SCARDHANDLE card = 0;
        const uint32_t lookup = LookupHandle(context, handle, card);
        if (lookup != kScardSuccess) return lookup;
        DWORD active = 0;
        const LONG rc = api_.reconnect(card, share_mode, preferred_protocols,
                                       initialization, &active);
        if (rc == kScardSuccess) active_protocol = active;
        return static_cast<uint32_t>(rc);
    }

 private:
    // Shared by GetStatusChange and GetStatusChangeW: long waits are polled in
    // 1 s steps exactly like FreeRDP smartcard_call.c:
    // smartcard_status_change_step, so a cancelled session is not stuck inside
    // one huge WinSCard call.
    template <typename NativeState, typename Fn>
    LONG WaitForStatusChange(SCARDCONTEXT native, uint32_t timeout_ms,
                             std::vector<NativeState>& native_states, Fn fn) {
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
            rc = fn(native, step,
                    native_states.empty() ? nullptr : native_states.data(),
                    static_cast<DWORD>(native_states.size()));
            if (rc != static_cast<LONG>(kScardETimeout)) break;
            if (total != kInfinite) {
                waited += step;
                if (waited >= total) break;
            }
        }
        return rc;
    }
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

    static std::vector<uint8_t> CopyMultiStringW(const wchar_t* raw, DWORD cch) {
        if (raw == nullptr || cch == 0) return {};
        const auto* bytes = reinterpret_cast<const uint8_t*>(raw);
        return std::vector<uint8_t>(bytes, bytes + cch * sizeof(wchar_t));
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
