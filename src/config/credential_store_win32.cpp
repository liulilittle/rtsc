// Saved-connection credentials: Windows Credential Manager backend.

#include "rtsc/config/credential_store.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincred.h>

#include <string>
#endif

namespace rtsc::config {

std::string CredentialTargetName(const std::string& host) {
    return "TERMSRV/" + host;
}

#if defined(_WIN32)
namespace {

std::wstring ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n);
    return out;
}

std::string ToUtf8(const wchar_t* s) {
    if (s == nullptr) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr,
                                      nullptr);
    if (n <= 1) return std::string();
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr);
    return out;
}

class Win32CredentialStore final : public CredentialStore {
 public:
    bool Save(const std::string& target, const StoredCredential& credential,
              std::string& error) override {
        const std::wstring target_w = ToWide(target);
        const std::wstring user_w = ToWide(credential.user);
        // The blob is the UTF-16 password without a terminator, matching what
        // mstsc stores under TERMSRV/<host>.
        const std::wstring password_w = ToWide(credential.password);
        if (target_w.empty() || user_w.empty()) {
            error = "empty credential target or user";
            return false;
        }
        CREDENTIALW cred{};
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = const_cast<LPWSTR>(target_w.c_str());
        cred.UserName = const_cast<LPWSTR>(user_w.c_str());
        cred.CredentialBlobSize =
            static_cast<DWORD>(password_w.size() * sizeof(wchar_t));
        cred.CredentialBlob = reinterpret_cast<LPBYTE>(
            const_cast<wchar_t*>(password_w.c_str()));
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
        if (!CredWriteW(&cred, 0)) {
            error = "CredWrite failed (" +
                    std::to_string(static_cast<unsigned long>(
                        GetLastError())) +
                    ")";
            return false;
        }
        return true;
    }

    bool Load(const std::string& target, StoredCredential& credential) override {
        const std::wstring target_w = ToWide(target);
        if (target_w.empty()) return false;
        PCREDENTIALW cred = nullptr;
        if (!CredReadW(target_w.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
            return false;
        }
        credential.user = ToUtf8(cred->UserName);
        const std::wstring password_w(
            reinterpret_cast<const wchar_t*>(cred->CredentialBlob),
            cred->CredentialBlobSize / sizeof(wchar_t));
        credential.password = ToUtf8(password_w.c_str());
        CredFree(cred);
        return true;
    }

    bool Delete(const std::string& target) override {
        const std::wstring target_w = ToWide(target);
        if (target_w.empty()) return false;
        return CredDeleteW(target_w.c_str(), CRED_TYPE_GENERIC, 0) != FALSE;
    }
};

}  // namespace
#endif

std::unique_ptr<CredentialStore> CreatePlatformCredentialStore() {
#if defined(_WIN32)
    return std::make_unique<Win32CredentialStore>();
#else
    return nullptr;
#endif
}

}  // namespace rtsc::config
