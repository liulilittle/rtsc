// Saved-connection credentials.
//
// mstsc stores a saved password in the Windows Credential Manager under the
// generic target name "TERMSRV/<host>" (user name + UTF-16 password blob).
// This module wraps that convention. Platforms without a credential store
// return nullptr from CreatePlatformCredentialStore() and nothing is saved.
//
// The password is never logged and never written to an .rdp file.

#pragma once

#include <memory>
#include <string>

namespace rtsc::config {

// The generic target name mstsc uses for a host: "TERMSRV/" + host.
std::string CredentialTargetName(const std::string& host);

struct StoredCredential {
    std::string user;
    std::string password;
};

class CredentialStore {
 public:
    virtual ~CredentialStore() = default;

    // Creates or replaces the entry. `error` receives a diagnostic on failure.
    virtual bool Save(const std::string& target,
                      const StoredCredential& credential,
                      std::string& error) = 0;
    // Fills `credential` from the store. Returns false when there is no entry.
    virtual bool Load(const std::string& target,
                      StoredCredential& credential) = 0;
    // Removes the entry. Returns false when there is nothing to remove.
    virtual bool Delete(const std::string& target) = 0;
};

// Windows: Credential Manager. Other platforms: nullptr.
std::unique_ptr<CredentialStore> CreatePlatformCredentialStore();

}  // namespace rtsc::config
