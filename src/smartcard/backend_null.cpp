// Null smart card backend: every operation fails closed with
// SCARD_E_NO_SERVICE. Used on non-Windows platforms and whenever winscard.dll
// or one of its entry points is missing, so the rdpdr handler always has an
// object to answer the server's SCARD_IOCTL_* requests ([MS-RDPESC] 3.1.4).

#include "rtsc/smartcard/backend.h"

namespace rtsc::smartcard {

namespace {

class NullSmartCardBackend final : public ISmartCardBackend {
 public:
    bool available() const override { return false; }

    uint32_t EstablishContext(uint32_t, std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t ReleaseContext(const std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t IsValidContext(const std::vector<uint8_t>&) override {
        // No context can exist without the service.
        return kScardEInvalidHandle;
    }
    uint32_t ListReaderGroups(const std::vector<uint8_t>&,
                              std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t ListReaderGroupsW(const std::vector<uint8_t>&,
                               std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t ListReaders(const std::vector<uint8_t>&,
                         const std::vector<uint8_t>&,
                         std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t ListReadersW(const std::vector<uint8_t>&,
                          const std::vector<uint8_t>&,
                          std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t GetStatusChange(const std::vector<uint8_t>&, uint32_t,
                             std::vector<ScardReaderState>&) override {
        return kScardENoService;
    }
    uint32_t GetStatusChangeW(const std::vector<uint8_t>&, uint32_t,
                              std::vector<ScardReaderStateW>&) override {
        return kScardENoService;
    }
    uint32_t LocateCards(const std::vector<uint8_t>&,
                         const std::vector<uint8_t>&,
                         std::vector<ScardReaderState>&) override {
        return kScardENoService;
    }
    uint32_t LocateCardsW(const std::vector<uint8_t>&,
                          const std::vector<uint8_t>&,
                          std::vector<ScardReaderStateW>&) override {
        return kScardENoService;
    }
    uint32_t LocateCardsByAtr(const std::vector<uint8_t>&,
                              const std::vector<ScardAtrMask>&,
                              std::vector<ScardReaderState>&) override {
        return kScardENoService;
    }
    uint32_t LocateCardsByAtrW(const std::vector<uint8_t>&,
                               const std::vector<ScardAtrMask>&,
                               std::vector<ScardReaderStateW>&) override {
        return kScardENoService;
    }
    uint32_t Connect(const std::vector<uint8_t>&, const std::string&, uint32_t,
                     uint32_t, std::vector<uint8_t>&,
                     uint32_t&) override {
        return kScardENoService;
    }
    uint32_t ConnectW(const std::vector<uint8_t>&, const std::u16string&,
                      uint32_t, uint32_t, std::vector<uint8_t>&,
                      uint32_t&) override {
        return kScardENoService;
    }
    uint32_t Disconnect(const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&, uint32_t) override {
        return kScardENoService;
    }
    uint32_t BeginTransaction(const std::vector<uint8_t>&,
                              const std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t EndTransaction(const std::vector<uint8_t>&,
                            const std::vector<uint8_t>&, uint32_t) override {
        return kScardENoService;
    }
    uint32_t Status(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                    std::vector<uint8_t>&, uint32_t&, uint32_t&,
                    std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t StatusW(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                     std::vector<uint8_t>&, uint32_t&, uint32_t&,
                     std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t Transmit(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                      const ScardPci&, const std::vector<uint8_t>&, bool,
                      uint32_t, ScardPci&, std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t Control(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                     uint32_t, const std::vector<uint8_t>&, uint32_t,
                     std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t GetAttrib(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                       uint32_t, bool, uint32_t, std::vector<uint8_t>&,
                       uint32_t&) override {
        return kScardENoService;
    }
    uint32_t SetAttrib(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                       uint32_t, const std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t ReadCache(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                       uint32_t, const std::string&, bool, uint32_t,
                       std::vector<uint8_t>&, uint32_t&) override {
        return kScardENoService;
    }
    uint32_t ReadCacheW(const std::vector<uint8_t>&,
                        const std::vector<uint8_t>&, uint32_t,
                        const std::u16string&, bool, uint32_t,
                        std::vector<uint8_t>&, uint32_t&) override {
        return kScardENoService;
    }
    uint32_t WriteCache(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                        uint32_t, const std::string&,
                        const std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t WriteCacheW(const std::vector<uint8_t>&,
                         const std::vector<uint8_t>&, uint32_t,
                         const std::u16string&,
                         const std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t GetReaderIcon(const std::vector<uint8_t>&, const std::u16string&,
                           std::vector<uint8_t>&, uint32_t&) override {
        return kScardENoService;
    }
    uint32_t GetDeviceTypeId(const std::vector<uint8_t>&, const std::u16string&,
                             uint32_t&) override {
        return kScardENoService;
    }
    uint32_t GetTransmitCount(const std::vector<uint8_t>&,
                              const std::vector<uint8_t>&,
                              uint32_t&) override {
        return kScardENoService;
    }
    uint32_t AccessStartedEvent() override { return kScardENoService; }
    uint32_t Cancel(const std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t State(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                   uint32_t&, uint32_t&, std::vector<uint8_t>&) override {
        return kScardENoService;
    }
    uint32_t Reconnect(const std::vector<uint8_t>&,
                       const std::vector<uint8_t>&, uint32_t, uint32_t,
                       uint32_t, uint32_t&) override {
        return kScardENoService;
    }
};

}  // namespace

std::unique_ptr<ISmartCardBackend> MakeNullSmartCardBackend() {
    return std::make_unique<NullSmartCardBackend>();
}

}  // namespace rtsc::smartcard
