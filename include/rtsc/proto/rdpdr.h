// Device redirection virtual channel (rdpdr) structure layer ([MS-RDPEFS] 2.2).
//
// Reference: [MS-RDPEFS] 2.2.1 (headers), 2.2.2 (core messages) and 2.2.3
// (drive redirection messages).
//
// The RDPDR_HEADER is 4 bytes (Component + PacketId); the packet length is
// implicit from the enclosing virtual channel PDU, so there is no PacketLength
// field here (verified against the 2.2.2.2 official 12-byte dump).

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "rtsc/proto/byte_order.h"

namespace rtsc::proto {

// RDPDR_HEADER.Component ([MS-RDPEFS] 2.2.1.1).
enum RdpdrComponent : uint16_t {
    kRdpdrCtypCore = 0x4472,
    kRdpdrCtypPrn = 0x5052,
};

// RDPDR_HEADER.PacketId ([MS-RDPEFS] 2.2.1.1).
enum RdpdrPacketId : uint16_t {
    kPakidCoreServerAnnounce = 0x496E,
    kPakidCoreClientidConfirm = 0x4343,
    kPakidCoreClientName = 0x434E,
    kPakidCoreDevicelistAnnounce = 0x4441,
    kPakidCoreDeviceReply = 0x6472,
    kPakidCoreDeviceIorequest = 0x4952,
    kPakidCoreDeviceIocompletion = 0x4943,
    kPakidCoreServerCapability = 0x5350,
    kPakidCoreClientCapability = 0x4350,
    kPakidCoreDevicelistRemove = 0x444D,
    kPakidCoreUserLoggedon = 0x554C,
};

const char* to_string(RdpdrPacketId id);

// DEVICE_ANNOUNCE.DeviceType ([MS-RDPEFS] 2.2.1.3).
enum RdpdrDeviceType : uint32_t {
    kRdpdrDtypSerial = 0x00000001,
    kRdpdrDtypParallel = 0x00000002,
    kRdpdrDtypPrint = 0x00000004,
    kRdpdrDtypFilesystem = 0x00000008,
    kRdpdrDtypSmartcard = 0x00000020,
};

// DR_DEVICE_IOREQUEST.MajorFunction ([MS-RDPEFS] 2.2.1.4).
enum RdpdrMajorFunction : uint32_t {
    kIrpMjCreate = 0x00000000,
    kIrpMjClose = 0x00000002,
    kIrpMjRead = 0x00000003,
    kIrpMjWrite = 0x00000004,
    kIrpMjQueryInformation = 0x00000005,
    kIrpMjSetInformation = 0x00000006,
    kIrpMjQueryVolumeInformation = 0x0000000A,
    kIrpMjSetVolumeInformation = 0x0000000B,
    kIrpMjDirectoryControl = 0x0000000C,
    kIrpMjDeviceControl = 0x0000000E,
    kIrpMjLockControl = 0x00000011,
};

// DR_DEVICE_IOREQUEST.MinorFunction ([MS-RDPEFS] 2.2.1.4).
enum RdpdrMinorFunction : uint32_t {
    kIrpMnQueryDirectory = 0x00000001,
    kIrpMnNotifyChangeDirectory = 0x00000002,
};

// NTSTATUS codes used by the drive redirection protocol ([MS-ERREF] 2.3).
enum RdpdrStatus : uint32_t {
    kStatusSuccess = 0x00000000,
    kStatusNoSuchFile = 0xC000000F,
    kStatusEndOfFile = 0xC0000011,
    kStatusAccessDenied = 0xC0000022,
    kStatusObjectNameNotFound = 0xC0000034,
    kStatusInvalidParameter = 0xC000000D,
    kStatusNotADirectory = 0xC0000103,
    kStatusUnsuccessful = 0xC0000001,
    kStatusNoMoreFiles = 0x80000006,
};

// CAPABILITY_HEADER.CapabilityType ([MS-RDPEFS] 2.2.1.2).
enum RdpdrCapabilityType : uint16_t {
    kCapGeneralType = 0x0001,
    kCapPrinterType = 0x0002,
    kCapPortType = 0x0003,
    kCapDriveType = 0x0004,
    kCapSmartcardType = 0x0005,
};

// CAPABILITY_HEADER.Version ([MS-RDPEFS] 2.2.1.2).
enum RdpdrCapabilityVersion : uint32_t {
    kGeneralCapabilityVersion01 = 0x00000001,
    kGeneralCapabilityVersion02 = 0x00000002,
    kDriveCapabilityVersion01 = 0x00000001,
    kDriveCapabilityVersion02 = 0x00000002,
};

// GENERAL_CAPS_SET.ioCode1 ([MS-RDPEFS] 2.2.2.7.1).
enum RdpdrIoCode : uint32_t {
    kRdpdrIrpMjCreate = 0x00000001,
    kRdpdrIrpMjCleanup = 0x00000002,
    kRdpdrIrpMjClose = 0x00000004,
    kRdpdrIrpMjRead = 0x00000008,
    kRdpdrIrpMjWrite = 0x00000010,
    kRdpdrIrpMjFlushBuffers = 0x00000020,
    kRdpdrIrpMjShutdown = 0x00000040,
    kRdpdrIrpMjDeviceControl = 0x00000080,
    kRdpdrIrpMjQueryVolumeInformation = 0x00000100,
    kRdpdrIrpMjSetVolumeInformation = 0x00000200,
    kRdpdrIrpMjQueryInformation = 0x00000400,
    kRdpdrIrpMjSetInformation = 0x00000800,
    kRdpdrIrpMjDirectoryControl = 0x00001000,
    kRdpdrIrpMjLockControl = 0x00002000,
};

// GENERAL_CAPS_SET.extendedPDU ([MS-RDPEFS] 2.2.2.7.1).
enum RdpdrExtendedPdu : uint32_t {
    kRdpdrDeviceRemovePdus = 0x00000001,
    kRdpdrClientDisplayNamePdu = 0x00000002,
    kRdpdrUserLoggedonPdu = 0x00000004,
};

// GENERAL_CAPS_SET.extraFlags1 ([MS-RDPEFS] 2.2.2.7.1).
enum RdpdrExtraFlags1 : uint32_t {
    kEnableAsyncio = 0x00000001,
};

// DR_CREATE_REQ.Information / DR_CREATE_RSP.Information ([MS-RDPEFS] 2.2.1.5.1).
enum RdpdrInformation : uint8_t {
    kFileSuperseded = 0x00,
    kFileOpened = 0x01,
    kFileOverwritten = 0x03,
};

// RDPDR_HEADER ([MS-RDPEFS] 2.2.1.1), 4 bytes.
struct RdpdrHeader {
    static constexpr size_t kSize = 4;

    uint16_t component = 0;
    uint16_t packet_id = 0;

    static Status parse(const uint8_t* data, size_t size, RdpdrHeader& out);
    void write(ByteWriter& w) const;
};

// DR_CORE_SERVER_ANNOUNCE_REQ ([MS-RDPEFS] 2.2.2.2), 12 bytes total.
struct RdpdrServerAnnounce {
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    uint32_t client_id = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpdrServerAnnounce& out);
    std::vector<uint8_t> encode() const;
};

// DR_CORE_CLIENT_ANNOUNCE_RSP ([MS-RDPEFS] 2.2.2.3), 12 bytes total. The body
// layout is identical to the server announce request.
struct RdpdrClientAnnounceReply {
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    uint32_t client_id = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpdrClientAnnounceReply& out);
    std::vector<uint8_t> encode() const;
};

// DR_CORE_SERVER_CLIENTID_CONFIRM ([MS-RDPEFS] 2.2.2.6), 12 bytes total. The
// body mirrors the client announce reply: VersionMajor(2) + VersionMinor(2) +
// ClientId(4). (An earlier 8-byte form with only ClientId was off-spec: real
// clients parse the version fields here and a shorter packet fails their
// length check, taking the rdpdr channel down.)
struct RdpdrServerClientIdConfirm {
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    uint32_t client_id = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpdrServerClientIdConfirm& out);
    std::vector<uint8_t> encode() const;
};

// DR_CORE_CLIENT_NAME_REQ ([MS-RDPEFS] 2.2.2.4).
struct RdpdrClientNameRequest {
    uint32_t unicode_flag = 1;
    uint32_t code_page = 0;
    uint32_t computer_name_len = 0;
    std::vector<uint8_t> computer_name;  // UTF-16LE including null terminator

    static Status parse(const std::vector<uint8_t>& data,
                        RdpdrClientNameRequest& out);
    std::vector<uint8_t> encode() const;
};

// CAPABILITY_HEADER ([MS-RDPEFS] 2.2.1.2), 8 bytes.
struct RdpdrCapabilityHeader {
    static constexpr size_t kSize = 8;

    uint16_t capability_type = 0;
    uint16_t capability_length = 0;
    uint32_t version = 0;

    static Status parse(const uint8_t* data, size_t size,
                        RdpdrCapabilityHeader& out);
    void write(ByteWriter& w) const;
};

// CAPABILITY_SET ([MS-RDPEFS] 2.2.1.2.1): header + type-specific data.
struct RdpdrCapabilitySet {
    RdpdrCapabilityHeader header;
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, RdpdrCapabilitySet& out);
    std::vector<uint8_t> encode() const;
};

// GENERAL_CAPS_SET ([MS-RDPEFS] 2.2.2.7.1). The SpecialTypeDeviceCap field is
// present only in version 2.
struct RdpdrGeneralCapsSet {
    static constexpr size_t kVersion01Size = 32;
    static constexpr size_t kVersion02Size = 36;

    uint32_t os_type = 0;
    uint32_t os_version = 0;
    uint16_t protocol_major_version = 1;
    uint16_t protocol_minor_version = 0;
    uint32_t io_code1 = 0;
    uint32_t io_code2 = 0;
    uint32_t extended_pdu = 0;
    uint32_t extra_flags1 = 0;
    uint32_t extra_flags2 = 0;
    uint32_t special_type_device_cap = 0;

    static Status parse(const std::vector<uint8_t>& data, uint32_t version,
                        RdpdrGeneralCapsSet& out);
    std::vector<uint8_t> encode(uint32_t version) const;
};

// DRIVE_CAPS_SET ([MS-RDPEFS] 2.2.2.7.3). The capability set has no body.
struct RdpdrDriveCapsSet {
    static Status parse(const std::vector<uint8_t>& data, RdpdrDriveCapsSet& out);
    std::vector<uint8_t> encode() const;
};

// DR_CORE_CAPABILITY_REQ / DR_CORE_CAPABILITY_RSP ([MS-RDPEFS] 2.2.2.7/2.2.2.8).
struct RdpdrCoreCapability {
    static constexpr size_t kFixedSize = 8;

    uint16_t num_capabilities = 0;
    uint16_t padding = 0;
    std::vector<RdpdrCapabilitySet> capabilities;

    static Status parse(const std::vector<uint8_t>& data, RdpdrCoreCapability& out);
    std::vector<uint8_t> encode() const;
};

// DEVICE_ANNOUNCE ([MS-RDPEFS] 2.2.1.3). The DeviceDataLength and DeviceData
// fields are present for every device type (a server that skips them for
// non-filesystem devices desynchronises the enclosing device list).
struct RdpdrDeviceAnnounce {
    static constexpr size_t kFixedSize = 20;
    static constexpr size_t kDosNameSize = 8;

    uint32_t device_type = 0;
    uint32_t device_id = 0;
    std::array<uint8_t, kDosNameSize> preferred_dos_name{};
    uint32_t device_data_length = 0;
    std::vector<uint8_t> device_data;

    static Status parse(const uint8_t* data, size_t size, RdpdrDeviceAnnounce& out);
    std::vector<uint8_t> encode() const;

    // The DOS name up to the first NUL (e.g. "C:").
    std::string dos_name() const;
};

// DR_CORE_DEVICELIST_ANNOUNCE_REQ ([MS-RDPEFS] 2.2.2.9).
struct RdpdrDeviceListAnnounce {
    uint32_t device_count = 0;
    std::vector<RdpdrDeviceAnnounce> devices;

    static Status parse(const std::vector<uint8_t>& data,
                        RdpdrDeviceListAnnounce& out);
    std::vector<uint8_t> encode() const;
};

// DR_CORE_DEVICE_ANNOUNCE_RSP ([MS-RDPEFS] 2.2.2.1).
struct RdpdrDeviceReply {
    uint32_t device_id = 0;
    uint32_t result_code = 0;

    static Status parse(const std::vector<uint8_t>& data, RdpdrDeviceReply& out);
    std::vector<uint8_t> encode() const;
};

// DR_DEVICE_IOREQUEST ([MS-RDPEFS] 2.2.1.4).
struct RdpdrDeviceIoRequest {
    static constexpr size_t kFixedSize = 20;

    uint32_t device_id = 0;
    uint32_t file_id = 0;
    uint32_t completion_id = 0;
    uint32_t major_function = 0;
    uint32_t minor_function = 0;

    static Status parse(const std::vector<uint8_t>& data, RdpdrDeviceIoRequest& out);
    std::vector<uint8_t> encode() const;
};

// DR_DEVICE_IOCOMPLETION ([MS-RDPEFS] 2.2.1.5).
struct RdpdrDeviceIoCompletion {
    uint32_t device_id = 0;
    uint32_t completion_id = 0;
    uint32_t io_status = 0;

    static Status parse(const std::vector<uint8_t>& data,
                        RdpdrDeviceIoCompletion& out);
    std::vector<uint8_t> encode() const;
};

// DR_CREATE_REQ ([MS-RDPEFS] 2.2.1.4.1).
struct RdpdrCreateReq {
    RdpdrDeviceIoRequest request;
    uint32_t desired_access = 0;
    uint64_t allocation_size = 0;
    uint32_t file_attributes = 0;
    uint32_t shared_access = 0;
    uint32_t create_disposition = 0;
    uint32_t create_options = 0;
    uint32_t path_length = 0;
    std::vector<uint8_t> path;  // UTF-16LE including null terminator

    static Status parse(const std::vector<uint8_t>& data, RdpdrCreateReq& out);
    std::string path_string() const;
};

// DR_CREATE_RSP ([MS-RDPEFS] 2.2.1.5.1).
struct RdpdrCreateRsp {
    RdpdrDeviceIoCompletion completion;
    uint32_t file_id = 0;
    uint8_t information = 0;

    std::vector<uint8_t> encode() const;
};

// DR_READ_REQ ([MS-RDPEFS] 2.2.1.4.3).
struct RdpdrReadReq {
    RdpdrDeviceIoRequest request;
    uint32_t length = 0;
    uint64_t offset = 0;

    static Status parse(const std::vector<uint8_t>& data, RdpdrReadReq& out);
};

// DR_READ_RSP ([MS-RDPEFS] 2.2.1.5.3).
struct RdpdrReadRsp {
    RdpdrDeviceIoCompletion completion;
    uint32_t length = 0;
    std::vector<uint8_t> data;

    std::vector<uint8_t> encode() const;
};

// DR_WRITE_REQ ([MS-RDPEFS] 2.2.1.4.4).
struct RdpdrWriteReq {
    RdpdrDeviceIoRequest request;
    uint32_t length = 0;
    uint64_t offset = 0;
    std::vector<uint8_t> data;

    static Status parse(const std::vector<uint8_t>& data, RdpdrWriteReq& out);
};

// DR_WRITE_RSP ([MS-RDPEFS] 2.2.1.5.4).
struct RdpdrWriteRsp {
    RdpdrDeviceIoCompletion completion;
    uint32_t length = 0;

    std::vector<uint8_t> encode() const;
};

// DR_CLOSE_REQ ([MS-RDPEFS] 2.2.1.4.2).
struct RdpdrCloseReq {
    RdpdrDeviceIoRequest request;

    static Status parse(const std::vector<uint8_t>& data, RdpdrCloseReq& out);
};

// DR_CLOSE_RSP ([MS-RDPEFS] 2.2.1.5.2).
struct RdpdrCloseRsp {
    RdpdrDeviceIoCompletion completion;

    std::vector<uint8_t> encode() const;
};

// DR_DRIVE_QUERY_DIRECTORY_REQ ([MS-RDPEFS] 2.2.3.3.4). The MajorFunction is
// IRP_MJ_DIRECTORY_CONTROL and the MinorFunction is IRP_MN_QUERY_DIRECTORY.
struct RdpdrQueryDirectoryReq {
    RdpdrDeviceIoRequest request;
    uint32_t fs_information_class = 0;
    uint8_t initial_query = 0;
    uint32_t path_length = 0;
    std::vector<uint8_t> path;  // UTF-16LE including null terminator

    static Status parse(const std::vector<uint8_t>& data,
                        RdpdrQueryDirectoryReq& out);
    std::string path_string() const;
};

// DR_CONTROL_REQ ([MS-RDPEFS] 2.2.1.4.5).
struct RdpdrControlReq {
    RdpdrDeviceIoRequest request;
    uint32_t output_buffer_length = 0;
    uint32_t input_buffer_length = 0;
    uint32_t io_control_code = 0;
    std::vector<uint8_t> input_buffer;

    static Status parse(const std::vector<uint8_t>& data, RdpdrControlReq& out);
};

// A parsed rdpdr PDU: header + the bytes that follow (packet-specific).
struct RdpdrPdu {
    RdpdrHeader header;
    std::vector<uint8_t> data;

    static Status parse(const uint8_t* data, size_t size, RdpdrPdu& out);
};

// Builds a complete rdpdr PDU (header + payload) for a client-sent message.
std::vector<uint8_t> BuildRdpdrPdu(uint16_t packet_id,
                                   const std::vector<uint8_t>& body);

// Decodes a NUL-terminated UTF-16LE field into UTF-8. Used for the client name
// and the redirect paths.
std::string RdpdrDecodeUtf16(const uint8_t* data, size_t size);

// Encodes a UTF-8 string as NUL-terminated UTF-16LE.
std::vector<uint8_t> RdpdrEncodeUtf16(const std::string& text);

}  // namespace rtsc::proto
