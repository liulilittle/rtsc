// Local file system bridge for RDPDR drive redirection ([MS-RDPEFS] 3.1).
//
// The handler translates a remote path (\\tsclient\<drive>\...) into a local
// path and then performs the requested operation through this interface. The
// default implementation (HostFileSystem) uses the host file system via
// std::filesystem; tests inject a fake so the protocol can be exercised without
// touching disk.

#pragma once

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace rtsc::rdpdr {

// Upper bound for one DR_READ_REQ ([MS-RDPEFS] 2.2.1.4.3). The length field
// is 32 bit and fully server controlled, so it must be bounded before it is
// turned into a buffer. The Windows redirector serves reads through the cache
// manager, which issues 4 KiB..64 KiB reads (64 KiB is also the SMB2 read
// granularity); 1 MiB keeps a 16x margin over that while capping the
// per-request allocation instead of trusting a possible 4 GiB.
inline constexpr uint32_t kMaxReadLength = 1u << 20;

class IFileSystem {
 public:
  virtual ~IFileSystem() = default;

  // Opens (or creates) the file at `local_path`. `for_write` selects the
  // access mode, `create` creates the file when it does not exist and
  // `truncate` discards any existing content ([MS-SMB2] FILE_SUPERSEDE /
  // FILE_OVERWRITE / FILE_OVERWRITE_IF). Returns a non-zero file id on
  // success, or false when the path cannot be opened.
  virtual bool Open(const std::string& local_path, bool for_write, bool create,
                    bool truncate, uint32_t& file_id) = 0;

  // Reads at most `length` bytes at `offset`. Returns false on failure.
  virtual bool Read(uint32_t file_id, uint64_t offset, uint32_t length,
                    std::vector<uint8_t>& out) = 0;

  // Writes `data` at `offset` (or appends when `offset` is
  // 0xFFFFFFFFFFFFFFFF). Returns the number of bytes written.
  virtual bool Write(uint32_t file_id, uint64_t offset,
                     const std::vector<uint8_t>& data, uint32_t& written) = 0;

  virtual bool Close(uint32_t file_id) = 0;

  // Enumerates one directory entry. `initial` starts a new enumeration;
  // subsequent calls return the next entry. `fs_information_class` selects the
  // [MS-FSCC] 2.4 record layout of the returned bytes. Returns false when the
  // enumeration is exhausted or the file is not a directory.
  virtual bool QueryDirectory(uint32_t file_id, bool initial,
                              uint32_t fs_information_class,
                              std::vector<uint8_t>& out) = 0;

  // Reports whether `local_path` exists and whether it is a directory.
  virtual bool Stat(const std::string& local_path, bool& is_directory) = 0;

  // Returns the [MS-FSCC] 2.5 volume information structure for
  // `fs_information_class` on the volume that contains the open handle.
  // Returns false for an unknown handle or an unsupported class.
  virtual bool QueryVolume(uint32_t file_id, uint32_t fs_information_class,
                           std::vector<uint8_t>& out) = 0;

  // Returns the [MS-FSCC] 2.4 file information structure for
  // `fs_information_class` on the open handle. Returns false for an unknown
  // handle or an unsupported class.
  virtual bool QueryInformation(uint32_t file_id, uint32_t fs_information_class,
                                std::vector<uint8_t>& out) = 0;

  // Sets the volume label of the volume that contains the open handle.
  virtual bool SetVolumeName(uint32_t file_id, const std::string& label) = 0;

  // Renames `local_path` to `new_path`. When `replace` is false an existing
  // target is a collision and the call fails.
  virtual bool Rename(const std::string& local_path,
                      const std::string& new_path, bool replace) = 0;

  // Deletes `local_path`. Returns false when it does not exist or the
  // deletion fails.
  virtual bool Delete(const std::string& local_path) = 0;
};

// Volume information used to answer IRP_MJ_QUERY_VOLUME_INFORMATION.
// `label` and `file_system_name` are UTF-16 code units.
struct VolumeInfo {
    uint64_t creation_time = 0;   // 100 ns since 1601-01-01; 0 is allowed
    uint32_t serial = 0;
    std::u16string label;
    bool supports_objects = false;
    uint32_t file_system_attributes = 0;
    uint32_t max_component_length = 0;
    std::u16string file_system_name;
    uint32_t device_type = 0x00000007;  // FILE_DEVICE_DISK
    uint32_t characteristics = 0x00000020;  // FILE_DEVICE_IS_MOUNTED
};

// Encodes the [MS-FSCC] 2.5 structure for `fs_information_class`:
//   0x01 FileFsVolumeInformation (no Reserved byte per [MS-RDPEFS] 2.2.3.3.6)
//   0x04 FileFsDeviceInformation
//   0x05 FileFsAttributeInformation
// Returns false for any other class.
bool EncodeVolumeInfo(uint32_t fs_information_class, const VolumeInfo& info,
                      std::vector<uint8_t>& out);

// File information used to answer IRP_MJ_QUERY_INFORMATION. Times are 100 ns
// intervals since 1601-01-01.
struct FileInfo {
    uint64_t creation_time = 0;
    uint64_t last_access_time = 0;
    uint64_t last_write_time = 0;
    uint64_t change_time = 0;
    uint32_t attributes = 0;
    uint64_t allocation_size = 0;
    uint64_t end_of_file = 0;
    uint32_t number_of_links = 1;
    bool delete_pending = false;
    bool is_directory = false;
    uint32_t reparse_tag = 0;
};

// Encodes the [MS-FSCC] 2.4 structure for `fs_information_class`:
//   0x04 FileBasicInformation (Reserved field omitted per [MS-RDPEFS]
//        2.2.3.3.8)
//   0x05 FileStandardInformation (Reserved field omitted per [MS-RDPEFS]
//        2.2.3.3.8)
//   0x23 FileAttributeTagInformation
// Returns false for any other class.
bool EncodeFileInformation(uint32_t fs_information_class, const FileInfo& info,
                           std::vector<uint8_t>& out);

// The host file system. Uses std::fstream for file I/O and std::filesystem for
// directory enumeration.
class HostFileSystem final : public IFileSystem {
 public:
  HostFileSystem();
  ~HostFileSystem() override;

  HostFileSystem(const HostFileSystem&) = delete;
  HostFileSystem& operator=(const HostFileSystem&) = delete;

  bool Open(const std::string& local_path, bool for_write, bool create,
            bool truncate, uint32_t& file_id) override;
  bool Read(uint32_t file_id, uint64_t offset, uint32_t length,
            std::vector<uint8_t>& out) override;
  bool Write(uint32_t file_id, uint64_t offset,
             const std::vector<uint8_t>& data, uint32_t& written) override;
  bool Close(uint32_t file_id) override;
  bool QueryDirectory(uint32_t file_id, bool initial,
                      uint32_t fs_information_class,
                      std::vector<uint8_t>& out) override;
  bool Stat(const std::string& local_path, bool& is_directory) override;
  bool QueryVolume(uint32_t file_id, uint32_t fs_information_class,
                   std::vector<uint8_t>& out) override;
  bool QueryInformation(uint32_t file_id, uint32_t fs_information_class,
                        std::vector<uint8_t>& out) override;
  bool SetVolumeName(uint32_t file_id, const std::string& label) override;
  bool Rename(const std::string& local_path, const std::string& new_path,
              bool replace) override;
  bool Delete(const std::string& local_path) override;

 private:
  struct File {
    std::fstream stream;
    bool is_directory = false;
    std::string directory;
    std::string local_path;
    std::vector<std::string> entries;
    size_t next_entry = 0;
  };

  File* Find(uint32_t file_id);
  void BuildDirectoryEntries(File& file, const std::string& local_path);
  uint32_t AllocateId();

  std::map<uint32_t, std::unique_ptr<File>> files_;
  // Free file ids, reused per [MS-RDPEFS] 2.2.1.5.1 before growing next_id_.
  std::vector<uint32_t> free_ids_;
  uint32_t next_id_ = 1;
};

}  // namespace rtsc::rdpdr
