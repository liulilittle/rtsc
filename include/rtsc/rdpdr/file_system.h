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
};

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

 private:
  struct File {
    std::fstream stream;
    bool is_directory = false;
    std::string directory;
    std::vector<std::string> entries;
    size_t next_entry = 0;
  };

  File* Find(uint32_t file_id);
  void BuildDirectoryEntries(File& file, const std::string& local_path);

  std::map<uint32_t, std::unique_ptr<File>> files_;
  uint32_t next_id_ = 1;
};

}  // namespace rtsc::rdpdr
