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
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace rtsc::rdpdr {

class IFileSystem {
 public:
  virtual ~IFileSystem() = default;

  // Opens (or creates) the file at `local_path`. Returns a non-zero file id on
  // success, or false when the path cannot be opened.
  virtual bool Open(const std::string& local_path, bool for_write, bool create,
                    uint32_t& file_id) = 0;

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
            uint32_t& file_id) override;
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
    std::vector<std::string> entries;
    size_t next_entry = 0;
  };

  File* Find(uint32_t file_id);
  void BuildDirectoryEntries(File& file, const std::string& local_path);

  std::map<uint32_t, std::unique_ptr<File>> files_;
  uint32_t next_id_ = 1;
};

}  // namespace rtsc::rdpdr
