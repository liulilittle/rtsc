// Shared path containment guard for RDPDR drive redirection ([MS-RDPEFS] 3.1).
//
// Resolves the part of a remote path that follows the redirected drive root
// into a local path that stays inside the configured root. Hosted here
// (header-only) so every redirected-side handler -- the client answering
// DR_DEVICE_IOREQUEST against a local directory and, on the route-A async I/O
// engine, any future consumer -- uses the same containment rules.
//
// Rejects parent traversal (".."), absolute paths, drive letters, UNC / device
// prefixes, reserved device names (CON, NUL, ...) and components Windows would
// rewrite (trailing dot or space). Leading separators are ignored; '.' parts
// are dropped. A missing root deliberately fails closed (the guard never
// fabricates a lexical path underneath a root the host does not know).

#pragma once

#include <cctype>
#include <filesystem>
#include <string>
#include <vector>

namespace rtsc::rdpdr {

inline bool IsPathSeparator(char c) { return c == '\\' || c == '/'; }

// Windows reserves the CON/PRN/AUX/NUL/COM1-9/LPT1-9 device names, with or
// without an extension ("CON.txt" still names the console device).
inline bool IsReservedDeviceName(const std::string& component) {
    std::string base = component.substr(0, component.find('.'));
    while (!base.empty() && (base.back() == '.' || base.back() == ' ')) {
        base.pop_back();
    }
    for (char& c : base) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
        base == "CONIN$" || base == "CONOUT$") {
        return true;
    }
    if (base.size() == 4 && base[0] == 'C' && base[1] == 'O' && base[2] == 'M' &&
        base[3] >= '1' && base[3] <= '9') {
        return true;
    }
    if (base.size() == 4 && base[0] == 'L' && base[1] == 'P' && base[2] == 'T' &&
        base[3] >= '1' && base[3] <= '9') {
        return true;
    }
    return false;
}

// A single path component that must not reach the host file system: parent
// traversal, a name Windows would rewrite (trailing dot or space), a
// character Windows forbids in a file name, or a reserved device name.
inline bool IsForbiddenComponent(const std::string& component) {
    if (component == ".") return false;
    if (component == "..") return true;
    const char last = component.back();
    if (last == '.' || last == ' ') return true;
    for (const char c : component) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7F) return true;
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' ||
            c == '>' || c == '|') {
            return true;
        }
    }
    return IsReservedDeviceName(component);
}

// Case-insensitive check that `candidate` is `root` or lies below it.
inline bool IsUnderRoot(const std::string& root, const std::string& candidate) {
    if (root.empty()) return false;
    std::string prefix = root;
    if (!IsPathSeparator(prefix.back())) prefix.push_back('\\');
    if (candidate.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (IsPathSeparator(prefix[i]) && IsPathSeparator(candidate[i])) {
            continue;
        }
        const unsigned char a = static_cast<unsigned char>(prefix[i]);
        const unsigned char b = static_cast<unsigned char>(candidate[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

// Resolves the part of a server-supplied path that follows the redirected
// drive root (`remote_relative`) into a local path that stays inside `root`.
// Leading separators are ignored; '.' components are dropped. Returns false
// when the path is rejected. When `remote_relative` is empty (the drive root
// itself) the normalized root is returned.
inline bool ResolvePathUnderRoot(const std::string& root,
                                 const std::string& remote_relative,
                                 std::string& out) {
    if (root.empty()) return false;

    // UNC ("\\server\share") and Win32 device ("\\.\", "\\?\") prefixes leave
    // the drive entirely; the redirector path is always rooted below the
    // drive, so more than one leading separator is rejected.
    size_t start = 0;
    while (start < remote_relative.size() &&
           IsPathSeparator(remote_relative[start])) {
        ++start;
    }
    if (start >= 2) return false;

    std::vector<std::string> parts;
    std::string current;
    for (size_t i = start; i <= remote_relative.size(); ++i) {
        const char c = i < remote_relative.size() ? remote_relative[i] : '\\';
        if (!IsPathSeparator(c)) {
            current.push_back(c);
            continue;
        }
        if (!current.empty()) {
            if (IsForbiddenComponent(current)) return false;
            if (current != ".") parts.push_back(current);
            current.clear();
        }
    }

    std::filesystem::path base(root);
    if (base.has_root_name() && !base.has_root_directory()) base += "\\";
    base = base.lexically_normal();
    if (parts.empty()) {
        // The redirected drive root itself (IRP_MJ_CREATE / QUERY_DIRECTORY on
        // "\\tsclient\C") must be accepted and normalized regardless of a
        // trailing separator or a trailing separator on the configured root.
        std::string root_text = base.string();
        while (root_text.size() > 3 && IsPathSeparator(root_text.back())) {
            root_text.pop_back();
        }
        out = root_text;
        return true;
    }
    std::filesystem::path resolved = base;
    for (const auto& part : parts) resolved /= part;
    std::string result = resolved.string();
    if (!IsUnderRoot(base.string(), result)) return false;

    // Lexical normalization cannot see reparse points (junctions/symlinks), so
    // resolve the real path and re-check containment. A missing suffix is
    // canonicalized through its deepest existing ancestor.
    std::error_code ec;
    const std::filesystem::path canonical =
        std::filesystem::weakly_canonical(resolved, ec);
    if (!ec) {
        const std::string canonical_text = canonical.string();
        if (!IsUnderRoot(std::filesystem::weakly_canonical(base, ec).string(),
                         canonical_text)) {
            return false;
        }
        result = canonical_text;
    } else {
        // The drive root itself must still resolve; if even that fails the
        // host cannot answer for the path.
        ec.clear();
        const std::filesystem::path canonical_base =
            std::filesystem::canonical(base, ec);
        if (!ec && !IsUnderRoot(canonical_base.string(), result)) return false;
    }
    out = result;
    return true;
}

}  // namespace rtsc::rdpdr