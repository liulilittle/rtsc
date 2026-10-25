#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace rtsc::test {

struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

inline int& failure_count() {
    static int n = 0;
    return n;
}

inline int& check_count() {
    static int n = 0;
    return n;
}

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

inline void report_failure(const char* file, int line, const std::string& msg) {
    ++failure_count();
    std::printf("  FAIL %s:%d  %s\n", file, line, msg.c_str());
}

}  // namespace rtsc::test

#define RTSC_TEST(name)                                             \
    static void name();                                             \
    static ::rtsc::test::Registrar rtsc_reg_##name(#name, &name);   \
    static void name()

#define CHECK(cond)                                                        \
    do {                                                                   \
        ++::rtsc::test::check_count();                                     \
        if (!(cond)) {                                                     \
            ::rtsc::test::report_failure(__FILE__, __LINE__, #cond);       \
        }                                                                  \
    } while (0)

#define CHECK_EQ(actual, expected)                                                  \
    do {                                                                            \
        ++::rtsc::test::check_count();                                              \
        const auto a_ = (actual);                                                   \
        const auto e_ = (expected);                                                 \
        if (!(a_ == e_)) {                                                          \
            ::rtsc::test::report_failure(__FILE__, __LINE__,                        \
                                         std::string(#actual " == " #expected) +    \
                                             " (got " + std::to_string(a_) +        \
                                             ", want " + std::to_string(e_) + ")"); \
        }                                                                           \
    } while (0)

#define CHECK_BYTES(actual, ...)                                                          \
    do {                                                                                  \
        ++::rtsc::test::check_count();                                                    \
        const std::vector<uint8_t> want_{__VA_ARGS__};                                     \
        const auto& got_src_ = (actual);                                                   \
        const std::vector<uint8_t> got_(got_src_.begin(), got_src_.end());                 \
        if (want_ != got_) {                                                              \
            std::string want_hex, got_hex;                                                \
            for (auto b : want_) { char wb[8]; std::snprintf(wb, 8, "%02X ", b); want_hex += wb; } \
            for (auto b : got_) { char gb[8]; std::snprintf(gb, 8, "%02X ", b); got_hex += gb; }  \
            ::rtsc::test::report_failure(__FILE__, __LINE__,                              \
                                         std::string(#actual " bytes\n    want: ") + want_hex + \
                                             "\n    got:  " + got_hex);                   \
        }                                                                                 \
    } while (0)
