// Probe: hostname matching edges that RFC 6125 requires us to reject.
#include <cstdio>

#include "rtsc/net/tls.h"

using rtsc::tls::DnsNameMatchesForTest;

static int failures = 0;
static void check(const char* what, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

int main() {
    // Baselines that must keep working.
    check("example.com == EXAMPLE.COM", DnsNameMatchesForTest("example.com", "EXAMPLE.COM"));
    check("*.example.com matches a.example.com",
          DnsNameMatchesForTest("*.example.com", "a.example.com"));
    check("*.example.com rejects a.b.example.com",
          !DnsNameMatchesForTest("*.example.com", "a.b.example.com"));
    check("*.example.com rejects example.com",
          !DnsNameMatchesForTest("*.example.com", "example.com"));

    // RFC 6125 6.4.3: the wildcard must not be the entire left-most label of a
    // public suffix. "*.com" would otherwise match every host under .com.
    check("*.com must be rejected (public suffix wildcard)",
          !DnsNameMatchesForTest("*.com", "x.com"));
    check("*.co.uk must be rejected (two-label public suffix)",
          !DnsNameMatchesForTest("*.co.uk", "x.co.uk"));

    // A trailing dot is the same name (FQDN form); matching it is a false
    // negative today, not a security hole, but it should behave.
    check("example.com. matches example.com",
          DnsNameMatchesForTest("example.com", "example.com."));
    check("example.com matches example.com.",
          DnsNameMatchesForTest("example.com.", "example.com"));

    // IDN: a certificate issued for the A-label must match the A-label user
    // input; the U-label form is a separate (documented) limitation.
    check("xn--bcher-kva.example matches itself",
          DnsNameMatchesForTest("xn--bcher-kva.example", "xn--bcher-kva.example"));

    std::printf("\nSUMMARY failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
