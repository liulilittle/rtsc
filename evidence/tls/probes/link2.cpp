#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <cstdio>
int main(){ SecPkgContext_ConnectionInfoEx e{}; (void)e; printf("ok %d\n", (int)sizeof(e)); return 0; }
