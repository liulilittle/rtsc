#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winternl.h>
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <cstdio>
#include <vector>
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ncrypt.lib")

struct C { CredHandle cred{}; CtxtHandle ctx{}; bool have=false; SecPkgContext_StreamSizes sz{}; };
static PCCERT_CONTEXT Mk(){ CERT_NAME_BLOB s{}; char n[]="CN=p"; CertStrToNameA(X509_ASN_ENCODING,n,CERT_X500_NAME_STR,nullptr,nullptr,&s.cbData,nullptr); std::vector<BYTE> b(s.cbData); s.pbData=b.data(); CertStrToNameA(X509_ASN_ENCODING,n,CERT_X500_NAME_STR,nullptr,s.pbData,&s.cbData,nullptr); return CertCreateSelfSignCertificate(0,&s,0,nullptr,nullptr,nullptr,nullptr,nullptr); }
static bool HS(C& c, C& s){
  TimeStamp ts{}; TLS_PARAMETERS tp{}; tp.grbitDisabledProtocols=SP_PROT_TLS1_2_CLIENT;
  SCH_CREDENTIALS sc{}; sc.dwVersion=SCH_CREDENTIALS_VERSION; sc.dwFlags=SCH_CRED_NO_SERVERNAME_CHECK|SCH_CRED_MANUAL_CRED_VALIDATION|SCH_CRED_NO_DEFAULT_CREDS; sc.cTlsParameters=1; sc.pTlsParameters=&tp;
  if(AcquireCredentialsHandleW(nullptr,(SEC_WCHAR*)UNISP_NAME_W,SECPKG_CRED_OUTBOUND,nullptr,&sc,nullptr,nullptr,&c.cred,&ts)!=0) return false;
  PCCERT_CONTEXT cert=Mk(); SCH_CREDENTIALS ss{}; ss.dwVersion=SCH_CREDENTIALS_VERSION; ss.cCreds=1; ss.paCred=&cert; ss.cTlsParameters=1; ss.pTlsParameters=&tp;
  if(AcquireCredentialsHandleW(nullptr,(SEC_WCHAR*)UNISP_NAME_W,SECPKG_CRED_INBOUND,nullptr,&ss,nullptr,nullptr,&s.cred,&ts)!=0) return false;
  std::vector<BYTE> t; SECURITY_STATUS a=SEC_I_CONTINUE_NEEDED,b=SEC_I_CONTINUE_NEEDED;
  for(int i=0;i<12;i++){
    SecBuffer ob{0,SECBUFFER_TOKEN,nullptr}; SecBufferDesc od{SECBUFFER_VERSION,1,&ob};
    SecBuffer ib{}; SecBufferDesc id{SECBUFFER_VERSION,0,nullptr};
    if(!t.empty()){ ib={(unsigned long)t.size(),SECBUFFER_TOKEN,t.data()}; id.cBuffers=1; id.pBuffers=&ib; }
    DWORD at=0;
    a=InitializeSecurityContextW(&c.cred,c.have?&c.ctx:nullptr,(SEC_WCHAR*)L"p",ISC_REQ_SEQUENCE_DETECT|ISC_REQ_REPLAY_DETECT|ISC_REQ_CONFIDENTIALITY|ISC_REQ_EXTENDED_ERROR|ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_STREAM|ISC_REQ_MANUAL_CRED_VALIDATION,0,SECURITY_NATIVE_DREP,t.empty()?nullptr:&id,0,&c.ctx,&od,&at,nullptr);
    c.have=true; t.clear(); if(ob.pvBuffer){ t.assign((BYTE*)ob.pvBuffer,(BYTE*)ob.pvBuffer+ob.cbBuffer); FreeContextBuffer(ob.pvBuffer);} 
    if(a!=SEC_I_CONTINUE_NEEDED&&a!=SEC_E_OK) return false; if(t.empty()&&a==SEC_E_OK) break;
    SecBuffer ob2{0,SECBUFFER_TOKEN,nullptr}; SecBufferDesc od2{SECBUFFER_VERSION,1,&ob2};
    SecBuffer ib2={(unsigned long)t.size(),SECBUFFER_TOKEN,t.data()}; SecBufferDesc id2{SECBUFFER_VERSION,1,&ib2}; DWORD at2=0;
    b=AcceptSecurityContext(&s.cred,s.have?&s.ctx:nullptr,&id2,ASC_REQ_SEQUENCE_DETECT|ASC_REQ_REPLAY_DETECT|ASC_REQ_CONFIDENTIALITY|ASC_REQ_EXTENDED_ERROR|ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_STREAM,SECURITY_NATIVE_DREP,&s.ctx,&od2,&at2,nullptr);
    s.have=true; t.clear(); if(ob2.pvBuffer){ t.assign((BYTE*)ob2.pvBuffer,(BYTE*)ob2.pvBuffer+ob2.cbBuffer); FreeContextBuffer(ob2.pvBuffer);} 
    if(b!=SEC_I_CONTINUE_NEEDED&&b!=SEC_E_OK) return false; if(a==SEC_E_OK&&b==SEC_E_OK) break;
  }
  if(a!=SEC_E_OK||b!=SEC_E_OK) return false;
  QueryContextAttributesW(&c.ctx,SECPKG_ATTR_STREAM_SIZES,&c.sz); QueryContextAttributesW(&s.ctx,SECPKG_ATTR_STREAM_SIZES,&s.sz); return true;
}
static void T(const char* label, DWORD req, bool nullInput){
  C c,s; if(!HS(c,s)){ printf("  hs fail\n"); return; }
  DWORD ctl=SCHANNEL_SHUTDOWN; SecBuffer cb{sizeof(ctl),SECBUFFER_TOKEN,&ctl}; SecBufferDesc cbd{SECBUFFER_VERSION,1,&cb};
  ApplyControlToken(&c.ctx,&cbd);
  SecBuffer ob{0,SECBUFFER_TOKEN,nullptr}; SecBufferDesc od{SECBUFFER_VERSION,1,&ob}; DWORD at=0;
  SecBuffer ib{0,SECBUFFER_EMPTY,nullptr}; SecBufferDesc id{SECBUFFER_VERSION,1,&ib};
  SECURITY_STATUS st=InitializeSecurityContextW(&c.cred,&c.ctx,(SEC_WCHAR*)L"p",req,0,SECURITY_NATIVE_DREP,nullInput?nullptr:&id,0,&c.ctx,&od,&at,nullptr);
  printf("  %-46s -> 0x%08lX out=%lu\n", label, (unsigned long)st, ob.cbBuffer);
  if(ob.pvBuffer) FreeContextBuffer(ob.pvBuffer);
}
int main(){
  printf("== close_notify: which flag matters? ==\n");
  T("ISC_REQ_STREAM only, null input", ISC_REQ_STREAM, true);
  T("ISC_REQ_STREAM only, empty desc", ISC_REQ_STREAM, false);
  T("STREAM|ALLOCATE_MEMORY, null input", ISC_REQ_STREAM|ISC_REQ_ALLOCATE_MEMORY, true);
  T("STREAM|ALLOCATE_MEMORY, empty desc", ISC_REQ_STREAM|ISC_REQ_ALLOCATE_MEMORY, false);
  return 0;
}
