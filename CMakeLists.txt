cmake_minimum_required(VERSION 3.25)

project(rtsc
    VERSION 0.1.0
    DESCRIPTION "RTSC - RDP client protocol stack (reverse-engineered from mstsc)"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /WX /permissive- /Zc:__cplusplus /utf-8)
else()
    add_compile_options(-Wall -Wextra -Werror -Wpedantic)
endif()

add_library(rtsc_proto STATIC
    src/proto/byte_order.cpp
    src/proto/ber.cpp
    src/proto/tpkt.cpp
    src/proto/x224.cpp
    src/proto/rdp_neg.cpp
    src/proto/connection_initiation.cpp
    src/proto/mcs.cpp
    src/proto/mcs_domain.cpp
    src/proto/client_info.cpp
    src/proto/connect_machine.cpp
    src/proto/framing.cpp
    src/proto/licensing.cpp
    src/proto/share.cpp
    src/proto/capabilities.cpp
    src/proto/multimon.cpp
    src/proto/finalization.cpp
    src/proto/session_setup.cpp
    src/proto/licensing_machine.cpp
    src/proto/input.cpp
    src/proto/output.cpp
    src/proto/bitmap.cpp
    src/proto/channel.cpp
    src/proto/surface.cpp
    src/proto/cliprdr.cpp
    src/proto/drdynvc.cpp
    src/proto/rdpusb.cpp
    src/proto/rdpdr.cpp
    src/proto/rdpsnd.cpp
    src/proto/rdp6.cpp
    src/proto/nsc.cpp
    src/proto/orders.cpp
    src/proto/rop.cpp
    src/proto/secondary.cpp
    src/proto/rail.cpp
    src/proto/gateway.cpp
)
target_include_directories(rtsc_proto PUBLIC include)
target_link_libraries(rtsc_proto PUBLIC rtsc_crypto)

# rdpsnd (audio output) virtual channel handler. Platform neutral: it decodes
# the [MS-RDPEA] protocol and hands PCM to an injected AudioPlayer; the server
# half captures PCM from an injected AudioCaptureSource (sine_source for the
# deterministic test / v1 path, a WASAPI loopback backend in a later phase).
add_library(rtsc_rdpsnd STATIC
    src/channel/rdpsnd_client.cpp
    src/channel/rdpsnd_server.cpp
    src/audio/sine_source.cpp)
target_include_directories(rtsc_rdpsnd PUBLIC include)
target_link_libraries(rtsc_rdpsnd PUBLIC rtsc_proto)

# cliprdr (clipboard) virtual channel handler. Platform neutral: the handler
# reads and writes the local clipboard through the rtsc::clipboard interface;
# the Win32 backend is the platform implementation (user32).
add_library(rtsc_cliprdr STATIC
    src/channel/cliprdr_client.cpp
    src/channel/cliprdr_server.cpp
    src/clipboard/clipboard.cpp
    src/clipboard/drop_files.cpp)
target_include_directories(rtsc_cliprdr PUBLIC include)
target_link_libraries(rtsc_cliprdr PUBLIC rtsc_proto)
if(WIN32)
    target_link_libraries(rtsc_cliprdr PUBLIC user32)
endif()

# RAIL (Remote Programs Virtual Channel) client handler ([MS-RDPERP]). Platform
# neutral: it runs the RAIL order protocol and reassembles the "rail" static
# virtual channel through proto::RailChannel.
add_library(rtsc_rail STATIC src/channel/rail_client.cpp)
target_include_directories(rtsc_rail PUBLIC include)
target_link_libraries(rtsc_rail PUBLIC rtsc_proto)

# rdpdr (device redirection) virtual channel handler ([MS-RDPEFS]). Platform
# neutral: it runs the drive redirection protocol and serves file I/O through
# the rdpdr::IFileSystem seam; HostFileSystem is the host implementation
# (std::fstream / std::filesystem). rdpdr_server.cpp is the server-side half:
# the channel-level minimum handshake (v1 announces no devices).
add_library(rtsc_rdpdr STATIC
    src/channel/rdpdr_client.cpp
    src/channel/rdpdr_server.cpp
    src/rdpdr/file_system.cpp
    src/rdpdr/drive_enum_win32.cpp)
target_include_directories(rtsc_rdpdr PUBLIC include)
target_link_libraries(rtsc_rdpdr PUBLIC rtsc_proto)

# waveOut audio backend (Windows only).
if(WIN32)
    add_library(rtsc_audio STATIC src/audio/audio_win32.cpp)
    target_include_directories(rtsc_audio PUBLIC include)
    target_link_libraries(rtsc_audio PUBLIC winmm)
endif()

# Crash capture (minidump + symbolized text) shared by every executable.
# The platform CSPRNG is a separate source per platform so neither file has to
# carry the other platform's system headers (scripts/linux-build-gate.sh asserts
# that windows.h never reaches the Linux build log). bcrypt is Windows-only.
add_library(rtsc_crypto STATIC src/crypto/hash.cpp src/crypto/rdp_security.cpp)
target_include_directories(rtsc_crypto PUBLIC include)
if(WIN32)
    target_sources(rtsc_crypto PRIVATE src/crypto/random_win.cpp src/crypto/rsa_win.cpp)
    target_link_libraries(rtsc_crypto PUBLIC bcrypt)
else()
    target_sources(rtsc_crypto PRIVATE src/crypto/random_posix.cpp src/crypto/rsa_posix.cpp)
endif()

add_library(rtsc_util STATIC src/util/crash_guard.cpp)
target_include_directories(rtsc_util PUBLIC include)
if(MSVC)
    target_link_libraries(rtsc_util PUBLIC dbghelp)
endif()

# TLS transport, three layers (S21 / M28).
#   rtsc_tls_api       INTERFACE, platform neutral, header only.
#   rtsc_tls_schannel  Windows only: the SChannel translation unit.
#   rtsc_tls           facade with the public CreateTlsTransport; always built,
#                      returns nullptr + reason on platforms with no backend.
add_library(rtsc_tls_api INTERFACE)
target_include_directories(rtsc_tls_api INTERFACE include)

if(WIN32)
    add_library(rtsc_tls_schannel STATIC src/net/tls_schannel.cpp)
    target_link_libraries(rtsc_tls_schannel PUBLIC rtsc_tls_api)
    target_link_libraries(rtsc_tls_schannel PUBLIC secur32 crypt32 bcrypt)
endif()

# OpenSSL backend for non-Windows platforms. Off by default (design-a D5: a
# REQUIRED find_package would break configure on hosts without OpenSSL).
option(RTSC_TLS_OPENSSL "Build the OpenSSL TLS backend (non-Windows)" OFF)
if(NOT WIN32 AND RTSC_TLS_OPENSSL)
    find_package(OpenSSL REQUIRED)
    add_library(rtsc_tls_openssl STATIC src/net/tls_openssl.cpp)
    target_link_libraries(rtsc_tls_openssl PUBLIC rtsc_tls_api)
    target_link_libraries(rtsc_tls_openssl PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(rtsc_tls_openssl PUBLIC RTSC_TLS_OPENSSL=1)
endif()

add_library(rtsc_tls STATIC src/net/tls_factory.cpp)
target_include_directories(rtsc_tls PUBLIC include)
target_link_libraries(rtsc_tls PUBLIC rtsc_tls_api)
target_include_directories(rtsc_tls PRIVATE src/net)
if(WIN32)
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_schannel)
elseif(RTSC_TLS_OPENSSL)
    target_link_libraries(rtsc_tls PUBLIC rtsc_tls_openssl)
endif()

add_executable(rtsc_tests tests/test_connection_initiation.cpp)
target_link_libraries(rtsc_tests PRIVATE rtsc_proto rtsc_util)
target_include_directories(rtsc_tests PRIVATE tests)

add_executable(rtsc_ber_tests tests/test_ber.cpp)
target_link_libraries(rtsc_ber_tests PRIVATE rtsc_proto rtsc_util)
target_include_directories(rtsc_ber_tests PRIVATE tests)

add_executable(rtsc_mcs_tests tests/test_mcs.cpp)
target_link_libraries(rtsc_mcs_tests PRIVATE rtsc_proto rtsc_util)
target_include_directories(rtsc_mcs_tests PRIVATE tests)

add_executable(rtsc_mcs_domain_tests tests/test_mcs_domain.cpp)
target_link_libraries(rtsc_mcs_domain_tests PRIVATE rtsc_proto rtsc_util)
target_include_directories(rtsc_mcs_domain_tests PRIVATE tests)

add_executable(rtsc_client_info_tests tests/test_client_info.cpp)
target_link_libraries(rtsc_client_info_tests PRIVATE rtsc_proto rtsc_util)
target_include_directories(rtsc_client_info_tests PRIVATE tests)

add_executable(rtsc_connect_machine_tests tests/test_connect_machine.cpp)
target_link_libraries(rtsc_connect_machine_tests PRIVATE rtsc_proto rtsc_util)
target_include_directories(rtsc_connect_machine_tests PRIVATE tests)

add_executable(rtsc_finalization_tests tests/test_finalization.cpp)
target_link_libraries(rtsc_finalization_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_finalization_tests PRIVATE tests)

add_executable(rtsc_session_setup_tests tests/test_session_setup.cpp)
target_link_libraries(rtsc_session_setup_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_session_setup_tests PRIVATE tests)

add_executable(rtsc_input_tests tests/test_input.cpp)
target_link_libraries(rtsc_input_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_input_tests PRIVATE tests)

add_executable(rtsc_output_tests tests/test_output.cpp)
target_link_libraries(rtsc_output_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_output_tests PRIVATE tests)

add_executable(rtsc_bitmap_tests tests/test_bitmap.cpp)
target_link_libraries(rtsc_bitmap_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_bitmap_tests PRIVATE tests)

add_executable(rtsc_channel_tests tests/test_channel.cpp)
target_link_libraries(rtsc_channel_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_channel_tests PRIVATE tests)

add_executable(rtsc_surface_tests tests/test_surface.cpp)
target_link_libraries(rtsc_surface_tests PRIVATE rtsc_proto rtsc_crypto rtsc_ui rtsc_util)
target_include_directories(rtsc_surface_tests PRIVATE tests)

add_executable(rtsc_cliprdr_tests tests/test_cliprdr.cpp)
target_link_libraries(rtsc_cliprdr_tests PRIVATE rtsc_cliprdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_cliprdr_tests PRIVATE tests)

# Server-side cliprdr handler: the protocol mirror of the client handler, driven
# with an injected fake clipboard (design S1-S13).
add_executable(rtsc_cliprdr_server_tests tests/test_cliprdr_server.cpp)
target_link_libraries(rtsc_cliprdr_server_tests PRIVATE rtsc_cliprdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_cliprdr_server_tests PRIVATE tests)

# Direction-B file-list provider (DropFileList / CreateDropFileListFromBytes).
add_executable(rtsc_clipboard_tests tests/test_drop_files.cpp)
target_link_libraries(rtsc_clipboard_tests PRIVATE rtsc_cliprdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_clipboard_tests PRIVATE tests)

add_executable(rtsc_drdynvc_tests tests/test_drdynvc.cpp)
target_link_libraries(rtsc_drdynvc_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_drdynvc_tests PRIVATE tests)

# URBDRC (RemoteFX USB redirection) channel handler. Platform neutral: it
# forwards TS_URB requests to an injected rtsc::usb::UsbDevice; the WinUSB
# backend is the platform implementation (see src/usb/usb_win32.cpp).
add_library(rtsc_urbrdc STATIC
    src/channel/drdynvc_client.cpp
    src/channel/rdpusb_client.cpp)
target_include_directories(rtsc_urbrdc PUBLIC include)
target_link_libraries(rtsc_urbrdc PUBLIC rtsc_proto)

# Windows USB backend (SetupAPI enumeration + WinUSB transfers).
if(WIN32)
    add_library(rtsc_usb_win32 STATIC src/usb/usb_win32.cpp)
    target_include_directories(rtsc_usb_win32 PUBLIC include)
    target_link_libraries(rtsc_usb_win32 PUBLIC setupapi winusb)
endif()

add_executable(rtsc_rdpusb_tests tests/test_rdpusb.cpp)
target_link_libraries(rtsc_rdpusb_tests PRIVATE rtsc_urbrdc rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdpusb_tests PRIVATE tests)
# The source-level regression guards (WinUSB control-transfer OUT copy and the
# GUI drdynvc advertisement gate) read the source tree, like the rdpdr ActiveLoop
# guard; RTSC_SOURCE_DIR comes from CMake in forward-slash form.
target_compile_definitions(rtsc_rdpusb_tests PRIVATE
                           "RTSC_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

add_executable(rtsc_rdpdr_tests tests/test_rdpdr.cpp tests/test_rdpdr_client.cpp)
target_link_libraries(rtsc_rdpdr_tests PRIVATE rtsc_rdpdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdpdr_tests PRIVATE tests)

# Server-side rdpdr handler: the channel-level minimum handshake (design S1-S6).
add_executable(rtsc_rdpdr_server_tests tests/test_rdpdr_server.cpp)
target_link_libraries(rtsc_rdpdr_server_tests PRIVATE rtsc_rdpdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdpdr_server_tests PRIVATE tests)

# Route-A async I/O engine: the server issues DR_DEVICE_IOREQUEST toward the
# client's shared drive and matches DR_DEVICE_IOCOMPLETION back through the
# outstanding table. Driven against the in-tree RdpdrClient over real wire
# encoding (design docs/spec/rdpdr-server-io-design.md section 8).
add_executable(rtsc_rdpdr_server_io_tests tests/test_rdpdr_server_io.cpp)
target_link_libraries(rtsc_rdpdr_server_io_tests PRIVATE rtsc_rdpdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdpdr_server_io_tests PRIVATE tests)

# Drive-enumeration policy: default fixed drives / whitelist / ALL / invalid
# spec over an injected candidate list, so no case touches a real drive.
add_executable(rtsc_drive_enum_tests tests/test_drive_enum.cpp)
target_link_libraries(rtsc_drive_enum_tests PRIVATE rtsc_rdpdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_drive_enum_tests PRIVATE tests)

add_executable(rtsc_rdpsnd_tests tests/test_rdpsnd.cpp)
target_link_libraries(rtsc_rdpsnd_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdpsnd_tests PRIVATE tests)

add_executable(rtsc_rdpsnd_client_tests tests/test_rdpsnd_client.cpp)
target_link_libraries(rtsc_rdpsnd_client_tests PRIVATE rtsc_rdpsnd rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdpsnd_client_tests PRIVATE tests)

# Server-side rdpsnd handler: byte-exact Wire2/formats contract, the training
# gate, the 8-block in-flight window, block-number wrap and the negotiation
# timeouts (design 7.1/7.2).
add_executable(rtsc_rdpsnd_server_tests tests/test_rdpsnd_server.cpp)
target_link_libraries(rtsc_rdpsnd_server_tests PRIVATE rtsc_rdpsnd rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdpsnd_server_tests PRIVATE tests)

# Server-side audio capture source seam and the sine test source.
add_executable(rtsc_audio_source_tests tests/test_audio_source.cpp)
target_link_libraries(rtsc_audio_source_tests PRIVATE rtsc_rdpsnd rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_audio_source_tests PRIVATE tests)

add_executable(rtsc_rdp6_tests tests/test_rdp6.cpp)
target_link_libraries(rtsc_rdp6_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdp6_tests PRIVATE tests)

add_executable(rtsc_nsc_tests tests/test_nsc.cpp)
target_link_libraries(rtsc_nsc_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_nsc_tests PRIVATE tests)

add_executable(rtsc_orders_tests tests/test_orders.cpp tests/test_order_engine.cpp tests/test_secondary.cpp)
target_link_libraries(rtsc_orders_tests PRIVATE rtsc_proto rtsc_render rtsc_crypto rtsc_util rtsc_client)
target_include_directories(rtsc_orders_tests PRIVATE tests)

add_executable(rtsc_rop_tests tests/test_rop.cpp)
target_link_libraries(rtsc_rop_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rop_tests PRIVATE tests)

add_executable(rtsc_ui_tests tests/test_ui.cpp)
target_link_libraries(rtsc_ui_tests PRIVATE rtsc_ui rtsc_util)
target_include_directories(rtsc_ui_tests PRIVATE tests)
# The fullscreen-dispatch regression guard in test_ui.cpp reads the one
# front-end file the suite cannot link (rtsc_gui is an executable running a
# full network client). CMake reports CMAKE_CURRENT_SOURCE_DIR with forward
# slashes, so the definition is directly usable as a C++ string literal.
target_compile_definitions(rtsc_ui_tests PRIVATE
                           "RTSC_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

add_executable(rtsc_graphics_tests tests/test_graphics.cpp)
target_link_libraries(rtsc_graphics_tests PRIVATE rtsc_client rtsc_proto rtsc_ui rtsc_util)
target_include_directories(rtsc_graphics_tests PRIVATE tests)

add_executable(rtsc_view_tests tests/test_view.cpp)
target_link_libraries(rtsc_view_tests PRIVATE rtsc_client rtsc_proto rtsc_ui rtsc_util)
target_include_directories(rtsc_view_tests PRIVATE tests)

add_executable(rtsc_client_tests tests/test_client.cpp)
target_link_libraries(rtsc_client_tests PRIVATE rtsc_client rtsc_security rtsc_net rtsc_proto rtsc_ui rtsc_util)
target_include_directories(rtsc_client_tests PRIVATE tests)

add_executable(rtsc_session_info_tests tests/test_session_info.cpp)
target_link_libraries(rtsc_session_info_tests PRIVATE rtsc_client rtsc_proto rtsc_ui rtsc_util)
target_include_directories(rtsc_session_info_tests PRIVATE tests)

add_executable(rtsc_capabilities_tests tests/test_capabilities.cpp)
target_link_libraries(rtsc_capabilities_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_capabilities_tests PRIVATE tests)

add_executable(rtsc_multimon_tests tests/test_multimon.cpp)
target_link_libraries(rtsc_multimon_tests PRIVATE rtsc_client rtsc_proto rtsc_ui rtsc_util)
target_include_directories(rtsc_multimon_tests PRIVATE tests)

add_executable(rtsc_share_tests tests/test_share.cpp)
target_link_libraries(rtsc_share_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_share_tests PRIVATE tests)

add_executable(rtsc_licensing_tests tests/test_licensing.cpp)
target_link_libraries(rtsc_licensing_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_licensing_tests PRIVATE tests)

add_executable(rtsc_licensing_machine_tests tests/test_licensing_machine.cpp)
target_link_libraries(rtsc_licensing_machine_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_licensing_machine_tests PRIVATE tests)

add_executable(rtsc_crypto_tests tests/test_crypto.cpp)
target_link_libraries(rtsc_crypto_tests PRIVATE rtsc_crypto rtsc_util)
target_include_directories(rtsc_crypto_tests PRIVATE tests)

add_executable(rtsc_rsa_tests tests/test_rsa.cpp)
target_link_libraries(rtsc_rsa_tests PRIVATE rtsc_crypto rtsc_util)
target_include_directories(rtsc_rsa_tests PRIVATE tests)

add_executable(rtsc_rdp_security_tests tests/test_rdp_security.cpp)
target_link_libraries(rtsc_rdp_security_tests PRIVATE rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdp_security_tests PRIVATE tests)

add_executable(rtsc_framing_tests tests/test_framing.cpp)
target_link_libraries(rtsc_framing_tests PRIVATE rtsc_proto rtsc_util)
target_include_directories(rtsc_framing_tests PRIVATE tests)

if(WIN32)
    add_executable(rtsc_tls_tests tests/test_tls.cpp)
    target_link_libraries(rtsc_tls_tests PRIVATE rtsc_tls rtsc_util)
    target_include_directories(rtsc_tls_tests PRIVATE tests)
endif()

if(NOT WIN32 AND RTSC_TLS_OPENSSL)
    add_executable(rtsc_tls_openssl_tests tests/test_tls_openssl.cpp)
    target_link_libraries(rtsc_tls_openssl_tests PRIVATE rtsc_tls rtsc_util OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(rtsc_tls_openssl_tests PRIVATE tests)
endif()

# CredSSP message layer. Platform neutral: it only needs the crypto primitives,
# so it builds unchanged on Linux/Android/macOS.
add_library(rtsc_credssp STATIC
    src/credssp/ts_request.cpp
    src/credssp/ntlm.cpp
    src/credssp/credssp.cpp
    src/credssp/credssp_server.cpp
)
target_include_directories(rtsc_credssp PUBLIC include)
target_link_libraries(rtsc_credssp PUBLIC rtsc_crypto)

add_executable(rtsc_credssp_tests tests/test_credssp.cpp)
target_link_libraries(rtsc_credssp_tests PRIVATE rtsc_credssp rtsc_util)
target_include_directories(rtsc_credssp_tests PRIVATE tests)

add_executable(rtsc_ntlm_tests tests/test_ntlm.cpp)
target_link_libraries(rtsc_ntlm_tests PRIVATE rtsc_credssp rtsc_util)
target_include_directories(rtsc_ntlm_tests PRIVATE tests)

add_executable(rtsc_credssp_sm_tests tests/test_credssp_sm.cpp)
target_link_libraries(rtsc_credssp_sm_tests PRIVATE rtsc_credssp rtsc_util)
target_include_directories(rtsc_credssp_sm_tests PRIVATE tests)

add_library(rtsc_security STATIC src/security/security_layer.cpp src/security/standard_rdp_security.cpp src/security/connection_driver.cpp src/security/server_security_layer.cpp)
target_include_directories(rtsc_security PUBLIC include)
target_link_libraries(rtsc_security PUBLIC rtsc_tls rtsc_credssp rtsc_proto rtsc_crypto)

add_executable(rtsc_security_tests tests/test_security_layer.cpp)
target_link_libraries(rtsc_security_tests PRIVATE rtsc_security rtsc_tls rtsc_credssp rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_security_tests PRIVATE tests)

add_test(NAME security COMMAND rtsc_security_tests)

# Standard RDP Security (PROTOCOL_RDP): unit tests for the RC4 data plane plus
# an end-to-end loopback against the in-tree RDP server.
add_executable(rtsc_rdp_standard_security_tests
               tests/test_rdp_standard_security.cpp)
target_link_libraries(rtsc_rdp_standard_security_tests PRIVATE
                      rtsc_security rtsc_server rtsc_client rtsc_net
                      rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rdp_standard_security_tests PRIVATE tests)
add_test(NAME rdp_standard_security COMMAND rtsc_rdp_standard_security_tests)

# Server-side enhanced security: TLS accept + CredSSP server + EUAR, driven
# against the project's own client security stack.
add_executable(rtsc_server_security_tests tests/test_server_security.cpp)
target_link_libraries(rtsc_server_security_tests PRIVATE
                      rtsc_client rtsc_server rtsc_security rtsc_tls rtsc_credssp
                      rtsc_proto rtsc_crypto rtsc_net rtsc_util)
target_include_directories(rtsc_server_security_tests PRIVATE tests)
add_test(NAME server_security COMMAND rtsc_server_security_tests)

# GUI send path: input and static virtual channels through the application
# data plane, against the in-tree server over PROTOCOL_RDP.
add_executable(rtsc_gui_send_tests tests/test_gui_send.cpp)
target_link_libraries(rtsc_gui_send_tests PRIVATE
                      rtsc_client rtsc_security rtsc_server rtsc_net
                      rtsc_proto rtsc_crypto rtsc_ui rtsc_util rtsc_urbrdc)
target_include_directories(rtsc_gui_send_tests PRIVATE tests)
add_test(NAME gui_send COMMAND rtsc_gui_send_tests)

# Blocking TCP transport. Windows = Winsock; POSIX = POSIX sockets.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_library(rtsc_net STATIC src/net/winsock_transport.cpp)
    target_include_directories(rtsc_net PUBLIC include)
    target_link_libraries(rtsc_net PUBLIC ws2_32)
else()
    add_library(rtsc_net STATIC src/net/posix_transport.cpp)
    target_include_directories(rtsc_net PUBLIC include)
endif()

# ConnectTcp hardening: connect-timeout / refused / success (and boundary)
# behavior of the handshake, driven over the public Transport/Listener API.
# src/net is on the include path for the internal ConnectAddresses() seam the
# budget-slicing regression test injects an address list through.
add_executable(rtsc_net_tests tests/test_transport.cpp)
target_link_libraries(rtsc_net_tests PRIVATE rtsc_net rtsc_util)
target_include_directories(rtsc_net_tests PRIVATE tests src/net)
add_test(NAME net COMMAND rtsc_net_tests)

# RD Gateway tunnel + RDP-UDP transport ([MS-TSGU] / [MS-RDPEUDP]).
# Platform neutral: the transport logic lives in gateway_transport.cpp; the
# UDP socket seam has a Winsock backend (Windows) and a POSIX backend.
# The RDGSP transport composes two byte transports and runs the NTLM message
# layer, so the library links rtsc_net (ConnectTcp fallback), rtsc_credssp
# (NTLM messages) and rtsc_tls (outer-gateway TLS byte adapter).
add_library(rtsc_gateway STATIC src/net/gateway_transport.cpp)
target_include_directories(rtsc_gateway PUBLIC include)
target_link_libraries(rtsc_gateway PUBLIC rtsc_proto rtsc_net rtsc_credssp rtsc_tls)
if(WIN32)
    target_sources(rtsc_gateway PRIVATE src/net/udp_winsock.cpp)
    target_link_libraries(rtsc_gateway PUBLIC ws2_32)
else()
    target_sources(rtsc_gateway PRIVATE src/net/udp_posix.cpp)
endif()

add_library(rtsc_client STATIC src/client/graphics.cpp src/client/client.cpp src/client/view.cpp src/client/resample.cpp src/client/session_info.cpp)
target_include_directories(rtsc_client PUBLIC include)
# view.cpp includes "resample.h" from its own directory.
target_include_directories(rtsc_client PRIVATE src/client)
target_link_libraries(rtsc_client PUBLIC rtsc_proto rtsc_render rtsc_ui rtsc_security rtsc_net rtsc_rail)
# RtlGetVersion (the connection-information dialog's local-OS field) lives in
# ntdll.dll. GetVersionExW is the alternative but is deprecated and trips C4996,
# which is fatal under /WX.
if(WIN32)
    target_link_libraries(rtsc_client PUBLIC ntdll)
endif()

# The security test also exercises the client's channel registration wrapper.
target_link_libraries(rtsc_security_tests PRIVATE rtsc_client)

add_library(rtsc_ui STATIC src/ui/surface.cpp src/ui/window.cpp)
target_include_directories(rtsc_ui PUBLIC include)
if(WIN32)
    target_sources(rtsc_ui PRIVATE src/ui/window_win32.cpp)
    target_include_directories(rtsc_ui PRIVATE src/ui)
    target_link_libraries(rtsc_ui PUBLIC user32 gdi32)
else()
    # X11 backend. Off by default (a REQUIRED find_package would break configure
    # on hosts without libX11).
    option(RTSC_UI_X11 "Build the X11 window backend (non-Windows)" OFF)
    if(RTSC_UI_X11)
        find_package(X11 REQUIRED)
        target_sources(rtsc_ui PRIVATE src/ui/window_x11.cpp)
        target_include_directories(rtsc_ui PRIVATE src/ui)
        target_link_libraries(rtsc_ui PUBLIC X11::X11)
        target_compile_definitions(rtsc_ui PUBLIC RTSC_UI_X11=1)
    endif()

    option(RTSC_UI_WAYLAND "Build the Wayland window backend (non-Windows)" OFF)
    if(RTSC_UI_WAYLAND)
        # wayland-scanner emits a C translation unit; the project is CXX-only.
        enable_language(C)
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(WAYLAND_CLIENT REQUIRED wayland-client)
        find_program(WAYLAND_SCANNER wayland-scanner REQUIRED)
        find_file(XDG_SHELL_XML xdg-shell.xml
                  PATHS /usr/share/wayland-protocols/stable/xdg-shell REQUIRED)
        set(WS_DIR ${CMAKE_CURRENT_BINARY_DIR}/wayland-protocols)
        add_custom_command(
            OUTPUT ${WS_DIR}/xdg-shell-client-protocol.h ${WS_DIR}/xdg-shell-protocol.c
            COMMAND ${CMAKE_COMMAND} -E make_directory ${WS_DIR}
            COMMAND ${WAYLAND_SCANNER} client-header ${XDG_SHELL_XML}
                    ${WS_DIR}/xdg-shell-client-protocol.h
            COMMAND ${WAYLAND_SCANNER} private-code ${XDG_SHELL_XML}
                    ${WS_DIR}/xdg-shell-protocol.c
            DEPENDS ${XDG_SHELL_XML})
        target_sources(rtsc_ui PRIVATE src/ui/window_wayland.cpp
                                     ${WS_DIR}/xdg-shell-protocol.c)
        target_include_directories(rtsc_ui PRIVATE src/ui ${WS_DIR}
                                   ${WAYLAND_CLIENT_INCLUDE_DIRS})
        target_link_libraries(rtsc_ui PUBLIC ${WAYLAND_CLIENT_LIBRARIES})
        target_compile_definitions(rtsc_ui PUBLIC RTSC_UI_WAYLAND=1)
    endif()
endif()

# Order application layer: the orders are decoded by rtsc::proto and applied to
# a ui::Surface here. This keeps rtsc::proto free of any UI dependency.
add_library(rtsc_render STATIC src/render/orders_apply.cpp src/render/order_engine.cpp)
target_include_directories(rtsc_render PUBLIC include)
target_link_libraries(rtsc_render PUBLIC rtsc_proto rtsc_ui)

add_executable(rtsc_probe tools/rtsc_probe/main.cpp)
target_link_libraries(rtsc_probe PRIVATE rtsc_proto rtsc_util)

# Reproducible performance benchmark. Measures bitmap decode throughput (raw /
# Interleaved RLE / RDP6 ARGB + AYCoCg / NSCodec), end-to-end frame latency over
# the scripted TLS loopback, and process CPU occupancy. Read-only w.r.t. the
# product sources: it only links the public libraries and the test TLS seam.
add_executable(rtsc_bench tools/rtsc_bench/main.cpp)
target_link_libraries(rtsc_bench PRIVATE
                      rtsc_client rtsc_proto rtsc_ui rtsc_util
                      rtsc_security rtsc_tls rtsc_credssp rtsc_crypto)
target_include_directories(rtsc_bench PRIVATE include)

# Real-connection driver: ties the state machine and the security layer to a
# TCP socket.
add_executable(rtsc_connect tools/rtsc_connect/main.cpp)
target_link_libraries(rtsc_connect PRIVATE rtsc_security rtsc_net rtsc_proto rtsc_util)

# Full client: connection driver + graphics pipeline + window backend.
# Windows only: the window backend, the connection-info dialog and the USB
# redirection path are all Win32.
if(WIN32)
add_executable(rtsc_gui tools/rtsc_gui/main.cpp
               tools/rtsc_gui/connection_info_dialog_win32.cpp)
target_link_libraries(rtsc_gui PRIVATE rtsc_client rtsc_ui rtsc_security rtsc_net rtsc_gateway rtsc_proto rtsc_util)
target_link_libraries(rtsc_gui PRIVATE rtsc_rdpsnd rtsc_cliprdr rtsc_rdpdr rtsc_urbrdc)
if(WIN32)
    target_link_libraries(rtsc_gui PRIVATE rtsc_audio rtsc_usb_win32)
endif()
endif()

# Crash-guard self test. Not registered with ctest: it intentionally terminates
# the process, so verify.ps1 -CrashCheck drives it and asserts on the artifacts.
add_executable(rtsc_crashtest tools/rtsc_crashtest/main.cpp)
target_link_libraries(rtsc_crashtest PRIVATE rtsc_util)

# RDP server role (Standard RDP Security, [MS-RDPBCGR] 3.3). Platform neutral:
# it only needs the proto/crypto/net seams. The RSA backend is Windows-only
# (rsa_server.cpp); rsa_posix_stub.cpp fails closed where there is no backend,
# so the server degrades to "no encryption" rather than a broken key.
add_library(rtsc_server STATIC
    src/server/server.cpp
    src/server/rsa_posix_stub.cpp
    src/crypto/rsa_server.cpp)
target_include_directories(rtsc_server PUBLIC include)
# The server's cliprdr static virtual channel runs the CliprdrServer handler
# (src/channel/cliprdr_server.cpp, built into rtsc_cliprdr); the rdpdr static
# virtual channel runs the RdpdrServer minimum handshake (built into
# rtsc_rdpdr); the rdpsnd static virtual channel runs the RdpsndServer audio
# handler fed by the ServerConfig audio_source_factory seam (built into
# rtsc_rdpsnd).
target_link_libraries(rtsc_server PUBLIC rtsc_proto rtsc_crypto rtsc_net rtsc_security rtsc_cliprdr rtsc_rdpdr rtsc_rdpsnd)

add_executable(rtsc_server_tests tests/test_server.cpp)
target_link_libraries(rtsc_server_tests PRIVATE rtsc_server rtsc_proto rtsc_crypto rtsc_net rtsc_util)
target_include_directories(rtsc_server_tests PRIVATE tests)

# RDP server multi-session concurrency: N concurrent clients over Standard RDP
# Security, asserting per-session isolation (desktop geometry, framebuffer
# capture, session counter) plus cliprdr shared-clipboard concurrency
# (handshake, last-writer-wins, disconnect, stress).
add_executable(rtsc_server_multisession_tests tests/test_server_multisession.cpp)
target_link_libraries(rtsc_server_multisession_tests PRIVATE
                      rtsc_client rtsc_server rtsc_cliprdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_server_multisession_tests PRIVATE tests)

# Server-side CLIPRDR over real loopback sockets: one server session and the
# project's own client, asserting the clipboard round-trip in both directions
# and the handshake counters (design E1-E3).
add_executable(rtsc_server_cliprdr_e2e_tests tests/test_server_cliprdr_e2e.cpp)
target_link_libraries(rtsc_server_cliprdr_e2e_tests PRIVATE
                      rtsc_client rtsc_server rtsc_cliprdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_server_cliprdr_e2e_tests PRIVATE tests)

# Server-side RDPDR pairing over real loopback sockets: one server session
# running the RdpdrServer minimum handshake on its rdpdr static virtual channel
# and the project's own RdpdrClient, asserting the two sides interoperate
# (design R1-R5). A companion handler-pair harness pins the server-side
# diagnostics the live RdpServer does not publish.
add_executable(rtsc_server_rdpdr_e2e_tests tests/test_server_rdpdr_e2e.cpp)
target_link_libraries(rtsc_server_rdpdr_e2e_tests PRIVATE
                      rtsc_client rtsc_server rtsc_rdpdr rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_server_rdpdr_e2e_tests PRIVATE tests)
# The W11 route-A ActiveLoop wiring guard reads src/server/server.cpp at
# runtime, so the test needs the source root.
target_compile_definitions(rtsc_server_rdpdr_e2e_tests PRIVATE
                           "RTSC_SOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

# Server-side RDPSND over real loopback sockets: one server session running the
# RdpsndServer audio handler on its rdpsnd static virtual channel with the
# deterministic sine capture source, paired with the project's own RdpsndClient
# and a mock sink, asserting the negotiated wire handshake, that the client's
# Wave Confirm count matches the received Wave2 count, the channel id the name
# table assigns, and that a second concurrent session streams to a second
# client too (design 7.6).
add_executable(rtsc_server_rdpsnd_e2e_tests tests/test_server_rdpsnd_e2e.cpp)
target_link_libraries(rtsc_server_rdpsnd_e2e_tests PRIVATE
                      rtsc_client rtsc_server rtsc_rdpsnd rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_server_rdpsnd_e2e_tests PRIVATE tests)

# Windows GDI desktop capture: the real-desktop DesktopSource. Windows only;
# the DesktopSource interface stays platform neutral in rtsc/server/server.h.
# The implementation only needs the header plus gdi32/user32, so it does not
# link the whole rtsc_server library.
if(WIN32)
    add_library(rtsc_server_desktop_gdi STATIC src/server/desktop_gdi.cpp)
    target_include_directories(rtsc_server_desktop_gdi PUBLIC include)
    target_link_libraries(rtsc_server_desktop_gdi PUBLIC gdi32 user32)

    add_executable(rtsc_desktop_gdi_tests tests/test_desktop_gdi.cpp)
    target_link_libraries(rtsc_desktop_gdi_tests PRIVATE rtsc_server_desktop_gdi rtsc_util)
    target_include_directories(rtsc_desktop_gdi_tests PRIVATE tests)
endif()

# Server-side desktop input injection. The mapping layer is platform neutral
# (it only turns InputEvent into PlatformInput) and is covered by ctest on every
# platform. The sink itself posts SendInput calls from a single worker thread on
# Windows; other platforms get a counting no-op so the host links unchanged.
add_library(rtsc_server_desktop_input_map STATIC src/server/desktop_input_map.cpp)
target_include_directories(rtsc_server_desktop_input_map PUBLIC include)

add_executable(rtsc_desktop_input_tests tests/test_desktop_input.cpp)
# The null sink is built into this test on every platform -- including Windows,
# where the production factory is the SendInput backend -- so the sink's
# Stats()/Inject accounting can be asserted without injecting real input or
# starting the Win32 worker thread.
target_sources(rtsc_desktop_input_tests PRIVATE src/server/desktop_input_null.cpp)
target_link_libraries(rtsc_desktop_input_tests PRIVATE rtsc_server_desktop_input_map rtsc_util)
target_include_directories(rtsc_desktop_input_tests PRIVATE tests)

if(WIN32)
    add_library(rtsc_server_desktop_input STATIC src/server/desktop_input_win32.cpp)
    target_link_libraries(rtsc_server_desktop_input PUBLIC rtsc_server_desktop_input_map user32)
else()
    add_library(rtsc_server_desktop_input STATIC src/server/desktop_input_null.cpp)
    target_link_libraries(rtsc_server_desktop_input PUBLIC rtsc_server_desktop_input_map)
endif()

# Standalone host for the RDP server role: the same RdpServer the loopback
# tests drive, configured from the command line and served to a real client
# (mstsc). The GDI desktop capture is Windows-only; other platforms fall back to
# the synthetic test pattern inside the tool.
add_executable(rtsc_server_host tools/rtsc_server/main.cpp)
target_link_libraries(rtsc_server_host PRIVATE
                      rtsc_server rtsc_util rtsc_rdpsnd rtsc_server_desktop_input)
if(WIN32)
    target_link_libraries(rtsc_server_host PRIVATE rtsc_server_desktop_gdi)
endif()

# RAIL ([MS-RDPERP]) wire structures and virtual channel.
add_executable(rtsc_rail_tests tests/test_rail.cpp)
target_link_libraries(rtsc_rail_tests PRIVATE rtsc_proto rtsc_crypto rtsc_util)
target_include_directories(rtsc_rail_tests PRIVATE tests)

# RAIL client integration: the "rail" static virtual channel handler, the
# Confirm Active RAIL capability set, and the Client-side registration.
add_executable(rtsc_rail_client_tests tests/test_rail_client.cpp)
target_link_libraries(rtsc_rail_client_tests PRIVATE
                       rtsc_rail rtsc_client rtsc_security rtsc_tls
                       rtsc_credssp rtsc_proto rtsc_crypto rtsc_net rtsc_ui rtsc_util)
target_include_directories(rtsc_rail_client_tests PRIVATE tests)

# RD Gateway ([MS-TSGU]) and RDP-UDP ([MS-RDPEUDP]) wire structures + tunnel.
# The end-to-end test drives the in-tree server through the tunnel, so this
# target links the client/server stack as well.
add_executable(rtsc_gateway_tests tests/test_gateway.cpp)
target_link_libraries(rtsc_gateway_tests PRIVATE
                      rtsc_gateway rtsc_client rtsc_server rtsc_proto
                      rtsc_crypto rtsc_util)
target_include_directories(rtsc_gateway_tests PRIVATE tests)

enable_testing()
add_test(NAME proto COMMAND rtsc_tests)
add_test(NAME ber COMMAND rtsc_ber_tests)
add_test(NAME mcs COMMAND rtsc_mcs_tests)
add_test(NAME mcs_domain COMMAND rtsc_mcs_domain_tests)
add_test(NAME client_info COMMAND rtsc_client_info_tests)
add_test(NAME connect_machine COMMAND rtsc_connect_machine_tests)
add_test(NAME framing COMMAND rtsc_framing_tests)
add_test(NAME crypto COMMAND rtsc_crypto_tests)
add_test(NAME rsa COMMAND rtsc_rsa_tests)
add_test(NAME rdp_security COMMAND rtsc_rdp_security_tests)
add_test(NAME licensing COMMAND rtsc_licensing_tests)
add_test(NAME licensing_machine COMMAND rtsc_licensing_machine_tests)
add_test(NAME share COMMAND rtsc_share_tests)
add_test(NAME capabilities COMMAND rtsc_capabilities_tests)
add_test(NAME multimon COMMAND rtsc_multimon_tests)
add_test(NAME finalization COMMAND rtsc_finalization_tests)
add_test(NAME session_setup COMMAND rtsc_session_setup_tests)
add_test(NAME input COMMAND rtsc_input_tests)
add_test(NAME output COMMAND rtsc_output_tests)
add_test(NAME bitmap COMMAND rtsc_bitmap_tests)
add_test(NAME channel COMMAND rtsc_channel_tests)
add_test(NAME surface COMMAND rtsc_surface_tests)
add_test(NAME cliprdr COMMAND rtsc_cliprdr_tests)
add_test(NAME cliprdr_server COMMAND rtsc_cliprdr_server_tests)
add_test(NAME clipboard COMMAND rtsc_clipboard_tests)
add_test(NAME drdynvc COMMAND rtsc_drdynvc_tests)
add_test(NAME rdpusb COMMAND rtsc_rdpusb_tests)
add_test(NAME rdpdr COMMAND rtsc_rdpdr_tests)
add_test(NAME rdpdr_server COMMAND rtsc_rdpdr_server_tests)
add_test(NAME rdpdr_server_io COMMAND rtsc_rdpdr_server_io_tests)
add_test(NAME drive_enum COMMAND rtsc_drive_enum_tests)
add_test(NAME rdpsnd COMMAND rtsc_rdpsnd_tests)
add_test(NAME rdpsnd_client COMMAND rtsc_rdpsnd_client_tests)
add_test(NAME rdpsnd_server COMMAND rtsc_rdpsnd_server_tests)
add_test(NAME audio_source COMMAND rtsc_audio_source_tests)
add_test(NAME rdp6 COMMAND rtsc_rdp6_tests)
add_test(NAME nsc COMMAND rtsc_nsc_tests)
add_test(NAME orders COMMAND rtsc_orders_tests)
add_test(NAME rop COMMAND rtsc_rop_tests)
add_test(NAME ui COMMAND rtsc_ui_tests)
add_test(NAME graphics COMMAND rtsc_graphics_tests)
add_test(NAME view COMMAND rtsc_view_tests)
add_test(NAME session_info COMMAND rtsc_session_info_tests)
add_test(NAME client COMMAND rtsc_client_tests)
add_test(NAME desktop_input COMMAND rtsc_desktop_input_tests)
if(WIN32)
    add_test(NAME tls COMMAND rtsc_tls_tests)
endif()
if(NOT WIN32 AND RTSC_TLS_OPENSSL)
    add_test(NAME tls_openssl COMMAND rtsc_tls_openssl_tests)
endif()
add_test(NAME credssp COMMAND rtsc_credssp_tests)
add_test(NAME ntlm COMMAND rtsc_ntlm_tests)
add_test(NAME credssp_sm COMMAND rtsc_credssp_sm_tests)
add_test(NAME server COMMAND rtsc_server_tests)
add_test(NAME server_multisession COMMAND rtsc_server_multisession_tests)
add_test(NAME server_cliprdr_e2e COMMAND rtsc_server_cliprdr_e2e_tests)
add_test(NAME server_rdpdr_e2e COMMAND rtsc_server_rdpdr_e2e_tests)
add_test(NAME server_rdpsnd_e2e COMMAND rtsc_server_rdpsnd_e2e_tests)
if(WIN32)
    add_test(NAME desktop_gdi COMMAND rtsc_desktop_gdi_tests)
endif()
add_test(NAME rail COMMAND rtsc_rail_tests)
add_test(NAME rail_client COMMAND rtsc_rail_client_tests)
add_test(NAME gateway COMMAND rtsc_gateway_tests)

if(MSVC)
    target_compile_options(rtsc_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_ber_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_mcs_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_mcs_domain_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_client_info_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_connect_machine_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_framing_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_crypto_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rsa_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdp_security_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_licensing_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_licensing_machine_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_share_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_capabilities_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_multimon_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_finalization_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_session_setup_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_input_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_output_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_bitmap_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_channel_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_surface_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_cliprdr_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_cliprdr_server_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_clipboard_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_drdynvc_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdpusb_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_urbrdc PRIVATE /W4 /WX)
    if(WIN32)
        target_compile_options(rtsc_usb_win32 PRIVATE /W4 /WX)
    endif()
    target_compile_options(rtsc_rdpdr_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdpdr_server_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdpdr_server_io_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_drive_enum_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdpdr PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdpsnd_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdpsnd_client_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdpsnd_server_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_audio_source_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_cliprdr PRIVATE /W4 /WX)
    if(WIN32)
        target_compile_options(rtsc_audio PRIVATE /W4 /WX)
        target_compile_options(rtsc_rdpsnd PRIVATE /W4 /WX)
    endif()
    target_compile_options(rtsc_rdp6_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_nsc_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_orders_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rop_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_render PRIVATE /W4 /WX)
    target_compile_options(rtsc_ui_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_graphics_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_view_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_session_info_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_client_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_net_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_security_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rdp_standard_security_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_security_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_gui_send_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_connect PRIVATE /W4 /WX)
    target_compile_options(rtsc_gui PRIVATE /W4 /WX)
    target_compile_options(rtsc_bench PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_host PRIVATE /W4 /WX)
    if(WIN32)
        target_compile_options(rtsc_tls_tests PRIVATE /W4 /WX)
    endif()
    target_compile_options(rtsc_credssp_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_ntlm_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_credssp_sm_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_server PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_multisession_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_cliprdr_e2e_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_rdpdr_e2e_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_rdpsnd_e2e_tests PRIVATE /W4 /WX)
    if(WIN32)
        target_compile_options(rtsc_server_desktop_gdi PRIVATE /W4 /WX)
        target_compile_options(rtsc_desktop_gdi_tests PRIVATE /W4 /WX)
    endif()
    target_compile_options(rtsc_server_desktop_input_map PRIVATE /W4 /WX)
    target_compile_options(rtsc_server_desktop_input PRIVATE /W4 /WX)
    target_compile_options(rtsc_desktop_input_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rail_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_rail PRIVATE /W4 /WX)
    target_compile_options(rtsc_rail_client_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_gateway_tests PRIVATE /W4 /WX)
    target_compile_options(rtsc_gateway PRIVATE /W4 /WX)
endif()
