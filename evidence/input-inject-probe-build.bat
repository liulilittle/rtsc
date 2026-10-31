@echo off
rem Builds the two read-only probes used by docs/spec/input-injection-evidence.md.
rem Neither program calls SendInput/keybd_event/mouse_event/SetCursorPos.
setlocal
pushd "%~dp0"
if not defined VCINSTALLDIR (
  call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul
)
cl /nologo /W4 /WX /EHsc input-inject-mapping-probe.cpp /Fe:input-inject-mapping-probe.exe user32.lib kernel32.lib
if errorlevel 1 goto fail
cl /nologo /W4 /WX /EHsc input-inject-mapping-harness.cpp /Fe:input-inject-mapping-harness.exe user32.lib kernel32.lib
if errorlevel 1 goto fail
popd
exit /b 0
:fail
set RC=%ERRORLEVEL%
popd
exit /b %RC%
