@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d C:\Users\liulilte\AppData\Local\Temp\opencode
cl /nologo /std:c++17 /EHsc /MD /O2 /I F:\rtsc\include probe_hostmatch.cpp /Fe:phm.exe /link /LIBPATH:F:\rtsc\build\Release rtsc_tls.lib rtsc_tls_schannel.lib secur32.lib crypt32.lib bcrypt.lib ws2_32.lib > phm.log 2>&1
echo BUILD=%ERRORLEVEL%
findstr /C:"error C" /C:"error LNK" phm.log
if exist phm.exe ( phm.exe & echo RC=%ERRORLEVEL% )
