@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d C:\Users\liulilte\AppData\Local\Temp\opencode
cl /nologo /std:c++17 /EHsc /MD /O2 /I F:\rtsc\include probe_accept_vector.cpp /Fe:pav.exe /link /LIBPATH:F:\rtsc\build\Release rtsc_crypto.lib rtsc_proto.lib rtsc_util.lib bcrypt.lib > pav.log 2>&1
echo BUILD=%ERRORLEVEL%
findstr /C:"error C" /C:"error LNK" pav.log
if exist pav.exe ( pav.exe & echo RC=%ERRORLEVEL% )
