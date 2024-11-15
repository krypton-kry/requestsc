@echo off

pushd build
cl /Zi /nologo /I ..\external /I ..\external\BearSSL ..\code\main.c /Fe:main.exe Ws2_32.lib libssl.lib libcrypto.lib
popd
