@echo off
setlocal
rem Locate a C++17 compiler: prefer the MSYS2 UCRT64 toolchain, fall back to PATH.
set "CXX=C:\msys64\ucrt64\bin\g++.exe"
if not exist "%CXX%" set "CXX=g++"

"%CXX%" -std=c++17 -O2 -Wall -Wextra -static -o "%~dp0pclautopatch.exe" "%~dp0pclautopatch.cpp"
if errorlevel 1 (
    echo Build failed. Install MSYS2 ^(UCRT64^) or put g++ on PATH.
    exit /b 1
)
echo Built: %~dp0pclautopatch.exe
endlocal
