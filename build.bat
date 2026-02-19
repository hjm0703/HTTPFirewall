@echo off
g++ -std=c++17 -O2 -mwindows -I include -I httplib ^
    src/main.cpp src/wfp_manager.cpp src/ip_store.cpp src/api_server.cpp ^
    -o wfp-firewall.exe ^
    -L. -lWinDivert -lws2_32 -liphlpapi -lpsapi -lshell32 -fexec-charset=GBK
if %errorlevel%==0 (
    echo Build success: wfp-firewall.exe
) else (
    echo Build failed
)