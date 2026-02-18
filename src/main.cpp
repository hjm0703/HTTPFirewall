#include "wfp_manager.h"
#include "ip_store.h"
#include "api_server.h"

#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <csignal>
#include <memory>
#include <cstdio>
#include <string>
#include <thread>

// 托盘图标 ID
#define ID_TRAY_ICON 1001
#define ID_MENU_OPEN 1002
#define ID_MENU_EXIT 1003

std::unique_ptr<ApiServer> g_server;
std::atomic<bool> g_stopped{false};  // 防止重复调用 stop
HWND g_hwnd = nullptr;
bool g_running = true;
NOTIFYICONDATA g_nid = {};

// 创建托盘图标
void createTrayIcon(HWND hwnd) {
    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(NOTIFYICONDATA);
    g_nid.hWnd = hwnd;
    g_nid.uID = ID_TRAY_ICON;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_USER + 1;
    g_nid.hIcon = LoadIcon(NULL, IDI_SHIELD);  // 使用盾牌图标
    strcpy_s(g_nid.szTip, "WFP Firewall Manager");
    Shell_NotifyIcon(NIM_ADD, &g_nid);
}

// 删除托盘图标
void removeTrayIcon() {
    Shell_NotifyIcon(NIM_DELETE, &g_nid);
}

// 显示托盘菜单
void showTrayMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    
    HMENU hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING, ID_MENU_OPEN, "打开控制台");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, ID_MENU_EXIT, "退出");
    
    // 需要设置前台窗口，否则菜单可能不会正确关闭
    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_BOTTOMALIGN | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

// 窗口过程
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_USER + 1:  // 托盘图标消息
            if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_LBUTTONUP) {
                showTrayMenu(hwnd);
            }
            break;
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_MENU_OPEN:
                    // 显示控制台窗口
                    ShowWindow(GetConsoleWindow(), SW_SHOW);
                    SetForegroundWindow(GetConsoleWindow());
                    break;
                case ID_MENU_EXIT:
                    // 退出程序
                    g_running = false;
                    if (g_server && !g_stopped.exchange(true)) {
                        g_server->stop();
                    }
                    PostQuitMessage(0);
                    break;
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// 创建隐藏窗口（用于接收托盘消息）
HWND createMessageWindow(HINSTANCE hInstance) {
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "WfpFirewallTray";
    RegisterClassEx(&wc);
    
    return CreateWindowEx(0, "WfpFirewallTray", "WFP Firewall", 0, 
                          0, 0, 0, 0, HWND_MESSAGE, NULL, hInstance, NULL);
}

void signalHandler(int) {
    std::cout << "\nShutting down..." << std::endl;
    g_running = false;
    if (g_server && !g_stopped.exchange(true)) {
        g_server->stop();
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 分配控制台
    AllocConsole();
    
    // 设置控制台代码页为 UTF-8
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    
    // 重定向标准流
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    freopen_s(&fp, "CONIN$", "r", stdin);
    
    // 设置标准流为 UTF-8
    setvbuf(stdout, nullptr, _IOFBF, 4096);
    setvbuf(stderr, nullptr, _IOFBF, 4096);
    
    // 隐藏控制台窗口
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    std::cout << R"(
===============================================
    WFP Firewall Manager
    IP/MAC Whitelist & CVE Protection
===============================================
)" << std::endl;

    // 解析命令行参数
    int argc = __argc;
    char** argv = __argv;

    // Check admin
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    if (!isAdmin) {
        std::cerr << "\n[ERROR] Requires Administrator privileges!" << std::endl;
        std::cerr << "Please run as Administrator." << std::endl;
        MessageBox(NULL, "需要管理员权限运行！", "WFP Firewall Manager", MB_OK | MB_ICONERROR);
        return 1;
    }

    WfpManager wfp;
    if (!wfp.initialize()) {
        std::cerr << "\n[ERROR] WFP init failed: " << wfp.getLastError() << std::endl;
        MessageBox(NULL, ("WFP 初始化失败: " + wfp.getLastError()).c_str(), "WFP Firewall Manager", MB_OK | MB_ICONERROR);
        return 1;
    }
    std::cout << "[OK] WFP initialized" << std::endl;

    // 加载配置文件 (settings.json)
    IpStore store("settings.json");
    store.load();
    std::cout << "[OK] Config loaded from settings.json" << std::endl;

    // Restore IP filter status
    if (store.isIpFilterEnabled()) {
        wfp.setIpFilterEnabled(true);
        std::cout << "[OK] IP filter restored (enabled)" << std::endl;
    }

    // Restore MAC filter status
    if (store.isMacFilterEnabled()) {
        wfp.setMacFilterEnabled(true);
        std::cout << "[OK] MAC filter restored (enabled)" << std::endl;
    }

    // Restore IP whitelist
    auto ips = store.getAllIps();
    for (const auto& r : ips) {
        bool ok = wfp.addIpToWhitelist(r.ip, r.description);
        std::cout << (ok ? "[OK]" : "[ERR]") << " Restored IP whitelist: " << r.ip << std::endl;
    }
    std::cout << "[OK] Restored " << ips.size() << " IPs to whitelist" << std::endl;

    // Restore MAC whitelist
    auto macs = store.getAllMacs();
    for (const auto& m : macs) {
        bool ok = wfp.addMacToWhitelist(m.mac, m.description, m.ipv4);
        std::cout << (ok ? "[OK]" : "[ERR]") << " Restored MAC whitelist: " << m.mac << std::endl;
    }
    std::cout << "[OK] Restored " << macs.size() << " MACs to whitelist" << std::endl;

    // Restore CVE protections
    if (store.isCve2017_0144Enabled()) {
        wfp.enableCve2017_0144Protection();
        std::cout << "[OK] CVE-2017-0144 (EternalBlue) protection restored" << std::endl;
    }
    if (store.isCve2024_38063Enabled()) {
        wfp.enableCve2024_38063Protection();
        std::cout << "[OK] CVE-2024-38063 protection restored" << std::endl;
    }
    if (store.isCve2023_44487Enabled()) {
        wfp.enableCve2023_44487Protection();
        std::cout << "[OK] CVE-2023-44487 protection restored" << std::endl;
    }
    if (store.isCve2023_38545Enabled()) {
        wfp.enableCve2023_38545Protection();
        std::cout << "[OK] CVE-2023-38545 protection restored" << std::endl;
    }
    if (store.isCve2024_45177Enabled()) {
        wfp.enableCve2024_45177Protection();
        std::cout << "[OK] CVE-2024-45177 (RDP) protection restored" << std::endl;
    }
    if (store.isCve2023_23397Enabled()) {
        wfp.enableCve2023_23397Protection();
        std::cout << "[OK] CVE-2023-23397 (Outlook) protection restored" << std::endl;
    }
    if (store.isCve2021_34527Enabled()) {
        wfp.enableCve2021_34527Protection();
        std::cout << "[OK] CVE-2021-34527 (PrintNightmare) protection restored" << std::endl;
    }
    if (store.isCve2024_21745Enabled()) {
        wfp.enableCve2024_21745Protection();
        std::cout << "[OK] CVE-2024-21745 (DNS) protection restored" << std::endl;
    }
    if (store.isCve2021_44228Enabled()) {
        wfp.enableCve2021_44228Protection();
        std::cout << "[OK] CVE-2021-44228 (Log4j) protection restored" << std::endl;
    }

    g_server = std::make_unique<ApiServer>(wfp, store);
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::string host = "127.0.0.1";  // 只监听本地，拒绝外部访问
    int port = 8080;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if ((a == "-p" || a == "--port") && i + 1 < argc) port = std::atoi(argv[++i]);
        else if ((a == "-h" || a == "--host") && i + 1 < argc) host = argv[++i];
        else if (a == "--enable-cve") {
            if (wfp.enableCve2024_38063Protection()) {
                store.setCve2024_38063Enabled(true);
                std::cout << "[OK] CVE protection enabled" << std::endl;
            }
        } else if (a == "--help") {
            ShowWindow(GetConsoleWindow(), SW_SHOW);
            std::cout << "Usage: " << argv[0] << " [-h host] [-p port] [--enable-cve]" << std::endl;
            return 0;
        }
    }

    // 创建消息窗口和托盘图标
    g_hwnd = createMessageWindow(hInstance);
    createTrayIcon(g_hwnd);

    std::cout << "\n===============================================" << std::endl;
    std::cout << "Server starting..." << std::endl;
    std::cout << "Open http://localhost:" << port << " in browser" << std::endl;
    std::cout << "Minimized to system tray" << std::endl;
    std::cout << "===============================================\n" << std::endl;

    // 在后台线程启动服务器
    // 注意：start() 是阻塞调用，只有 stop() 后才会返回
    std::thread serverThread([&]() {
        if (!g_server->start(host, port)) {
            std::cerr << "\n[ERROR] Failed to start server!" << std::endl;
            g_running = false;
            PostMessage(g_hwnd, WM_QUIT, 0, 0);
        }
    });

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) && g_running) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 清理
    g_running = false;
    
    // 停止服务器 - 使用原子标志防止重复调用
    if (g_server && !g_stopped.exchange(true)) {
        g_server->stop();
    }
    
    if (serverThread.joinable()) {
        serverThread.join();
    }
    
    removeTrayIcon();
    
    std::cout << "Server stopped." << std::endl;
    FreeConsole();
    
    return 0;
}

