# WFP Firewall Manager

基于 Windows Filtering Platform (WFP) 和 WinDivert 的轻量级防火墙管理工具。

## 功能特性

- **IP 白名单** - 支持 IPv4/IPv6 地址白名单，启用后只有白名单中的 IP 才能入站连接
- **MAC 白名单** - 基于 MAC 地址的访问控制，防止 IP 伪造攻击
- **CVE 防护** - 内置多个高危漏洞防护：
  - CVE-2017-0144 (EternalBlue 永恒之蓝) - 阻断 SMB 445 端口入站
  - CVE-2024-38063 (Windows IPv6 RCE) - 阻断 IPv6 流量
  - CVE-2023-44487 (HTTP/2 Rapid Reset) - 防护 HTTPS RST 攻击
  - CVE-2023-38545 (curl SOCKS5) - 阻断 SOCKS5 代理流量
  - CVE-2024-45177 (Windows RDP RCE) - 阻断 RDP 3389 端口入站
  - CVE-2023-23397 (Outlook 权限提升) - 阻断出站 SMB 流量
  - CVE-2021-34527 (PrintNightmare) - 阻断打印机端口 9100
  - CVE-2024-21745 (Windows DNS RCE) - 阻断入站 DNS 流量
  - CVE-2021-44228 (Log4j/Log4Shell) - 检测 JNDI 注入特征
- **局域网扫描** - ARP 表扫描，快速发现局域网设备
- **拦截日志** - 记录所有被拦截的数据包信息
- **系统托盘** - 后台运行，托盘图标控制

## 系统要求

- Windows 10/11 (64位)
- 管理员权限

## 编译

需要 MinGW-w64 或 MSVC 编译器：

```bash
g++ -std=c++17 -O2 -mwindows -I include -I httplib ^
    src/main.cpp src/wfp_manager.cpp src/ip_store.cpp src/api_server.cpp ^
    -o wfp-firewall.exe ^
    -L. -lWinDivert -lws2_32 -liphlpapi -lshell32
```

或直接运行：

```bash
build.bat
```

## 使用方法

1. **以管理员身份运行** `wfp-firewall.exe`
2. 程序启动后自动最小化到系统托盘
3. 打开浏览器访问 `http://localhost:8080`
4. 右键托盘图标可打开控制台或退出程序

## 命令行参数

| 参数 | 说明 |
|------|------|
| `-h, --host` | 监听地址 (默认: 127.0.0.1) |
| `-p, --port` | 监听端口 (默认: 8080) |
| `--enable-cve` | 启用 CVE 防护 |
| `--help` | 显示帮助信息 |

## 配置文件

- `settings.json` - 统一配置文件，包含：
  - IP 过滤开关状态
  - MAC 过滤开关状态
  - IP 白名单列表
  - MAC 白名单列表
  - CVE 防护配置
- `block_logs/` - 拦截日志目录

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/ips` | 获取 IP 白名单列表 |
| POST | `/api/ips` | 添加 IP 到白名单 |
| DELETE | `/api/ips` | 从白名单移除 IP |
| DELETE | `/api/ips/all` | 清空 IP 白名单 |
| POST | `/api/ips/toggle` | 开关 IP 过滤 |
| GET | `/api/mac` | 获取 MAC 白名单 |
| POST | `/api/mac` | 添加 MAC 到白名单 |
| DELETE | `/api/mac` | 移除 MAC |
| DELETE | `/api/mac/all` | 清空 MAC 白名单 |
| POST | `/api/mac/toggle` | 开关 MAC 过滤 |
| GET | `/api/lan` | 获取局域网设备 |
| POST | `/api/lan/scan` | 扫描局域网 |
| GET | `/api/logs` | 获取拦截日志 |
| DELETE | `/api/logs` | 清空拦截日志 |
| GET | `/api/cve/status` | 获取 CVE 防护状态 |
| POST | `/api/cve/toggle` | 开关 CVE 防护 |
| GET | `/api/status` | 获取整体状态 |

## 依赖

- [WinDivert](https://reqrypt.org/windivert.html) - Windows 数据包拦截库
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) - C++ HTTP 库

## 许可证

MIT License