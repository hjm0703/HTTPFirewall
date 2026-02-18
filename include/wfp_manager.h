#ifndef WFP_MANAGER_H
#define WFP_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <thread>
#include <atomic>
#include <mutex>
#include <deque>

// IP 地址类型
enum class IpType {
    IPv4,
    IPv6
};

// IP 白名单规则结构
struct IpWhitelistEntry {
    std::string ip;
    std::string description;
    bool isActive;
    IpType ipType;
};

// CVE 防护状态
struct CveProtectionStatus {
    // CVE-2017-0144: EternalBlue (永恒之蓝) - SMB RCE
    bool cve2017_0144;
    // CVE-2024-38063: Windows IPv6 RCE
    bool cve2024_38063;
    // CVE-2024-21320: Windows SmartScreen 绕过
    bool cve2024_21320;
    // CVE-2024-21412: Windows SmartAppControl 绕过
    bool cve2024_21412;
    // CVE-2023-44487: HTTP/2 Rapid Reset DoS
    bool cve2023_44487;
    // CVE-2023-4863: WebP 堆缓冲区溢出
    bool cve2023_4863;
    // CVE-2023-38545: curl SOCKS5 堆溢出
    bool cve2023_38545;
    // CVE-2024-45177: Windows RDP 远程代码执行
    bool cve2024_45177;
    // CVE-2023-23397: Microsoft Outlook 权限提升
    bool cve2023_23397;
    // CVE-2021-34527: PrintNightmare 打印机漏洞
    bool cve2021_34527;
    // CVE-2024-21745: Windows DNS Server RCE
    bool cve2024_21745;
    // CVE-2021-44228: Log4j 远程代码执行
    bool cve2021_44228;
    // 全局 IPv6 阻断
    bool ipv6Blocked;
};

// 局域网设备信息
struct LanDevice {
    std::string hostname;
    std::string ipv4;
    std::string ipv6;
    std::string mac;
    bool isReachable;
};

// 拦截日志条目
struct BlockLogEntry {
    std::string timestamp;      // 时间戳
    std::string srcIp;          // 源 IP
    std::string dstIp;          // 目标 IP
    std::string protocol;       // 协议 (TCP/UDP/ICMP/IPv6)
    uint16_t srcPort;           // 源端口
    uint16_t dstPort;           // 目标端口
    std::string direction;      // 方向 (inbound/outbound)
    std::string blockedIp;      // 触发拦截的 IP
    std::string filename;       // 日志文件名
};

// MAC 白名单条目
struct MacWhitelistEntry {
    std::string mac;            // MAC 地址 (XX:XX:XX:XX:XX:XX)
    std::string description;    // 描述/设备名
    std::string ipv4;           // 关联的 IPv4
    bool isActive;              // 是否启用
};

// WinDivert 防火墙管理器
class WfpManager {
public:
    WfpManager();
    ~WfpManager();

    bool initialize();
    void cleanup();

    // IP 白名单
    bool addIpToWhitelist(const std::string& ip, const std::string& description = "");
    bool removeIpFromWhitelist(const std::string& ip);
    std::vector<IpWhitelistEntry> getIpWhitelist() const;
    bool isIpWhitelisted(const std::string& ip) const;
    bool isIpFilterEnabled() const;
    void setIpFilterEnabled(bool enabled);
    bool clearIpWhitelist();
    int getIpWhitelistCount() const;

    // CVE 防护
    // CVE-2017-0144: EternalBlue (永恒之蓝) - SMB端口445 RCE
    bool enableCve2017_0144Protection();
    bool disableCve2017_0144Protection();
    
    // CVE-2024-38063: Windows IPv6 RCE (CVSS 9.8) - 阻断所有 IPv6
    bool enableCve2024_38063Protection();
    bool disableCve2024_38063Protection();
    
    // CVE-2023-44487: HTTP/2 Rapid Reset DoS - 限制 HTTP/2 连接速率
    bool enableCve2023_44487Protection();
    bool disableCve2023_44487Protection();
    
    // CVE-2023-38545: curl SOCKS5 堆溢出 - 阻断 SOCKS5 流量
    bool enableCve2023_38545Protection();
    bool disableCve2023_38545Protection();
    
    // CVE-2024-45177: Windows RDP 远程代码执行 - 阻断 RDP 3389 入站
    bool enableCve2024_45177Protection();
    bool disableCve2024_45177Protection();
    
    // CVE-2023-23397: Microsoft Outlook 权限提升 - 阻断可疑 UNC 路径流量
    bool enableCve2023_23397Protection();
    bool disableCve2023_23397Protection();
    
    // CVE-2021-34527: PrintNightmare 打印机漏洞 - 阻断打印机端口 9100
    bool enableCve2021_34527Protection();
    bool disableCve2021_34527Protection();
    
    // CVE-2024-21745: Windows DNS Server RCE - 阻断异常 DNS 流量
    bool enableCve2024_21745Protection();
    bool disableCve2024_21745Protection();
    
    // CVE-2021-44228: Log4j 远程代码执行 - 检测 JNDI 注入特征
    bool enableCve2021_44228Protection();
    bool disableCve2021_44228Protection();
    
    CveProtectionStatus getCveProtectionStatus() const;
    bool isCveProtectionEnabled() const;
    void setCveProtection(const std::string& cveId, bool enabled);

    // MAC 白名单
    bool addMacToWhitelist(const std::string& mac, const std::string& description = "", const std::string& ipv4 = "");
    bool removeMacFromWhitelist(const std::string& mac);
    std::vector<MacWhitelistEntry> getMacWhitelist() const;
    bool isMacWhitelisted(const std::string& mac) const;
    bool isMacFilterEnabled() const;
    void setMacFilterEnabled(bool enabled);
    bool clearMacWhitelist();
    int getMacWhitelistCount() const;

    // 局域网扫描
    std::vector<LanDevice> scanLan();
    std::vector<LanDevice> getLastLanScan() const;

    // 拦截日志功能
    void setLoggingEnabled(bool enabled);
    bool isLoggingEnabled() const;
    std::vector<BlockLogEntry> getBlockLogs() const;
    void clearBlockLogs();
    int getBlockLogCount() const;

    // 通用方法
    std::string getLastError() const;
    IpType detectIpType(const std::string& ip) const;

private:
    void* divertHandle_;                    // WinDivert 句柄
    std::vector<IpWhitelistEntry> ipWhitelist_;  // IP 白名单
    std::vector<LanDevice> lanDevices_;      // 局域网设备
    mutable std::mutex mutex_;               // 线程安全锁
    std::string lastError_;                  // 最后错误信息
    CveProtectionStatus cveStatus_;          // CVE 防护状态
    std::atomic<bool> running_;              // 运行标志
    std::thread packetThread_;               // 数据包处理线程
    
    // WinDivert 过滤器字符串
    std::string filterString_;
    
    // 拦截日志
    std::deque<BlockLogEntry> blockLogs_;    // 内存日志队列（最多100条）
    std::atomic<bool> loggingEnabled_;       // 日志开关
    int logFileCount_;                       // 日志文件计数
    std::string logDir_;                     // 日志目录
    
    // MAC 白名单
    std::vector<MacWhitelistEntry> macWhitelist_;  // MAC 白名单
    std::atomic<bool> macFilterEnabled_;           // MAC 过滤开关
    
    // IP 白名单过滤开关
    std::atomic<bool> ipFilterEnabled_;            // IP 过滤开关
    
    // 内部方法
    bool isValidIpv4(const std::string& ip) const;
    bool isValidIpv6(const std::string& ip) const;
    bool isValidMac(const std::string& mac) const;
    std::string normalizeMac(const std::string& mac) const;
    void rebuildFilter();
    void packetLoop();
    void logBlockedPacket(const std::string& srcIp, const std::string& dstIp, 
                          const std::string& protocol, uint16_t srcPort, uint16_t dstPort,
                          const std::string& direction, const std::string& blockedIp);
    void saveLogToFile(const BlockLogEntry& entry);
    void rotateLogFiles();
};

#endif
