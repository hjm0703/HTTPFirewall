#include "wfp_manager.h"

// 先包含标准库头文件
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <fstream>
#include <ctime>
#include <filesystem>

// Winsock2 必须在 windows.h 之前包含
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <windivert.h>

#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

WfpManager::WfpManager() : divertHandle_(nullptr), running_(false), loggingEnabled_(true), logFileCount_(0), macFilterEnabled_(false), ipFilterEnabled_(false) {
    // 初始化所有 CVE 防护状态
    cveStatus_.cve2017_0144 = false;
    cveStatus_.cve2024_38063 = false;
    cveStatus_.cve2024_21320 = false;
    cveStatus_.cve2024_21412 = false;
    cveStatus_.cve2023_44487 = false;
    cveStatus_.cve2023_4863 = false;
    cveStatus_.cve2023_38545 = false;
    cveStatus_.cve2024_45177 = false;
    cveStatus_.cve2023_23397 = false;
    cveStatus_.cve2021_34527 = false;
    cveStatus_.cve2024_21745 = false;
    cveStatus_.cve2021_44228 = false;
    cveStatus_.ipv6Blocked = false;
    cveStatus_.highRiskPortsBlocked = false;
    logDir_ = "block_logs";
}

WfpManager::~WfpManager() {
    cleanup();
}

bool WfpManager::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 初始过滤器：放行所有流量
    filterString_ = "true";
    
    // 创建日志目录
    if (!CreateDirectoryA(logDir_.c_str(), nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            std::ostringstream oss;
            oss << "Failed to create log directory: " << err;
            lastError_ = oss.str();
            // 非致命错误，继续执行
        }
    }
    
    // 打开 WinDivert
    divertHandle_ = WinDivertOpen(filterString_.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (divertHandle_ == nullptr) {
        DWORD err = GetLastError();
        std::ostringstream oss;
        oss << "WinDivertOpen failed: " << err << " (0x" << std::hex << err << ")";
        if (err == 5) {
            oss << " - Need Administrator privileges!";
        }
        lastError_ = oss.str();
        return false;
    }
    
    // 启动数据包处理线程
    running_ = true;
    packetThread_ = std::thread(&WfpManager::packetLoop, this);
    
    return true;
}

void WfpManager::cleanup() {
    running_ = false;
    
    if (packetThread_.joinable()) {
        packetThread_.join();
    }
    
    if (divertHandle_ != nullptr) {
        WinDivertClose(divertHandle_);
        divertHandle_ = nullptr;
    }
    
    ipWhitelist_.clear();
    cveStatus_.ipv6Blocked = false;
    cveStatus_.cve2024_38063 = false;
}

void WfpManager::rebuildFilter() {
    std::ostringstream filter;
    filter << "true";
    
    // IP 白名单过滤：不在白名单中的入站IP将被拦截
    if (ipFilterEnabled_ && !ipWhitelist_.empty()) {
        filter << " and (";
        bool first = true;
        
        for (const auto& entry : ipWhitelist_) {
            if (!entry.isActive) continue;
            
            if (!first) filter << " or ";
            first = false;
            
            if (entry.ipType == IpType::IPv4) {
                filter << "(ip.SrcAddr = " << entry.ip << ")";
            } else {
                filter << "(ipv6.SrcAddr = " << entry.ip << ")";
            }
        }
        filter << ")";
    }
    
    // CVE IPv6 全局阻断
    if (cveStatus_.ipv6Blocked) {
        filter << " and (not ipv6)";  // 阻断所有 IPv6
    }
    
    filterString_ = filter.str();
}

void WfpManager::packetLoop() {
    WINDIVERT_ADDRESS addr;
    char packet[65535];
    UINT packetLen;
    
    while (running_ && divertHandle_ != nullptr) {
        // 接收数据包
        if (!WinDivertRecv(divertHandle_, packet, sizeof(packet), &packetLen, &addr)) {
            DWORD err = GetLastError();
            if (err == 995) { // ERROR_OPERATION_ABORTED - 正常关闭
                break;
            }
            continue;
        }
        
        // 解析数据包
        PWINDIVERT_IPHDR ipHdr = nullptr;
        PWINDIVERT_IPV6HDR ipv6Hdr = nullptr;
        UINT8 protocol;
        PWINDIVERT_ICMPHDR icmpHdr = nullptr;
        PWINDIVERT_ICMPV6HDR icmpv6Hdr = nullptr;
        PWINDIVERT_TCPHDR tcpHdr = nullptr;
        PWINDIVERT_UDPHDR udpHdr = nullptr;
        WinDivertHelperParsePacket(packet, packetLen, &ipHdr, &ipv6Hdr, &protocol, &icmpHdr, &icmpv6Hdr, &tcpHdr, &udpHdr, nullptr, nullptr, nullptr, nullptr);
        
        bool shouldDrop = false;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // 检查 IPv6 全局阻断
            if (ipv6Hdr != nullptr && cveStatus_.ipv6Blocked) {
                shouldDrop = true;
            }
            
            // IP 白名单过滤（仅对入站流量）
            // 只拦截 192.x.x.x 和 172.16-31.x.x 私有网段中不在白名单的 IP
            // 其他 IP（公网、10.x、127.x 等）全部放行
            if (!shouldDrop && ipFilterEnabled_ && !addr.Outbound && ipHdr != nullptr) {
                // 获取源 IP
                UINT32 srcAddr = ipHdr->SrcAddr;
                uint8_t b1 = (srcAddr >> 0) & 0xFF;   // 第一段
                uint8_t b2 = (srcAddr >> 8) & 0xFF;   // 第二段
                
                // 检查是否是私有网段 192.x.x.x 或 172.16-31.x.x
                bool isPrivate192 = (b1 == 192);
                bool isPrivate172 = (b1 == 172 && b2 >= 16 && b2 <= 31);
                
                // 只对私有网段进行白名单检查
                if (isPrivate192 || isPrivate172) {
                    bool inWhitelist = false;
                    
                    // 检查源 IP 是否在白名单中
                    for (const auto& entry : ipWhitelist_) {
                        if (!entry.isActive || entry.ipType != IpType::IPv4) continue;
                        
                        IN_ADDR whitelistAddr;
                        inet_pton(AF_INET, entry.ip.c_str(), &whitelistAddr);
                        
                        if (srcAddr == whitelistAddr.S_un.S_addr) {
                            inWhitelist = true;
                            break;
                        }
                    }
                    
                    // 如果私有 IP 不在白名单中，拦截
                    if (!inWhitelist) {
                        shouldDrop = true;
                    }
                }
                // 其他 IP（公网、10.x、127.x 等）自动放行
            }
            
            // MAC 白名单过滤（仅对入站 IPv4 流量）
            if (!shouldDrop && macFilterEnabled_ && !addr.Outbound && ipHdr != nullptr) {
                // 获取源 IP 对应的 MAC 地址
                UINT32 srcAddr = ipHdr->SrcAddr;
                
                // 通过 ARP 表查找 MAC
                PMIB_IPNETTABLE pIpNetTable = nullptr;
                ULONG size = 0;
                
                if (GetIpNetTable(nullptr, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                    pIpNetTable = (PMIB_IPNETTABLE)malloc(size);
                    if (pIpNetTable) {
                        if (GetIpNetTable(pIpNetTable, &size, FALSE) == NO_ERROR) {
                            bool found = false;
                            for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                                if (pIpNetTable->table[i].dwAddr == srcAddr) {
                                    // 找到 MAC 地址
                                    char macStr[18];
                                    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                                        pIpNetTable->table[i].bPhysAddr[0], pIpNetTable->table[i].bPhysAddr[1],
                                        pIpNetTable->table[i].bPhysAddr[2], pIpNetTable->table[i].bPhysAddr[3],
                                        pIpNetTable->table[i].bPhysAddr[4], pIpNetTable->table[i].bPhysAddr[5]);
                                    
                                    // 检查是否在白名单中
                                    if (!isMacWhitelisted(macStr)) {
                                        shouldDrop = true;
                                    }
                                    found = true;
                                    break;
                                }
                            }
                            // 如果源 IP 不在 ARP 表中（可能是本机或路由器），放行
                            if (!found) {
                                // 检查是否是本机 IP
                                PMIB_IPADDRTABLE pIpAddrTable = nullptr;
                                ULONG addrSize = 0;
                                if (GetIpAddrTable(nullptr, &addrSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
                                    pIpAddrTable = (PMIB_IPADDRTABLE)malloc(addrSize);
                                    if (pIpAddrTable) {
                                        if (GetIpAddrTable(pIpAddrTable, &addrSize, FALSE) == NO_ERROR) {
                                            bool isLocal = false;
                                            for (DWORD i = 0; i < pIpAddrTable->dwNumEntries; i++) {
                                                if (pIpAddrTable->table[i].dwAddr == srcAddr) {
                                                    isLocal = true;
                                                    break;
                                                }
                                            }
                                            // 本机流量放行，非本机且不在 ARP 表中可能是伪造 IP
                                            if (!isLocal) {
                                                // 对于不在 ARP 表中的外部 IP，可能是伪造的
                                                // 这里选择放行，因为无法确定其 MAC
                                                // 如果需要更严格，可以设置 shouldDrop = true
                                            }
                                        }
                                        free(pIpAddrTable);
                                    }
                                }
                            }
                        }
                        free(pIpNetTable);
                    }
                }
            }
            
            // CVE-2023-38545: 阻断 SOCKS5 代理流量（端口 1080）
            if (!shouldDrop && cveStatus_.cve2023_38545 && tcpHdr != nullptr) {
                uint16_t dstPort = ntohs(tcpHdr->DstPort);
                uint16_t srcPort = ntohs(tcpHdr->SrcPort);
                if (dstPort == 1080 || srcPort == 1080) {
                    shouldDrop = true;
                }
            }
            
            // CVE-2017-0144: EternalBlue (永恒之蓝) - 阻断 SMB 端口 445 入站流量
            if (!shouldDrop && cveStatus_.cve2017_0144 && tcpHdr != nullptr && !addr.Outbound) {
                uint16_t dstPort = ntohs(tcpHdr->DstPort);
                // 阻断入站到 445 端口的连接
                if (dstPort == 445) {
                    shouldDrop = true;
                }
            }
            
            // CVE-2023-44487: HTTP/2 Rapid Reset DoS 防护
            // 检测异常的 RST_STREAM 帧（通过端口443的HTTPS流量）
            // 这里简化处理：对HTTPS端口的异常连接进行限制
            if (!shouldDrop && cveStatus_.cve2023_44487 && tcpHdr != nullptr) {
                uint16_t dstPort = ntohs(tcpHdr->DstPort);
                uint16_t srcPort = ntohs(tcpHdr->SrcPort);
                // 检测到443端口的RST标志，可能是HTTP/2 Rapid Reset攻击
                if ((dstPort == 443 || srcPort == 443) && tcpHdr->Rst) {
                    shouldDrop = true;
                }
            }
            
            // CVE-2024-45177: Windows RDP 远程代码执行 - 阻断 RDP 3389 入站
            if (!shouldDrop && cveStatus_.cve2024_45177 && tcpHdr != nullptr && !addr.Outbound) {
                uint16_t dstPort = ntohs(tcpHdr->DstPort);
                if (dstPort == 3389) {
                    shouldDrop = true;
                }
            }
            
            // CVE-2023-23397: Microsoft Outlook 权限提升 - 阻断可疑 UNC 路径流量
            // 该漏洞通过 Outlook 日历/任务项中的 UNC 路径窃取 NTLM 凭证
            // 防护：阻断到 445 端口的出站 SMB 流量（入站已由 EternalBlue 防护覆盖）
            if (!shouldDrop && cveStatus_.cve2023_23397 && tcpHdr != nullptr && addr.Outbound) {
                uint16_t dstPort = ntohs(tcpHdr->DstPort);
                if (dstPort == 445) {
                    shouldDrop = true;
                }
            }
            
            // CVE-2021-34527: PrintNightmare 打印机漏洞 - 阻断打印机端口 9100
            if (!shouldDrop && cveStatus_.cve2021_34527 && tcpHdr != nullptr) {
                uint16_t dstPort = ntohs(tcpHdr->DstPort);
                uint16_t srcPort = ntohs(tcpHdr->SrcPort);
                if (dstPort == 9100 || srcPort == 9100) {
                    shouldDrop = true;
                }
            }
            
            // CVE-2024-21745: Windows DNS Server RCE - 阻断异常 DNS 流量
            // 阻断入站的 53 端口（防止外部 DNS 攻击）
            if (!shouldDrop && cveStatus_.cve2024_21745 && !addr.Outbound) {
                if (udpHdr != nullptr) {
                    uint16_t dstPort = ntohs(udpHdr->DstPort);
                    if (dstPort == 53) {
                        shouldDrop = true;
                    }
                } else if (tcpHdr != nullptr) {
                    uint16_t dstPort = ntohs(tcpHdr->DstPort);
                    if (dstPort == 53) {
                        shouldDrop = true;
                    }
                }
            }
            
            // CVE-2021-44228: Log4j 远程代码执行 - 检测 JNDI 注入特征
            // 在网络层检测包含 jndi: 字符串的数据包
            if (!shouldDrop && cveStatus_.cve2021_44228 && packetLen > 20) {
                // 简单检测数据包 payload 中是否包含 jndi 特征
                // 注意：这只是网络层的基本检测，应用层防护更有效
                for (size_t i = 0; i + 5 < packetLen; i++) {
                    if ((packet[i] == 'j' || packet[i] == 'J') &&
                        (packet[i+1] == 'n' || packet[i+1] == 'N') &&
                        (packet[i+2] == 'd' || packet[i+2] == 'D') &&
                        (packet[i+3] == 'i' || packet[i+3] == 'I') &&
                        packet[i+4] == ':') {
                        shouldDrop = true;
                        break;
                    }
                }
            }
            
            // 高危端口防护 - 阻断 135, 137, 138, 139, 445 端口的入站流量
            // 这些端口是 Windows 系统中最常被攻击的高风险端口
            if (!shouldDrop && cveStatus_.highRiskPortsBlocked && !addr.Outbound) {
                uint16_t dstPort = 0;
                uint16_t srcPort = 0;
                
                if (tcpHdr != nullptr) {
                    dstPort = ntohs(tcpHdr->DstPort);
                    srcPort = ntohs(tcpHdr->SrcPort);
                } else if (udpHdr != nullptr) {
                    dstPort = ntohs(udpHdr->DstPort);
                    srcPort = ntohs(udpHdr->SrcPort);
                }
                
                // 高危端口列表：135(RPC), 137-139(NetBIOS), 445(SMB)
                if (dstPort == 135 || dstPort == 137 || dstPort == 138 || 
                    dstPort == 139 || dstPort == 445) {
                    shouldDrop = true;
                }
            }
        }
        
        if (shouldDrop) {
            // 记录拦截日志
            if (loggingEnabled_) {
                std::string srcIp, dstIp, protocolStr, blockedIp;
                uint16_t srcPort = 0, dstPort = 0;
                
                if (ipHdr != nullptr) {
                    char srcStr[INET_ADDRSTRLEN], dstStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ipHdr->SrcAddr, srcStr, sizeof(srcStr));
                    inet_ntop(AF_INET, &ipHdr->DstAddr, dstStr, sizeof(dstStr));
                    srcIp = srcStr;
                    dstIp = dstStr;
                    
                    // 确定哪个 IP 触发了拦截
                    blockedIp = srcIp;  // 白名单模式下，是源IP不在白名单中
                    
                    // 协议
                    switch (protocol) {
                        case IPPROTO_TCP: protocolStr = "TCP"; break;
                        case IPPROTO_UDP: protocolStr = "UDP"; break;
                        case IPPROTO_ICMP: protocolStr = "ICMP"; break;
                        default: protocolStr = "Other(" + std::to_string((int)protocol) + ")";
                    }
                    
                    // 端口
                    if (tcpHdr != nullptr) {
                        srcPort = ntohs(tcpHdr->SrcPort);
                        dstPort = ntohs(tcpHdr->DstPort);
                    } else if (udpHdr != nullptr) {
                        srcPort = ntohs(udpHdr->SrcPort);
                        dstPort = ntohs(udpHdr->DstPort);
                    }
                } else if (ipv6Hdr != nullptr) {
                    char srcStr[INET6_ADDRSTRLEN], dstStr[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, ipv6Hdr->SrcAddr, srcStr, sizeof(srcStr));
                    inet_ntop(AF_INET6, ipv6Hdr->DstAddr, dstStr, sizeof(dstStr));
                    srcIp = srcStr;
                    dstIp = dstStr;
                    protocolStr = "IPv6";
                    blockedIp = "IPv6-Global-Block";
                }
                
                // 方向 - WinDivert 使用 Outbound 标志
                std::string direction = addr.Outbound ? "outbound" : "inbound";
                
                // 记录日志
                logBlockedPacket(srcIp, dstIp, protocolStr, srcPort, dstPort, direction, blockedIp);
            }
            
            // 丢弃数据包
            continue;
        }
        
        // 放行数据包
        if (!WinDivertSend(divertHandle_, packet, packetLen, nullptr, &addr)) {
            // 发送失败，记录错误但不中断循环
            DWORD err = GetLastError();
            if (err != 995) { // 忽略 ERROR_OPERATION_ABORTED
                // 可以选择记录日志，但为避免日志过多，这里静默处理
            }
        }
    }
}

IpType WfpManager::detectIpType(const std::string& ip) const {
    if (isValidIpv4(ip)) return IpType::IPv4;
    if (isValidIpv6(ip)) return IpType::IPv6;
    return IpType::IPv4;
}

bool WfpManager::isValidIpv4(const std::string& ip) const {
    IN_ADDR addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

bool WfpManager::isValidIpv6(const std::string& ip) const {
    IN6_ADDR addr;
    return inet_pton(AF_INET6, ip.c_str(), &addr) == 1;
}

// ==================== IP 白名单功能 ====================

bool WfpManager::addIpToWhitelist(const std::string& ip, const std::string& description) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    IpType ipType = detectIpType(ip);
    if (ipType == IpType::IPv4 && !isValidIpv4(ip)) {
        lastError_ = "Invalid IPv4 address: " + ip;
        return false;
    }
    if (ipType == IpType::IPv6 && !isValidIpv6(ip)) {
        lastError_ = "Invalid IPv6 address: " + ip;
        return false;
    }
    
    if (isIpWhitelisted(ip)) {
        lastError_ = "IP already in whitelist: " + ip;
        return false;
    }
    
    IpWhitelistEntry entry;
    entry.ip = ip;
    entry.description = description;
    entry.isActive = true;
    entry.ipType = ipType;
    ipWhitelist_.push_back(entry);
    
    return true;
}

bool WfpManager::removeIpFromWhitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = std::find_if(ipWhitelist_.begin(), ipWhitelist_.end(), 
        [&ip](const IpWhitelistEntry& e) { return e.ip == ip; });
    
    if (it == ipWhitelist_.end()) {
        lastError_ = "IP not found: " + ip;
        return false;
    }
    
    ipWhitelist_.erase(it);
    return true;
}

std::vector<IpWhitelistEntry> WfpManager::getIpWhitelist() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ipWhitelist_;
}

bool WfpManager::isIpWhitelisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::any_of(ipWhitelist_.begin(), ipWhitelist_.end(), 
        [&ip](const IpWhitelistEntry& e) { return e.ip == ip; });
}

bool WfpManager::isIpFilterEnabled() const {
    return ipFilterEnabled_;
}

void WfpManager::setIpFilterEnabled(bool enabled) {
    ipFilterEnabled_ = enabled;
}

bool WfpManager::clearIpWhitelist() {
    std::lock_guard<std::mutex> lock(mutex_);
    ipWhitelist_.clear();
    return true;
}

int WfpManager::getIpWhitelistCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(ipWhitelist_.size());
}

// ==================== CVE 防护 ====================

// CVE-2024-38063: Windows TCP/IP IPv6 远程代码执行漏洞
// CVSS 9.8 - 攻击者可通过发送特制 IPv6 数据包远程执行代码
// 防护方式：阻断所有 IPv6 流量
bool WfpManager::enableCve2024_38063Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (cveStatus_.cve2024_38063) {
        return true;
    }
    
    cveStatus_.ipv6Blocked = true;
    cveStatus_.cve2024_38063 = true;
    
    return true;
}

bool WfpManager::disableCve2024_38063Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    cveStatus_.ipv6Blocked = false;
    cveStatus_.cve2024_38063 = false;
    
    return true;
}

// CVE-2017-0144: EternalBlue (永恒之蓝)
// CVSS 8.8 - Windows SMB 远程代码执行漏洞
// 防护方式：阻断 SMB 端口 445 的入站流量
bool WfpManager::enableCve2017_0144Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2017_0144 = true;
    return true;
}

bool WfpManager::disableCve2017_0144Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2017_0144 = false;
    return true;
}

// CVE-2023-44487: HTTP/2 Rapid Reset DoS 攻击
// CVSS 7.5 - 攻击者可发送大量 HTTP/2 RST_STREAM 帧导致 DoS
// 防护方式：限制 HTTP/2 连接（通过阻断 443 端口的异常流量）
bool WfpManager::enableCve2023_44487Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2023_44487 = true;
    return true;
}

bool WfpManager::disableCve2023_44487Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2023_44487 = false;
    return true;
}

// CVE-2023-38545: curl SOCKS5 堆缓冲区溢出
// CVSS 9.8 - 当使用 SOCKS5 代理时可能导致远程代码执行
// 防护方式：阻断 SOCKS5 代理流量（端口 1080）
bool WfpManager::enableCve2023_38545Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2023_38545 = true;
    return true;
}

bool WfpManager::disableCve2023_38545Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2023_38545 = false;
    return true;
}

// CVE-2024-45177: Windows RDP 远程代码执行漏洞
// CVSS 9.8 - 攻击者可通过 RDP 远程执行代码
// 防护方式：阻断 RDP 端口 3389 的入站流量
bool WfpManager::enableCve2024_45177Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2024_45177 = true;
    return true;
}

bool WfpManager::disableCve2024_45177Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2024_45177 = false;
    return true;
}

// CVE-2023-23397: Microsoft Outlook 权限提升漏洞
// CVSS 9.8 - 通过 Outlook 日历/任务项中的 UNC 路径窃取 NTLM 凭证
// 防护方式：阻断出站 SMB 流量（端口 445）
bool WfpManager::enableCve2023_23397Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2023_23397 = true;
    return true;
}

bool WfpManager::disableCve2023_23397Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2023_23397 = false;
    return true;
}

// CVE-2021-34527: PrintNightmare 打印机漏洞
// CVSS 8.8 - Windows 打印后台处理程序远程代码执行
// 防护方式：阻断打印机端口 9100
bool WfpManager::enableCve2021_34527Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2021_34527 = true;
    return true;
}

bool WfpManager::disableCve2021_34527Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2021_34527 = false;
    return true;
}

// CVE-2024-21745: Windows DNS Server 远程代码执行漏洞
// CVSS 8.8 - DNS 服务器缓冲区溢出
// 防护方式：阻断入站 DNS 流量（端口 53）
bool WfpManager::enableCve2024_21745Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2024_21745 = true;
    return true;
}

bool WfpManager::disableCve2024_21745Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2024_21745 = false;
    return true;
}

// CVE-2021-44228: Log4j 远程代码执行漏洞 (Log4Shell)
// CVSS 10.0 - 通过 JNDI 注入实现远程代码执行
// 防护方式：在网络层检测 JNDI 注入特征
bool WfpManager::enableCve2021_44228Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2021_44228 = true;
    return true;
}

bool WfpManager::disableCve2021_44228Protection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.cve2021_44228 = false;
    return true;
}

// ==================== 高危端口防护 ====================
// 阻断 Windows 高危端口：135(RPC), 137-139(NetBIOS), 445(SMB)
// 这些端口是永恒之蓝、冲击波等病毒的主要攻击目标
bool WfpManager::enableHighRiskPortsProtection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.highRiskPortsBlocked = true;
    return true;
}

bool WfpManager::disableHighRiskPortsProtection() {
    std::lock_guard<std::mutex> lock(mutex_);
    cveStatus_.highRiskPortsBlocked = false;
    return true;
}

bool WfpManager::isHighRiskPortsProtected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cveStatus_.highRiskPortsBlocked;
}

CveProtectionStatus WfpManager::getCveProtectionStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cveStatus_;
}

bool WfpManager::isCveProtectionEnabled() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cveStatus_.cve2024_38063 || cveStatus_.cve2023_44487 || cveStatus_.cve2023_38545 ||
           cveStatus_.cve2024_45177 || cveStatus_.cve2023_23397 || cveStatus_.cve2021_34527 ||
           cveStatus_.cve2024_21745 || cveStatus_.cve2021_44228;
}

void WfpManager::setCveProtection(const std::string& cveId, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (cveId == "cve2024_38063") {
        cveStatus_.cve2024_38063 = enabled;
        cveStatus_.ipv6Blocked = enabled;
    } else if (cveId == "cve2023_44487") {
        cveStatus_.cve2023_44487 = enabled;
    } else if (cveId == "cve2023_38545") {
        cveStatus_.cve2023_38545 = enabled;
    } else if (cveId == "cve2024_21320") {
        cveStatus_.cve2024_21320 = enabled;
    } else if (cveId == "cve2024_21412") {
        cveStatus_.cve2024_21412 = enabled;
    } else if (cveId == "cve2023_4863") {
        cveStatus_.cve2023_4863 = enabled;
    } else if (cveId == "cve2017_0144") {
        cveStatus_.cve2017_0144 = enabled;
    } else if (cveId == "cve2024_45177") {
        cveStatus_.cve2024_45177 = enabled;
    } else if (cveId == "cve2023_23397") {
        cveStatus_.cve2023_23397 = enabled;
    } else if (cveId == "cve2021_34527") {
        cveStatus_.cve2021_34527 = enabled;
    } else if (cveId == "cve2024_21745") {
        cveStatus_.cve2024_21745 = enabled;
    } else if (cveId == "cve2021_44228") {
        cveStatus_.cve2021_44228 = enabled;
    } else if (cveId == "highRiskPorts") {
        cveStatus_.highRiskPortsBlocked = enabled;
    }
}

std::string WfpManager::getLastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastError_;
}

// ==================== 局域网扫描 ====================

std::vector<LanDevice> WfpManager::getLastLanScan() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lanDevices_;
}

// 快速获取主机名（带超时，不阻塞）
static std::string getHostnameFast(const std::string& ip) {
    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return "Unknown";
    }
    
    // 创建非阻塞 socket 进行快速探测
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return "Unknown";
    }
    
    // 设置非阻塞模式
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    
    // 尝试连接一个常见端口（触发 ARP 和可能的名称解析）
    sa.sin_port = htons(445);  // SMB 端口
    connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    
    // 使用 select 等待最多 100ms
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;  // 100ms
    
    select(0, nullptr, &writeSet, nullptr, &timeout);
    closesocket(sock);
    
    // 尝试 getnameinfo（通常很快）
    struct sockaddr_in nameSa;
    memset(&nameSa, 0, sizeof(nameSa));
    nameSa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &nameSa.sin_addr);
    
    char host[NI_MAXHOST] = {0};
    // 使用 NI_DGRAM 通常更快
    if (getnameinfo((struct sockaddr*)&nameSa, sizeof(nameSa), host, sizeof(host), nullptr, 0, NI_NAMEREQD | NI_DGRAM) == 0) {
        WSACleanup();
        return std::string(host);
    }
    
    WSACleanup();
    return "Unknown";
}

std::vector<LanDevice> WfpManager::scanLan() {
    std::lock_guard<std::mutex> lock(mutex_);
    lanDevices_.clear();
    
    // 获取 ARP 表
    PMIB_IPNETTABLE pIpNetTable = nullptr;
    ULONG size = 0;
    
    if (GetIpNetTable(nullptr, &size, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        pIpNetTable = (PMIB_IPNETTABLE)malloc(size);
        if (pIpNetTable && GetIpNetTable(pIpNetTable, &size, FALSE) == NO_ERROR) {
            for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) {
                // 检查 MAC 地址是否有效（跳过全00和无效长度）
                if (pIpNetTable->table[i].dwPhysAddrLen != 6) continue;
                
                bool validMac = false;
                for (int j = 0; j < 6; j++) {
                    if (pIpNetTable->table[i].bPhysAddr[j] != 0) {
                        validMac = true;
                        break;
                    }
                }
                if (!validMac) continue;  // 跳过全00 MAC
                
                LanDevice dev;
                dev.ipv4 = std::to_string((pIpNetTable->table[i].dwAddr >> 0) & 0xFF) + "." +
                           std::to_string((pIpNetTable->table[i].dwAddr >> 8) & 0xFF) + "." +
                           std::to_string((pIpNetTable->table[i].dwAddr >> 16) & 0xFF) + "." +
                           std::to_string((pIpNetTable->table[i].dwAddr >> 24) & 0xFF);
                
                // MAC 地址
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                    pIpNetTable->table[i].bPhysAddr[0], pIpNetTable->table[i].bPhysAddr[1],
                    pIpNetTable->table[i].bPhysAddr[2], pIpNetTable->table[i].bPhysAddr[3],
                    pIpNetTable->table[i].bPhysAddr[4], pIpNetTable->table[i].bPhysAddr[5]);
                dev.mac = macStr;
                
                // 快速获取主机名（跳过以加速扫描）
                dev.hostname = "Unknown";  // 先设为 Unknown，后续可手动刷新
                dev.isReachable = true;
                lanDevices_.push_back(dev);
            }
        }
        if (pIpNetTable) free(pIpNetTable);
    }
    
    // 后台异步解析主机名（不阻塞扫描结果返回）
    // 这里我们简单地跳过主机名解析，用户可以手动刷新
    
    // 获取本机 IPv6 地址
    ULONG adapterSize = 0;
    if (GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &adapterSize) == ERROR_BUFFER_OVERFLOW) {
        PIP_ADAPTER_ADDRESSES pAdapters = (PIP_ADAPTER_ADDRESSES)malloc(adapterSize);
        if (pAdapters && GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapters, &adapterSize) == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES pAdapter = pAdapters;
            while (pAdapter) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
                while (pUnicast) {
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                        char ipv6Str[INET6_ADDRSTRLEN] = {0};
                        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)pUnicast->Address.lpSockaddr;
                        inet_ntop(AF_INET6, &addr6->sin6_addr, ipv6Str, sizeof(ipv6Str));
                        
                        // 跳过链路本地地址 (fe80::)
                        if (strncmp(ipv6Str, "fe80", 4) != 0) {
                            LanDevice dev;
                            dev.hostname = "Local";
                            dev.ipv4 = "-";
                            dev.ipv6 = ipv6Str;
                            dev.mac = "-";
                            dev.isReachable = true;
                            
                            bool exists = false;
                            for (const auto& d : lanDevices_) {
                                if (d.ipv6 == ipv6Str) {
                                    exists = true;
                                    break;
                                }
                            }
                            if (!exists) lanDevices_.push_back(dev);
                        }
                    }
                    pUnicast = pUnicast->Next;
                }
                pAdapter = pAdapter->Next;
            }
        }
        if (pAdapters) free(pAdapters);
    }
    
    // 更新现有设备的 IPv6
    ULONG adapterSize4 = 0;
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS, nullptr, nullptr, &adapterSize4) == ERROR_BUFFER_OVERFLOW) {
        PIP_ADAPTER_ADDRESSES pAdapters = (PIP_ADAPTER_ADDRESSES)malloc(adapterSize4);
        if (pAdapters && GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS, nullptr, pAdapters, &adapterSize4) == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES pAdapter = pAdapters;
            while (pAdapter) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
                std::string adapterIpv6;
                while (pUnicast && adapterIpv6.empty()) {
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                        char ipv6Str[INET6_ADDRSTRLEN] = {0};
                        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)pUnicast->Address.lpSockaddr;
                        inet_ntop(AF_INET6, &addr6->sin6_addr, ipv6Str, sizeof(ipv6Str));
                        if (strncmp(ipv6Str, "fe80", 4) != 0) {
                            adapterIpv6 = ipv6Str;
                        }
                    }
                    pUnicast = pUnicast->Next;
                }
                
                if (!adapterIpv6.empty() && pAdapter->PhysicalAddressLength == 6) {
                    char macStr[18];
                    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                        pAdapter->PhysicalAddress[0], pAdapter->PhysicalAddress[1],
                        pAdapter->PhysicalAddress[2], pAdapter->PhysicalAddress[3],
                        pAdapter->PhysicalAddress[4], pAdapter->PhysicalAddress[5]);
                    
                    for (auto& dev : lanDevices_) {
                        if (dev.mac == macStr && (dev.ipv6.empty() || dev.ipv6 == "-")) {
                            dev.ipv6 = adapterIpv6;
                        }
                    }
                }
                pAdapter = pAdapter->Next;
            }
        }
        if (pAdapters) free(pAdapters);
    }
    
    // 设置空的 IPv6 为 "-"
    for (auto& dev : lanDevices_) {
        if (dev.ipv6.empty()) dev.ipv6 = "-";
    }
    
    return lanDevices_;
}

// ==================== 拦截日志功能 ====================

void WfpManager::setLoggingEnabled(bool enabled) {
    loggingEnabled_ = enabled;
}

bool WfpManager::isLoggingEnabled() const {
    return loggingEnabled_;
}

std::vector<BlockLogEntry> WfpManager::getBlockLogs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<BlockLogEntry>(blockLogs_.begin(), blockLogs_.end());
}

void WfpManager::clearBlockLogs() {
    std::lock_guard<std::mutex> lock(mutex_);
    blockLogs_.clear();
}

int WfpManager::getBlockLogCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(blockLogs_.size());
}

void WfpManager::logBlockedPacket(const std::string& srcIp, const std::string& dstIp, 
                                   const std::string& protocol, uint16_t srcPort, uint16_t dstPort,
                                   const std::string& direction, const std::string& blockedIp) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 创建日志条目
    BlockLogEntry entry;
    
    // 获取时间戳
    time_t now = time(nullptr);
    struct tm* tm_info = localtime(&now);
    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", tm_info);
    entry.timestamp = timeStr;
    
    entry.srcIp = srcIp;
    entry.dstIp = dstIp;
    entry.protocol = protocol;
    entry.srcPort = srcPort;
    entry.dstPort = dstPort;
    entry.direction = direction;
    entry.blockedIp = blockedIp;
    
    // 生成文件名
    char filename[64];
    strftime(filename, sizeof(filename), "block_%Y%m%d_%H%M%S", tm_info);
    entry.filename = std::string(filename) + "_" + std::to_string(logFileCount_++) + ".log";
    
    // 添加到内存队列（最多保留100条）
    blockLogs_.push_back(entry);
    if (blockLogs_.size() > 100) {
        blockLogs_.pop_front();
    }
    
    // 保存到文件
    saveLogToFile(entry);
    
    // 轮转日志文件（最多保留10个）
    rotateLogFiles();
}

void WfpManager::saveLogToFile(const BlockLogEntry& entry) {
    std::string filepath = logDir_ + "/" + entry.filename;
    std::ofstream file(filepath);
    if (file.is_open()) {
        file << "Timestamp: " << entry.timestamp << "\n";
        file << "Blocked IP: " << entry.blockedIp << "\n";
        file << "Direction: " << entry.direction << "\n";
        file << "Source: " << entry.srcIp << ":" << entry.srcPort << "\n";
        file << "Destination: " << entry.dstIp << ":" << entry.dstPort << "\n";
        file << "Protocol: " << entry.protocol << "\n";
        file.close();
    }
}

void WfpManager::rotateLogFiles() {
    // 获取日志目录下的所有文件
    WIN32_FIND_DATAA findData;
    std::vector<std::string> logFiles;
    
    std::string searchPath = logDir_ + "\\block_*.log";
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            logFiles.push_back(findData.cFileName);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    // 如果超过10个文件，删除最旧的
    if (logFiles.size() > 10) {
        // 按文件名排序（包含时间戳）
        std::sort(logFiles.begin(), logFiles.end());
        
        // 删除多余的文件
        while (logFiles.size() > 10) {
            std::string fileToDelete = logDir_ + "/" + logFiles[0];
            DeleteFileA(fileToDelete.c_str());
            logFiles.erase(logFiles.begin());
        }
    }
}

// ==================== MAC 白名单功能 ====================

bool WfpManager::isValidMac(const std::string& mac) const {
    // 支持 XX:XX:XX:XX:XX:XX 或 XX-XX-XX-XX-XX-XX 格式
    if (mac.length() != 17) return false;
    
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac[i] != ':' && mac[i] != '-') return false;
        } else {
            if (!isxdigit(mac[i])) return false;
        }
    }
    return true;
}

std::string WfpManager::normalizeMac(const std::string& mac) const {
    // 统一转换为大写，用 : 分隔
    std::string result = mac;
    for (char& c : result) {
        c = toupper(c);
        if (c == '-') c = ':';
    }
    return result;
}

bool WfpManager::addMacToWhitelist(const std::string& mac, const std::string& description, const std::string& ipv4) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string normalizedMac = normalizeMac(mac);
    if (!isValidMac(normalizedMac)) {
        lastError_ = "Invalid MAC address format: " + mac;
        return false;
    }
    
    // 检查是否已存在
    for (const auto& entry : macWhitelist_) {
        if (normalizeMac(entry.mac) == normalizedMac) {
            lastError_ = "MAC already in whitelist: " + normalizedMac;
            return false;
        }
    }
    
    MacWhitelistEntry entry;
    entry.mac = normalizedMac;
    entry.description = description;
    entry.ipv4 = ipv4;
    entry.isActive = true;
    
    macWhitelist_.push_back(entry);
    return true;
}

bool WfpManager::removeMacFromWhitelist(const std::string& mac) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string normalizedMac = normalizeMac(mac);
    auto it = std::find_if(macWhitelist_.begin(), macWhitelist_.end(),
        [&normalizedMac, this](const MacWhitelistEntry& e) {
            return normalizeMac(e.mac) == normalizedMac;
        });
    
    if (it == macWhitelist_.end()) {
        lastError_ = "MAC not found in whitelist: " + normalizedMac;
        return false;
    }
    
    macWhitelist_.erase(it);
    return true;
}

std::vector<MacWhitelistEntry> WfpManager::getMacWhitelist() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return macWhitelist_;
}

bool WfpManager::isMacWhitelisted(const std::string& mac) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string normalizedMac = normalizeMac(mac);
    for (const auto& entry : macWhitelist_) {
        if (normalizeMac(entry.mac) == normalizedMac && entry.isActive) {
            return true;
        }
    }
    return false;
}

bool WfpManager::isMacFilterEnabled() const {
    return macFilterEnabled_;
}

void WfpManager::setMacFilterEnabled(bool enabled) {
    macFilterEnabled_ = enabled;
}

bool WfpManager::clearMacWhitelist() {
    std::lock_guard<std::mutex> lock(mutex_);
    macWhitelist_.clear();
    return true;
}

int WfpManager::getMacWhitelistCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(macWhitelist_.size());
}

// ==================== 端口管理功能 ====================

std::vector<PortEntry> WfpManager::getPorts(const std::string& protocol, const std::string& state) {
    std::vector<PortEntry> ports;
    
    // 获取 TCP 连接表
    if (protocol == "all" || protocol == "tcp") {
        PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
        ULONG size = 0;
        
        if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
            if (pTcpTable && GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                    MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                    PortEntry entry;
                    entry.port = ntohs((u_short)row.dwLocalPort);
                    entry.protocol = "TCP";
                    entry.localAddress = std::to_string((row.dwLocalAddr >> 0) & 0xFF) + "." +
                                         std::to_string((row.dwLocalAddr >> 8) & 0xFF) + "." +
                                         std::to_string((row.dwLocalAddr >> 16) & 0xFF) + "." +
                                         std::to_string((row.dwLocalAddr >> 24) & 0xFF);
                    entry.remoteAddress = std::to_string((row.dwRemoteAddr >> 0) & 0xFF) + "." +
                                          std::to_string((row.dwRemoteAddr >> 8) & 0xFF) + "." +
                                          std::to_string((row.dwRemoteAddr >> 16) & 0xFF) + "." +
                                          std::to_string((row.dwRemoteAddr >> 24) & 0xFF);
                    entry.remotePort = ntohs((u_short)row.dwRemotePort);
                    entry.pid = row.dwOwningPid;
                    
                    // 状态转换
                    switch (row.dwState) {
                        case MIB_TCP_STATE_CLOSED: entry.state = "CLOSED"; break;
                        case MIB_TCP_STATE_LISTEN: entry.state = "LISTENING"; break;
                        case MIB_TCP_STATE_SYN_SENT: entry.state = "SYN_SENT"; break;
                        case MIB_TCP_STATE_SYN_RCVD: entry.state = "SYN_RCVD"; break;
                        case MIB_TCP_STATE_ESTAB: entry.state = "ESTABLISHED"; break;
                        case MIB_TCP_STATE_FIN_WAIT1: entry.state = "FIN_WAIT1"; break;
                        case MIB_TCP_STATE_FIN_WAIT2: entry.state = "FIN_WAIT2"; break;
                        case MIB_TCP_STATE_CLOSE_WAIT: entry.state = "CLOSE_WAIT"; break;
                        case MIB_TCP_STATE_CLOSING: entry.state = "CLOSING"; break;
                        case MIB_TCP_STATE_LAST_ACK: entry.state = "LAST_ACK"; break;
                        case MIB_TCP_STATE_TIME_WAIT: entry.state = "TIME_WAIT"; break;
                        case MIB_TCP_STATE_DELETE_TCB: entry.state = "DELETE_TCB"; break;
                        default: entry.state = "UNKNOWN";
                    }
                    
                    // 获取进程名
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
                    if (hProcess) {
                        char processName[MAX_PATH] = {0};
                        if (GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH)) {
                            std::string name = processName;
                            size_t pos = name.find_last_of("\\/");
                            entry.processName = (pos != std::string::npos) ? name.substr(pos + 1) : name;
                        }
                        CloseHandle(hProcess);
                    }
                    if (entry.processName.empty()) entry.processName = "-";
                    
                    // 过滤状态
                    if (state == "all" || 
                        (state == "listening" && entry.state == "LISTENING") ||
                        (state == "established" && entry.state == "ESTABLISHED") ||
                        (state == "time_wait" && entry.state == "TIME_WAIT") ||
                        (state == "close_wait" && entry.state == "CLOSE_WAIT")) {
                        ports.push_back(entry);
                    }
                }
            }
            if (pTcpTable) free(pTcpTable);
        }
        
        // 获取 TCP IPv6 连接表
        PMIB_TCP6TABLE_OWNER_PID pTcp6Table = nullptr;
        size = 0;
        if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pTcp6Table = (PMIB_TCP6TABLE_OWNER_PID)malloc(size);
            if (pTcp6Table && GetExtendedTcpTable(pTcp6Table, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTcp6Table->dwNumEntries; i++) {
                    MIB_TCP6ROW_OWNER_PID& row = pTcp6Table->table[i];
                    PortEntry entry;
                    entry.port = ntohs((u_short)row.dwLocalPort);
                    entry.protocol = "TCP6";
                    
                    char localAddr[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET6, row.ucLocalAddr, localAddr, sizeof(localAddr));
                    entry.localAddress = std::string(localAddr);
                    
                    char remoteAddr[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET6, row.ucRemoteAddr, remoteAddr, sizeof(remoteAddr));
                    entry.remoteAddress = std::string(remoteAddr);
                    
                    entry.remotePort = ntohs((u_short)row.dwRemotePort);
                    entry.pid = row.dwOwningPid;
                    
                    switch (row.dwState) {
                        case MIB_TCP_STATE_CLOSED: entry.state = "CLOSED"; break;
                        case MIB_TCP_STATE_LISTEN: entry.state = "LISTENING"; break;
                        case MIB_TCP_STATE_SYN_SENT: entry.state = "SYN_SENT"; break;
                        case MIB_TCP_STATE_SYN_RCVD: entry.state = "SYN_RCVD"; break;
                        case MIB_TCP_STATE_ESTAB: entry.state = "ESTABLISHED"; break;
                        case MIB_TCP_STATE_FIN_WAIT1: entry.state = "FIN_WAIT1"; break;
                        case MIB_TCP_STATE_FIN_WAIT2: entry.state = "FIN_WAIT2"; break;
                        case MIB_TCP_STATE_CLOSE_WAIT: entry.state = "CLOSE_WAIT"; break;
                        case MIB_TCP_STATE_CLOSING: entry.state = "CLOSING"; break;
                        case MIB_TCP_STATE_LAST_ACK: entry.state = "LAST_ACK"; break;
                        case MIB_TCP_STATE_TIME_WAIT: entry.state = "TIME_WAIT"; break;
                        case MIB_TCP_STATE_DELETE_TCB: entry.state = "DELETE_TCB"; break;
                        default: entry.state = "UNKNOWN";
                    }
                    
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
                    if (hProcess) {
                        char processName[MAX_PATH] = {0};
                        if (GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH)) {
                            std::string name = processName;
                            size_t pos = name.find_last_of("\\/");
                            entry.processName = (pos != std::string::npos) ? name.substr(pos + 1) : name;
                        }
                        CloseHandle(hProcess);
                    }
                    if (entry.processName.empty()) entry.processName = "-";
                    
                    if (state == "all" || 
                        (state == "listening" && entry.state == "LISTENING") ||
                        (state == "established" && entry.state == "ESTABLISHED") ||
                        (state == "time_wait" && entry.state == "TIME_WAIT") ||
                        (state == "close_wait" && entry.state == "CLOSE_WAIT")) {
                        ports.push_back(entry);
                    }
                }
            }
            if (pTcp6Table) free(pTcp6Table);
        }
    }
    
    // 获取 UDP 连接表
    if (protocol == "all" || protocol == "udp") {
        PMIB_UDPTABLE_OWNER_PID pUdpTable = nullptr;
        ULONG size = 0;
        
        if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pUdpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
            if (pUdpTable && GetExtendedUdpTable(pUdpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                    MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];
                    PortEntry entry;
                    entry.port = ntohs((u_short)row.dwLocalPort);
                    entry.protocol = "UDP";
                    entry.state = "LISTENING";
                    entry.localAddress = std::to_string((row.dwLocalAddr >> 0) & 0xFF) + "." +
                                         std::to_string((row.dwLocalAddr >> 8) & 0xFF) + "." +
                                         std::to_string((row.dwLocalAddr >> 16) & 0xFF) + "." +
                                         std::to_string((row.dwLocalAddr >> 24) & 0xFF);
                    entry.remoteAddress = "-";
                    entry.remotePort = 0;
                    entry.pid = row.dwOwningPid;
                    
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
                    if (hProcess) {
                        char processName[MAX_PATH] = {0};
                        if (GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH)) {
                            std::string name = processName;
                            size_t pos = name.find_last_of("\\/");
                            entry.processName = (pos != std::string::npos) ? name.substr(pos + 1) : name;
                        }
                        CloseHandle(hProcess);
                    }
                    if (entry.processName.empty()) entry.processName = "-";
                    
                    if (state == "all" || state == "listening") {
                        ports.push_back(entry);
                    }
                }
            }
            if (pUdpTable) free(pUdpTable);
        }
        
        // 获取 UDP IPv6 连接表
        PMIB_UDP6TABLE_OWNER_PID pUdp6Table = nullptr;
        size = 0;
        if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
            pUdp6Table = (PMIB_UDP6TABLE_OWNER_PID)malloc(size);
            if (pUdp6Table && GetExtendedUdpTable(pUdp6Table, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pUdp6Table->dwNumEntries; i++) {
                    MIB_UDP6ROW_OWNER_PID& row = pUdp6Table->table[i];
                    PortEntry entry;
                    entry.port = ntohs((u_short)row.dwLocalPort);
                    entry.protocol = "UDP6";
                    entry.state = "LISTENING";
                    
                    char localAddr[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET6, row.ucLocalAddr, localAddr, sizeof(localAddr));
                    entry.localAddress = std::string(localAddr);
                    
                    entry.remoteAddress = "-";
                    entry.remotePort = 0;
                    entry.pid = row.dwOwningPid;
                    
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, row.dwOwningPid);
                    if (hProcess) {
                        char processName[MAX_PATH] = {0};
                        if (GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH)) {
                            std::string name = processName;
                            size_t pos = name.find_last_of("\\/");
                            entry.processName = (pos != std::string::npos) ? name.substr(pos + 1) : name;
                        }
                        CloseHandle(hProcess);
                    }
                    if (entry.processName.empty()) entry.processName = "-";
                    
                    if (state == "all" || state == "listening") {
                        ports.push_back(entry);
                    }
                }
            }
            if (pUdp6Table) free(pUdp6Table);
        }
    }
    
    return ports;
}

std::vector<PortEntry> WfpManager::getListeningPorts() {
    std::vector<PortEntry> ports;
    auto allPorts = getPorts("all", "listening");
    for (const auto& p : allPorts) {
        if (p.state == "LISTENING") {
            ports.push_back(p);
        }
    }
    return ports;
}

std::vector<PortEntry> WfpManager::getEstablishedConnections() {
    std::vector<PortEntry> ports;
    auto allPorts = getPorts("tcp", "established");
    for (const auto& p : allPorts) {
        if (p.state == "ESTABLISHED") {
            ports.push_back(p);
        }
    }
    return ports;
}

bool WfpManager::closeConnection(uint16_t localPort, const std::string& protocol) {
    // 只支持关闭 TCP 连接
    if (protocol != "tcp" && protocol != "TCP") {
        lastError_ = "Only TCP connections can be closed";
        return false;
    }
    
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
    ULONG size = 0;
    
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (pTcpTable && GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                if (ntohs((u_short)row.dwLocalPort) == localPort && 
                    row.dwState != MIB_TCP_STATE_LISTEN &&
                    row.dwState != MIB_TCP_STATE_CLOSED) {
                    
                    // 尝试关闭连接
                    MIB_TCPROW rowToClose;
                    rowToClose.dwState = MIB_TCP_STATE_DELETE_TCB;
                    rowToClose.dwLocalAddr = row.dwLocalAddr;
                    rowToClose.dwLocalPort = row.dwLocalPort;
                    rowToClose.dwRemoteAddr = row.dwRemoteAddr;
                    rowToClose.dwRemotePort = row.dwRemotePort;
                    
                    DWORD result = SetTcpEntry(&rowToClose);
                    free(pTcpTable);
                    
                    if (result == NO_ERROR) {
                        return true;
                    } else {
                        lastError_ = "Failed to close connection, error: " + std::to_string(result);
                        return false;
                    }
                }
            }
        }
        if (pTcpTable) free(pTcpTable);
    }
    
    lastError_ = "Connection not found on port " + std::to_string(localPort);
    return false;
}

int WfpManager::closeConnectionsByPort(uint16_t port, const std::string& protocol) {
    int closedCount = 0;
    
    // 关闭 IPv4 TCP 连接
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
    ULONG size = 0;
    
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (pTcpTable && GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                if (ntohs((u_short)row.dwLocalPort) == port && 
                    row.dwState != MIB_TCP_STATE_LISTEN &&
                    row.dwState != MIB_TCP_STATE_CLOSED) {
                    
                    MIB_TCPROW rowToClose;
                    rowToClose.dwState = MIB_TCP_STATE_DELETE_TCB;
                    rowToClose.dwLocalAddr = row.dwLocalAddr;
                    rowToClose.dwLocalPort = row.dwLocalPort;
                    rowToClose.dwRemoteAddr = row.dwRemoteAddr;
                    rowToClose.dwRemotePort = row.dwRemotePort;
                    
                    if (SetTcpEntry(&rowToClose) == NO_ERROR) {
                        closedCount++;
                    }
                }
            }
        }
        if (pTcpTable) free(pTcpTable);
    }
    
    return closedCount;
}

int WfpManager::closeConnectionsByPid(uint32_t pid) {
    int closedCount = 0;
    
    // 关闭指定进程的所有 TCP 连接
    PMIB_TCPTABLE_OWNER_PID pTcpTable = nullptr;
    ULONG size = 0;
    
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (pTcpTable && GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                if (row.dwOwningPid == pid && 
                    row.dwState != MIB_TCP_STATE_LISTEN &&
                    row.dwState != MIB_TCP_STATE_CLOSED) {
                    
                    MIB_TCPROW rowToClose;
                    rowToClose.dwState = MIB_TCP_STATE_DELETE_TCB;
                    rowToClose.dwLocalAddr = row.dwLocalAddr;
                    rowToClose.dwLocalPort = row.dwLocalPort;
                    rowToClose.dwRemoteAddr = row.dwRemoteAddr;
                    rowToClose.dwRemotePort = row.dwRemotePort;
                    
                    if (SetTcpEntry(&rowToClose) == NO_ERROR) {
                        closedCount++;
                    }
                }
            }
        }
        if (pTcpTable) free(pTcpTable);
    }
    
    return closedCount;
}