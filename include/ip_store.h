#ifndef IP_STORE_H
#define IP_STORE_H

#include <string>
#include <vector>
#include "wfp_manager.h"

struct CveConfig {
    bool cve2017_0144_enabled;
    bool cve2024_38063_enabled;
    bool cve2023_44487_enabled;
    bool cve2023_38545_enabled;
    bool cve2024_45177_enabled;
    bool cve2023_23397_enabled;
    bool cve2021_34527_enabled;
    bool cve2024_21745_enabled;
    bool cve2021_44228_enabled;
    bool highRiskPorts_enabled;
};

// MAC 主机名映射
struct MacHostnameEntry {
    std::string mac;
    std::string hostname;
};

struct MacWhitelistData {
    std::string mac;
    std::string description;
    std::string ipv4;
    bool isActive;
};

class IpStore {
public:
    explicit IpStore(const std::string& filePath = "settings.json");
    ~IpStore();

    bool load();
    bool save();
    
    // IP 白名单操作
    bool addIp(const std::string& ip, const std::string& description = "");
    bool removeIp(const std::string& ip);
    std::vector<IpWhitelistEntry> getAllIps() const;
    bool exists(const std::string& ip) const;
    bool clearIps();
    
    // IP 过滤开关
    void setIpFilterEnabled(bool enabled);
    bool isIpFilterEnabled() const;

    // MAC 白名单操作
    bool addMac(const std::string& mac, const std::string& description = "", const std::string& ipv4 = "");
    bool removeMac(const std::string& mac);
    std::vector<MacWhitelistData> getAllMacs() const;
    bool existsMac(const std::string& mac) const;
    bool clearMacs();
    
    // MAC 过滤开关
    void setMacFilterEnabled(bool enabled);
    bool isMacFilterEnabled() const;

    // CVE 配置
    void setCve2024_38063Enabled(bool enabled);
    bool isCve2024_38063Enabled() const;
    void setCve2017_0144Enabled(bool enabled);
    bool isCve2017_0144Enabled() const;
    void setCve2023_44487Enabled(bool enabled);
    bool isCve2023_44487Enabled() const;
    void setCve2023_38545Enabled(bool enabled);
    bool isCve2023_38545Enabled() const;
    void setCve2024_45177Enabled(bool enabled);
    bool isCve2024_45177Enabled() const;
    void setCve2023_23397Enabled(bool enabled);
    bool isCve2023_23397Enabled() const;
    void setCve2021_34527Enabled(bool enabled);
    bool isCve2021_34527Enabled() const;
    void setCve2024_21745Enabled(bool enabled);
    bool isCve2024_21745Enabled() const;
    void setCve2021_44228Enabled(bool enabled);
    bool isCve2021_44228Enabled() const;
    void setHighRiskPortsEnabled(bool enabled);
    bool isHighRiskPortsEnabled() const;
    CveConfig getCveConfig() const;
    std::string getLastError() const;
    
    // MAC 主机名映射
    bool setMacHostname(const std::string& mac, const std::string& hostname);
    std::string getMacHostname(const std::string& mac) const;
    std::vector<MacHostnameEntry> getAllMacHostnames() const;
    bool removeMacHostname(const std::string& mac);

private:
    std::string filePath_;
    std::vector<IpWhitelistEntry> ipList_;
    std::vector<MacWhitelistData> macList_;
    bool ipFilterEnabled_;
    bool macFilterEnabled_;
    CveConfig cveConfig_;
    std::vector<MacHostnameEntry> macHostnames_;
    std::string lastError_;
};

#endif // IP_STORE_H
