#include "ip_store.h"
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>

namespace {
std::string escapeJson(const std::string& s) {
    std::string r;
    for (char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            default: r += c;
        }
    }
    return r;
}

std::string parseStr(const std::string& j, size_t& p) {
    std::string r;
    if (p >= j.size() || j[p] != '"') return r;
    p++;
    while (p < j.size() && j[p] != '"') {
        if (j[p] == '\\' && p + 1 < j.size()) { p++; r += j[p]; }
        else r += j[p];
        p++;
    }
    if (p < j.size()) p++;
    return r;
}

void skipWS(const std::string& j, size_t& p) {
    while (p < j.size() && std::isspace((unsigned char)j[p])) p++;
}

bool parseBool(const std::string& j, size_t& p) {
    if (j.substr(p, 4) == "true") { p += 4; return true; }
    if (j.substr(p, 5) == "false") { p += 5; return false; }
    return false;
}
}

IpStore::IpStore(const std::string& fp) : filePath_(fp), ipFilterEnabled_(false), macFilterEnabled_(false) {
    cveConfig_.cve2017_0144_enabled = false;
    cveConfig_.cve2024_38063_enabled = false;
    cveConfig_.cve2023_44487_enabled = false;
    cveConfig_.cve2023_38545_enabled = false;
    cveConfig_.cve2024_45177_enabled = false;
    cveConfig_.cve2023_23397_enabled = false;
    cveConfig_.cve2021_34527_enabled = false;
    cveConfig_.cve2024_21745_enabled = false;
    cveConfig_.cve2021_44228_enabled = false;
}
IpStore::~IpStore() {}

bool IpStore::load() {
    std::ifstream f(filePath_);
    if (!f.is_open()) return true;
    std::stringstream b; b << f.rdbuf();
    std::string c = b.str(); f.close();
    if (c.empty()) return true;
    
    ipList_.clear();
    macList_.clear();
    size_t p = 0; skipWS(c, p);
    
    if (p < c.size() && c[p] == '{') {
        p++;
        while (p < c.size()) {
            skipWS(c, p);
            if (c[p] == '}') break;
            if (c[p] == ',') { p++; continue; }
            
            std::string key = parseStr(c, p);
            skipWS(c, p); if (p < c.size() && c[p] == ':') p++; skipWS(c, p);
            
            if (key == "ip_filter_enabled") {
                ipFilterEnabled_ = parseBool(c, p);
            } else if (key == "mac_filter_enabled") {
                macFilterEnabled_ = parseBool(c, p);
            } else if (key == "ip_whitelist" && c[p] == '[') {
                p++;
                while (p < c.size()) {
                    skipWS(c, p);
                    if (c[p] == ']') { p++; break; }
                    if (c[p] == ',') { p++; continue; }
                    if (c[p] != '{') break; p++;
                    
                    IpWhitelistEntry entry = {"", "", true, IpType::IPv4};
                    while (p < c.size()) {
                        skipWS(c, p);
                        if (c[p] == '}') { p++; break; }
                        if (c[p] == ',') { p++; continue; }
                        
                        std::string fk = parseStr(c, p);
                        skipWS(c, p); if (p < c.size() && c[p] == ':') p++; skipWS(c, p);
                        
                        if (fk == "ip") entry.ip = parseStr(c, p);
                        else if (fk == "description") entry.description = parseStr(c, p);
                        else if (fk == "active") entry.isActive = parseBool(c, p);
                        else if (fk == "ip_type") {
                            std::string t = parseStr(c, p);
                            entry.ipType = (t == "IPv6") ? IpType::IPv6 : IpType::IPv4;
                        } else {
                            if (c[p] == '"') parseStr(c, p);
                            else while (p < c.size() && c[p] != ',' && c[p] != '}') p++;
                        }
                    }
                    if (!entry.ip.empty()) ipList_.push_back(entry);
                }
            } else if (key == "mac_whitelist" && c[p] == '[') {
                p++;
                while (p < c.size()) {
                    skipWS(c, p);
                    if (c[p] == ']') { p++; break; }
                    if (c[p] == ',') { p++; continue; }
                    if (c[p] != '{') break; p++;
                    
                    MacWhitelistData entry = {"", "", "", true};
                    while (p < c.size()) {
                        skipWS(c, p);
                        if (c[p] == '}') { p++; break; }
                        if (c[p] == ',') { p++; continue; }
                        
                        std::string fk = parseStr(c, p);
                        skipWS(c, p); if (p < c.size() && c[p] == ':') p++; skipWS(c, p);
                        
                        if (fk == "mac") entry.mac = parseStr(c, p);
                        else if (fk == "description") entry.description = parseStr(c, p);
                        else if (fk == "ipv4") entry.ipv4 = parseStr(c, p);
                        else if (fk == "active") entry.isActive = parseBool(c, p);
                        else {
                            if (c[p] == '"') parseStr(c, p);
                            else while (p < c.size() && c[p] != ',' && c[p] != '}') p++;
                        }
                    }
                    if (!entry.mac.empty()) macList_.push_back(entry);
                }
            } else if (key == "cve_config" && c[p] == '{') {
                p++;
                while (p < c.size()) {
                    skipWS(c, p);
                    if (c[p] == '}') { p++; break; }
                    if (c[p] == ',') { p++; continue; }
                    
                    std::string ck = parseStr(c, p);
                    skipWS(c, p); if (p < c.size() && c[p] == ':') p++; skipWS(c, p);
                    
                    if (ck == "cve2017_0144_enabled") cveConfig_.cve2017_0144_enabled = parseBool(c, p);
                    else if (ck == "cve2024_38063_enabled") cveConfig_.cve2024_38063_enabled = parseBool(c, p);
                    else if (ck == "cve2023_44487_enabled") cveConfig_.cve2023_44487_enabled = parseBool(c, p);
                    else if (ck == "cve2023_38545_enabled") cveConfig_.cve2023_38545_enabled = parseBool(c, p);
                    else if (ck == "cve2024_45177_enabled") cveConfig_.cve2024_45177_enabled = parseBool(c, p);
                    else if (ck == "cve2023_23397_enabled") cveConfig_.cve2023_23397_enabled = parseBool(c, p);
                    else if (ck == "cve2021_34527_enabled") cveConfig_.cve2021_34527_enabled = parseBool(c, p);
                    else if (ck == "cve2024_21745_enabled") cveConfig_.cve2024_21745_enabled = parseBool(c, p);
                    else if (ck == "cve2021_44228_enabled") cveConfig_.cve2021_44228_enabled = parseBool(c, p);
                    else while (p < c.size() && c[p] != ',' && c[p] != '}') p++;
                }
            } else {
                if (c[p] == '"') parseStr(c, p);
                else if (c[p] == '[' || c[p] == '{') {
                    int d = 1; p++;
                    while (p < c.size() && d > 0) { if (c[p] == '[' || c[p] == '{') d++; else if (c[p] == ']' || c[p] == '}') d--; p++; }
                } else while (p < c.size() && c[p] != ',' && c[p] != '}') p++;
            }
        }
    }
    return true;
}

bool IpStore::save() {
    std::ofstream f(filePath_);
    if (!f.is_open()) { lastError_ = "Cannot write: " + filePath_; return false; }
    
    f << "{\n";
    
    // 过滤开关
    f << "  \"ip_filter_enabled\": " << (ipFilterEnabled_ ? "true" : "false") << ",\n";
    f << "  \"mac_filter_enabled\": " << (macFilterEnabled_ ? "true" : "false") << ",\n";
    
    // IP 白名单
    f << "  \"ip_whitelist\": [\n";
    for (size_t i = 0; i < ipList_.size(); i++) {
        const auto& r = ipList_[i];
        f << "    {\"ip\": \"" << escapeJson(r.ip) << "\", \"description\": \"" << escapeJson(r.description)
          << "\", \"active\": " << (r.isActive ? "true" : "false")
          << ", \"ip_type\": \"" << (r.ipType == IpType::IPv6 ? "IPv6" : "IPv4") << "\"}";
        if (i < ipList_.size() - 1) f << ",";
        f << "\n";
    }
    f << "  ],\n";
    
    // MAC 白名单
    f << "  \"mac_whitelist\": [\n";
    for (size_t i = 0; i < macList_.size(); i++) {
        const auto& m = macList_[i];
        f << "    {\"mac\": \"" << escapeJson(m.mac) << "\", \"description\": \"" << escapeJson(m.description)
          << "\", \"ipv4\": \"" << escapeJson(m.ipv4) << "\", \"active\": " << (m.isActive ? "true" : "false") << "}";
        if (i < macList_.size() - 1) f << ",";
        f << "\n";
    }
    f << "  ],\n";
    
    // CVE 配置
    f << "  \"cve_config\": {"
      << "\"cve2017_0144_enabled\": " << (cveConfig_.cve2017_0144_enabled ? "true" : "false") << ", "
      << "\"cve2024_38063_enabled\": " << (cveConfig_.cve2024_38063_enabled ? "true" : "false") << ", "
      << "\"cve2023_44487_enabled\": " << (cveConfig_.cve2023_44487_enabled ? "true" : "false") << ", "
      << "\"cve2023_38545_enabled\": " << (cveConfig_.cve2023_38545_enabled ? "true" : "false") << ", "
      << "\"cve2024_45177_enabled\": " << (cveConfig_.cve2024_45177_enabled ? "true" : "false") << ", "
      << "\"cve2023_23397_enabled\": " << (cveConfig_.cve2023_23397_enabled ? "true" : "false") << ", "
      << "\"cve2021_34527_enabled\": " << (cveConfig_.cve2021_34527_enabled ? "true" : "false") << ", "
      << "\"cve2024_21745_enabled\": " << (cveConfig_.cve2024_21745_enabled ? "true" : "false") << ", "
      << "\"cve2021_44228_enabled\": " << (cveConfig_.cve2021_44228_enabled ? "true" : "false")
      << "}\n}\n";
    return true;
}

// ==================== IP 白名单 ====================

bool IpStore::addIp(const std::string& ip, const std::string& desc) {
    if (exists(ip)) { lastError_ = "IP exists: " + ip; return false; }
    IpWhitelistEntry r = {ip, desc, true, IpType::IPv4};
    ipList_.push_back(r);
    return save();
}

bool IpStore::removeIp(const std::string& ip) {
    auto it = std::find_if(ipList_.begin(), ipList_.end(), [&ip](const IpWhitelistEntry& r) { return r.ip == ip; });
    if (it == ipList_.end()) { lastError_ = "IP not found: " + ip; return false; }
    ipList_.erase(it);
    return save();
}

std::vector<IpWhitelistEntry> IpStore::getAllIps() const { return ipList_; }

bool IpStore::exists(const std::string& ip) const {
    return std::any_of(ipList_.begin(), ipList_.end(), [&ip](const IpWhitelistEntry& r) { return r.ip == ip; });
}

bool IpStore::clearIps() { ipList_.clear(); return save(); }

void IpStore::setIpFilterEnabled(bool enabled) { ipFilterEnabled_ = enabled; save(); }
bool IpStore::isIpFilterEnabled() const { return ipFilterEnabled_; }

// ==================== MAC 白名单 ====================

bool IpStore::addMac(const std::string& mac, const std::string& description, const std::string& ipv4) {
    if (existsMac(mac)) { lastError_ = "MAC exists: " + mac; return false; }
    MacWhitelistData entry = {mac, description, ipv4, true};
    macList_.push_back(entry);
    return save();
}

bool IpStore::removeMac(const std::string& mac) {
    auto it = std::find_if(macList_.begin(), macList_.end(), [&mac](const MacWhitelistData& m) { return m.mac == mac; });
    if (it == macList_.end()) { lastError_ = "MAC not found: " + mac; return false; }
    macList_.erase(it);
    return save();
}

std::vector<MacWhitelistData> IpStore::getAllMacs() const { return macList_; }

bool IpStore::existsMac(const std::string& mac) const {
    return std::any_of(macList_.begin(), macList_.end(), [&mac](const MacWhitelistData& m) { return m.mac == mac; });
}

bool IpStore::clearMacs() { macList_.clear(); return save(); }

void IpStore::setMacFilterEnabled(bool enabled) { macFilterEnabled_ = enabled; save(); }
bool IpStore::isMacFilterEnabled() const { return macFilterEnabled_; }

// ==================== CVE 配置 ====================

void IpStore::setCve2024_38063Enabled(bool e) { cveConfig_.cve2024_38063_enabled = e; save(); }
bool IpStore::isCve2024_38063Enabled() const { return cveConfig_.cve2024_38063_enabled; }
void IpStore::setCve2017_0144Enabled(bool e) { cveConfig_.cve2017_0144_enabled = e; save(); }
bool IpStore::isCve2017_0144Enabled() const { return cveConfig_.cve2017_0144_enabled; }
void IpStore::setCve2023_44487Enabled(bool e) { cveConfig_.cve2023_44487_enabled = e; save(); }
bool IpStore::isCve2023_44487Enabled() const { return cveConfig_.cve2023_44487_enabled; }
void IpStore::setCve2023_38545Enabled(bool e) { cveConfig_.cve2023_38545_enabled = e; save(); }
bool IpStore::isCve2023_38545Enabled() const { return cveConfig_.cve2023_38545_enabled; }
void IpStore::setCve2024_45177Enabled(bool e) { cveConfig_.cve2024_45177_enabled = e; save(); }
bool IpStore::isCve2024_45177Enabled() const { return cveConfig_.cve2024_45177_enabled; }
void IpStore::setCve2023_23397Enabled(bool e) { cveConfig_.cve2023_23397_enabled = e; save(); }
bool IpStore::isCve2023_23397Enabled() const { return cveConfig_.cve2023_23397_enabled; }
void IpStore::setCve2021_34527Enabled(bool e) { cveConfig_.cve2021_34527_enabled = e; save(); }
bool IpStore::isCve2021_34527Enabled() const { return cveConfig_.cve2021_34527_enabled; }
void IpStore::setCve2024_21745Enabled(bool e) { cveConfig_.cve2024_21745_enabled = e; save(); }
bool IpStore::isCve2024_21745Enabled() const { return cveConfig_.cve2024_21745_enabled; }
void IpStore::setCve2021_44228Enabled(bool e) { cveConfig_.cve2021_44228_enabled = e; save(); }
bool IpStore::isCve2021_44228Enabled() const { return cveConfig_.cve2021_44228_enabled; }
CveConfig IpStore::getCveConfig() const { return cveConfig_; }
std::string IpStore::getLastError() const { return lastError_; }
