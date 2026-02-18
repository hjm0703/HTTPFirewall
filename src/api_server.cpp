#include "api_server.h"
#include "wfp_manager.h"
#include "ip_store.h"

#define CPPHTTPLIB_IMPLEMENTATION
#include <httplib.h>

#include <iostream>
#include <sstream>

class ApiServer::Impl { public: httplib::Server server; };

ApiServer::ApiServer(WfpManager& w, IpStore& s) : impl_(std::make_unique<Impl>()), wfpManager_(w), ipStore_(s) {}
ApiServer::~ApiServer() { stop(); }

namespace {
std::string esc(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '"') r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\n') r += "\\n";
        else r += c;
    }
    return r;
}

std::string ipWhitelistJson(const std::vector<IpWhitelistEntry>& entries) {
    std::ostringstream j; j << "[\n";
    for (size_t i = 0; i < entries.size(); i++) {
        const auto& r = entries[i];
        j << "  {\"ip\": \"" << esc(r.ip) << "\", \"description\": \"" << esc(r.description)
          << "\", \"active\": " << (r.isActive ? "true" : "false")
          << ", \"ip_type\": \"" << (r.ipType == IpType::IPv6 ? "IPv6" : "IPv4") << "\"}";
        if (i < entries.size() - 1) j << ",";
        j << "\n";
    }
    j << "]";
    return j.str();
}

std::string lanDevicesJson(const std::vector<LanDevice>& devices) {
    std::ostringstream j; j << "[\n";
    for (size_t i = 0; i < devices.size(); i++) {
        const auto& d = devices[i];
        j << "  {\"hostname\": \"" << esc(d.hostname) << "\", \"ipv4\": \"" << esc(d.ipv4)
          << "\", \"ipv6\": \"" << esc(d.ipv6) << "\", \"mac\": \"" << esc(d.mac)
          << "\", \"reachable\": " << (d.isReachable ? "true" : "false") << "}";
        if (i < devices.size() - 1) j << ",";
        j << "\n";
    }
    j << "]";
    return j.str();
}

std::string blockLogsJson(const std::vector<BlockLogEntry>& logs) {
    std::ostringstream j; j << "[\n";
    for (size_t i = 0; i < logs.size(); i++) {
        const auto& l = logs[i];
        j << "  {\"timestamp\": \"" << esc(l.timestamp) << "\", \"srcIp\": \"" << esc(l.srcIp)
          << "\", \"dstIp\": \"" << esc(l.dstIp) << "\", \"protocol\": \"" << esc(l.protocol)
          << "\", \"srcPort\": " << l.srcPort << ", \"dstPort\": " << l.dstPort
          << ", \"direction\": \"" << esc(l.direction) << "\", \"blockedIp\": \"" << esc(l.blockedIp)
          << "\", \"filename\": \"" << esc(l.filename) << "\"}";
        if (i < logs.size() - 1) j << ",";
        j << "\n";
    }
    j << "]";
    return j.str();
}

std::string macWhitelistJson(const std::vector<MacWhitelistData>& entries) {
    std::ostringstream j; j << "[\n";
    for (size_t i = 0; i < entries.size(); i++) {
        const auto& e = entries[i];
        j << "  {\"mac\": \"" << esc(e.mac) << "\", \"description\": \"" << esc(e.description)
          << "\", \"ipv4\": \"" << esc(e.ipv4) << "\", \"active\": " << (e.isActive ? "true" : "false") << "}";
        if (i < entries.size() - 1) j << ",";
        j << "\n";
    }
    j << "]";
    return j.str();
}

std::string okResp(const std::string& m) { return "{\"success\": true, \"message\": \"" + esc(m) + "\"}"; }
std::string errResp(const std::string& e) { return "{\"success\": false, \"error\": \"" + esc(e) + "\"}"; }
}

bool ApiServer::start(const std::string& host, int port) {
    impl_->server.set_mount_point("/", "./public");
    impl_->server.set_default_headers({{"Access-Control-Allow-Origin", "*"}, {"Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"}, {"Access-Control-Allow-Headers", "Content-Type"}});
    
    // IP 访问限制 - 只允许本地访问
    impl_->server.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        std::string clientIp = req.remote_addr;
        // 只允许本地访问 (127.0.0.1 或 ::1)
        if (clientIp != "127.0.0.1" && clientIp != "::1" && clientIp != "localhost") {
            res.status = 403;
            res.set_content("{\"error\": \"Access denied. Local access only.\"}", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    
    impl_->server.Options(".*", [](const httplib::Request&, httplib::Response& res) { res.status = 200; });

    // IP 白名单 API
    impl_->server.Get("/api/ips", [this](const httplib::Request&, httplib::Response& res) {
        res.set_content(ipWhitelistJson(ipStore_.getAllIps()), "application/json");
    });

    impl_->server.Post("/api/ips", [this](const httplib::Request& req, httplib::Response& res) {
        std::string ip = req.get_param_value("ip"), desc = req.get_param_value("description");
        std::cout << "[DEBUG] POST /api/ips - ip: '" << ip << "', desc: '" << desc << "'" << std::endl;
        if (ip.empty()) { res.set_content(errResp("请输入IP地址"), "application/json"); return; }
        if (!ipStore_.addIp(ip, desc)) { 
            std::cout << "[DEBUG] ipStore_.addIp failed: " << ipStore_.getLastError() << std::endl;
            res.set_content(errResp(ipStore_.getLastError()), "application/json"); 
            return; 
        }
        std::cout << "[DEBUG] ipStore_.addIp success" << std::endl;
        
        if (!wfpManager_.addIpToWhitelist(ip, desc)) { 
            std::cout << "[DEBUG] wfpManager addIpToWhitelist failed: " << wfpManager_.getLastError() << std::endl;
            ipStore_.removeIp(ip); 
            res.set_content(errResp(wfpManager_.getLastError()), "application/json"); 
            return; 
        }
        std::cout << "[DEBUG] IP added to whitelist successfully: " << ip << std::endl;
        res.set_content(okResp("IP已添加到白名单"), "application/json");
    });

    impl_->server.Delete("/api/ips", [this](const httplib::Request& req, httplib::Response& res) {
        std::string ip = req.get_param_value("ip");
        if (ip.empty()) { res.set_content(errResp("请输入IP地址"), "application/json"); return; }
        wfpManager_.removeIpFromWhitelist(ip); ipStore_.removeIp(ip);
        res.set_content(okResp("IP已从白名单移除"), "application/json");
    });

    impl_->server.Delete("/api/ips/all", [this](const httplib::Request&, httplib::Response& res) {
        wfpManager_.clearIpWhitelist(); ipStore_.clearIps();
        res.set_content(okResp("白名单已清空"), "application/json");
    });

    impl_->server.Post("/api/ips/toggle", [this](const httplib::Request& req, httplib::Response& res) {
        std::string enabled = req.get_param_value("enabled");
        bool en = (enabled == "true" || enabled == "1");
        wfpManager_.setIpFilterEnabled(en);
        ipStore_.setIpFilterEnabled(en);
        res.set_content(okResp(en ? "IP过滤已开启" : "IP过滤已关闭"), "application/json");
    });

    // MAC 白名单 API
    impl_->server.Get("/api/mac", [this](const httplib::Request&, httplib::Response& res) {
        res.set_content(macWhitelistJson(ipStore_.getAllMacs()), "application/json");
    });

    impl_->server.Post("/api/mac", [this](const httplib::Request& req, httplib::Response& res) {
        std::string mac = req.get_param_value("mac");
        std::string desc = req.get_param_value("description");
        std::string ipv4 = req.get_param_value("ipv4");
        if (mac.empty()) { res.set_content(errResp("请输入MAC地址"), "application/json"); return; }
        if (!ipStore_.addMac(mac, desc, ipv4)) {
            res.set_content(errResp(ipStore_.getLastError()), "application/json");
            return;
        }
        if (!wfpManager_.addMacToWhitelist(mac, desc, ipv4)) {
            ipStore_.removeMac(mac);
            res.set_content(errResp(wfpManager_.getLastError()), "application/json");
            return;
        }
        res.set_content(okResp("MAC已添加到白名单"), "application/json");
    });

    impl_->server.Delete("/api/mac", [this](const httplib::Request& req, httplib::Response& res) {
        std::string mac = req.get_param_value("mac");
        if (mac.empty()) { res.set_content(errResp("请输入MAC地址"), "application/json"); return; }
        wfpManager_.removeMacFromWhitelist(mac);
        ipStore_.removeMac(mac);
        res.set_content(okResp("MAC已从白名单移除"), "application/json");
    });

    impl_->server.Delete("/api/mac/all", [this](const httplib::Request&, httplib::Response& res) {
        wfpManager_.clearMacWhitelist();
        ipStore_.clearMacs();
        res.set_content(okResp("白名单已清空"), "application/json");
    });

    impl_->server.Post("/api/mac/toggle", [this](const httplib::Request& req, httplib::Response& res) {
        std::string enabled = req.get_param_value("enabled");
        bool en = (enabled == "true" || enabled == "1");
        wfpManager_.setMacFilterEnabled(en);
        ipStore_.setMacFilterEnabled(en);
        res.set_content(okResp(en ? "MAC过滤已开启" : "MAC过滤已关闭"), "application/json");
    });

    // 局域网扫描 API
    impl_->server.Get("/api/lan", [this](const httplib::Request&, httplib::Response& res) {
        res.set_content(lanDevicesJson(wfpManager_.getLastLanScan()), "application/json");
    });

    impl_->server.Post("/api/lan/scan", [this](const httplib::Request&, httplib::Response& res) {
        auto devices = wfpManager_.scanLan();
        res.set_content(lanDevicesJson(devices), "application/json");
    });

    // 状态 API
    impl_->server.Get("/api/status", [this](const httplib::Request&, httplib::Response& res) {
        auto ips = ipStore_.getAllIps();
        auto macs = ipStore_.getAllMacs();
        auto cveStatus = wfpManager_.getCveProtectionStatus();
        int v4 = 0, v6 = 0;
        for (const auto& ip : ips) { if (ip.ipType == IpType::IPv6) v6++; else v4++; }
        std::ostringstream j;
        j << "{\"running\": true, \"ipWhitelistCount\": " << ips.size() << ", \"ipv4Count\": " << v4
          << ", \"ipv6Count\": " << v6 
          << ", \"ipFilterEnabled\": " << (ipStore_.isIpFilterEnabled() ? "true" : "false")
          << ", \"macWhitelistCount\": " << macs.size()
          << ", \"macFilterEnabled\": " << (ipStore_.isMacFilterEnabled() ? "true" : "false")
          << ", \"cve\": {"
          << "\"cve2017_0144\": " << (cveStatus.cve2017_0144 ? "true" : "false") << ","
          << "\"cve2024_38063\": " << (cveStatus.cve2024_38063 ? "true" : "false") << ","
          << "\"cve2023_44487\": " << (cveStatus.cve2023_44487 ? "true" : "false") << ","
          << "\"cve2023_38545\": " << (cveStatus.cve2023_38545 ? "true" : "false") << ","
          << "\"cve2024_45177\": " << (cveStatus.cve2024_45177 ? "true" : "false") << ","
          << "\"cve2023_23397\": " << (cveStatus.cve2023_23397 ? "true" : "false") << ","
          << "\"cve2021_34527\": " << (cveStatus.cve2021_34527 ? "true" : "false") << ","
          << "\"cve2024_21745\": " << (cveStatus.cve2024_21745 ? "true" : "false") << ","
          << "\"cve2021_44228\": " << (cveStatus.cve2021_44228 ? "true" : "false")
          << "},"
          << "\"lanDevices\": " << wfpManager_.getLastLanScan().size()
          << ", \"loggingEnabled\": " << (wfpManager_.isLoggingEnabled() ? "true" : "false")
          << ", \"logCount\": " << wfpManager_.getBlockLogCount() << "}";
        res.set_content(j.str(), "application/json");
    });

    // CVE 防护 API - 统一接口
    impl_->server.Get("/api/cve/status", [this](const httplib::Request&, httplib::Response& res) {
        auto status = wfpManager_.getCveProtectionStatus();
        std::ostringstream j;
        j << "{\"cve2017_0144\": " << (status.cve2017_0144 ? "true" : "false") << ","
          << "\"cve2024_38063\": " << (status.cve2024_38063 ? "true" : "false") << ","
          << "\"cve2023_44487\": " << (status.cve2023_44487 ? "true" : "false") << ","
          << "\"cve2023_38545\": " << (status.cve2023_38545 ? "true" : "false") << ","
          << "\"cve2024_45177\": " << (status.cve2024_45177 ? "true" : "false") << ","
          << "\"cve2023_23397\": " << (status.cve2023_23397 ? "true" : "false") << ","
          << "\"cve2021_34527\": " << (status.cve2021_34527 ? "true" : "false") << ","
          << "\"cve2024_21745\": " << (status.cve2024_21745 ? "true" : "false") << ","
          << "\"cve2021_44228\": " << (status.cve2021_44228 ? "true" : "false") << "}";
        res.set_content(j.str(), "application/json");
    });

    impl_->server.Post("/api/cve/toggle", [this](const httplib::Request& req, httplib::Response& res) {
        std::string cveId = req.get_param_value("cve");
        std::string enabled = req.get_param_value("enabled");
        if (cveId.empty()) { res.set_content(errResp("请指定 CVE ID"), "application/json"); return; }
        bool en = (enabled == "true" || enabled == "1");
        wfpManager_.setCveProtection(cveId, en);
        // 同步保存到 JSON 配置
        if (cveId == "cve2017_0144") ipStore_.setCve2017_0144Enabled(en);
        else if (cveId == "cve2024_38063") ipStore_.setCve2024_38063Enabled(en);
        else if (cveId == "cve2023_44487") ipStore_.setCve2023_44487Enabled(en);
        else if (cveId == "cve2023_38545") ipStore_.setCve2023_38545Enabled(en);
        else if (cveId == "cve2024_45177") ipStore_.setCve2024_45177Enabled(en);
        else if (cveId == "cve2023_23397") ipStore_.setCve2023_23397Enabled(en);
        else if (cveId == "cve2021_34527") ipStore_.setCve2021_34527Enabled(en);
        else if (cveId == "cve2024_21745") ipStore_.setCve2024_21745Enabled(en);
        else if (cveId == "cve2021_44228") ipStore_.setCve2021_44228Enabled(en);
        res.set_content(okResp(en ? "防护已开启" : "防护已关闭"), "application/json");
    });

    // 保留旧 API 兼容性
    impl_->server.Post("/api/cve/cve2024-38063/enable", [this](const httplib::Request&, httplib::Response& res) {
        wfpManager_.enableCve2024_38063Protection();
        ipStore_.setCve2024_38063Enabled(true);
        res.set_content(okResp("CVE-2024-38063 enabled"), "application/json");
    });

    impl_->server.Post("/api/cve/cve2024-38063/disable", [this](const httplib::Request&, httplib::Response& res) {
        wfpManager_.disableCve2024_38063Protection();
        ipStore_.setCve2024_38063Enabled(false);
        res.set_content(okResp("CVE-2024-38063 disabled"), "application/json");
    });

    // 拦截日志 API
    impl_->server.Get("/api/logs", [this](const httplib::Request&, httplib::Response& res) {
        res.set_content(blockLogsJson(wfpManager_.getBlockLogs()), "application/json");
    });

    impl_->server.Post("/api/logs/toggle", [this](const httplib::Request& req, httplib::Response& res) {
        std::string enabled = req.get_param_value("enabled");
        bool en = (enabled == "true" || enabled == "1");
        wfpManager_.setLoggingEnabled(en);
        res.set_content(okResp(en ? "Logging enabled" : "Logging disabled"), "application/json");
    });

    impl_->server.Delete("/api/logs", [this](const httplib::Request&, httplib::Response& res) {
        wfpManager_.clearBlockLogs();
        res.set_content(okResp("Logs cleared"), "application/json");
    });

    impl_->server.set_error_handler([](const httplib::Request&, httplib::Response& res) { res.set_content(errResp("Not Found"), "application/json"); });

    std::cout << "Server at http://" << host << ":" << port << std::endl;
    return impl_->server.listen(host, port);
}

void ApiServer::stop() { 
    // 只在服务器运行时才调用 stop，避免 httplib 内部断言失败
    if (impl_->server.is_running()) {
        impl_->server.stop(); 
    }
}
bool ApiServer::isRunning() const { return impl_->server.is_running(); }
