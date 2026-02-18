#ifndef API_SERVER_H
#define API_SERVER_H

#include <string>
#include <memory>
#include "wfp_manager.h"
#include "ip_store.h"

class ApiServer {
public:
    ApiServer(WfpManager& wfpManager, IpStore& ipStore);
    ~ApiServer();

    bool start(const std::string& host = "0.0.0.0", int port = 8080);
    void stop();
    bool isRunning() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    WfpManager& wfpManager_;
    IpStore& ipStore_;
};

#endif // API_SERVER_H
