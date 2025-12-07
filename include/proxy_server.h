/*
 * proxy_server.h
 * 本地代理服务器 - 接收重定向的连接并转发到 SOCKS5 代理
 */

#ifndef PROXY_SERVER_H
#define PROXY_SERVER_H

#include <windows.h>
#include <winsock2.h>
#include <string>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

namespace proxifier {

// 前向声明
struct ProxyServer;
struct ConnectionInfo;

// 连接会话
struct ProxySession {
    UINT64 sessionId;
    
    // 客户端连接（被重定向的原始连接）
    SOCKET clientSocket = INVALID_SOCKET;
    
    // 代理连接（到 SOCKS5 服务器）
    SOCKET proxySocket = INVALID_SOCKET;
    
    // 原始目标信息
    UINT32 originalDstAddr = 0;
    UINT16 originalDstPort = 0;
    bool isIPv6 = false;
    UINT32 originalDstAddrV6[4] = {0};
    
    // 进程信息
    UINT32 processId = 0;
    std::string processName;
    
    // 代理服务器信息
    const ProxyServer* proxyServer = nullptr;
    
    // 状态
    bool connected = false;
    bool closed = false;
    
    // 统计
    UINT64 bytesSent = 0;
    UINT64 bytesReceived = 0;
    
    // 时间戳
    INT64 createTime = 0;
    INT64 lastActiveTime = 0;
};

// 会话事件回调
using SessionCallback = std::function<void(ProxySession* session, const std::string& event)>;

// 本地代理服务器类
class LocalProxyServer {
public:
    LocalProxyServer();
    ~LocalProxyServer();
    
    // 启动/停止服务器
    bool start(const std::string& bindAddr = "127.0.0.1", int port = 0);
    void stop();
    bool isRunning() const { return running_; }
    
    // 获取监听地址和端口
    std::string getBindAddress() const { return bindAddr_; }
    int getBindPort() const { return bindPort_; }
    
    // 注册原始目标信息（在连接被重定向之前调用）
    void registerOriginalTarget(UINT32 srcAddr, UINT16 srcPort,
                                UINT32 dstAddr, UINT16 dstPort,
                                UINT32 processId, const std::string& processName,
                                const ProxyServer* proxyServer);
    
    void registerOriginalTargetV6(const UINT32* srcAddr, UINT16 srcPort,
                                  const UINT32* dstAddr, UINT16 dstPort,
                                  UINT32 processId, const std::string& processName,
                                  const ProxyServer* proxyServer);
    
    // 设置回调
    void setSessionCallback(SessionCallback callback) { sessionCallback_ = callback; }
    
    // 获取活动会话
    std::map<UINT64, std::shared_ptr<ProxySession>> getActiveSessions() const;
    
    // 获取统计信息
    UINT64 getTotalSessions() const { return totalSessions_; }
    UINT64 getActiveSessions() const;
    UINT64 getTotalBytesSent() const { return totalBytesSent_; }
    UINT64 getTotalBytesReceived() const { return totalBytesReceived_; }

private:
    void acceptThread();
    void sessionThread(std::shared_ptr<ProxySession> session);
    void relayData(ProxySession* session);
    
    bool connectToSocks5(ProxySession* session);
    std::string makeTargetKey(UINT32 srcAddr, UINT16 srcPort) const;
    
    struct OriginalTarget {
        UINT32 dstAddr = 0;
        UINT16 dstPort = 0;
        bool isIPv6 = false;
        UINT32 dstAddrV6[4] = {0};
        UINT32 processId = 0;
        std::string processName;
        const ProxyServer* proxyServer = nullptr;
        INT64 timestamp = 0;
    };

private:
    SOCKET listenSocket_ = INVALID_SOCKET;
    std::string bindAddr_;
    int bindPort_ = 0;
    
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    
    mutable std::mutex sessionsMutex_;
    std::map<UINT64, std::shared_ptr<ProxySession>> sessions_;
    std::atomic<UINT64> nextSessionId_{1};
    
    mutable std::mutex targetsMutex_;
    std::map<std::string, OriginalTarget> originalTargets_;
    
    SessionCallback sessionCallback_;
    
    // 统计
    std::atomic<UINT64> totalSessions_{0};
    std::atomic<UINT64> totalBytesSent_{0};
    std::atomic<UINT64> totalBytesReceived_{0};
};

// 全局代理服务器实例
LocalProxyServer& getLocalProxyServer();

} // namespace proxifier

#endif // PROXY_SERVER_H