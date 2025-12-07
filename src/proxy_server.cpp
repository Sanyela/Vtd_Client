/*
 * proxy_server.cpp
 * 本地代理服务器实现
 */

#include "proxy_server.h"
#include "socks5_client.h"
#include "config.h"
#include <sstream>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

namespace proxifier {

// 全局代理服务器实例
static LocalProxyServer g_localProxyServer;
LocalProxyServer& getLocalProxyServer() { return g_localProxyServer; }

// 获取当前时间戳
static INT64 getCurrentTimestamp() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

LocalProxyServer::LocalProxyServer() {
    socks5::initWinsock();
}

LocalProxyServer::~LocalProxyServer() {
    stop();
    socks5::cleanupWinsock();
}

bool LocalProxyServer::start(const std::string& bindAddr, int port) {
    if (running_) return true;
    
    // 创建监听 socket
    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket_ == INVALID_SOCKET) {
        return false;
    }
    
    // 设置 SO_REUSEADDR
    int optval = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));
    
    // 绑定地址
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, bindAddr.c_str(), &addr.sin_addr);
    
    if (bind(listenSocket_, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return false;
    }
    
    // 获取实际绑定的端口
    int addrLen = sizeof(addr);
    getsockname(listenSocket_, (struct sockaddr*)&addr, &addrLen);
    bindAddr_ = bindAddr;
    bindPort_ = ntohs(addr.sin_port);
    
    // 开始监听
    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
        return false;
    }
    
    running_ = true;
    acceptThread_ = std::thread(&LocalProxyServer::acceptThread, this);
    
    return true;
}

void LocalProxyServer::stop() {
    if (!running_) return;
    
    running_ = false;
    
    // 关闭监听 socket
    if (listenSocket_ != INVALID_SOCKET) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }
    
    // 等待接受线程结束
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
    
    // 关闭所有会话
    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        for (auto& pair : sessions_) {
            pair.second->closed = true;
            if (pair.second->clientSocket != INVALID_SOCKET) {
                closesocket(pair.second->clientSocket);
            }
            if (pair.second->proxySocket != INVALID_SOCKET) {
                closesocket(pair.second->proxySocket);
            }
        }
        sessions_.clear();
    }
}

void LocalProxyServer::registerOriginalTarget(UINT32 srcAddr, UINT16 srcPort,
                                              UINT32 dstAddr, UINT16 dstPort,
                                              UINT32 processId, const std::string& processName,
                                              const ProxyServer* proxyServer) {
    std::lock_guard<std::mutex> lock(targetsMutex_);
    
    std::string key = makeTargetKey(srcAddr, srcPort);
    
    OriginalTarget target;
    target.dstAddr = dstAddr;
    target.dstPort = dstPort;
    target.isIPv6 = false;
    target.processId = processId;
    target.processName = processName;
    target.proxyServer = proxyServer;
    target.timestamp = getCurrentTimestamp();
    
    originalTargets_[key] = target;
    
    // 清理过期的目标信息（超过 30 秒）
    INT64 now = getCurrentTimestamp();
    for (auto it = originalTargets_.begin(); it != originalTargets_.end(); ) {
        if (now - it->second.timestamp > 30000) {
            it = originalTargets_.erase(it);
        } else {
            ++it;
        }
    }
}

void LocalProxyServer::registerOriginalTargetV6(const UINT32* srcAddr, UINT16 srcPort,
                                                const UINT32* dstAddr, UINT16 dstPort,
                                                UINT32 processId, const std::string& processName,
                                                const ProxyServer* proxyServer) {
    // IPv6 支持（简化实现）
    registerOriginalTarget(srcAddr[0], srcPort, dstAddr[0], dstPort, 
                          processId, processName, proxyServer);
}

std::string LocalProxyServer::makeTargetKey(UINT32 srcAddr, UINT16 srcPort) const {
    std::ostringstream oss;
    oss << std::hex << srcAddr << ":" << srcPort;
    return oss.str();
}

void LocalProxyServer::acceptThread() {
    while (running_) {
        struct sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(listenSocket_, (struct sockaddr*)&clientAddr, &addrLen);
        if (clientSocket == INVALID_SOCKET) {
            if (!running_) break;
            continue;
        }
        
        // 创建会话
        auto session = std::make_shared<ProxySession>();
        session->sessionId = nextSessionId_++;
        session->clientSocket = clientSocket;
        session->createTime = getCurrentTimestamp();
        session->lastActiveTime = session->createTime;
        
        // 查找原始目标信息
        UINT32 srcAddr = clientAddr.sin_addr.s_addr;
        UINT16 srcPort = ntohs(clientAddr.sin_port);
        std::string key = makeTargetKey(srcAddr, srcPort);
        
        {
            std::lock_guard<std::mutex> lock(targetsMutex_);
            auto it = originalTargets_.find(key);
            if (it != originalTargets_.end()) {
                session->originalDstAddr = it->second.dstAddr;
                session->originalDstPort = it->second.dstPort;
                session->isIPv6 = it->second.isIPv6;
                session->processId = it->second.processId;
                session->processName = it->second.processName;
                session->proxyServer = it->second.proxyServer;
                
                if (it->second.isIPv6) {
                    memcpy(session->originalDstAddrV6, it->second.dstAddrV6, 
                           sizeof(session->originalDstAddrV6));
                }
                
                originalTargets_.erase(it);
            } else {
                // 找不到原始目标信息，关闭连接
                closesocket(clientSocket);
                continue;
            }
        }
        
        // 添加到会话列表
        {
            std::lock_guard<std::mutex> lock(sessionsMutex_);
            sessions_[session->sessionId] = session;
        }
        
        totalSessions_++;
        
        // 启动会话处理线程
        std::thread(&LocalProxyServer::sessionThread, this, session).detach();
    }
}

void LocalProxyServer::sessionThread(std::shared_ptr<ProxySession> session) {
    // 通知会话开始
    if (sessionCallback_) {
        sessionCallback_(session.get(), "started");
    }
    
    // 连接到 SOCKS5 代理
    if (!connectToSocks5(session.get())) {
        if (sessionCallback_) {
            sessionCallback_(session.get(), "connect_failed");
        }
        
        closesocket(session->clientSocket);
        session->clientSocket = INVALID_SOCKET;
        
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        sessions_.erase(session->sessionId);
        return;
    }
    
    session->connected = true;
    
    if (sessionCallback_) {
        sessionCallback_(session.get(), "connected");
    }
    
    // 开始数据转发
    relayData(session.get());
    
    // 清理
    session->closed = true;
    
    if (session->clientSocket != INVALID_SOCKET) {
        closesocket(session->clientSocket);
        session->clientSocket = INVALID_SOCKET;
    }
    
    if (session->proxySocket != INVALID_SOCKET) {
        closesocket(session->proxySocket);
        session->proxySocket = INVALID_SOCKET;
    }
    
    // 更新统计
    totalBytesSent_ += session->bytesSent;
    totalBytesReceived_ += session->bytesReceived;
    
    if (sessionCallback_) {
        sessionCallback_(session.get(), "closed");
    }
    
    // 从会话列表移除
    {
        std::lock_guard<std::mutex> lock(sessionsMutex_);
        sessions_.erase(session->sessionId);
    }
}

bool LocalProxyServer::connectToSocks5(ProxySession* session) {
    if (session->proxyServer == nullptr) {
        return false;
    }
    
    Socks5Client client;
    client.setProxy(session->proxyServer->address, session->proxyServer->port);
    
    if (session->proxyServer->authEnabled) {
        client.setAuth(session->proxyServer->username, session->proxyServer->password);
    }
    
    // 连接到代理服务器
    if (!client.connectToProxy()) {
        return false;
    }
    
    // 通过代理连接到目标
    Socks5ConnectResult result;
    if (session->isIPv6) {
        result = client.connectToTargetIPv6(session->originalDstAddrV6, session->originalDstPort);
    } else {
        result = client.connectToTarget(session->originalDstAddr, session->originalDstPort);
    }
    
    if (!result.success) {
        return false;
    }
    
    // 获取代理 socket
    session->proxySocket = client.releaseSocket();
    
    return true;
}

void LocalProxyServer::relayData(ProxySession* session) {
    // 使用 select 进行双向数据转发
    fd_set readfds;
    char buffer[65536];
    
    SOCKET maxfd = max(session->clientSocket, session->proxySocket);
    
    while (!session->closed && running_) {
        FD_ZERO(&readfds);
        FD_SET(session->clientSocket, &readfds);
        FD_SET(session->proxySocket, &readfds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int ret = select((int)maxfd + 1, &readfds, NULL, NULL, &timeout);
        if (ret <= 0) {
            if (ret < 0) break;  // 错误
            continue;  // 超时
        }
        
        // 客户端 -> 代理
        if (FD_ISSET(session->clientSocket, &readfds)) {
            int received = recv(session->clientSocket, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            int sent = send(session->proxySocket, buffer, received, 0);
            if (sent <= 0) break;
            
            session->bytesSent += received;
            session->lastActiveTime = getCurrentTimestamp();
        }
        
        // 代理 -> 客户端
        if (FD_ISSET(session->proxySocket, &readfds)) {
            int received = recv(session->proxySocket, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            
            int sent = send(session->clientSocket, buffer, received, 0);
            if (sent <= 0) break;
            
            session->bytesReceived += received;
            session->lastActiveTime = getCurrentTimestamp();
        }
    }
}

std::map<UINT64, std::shared_ptr<ProxySession>> LocalProxyServer::getActiveSessions() const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    return sessions_;
}

UINT64 LocalProxyServer::getActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(sessionsMutex_);
    return sessions_.size();
}

} // namespace proxifier