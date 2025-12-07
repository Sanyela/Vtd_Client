/*
 * traffic_interceptor.h
 * 流量拦截器 - 使用 WinDivert 拦截和重定向网络流量
 */

#ifndef TRAFFIC_INTERCEPTOR_H
#define TRAFFIC_INTERCEPTOR_H

#include <windows.h>
#include <string>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>

namespace proxifier {

// 前向声明
struct Rule;
struct ProxyServer;
class Config;
class ProcessMonitor;
class LocalProxyServer;

// 拦截动作
enum class InterceptAction {
    ALLOW,      // 允许通过（直连）
    REDIRECT,   // 重定向到代理
    BLOCK       // 阻止
};

// 拦截决策
struct InterceptDecision {
    InterceptAction action = InterceptAction::ALLOW;
    const ProxyServer* proxyServer = nullptr;
    const Rule* matchedRule = nullptr;
    std::string reason;
};

// 连接跟踪信息
struct TrackedConnection {
    UINT32 srcAddr = 0;
    UINT16 srcPort = 0;
    UINT32 dstAddr = 0;
    UINT16 dstPort = 0;
    
    bool isIPv6 = false;
    UINT32 srcAddrV6[4] = {0};
    UINT32 dstAddrV6[4] = {0};
    
    InterceptAction action = InterceptAction::ALLOW;
    const ProxyServer* proxyServer = nullptr;
    
    UINT32 processId = 0;
    std::string processName;
    
    // TCP 状态跟踪
    bool synSeen = false;
    bool established = false;
    bool redirected = false;
    
    INT64 createTime = 0;
    INT64 lastActiveTime = 0;
};

// 拦截统计
struct InterceptStats {
    UINT64 packetsReceived = 0;
    UINT64 packetsAllowed = 0;
    UINT64 packetsRedirected = 0;
    UINT64 packetsBlocked = 0;
    UINT64 packetsDropped = 0;
    
    UINT64 connectionsTracked = 0;
    UINT64 connectionsRedirected = 0;
    UINT64 connectionsBlocked = 0;
};

// 流量拦截器类
class TrafficInterceptor {
public:
    TrafficInterceptor();
    ~TrafficInterceptor();
    
    // 设置依赖
    void setConfig(Config* config) { config_ = config; }
    void setProcessMonitor(ProcessMonitor* monitor) { processMonitor_ = monitor; }
    void setLocalProxyServer(LocalProxyServer* server) { proxyServer_ = server; }
    
    // 启动/停止拦截
    bool start();
    void stop();
    bool isRunning() const { return running_; }
    
    // 获取统计信息
    InterceptStats getStats() const;
    
    // 获取活动连接
    std::map<std::string, TrackedConnection> getTrackedConnections() const;
    
    // 手动添加/移除进程到代理列表
    void addProcessToProxy(UINT32 pid, const ProxyServer* proxy);
    void removeProcessFromProxy(UINT32 pid);
    
    // 设置本地代理地址
    void setLocalProxyAddress(UINT32 addr, UINT16 port);

private:
    void interceptThread();
    void processPacket(void* packet, UINT packetLen, void* addr);
    
    // 决策函数
    InterceptDecision makeDecision(UINT32 processId, const std::string& processName,
                                   UINT32 dstAddr, UINT16 dstPort, UINT8 protocol);
    
    InterceptDecision makeDecisionV6(UINT32 processId, const std::string& processName,
                                     const UINT32* dstAddr, UINT16 dstPort, UINT8 protocol);
    
    // 连接跟踪
    std::string makeConnectionKey(UINT32 srcAddr, UINT16 srcPort,
                                  UINT32 dstAddr, UINT16 dstPort) const;
    
    TrackedConnection* getOrCreateConnection(UINT32 srcAddr, UINT16 srcPort,
                                             UINT32 dstAddr, UINT16 dstPort,
                                             UINT8 protocol);
    
    void cleanupExpiredConnections();
    
    // 包处理
    bool redirectPacket(void* packet, UINT packetLen, void* addr,
                        TrackedConnection* conn);
    
    bool restorePacket(void* packet, UINT packetLen, void* addr,
                       TrackedConnection* conn);
    
    // 辅助函数
    std::string ipToString(UINT32 addr) const;
    std::string ipv6ToString(const UINT32* addr) const;
    bool isLocalAddress(UINT32 addr) const;
    bool isLocalAddressV6(const UINT32* addr) const;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> running_{false};
    std::thread interceptThread_;
    
    Config* config_ = nullptr;
    ProcessMonitor* processMonitor_ = nullptr;
    LocalProxyServer* proxyServer_ = nullptr;
    
    // 本地代理地址
    UINT32 localProxyAddr_ = 0x0100007F;  // 127.0.0.1
    UINT16 localProxyPort_ = 0;
    
    // 连接跟踪
    mutable std::mutex connectionsMutex_;
    std::map<std::string, TrackedConnection> connections_;
    
    // 手动代理进程列表
    mutable std::mutex manualProxyMutex_;
    std::map<UINT32, const ProxyServer*> manualProxyProcesses_;
    
    // 统计
    InterceptStats stats_;
    mutable std::mutex statsMutex_;
};

// 全局拦截器实例
TrafficInterceptor& getTrafficInterceptor();

} // namespace proxifier

#endif // TRAFFIC_INTERCEPTOR_H