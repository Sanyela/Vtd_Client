/*
 * process_monitor.h
 * 进程监控 - 使用 WinDivert FLOW 层跟踪进程的网络连接
 */

#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#include <windows.h>
#include <string>
#include <map>
#include <mutex>
#include <functional>
#include <thread>
#include <atomic>

namespace proxifier {

// 连接信息
struct ConnectionInfo {
    UINT32 processId;
    std::string processName;
    std::string processPath;
    
    UINT32 localAddr[4];    // IPv6 格式（IPv4 映射到 IPv6）
    UINT32 remoteAddr[4];
    UINT16 localPort;
    UINT16 remotePort;
    UINT8 protocol;         // TCP=6, UDP=17
    bool isIPv6;
    bool outbound;
    
    UINT64 endpointId;
    UINT64 parentEndpointId;
    
    // 时间戳
    INT64 timestamp;
};

// 连接事件类型
enum class ConnectionEvent {
    ESTABLISHED,    // 连接建立
    DELETED         // 连接关闭
};

// 连接事件回调
using ConnectionCallback = std::function<void(ConnectionEvent event, const ConnectionInfo& info)>;

// 进程监控类
class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();
    
    // 启动/停止监控
    bool start(const std::string& filter = "true");
    void stop();
    bool isRunning() const { return running_; }
    
    // 设置回调
    void setCallback(ConnectionCallback callback) { callback_ = callback; }
    
    // 根据 PID 获取进程名
    static std::string getProcessName(DWORD pid);
    static std::string getProcessPath(DWORD pid);
    
    // 根据连接信息查找进程
    const ConnectionInfo* findConnection(UINT32 localAddr, UINT16 localPort,
                                         UINT32 remoteAddr, UINT16 remotePort,
                                         UINT8 protocol) const;
    
    // 根据端点ID查找连接
    const ConnectionInfo* findConnectionByEndpoint(UINT64 endpointId) const;
    
    // 获取所有活动连接
    std::map<UINT64, ConnectionInfo> getActiveConnections() const;
    
    // 清理过期连接
    void cleanupExpiredConnections(int maxAgeSeconds = 300);

private:
    void monitorThread();
    void processFlowEvent(const void* packet, UINT packetLen, const void* addr);
    
    std::string makeConnectionKey(UINT32 localAddr, UINT16 localPort,
                                  UINT32 remoteAddr, UINT16 remotePort,
                                  UINT8 protocol) const;

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::atomic<bool> running_{false};
    std::thread monitorThread_;
    
    mutable std::mutex connectionsMutex_;
    std::map<UINT64, ConnectionInfo> connections_;  // endpointId -> ConnectionInfo
    std::map<std::string, UINT64> connectionIndex_; // key -> endpointId
    
    ConnectionCallback callback_;
};

// 全局进程监控实例
ProcessMonitor& getProcessMonitor();

} // namespace proxifier

#endif // PROCESS_MONITOR_H