/*
 * process_monitor.cpp
 * 进程监控实现 - 使用 WinDivert FLOW 层
 */

#include "process_monitor.h"
#include "windivert.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

namespace proxifier {

// 全局进程监控实例
static ProcessMonitor g_processMonitor;
ProcessMonitor& getProcessMonitor() { return g_processMonitor; }

ProcessMonitor::ProcessMonitor() {}

ProcessMonitor::~ProcessMonitor() {
    stop();
}

std::string ProcessMonitor::getProcessName(DWORD pid) {
    if (pid == 0) return "System Idle Process";
    if (pid == 4) return "System";
    
    std::string name = "<unknown>";
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess != NULL) {
        char buffer[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        
        if (QueryFullProcessImageNameA(hProcess, 0, buffer, &size)) {
            // 提取文件名
            std::string fullPath = buffer;
            size_t pos = fullPath.find_last_of("\\/");
            if (pos != std::string::npos) {
                name = fullPath.substr(pos + 1);
            } else {
                name = fullPath;
            }
        }
        
        CloseHandle(hProcess);
    }
    
    return name;
}

std::string ProcessMonitor::getProcessPath(DWORD pid) {
    if (pid == 0 || pid == 4) return "";
    
    std::string path;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        char buffer[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        
        if (QueryFullProcessImageNameA(hProcess, 0, buffer, &size)) {
            path = buffer;
        }
        
        CloseHandle(hProcess);
    }
    
    return path;
}

bool ProcessMonitor::start(const std::string& filter) {
    if (running_) return true;
    
    // 打开 FLOW 层句柄
    // FLOW 层需要 SNIFF 和 RECV_ONLY 标志
    handle_ = WinDivertOpen(
        filter.c_str(),
        WINDIVERT_LAYER_FLOW,
        0,
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
    );
    
    if (handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    running_ = true;
    monitorThread_ = std::thread(&ProcessMonitor::monitorThread, this);
    
    return true;
}

void ProcessMonitor::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
    
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

void ProcessMonitor::monitorThread() {
    WINDIVERT_ADDRESS addr;
    
    while (running_) {
        // FLOW 层不返回数据包，只返回地址信息
        if (!WinDivertRecv(handle_, NULL, 0, NULL, &addr)) {
            DWORD error = GetLastError();
            if (error == ERROR_NO_DATA) {
                break;  // 句柄已关闭
            }
            continue;
        }
        
        processFlowEvent(NULL, 0, &addr);
    }
}

void ProcessMonitor::processFlowEvent(const void* packet, UINT packetLen, const void* addrPtr) {
    const WINDIVERT_ADDRESS* addr = static_cast<const WINDIVERT_ADDRESS*>(addrPtr);
    
    ConnectionInfo info;
    info.timestamp = addr->Timestamp;
    info.processId = addr->Flow.ProcessId;
    info.processName = getProcessName(info.processId);
    info.processPath = getProcessPath(info.processId);
    
    memcpy(info.localAddr, addr->Flow.LocalAddr, sizeof(info.localAddr));
    memcpy(info.remoteAddr, addr->Flow.RemoteAddr, sizeof(info.remoteAddr));
    info.localPort = addr->Flow.LocalPort;
    info.remotePort = addr->Flow.RemotePort;
    info.protocol = addr->Flow.Protocol;
    info.isIPv6 = addr->IPv6;
    info.outbound = addr->Outbound;
    info.endpointId = addr->Flow.EndpointId;
    info.parentEndpointId = addr->Flow.ParentEndpointId;
    
    ConnectionEvent event;
    if (addr->Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
        event = ConnectionEvent::ESTABLISHED;
        
        // 添加到连接表
        std::lock_guard<std::mutex> lock(connectionsMutex_);
        connections_[info.endpointId] = info;
        
        // 创建索引
        std::string key = makeConnectionKey(
            info.localAddr[0], info.localPort,
            info.remoteAddr[0], info.remotePort,
            info.protocol
        );
        connectionIndex_[key] = info.endpointId;
        
    } else if (addr->Event == WINDIVERT_EVENT_FLOW_DELETED) {
        event = ConnectionEvent::DELETED;
        
        // 从连接表移除
        std::lock_guard<std::mutex> lock(connectionsMutex_);
        auto it = connections_.find(info.endpointId);
        if (it != connections_.end()) {
            std::string key = makeConnectionKey(
                it->second.localAddr[0], it->second.localPort,
                it->second.remoteAddr[0], it->second.remotePort,
                it->second.protocol
            );
            connectionIndex_.erase(key);
            connections_.erase(it);
        }
    } else {
        return;  // 未知事件
    }
    
    // 调用回调
    if (callback_) {
        callback_(event, info);
    }
}

std::string ProcessMonitor::makeConnectionKey(UINT32 localAddr, UINT16 localPort,
                                              UINT32 remoteAddr, UINT16 remotePort,
                                              UINT8 protocol) const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << localAddr << ":"
        << std::setw(4) << localPort << "-"
        << std::setw(8) << remoteAddr << ":"
        << std::setw(4) << remotePort << "-"
        << std::setw(2) << (int)protocol;
    return oss.str();
}

const ConnectionInfo* ProcessMonitor::findConnection(UINT32 localAddr, UINT16 localPort,
                                                     UINT32 remoteAddr, UINT16 remotePort,
                                                     UINT8 protocol) const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    std::string key = makeConnectionKey(localAddr, localPort, remoteAddr, remotePort, protocol);
    auto indexIt = connectionIndex_.find(key);
    if (indexIt != connectionIndex_.end()) {
        auto connIt = connections_.find(indexIt->second);
        if (connIt != connections_.end()) {
            return &connIt->second;
        }
    }
    
    return nullptr;
}

const ConnectionInfo* ProcessMonitor::findConnectionByEndpoint(UINT64 endpointId) const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(endpointId);
    if (it != connections_.end()) {
        return &it->second;
    }
    
    return nullptr;
}

std::map<UINT64, ConnectionInfo> ProcessMonitor::getActiveConnections() const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    return connections_;
}

void ProcessMonitor::cleanupExpiredConnections(int maxAgeSeconds) {
    // FLOW 层会自动通知连接删除，所以这里不需要手动清理
    // 但可以用于清理可能遗漏的连接
}

} // namespace proxifier