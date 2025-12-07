/*
 * traffic_interceptor.cpp
 * 流量拦截器实现
 */

#include "traffic_interceptor.h"
#include "config.h"
#include "process_monitor.h"
#include "proxy_server.h"
#include "windivert_loader.h"
#include <sstream>
#include <chrono>

namespace proxifier {

// 全局拦截器实例
static TrafficInterceptor g_trafficInterceptor;
TrafficInterceptor& getTrafficInterceptor() { return g_trafficInterceptor; }

// 获取当前时间戳
static INT64 getCurrentTimestamp() {
    auto now = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

TrafficInterceptor::TrafficInterceptor() {}

TrafficInterceptor::~TrafficInterceptor() {
    stop();
}

bool TrafficInterceptor::start() {
    if (running_) return true;
    
    if (config_ == nullptr || processMonitor_ == nullptr || proxyServer_ == nullptr) {
        return false;
    }
    
    // 获取本地代理地址
    localProxyPort_ = proxyServer_->getBindPort();
    if (localProxyPort_ == 0) {
        return false;
    }
    
    // 打开 NETWORK 层句柄
    // 只拦截出站 TCP 连接
    std::string filter = "outbound and tcp and !loopback";
    
    handle_ = WinDivertOpen(
        filter.c_str(),
        WINDIVERT_LAYER_NETWORK,
        0,  // 优先级
        0   // 标志
    );
    
    if (handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // 设置队列参数
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_SIZE, 4194304);
    
    running_ = true;
    interceptThread_ = std::thread(&TrafficInterceptor::interceptThread, this);
    
    return true;
}

void TrafficInterceptor::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (handle_ != INVALID_HANDLE_VALUE) {
        WinDivertShutdown(handle_, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(handle_);
        handle_ = INVALID_HANDLE_VALUE;
    }
    
    if (interceptThread_.joinable()) {
        interceptThread_.join();
    }
}

void TrafficInterceptor::interceptThread() {
    unsigned char packet[65535];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;
    
    while (running_) {
        if (!WinDivertRecv(handle_, packet, sizeof(packet), &packetLen, &addr)) {
            DWORD error = GetLastError();
            if (error == ERROR_NO_DATA) {
                break;
            }
            continue;
        }
        
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.packetsReceived++;
        }
        
        processPacket(packet, packetLen, &addr);
    }
}

void TrafficInterceptor::processPacket(void* packet, UINT packetLen, void* addrPtr) {
    WINDIVERT_ADDRESS* addr = static_cast<WINDIVERT_ADDRESS*>(addrPtr);
    
    // 解析包头
    PWINDIVERT_IPHDR ipHdr = nullptr;
    PWINDIVERT_IPV6HDR ipv6Hdr = nullptr;
    PWINDIVERT_TCPHDR tcpHdr = nullptr;
    
    WinDivertHelperParsePacket(packet, packetLen, &ipHdr, &ipv6Hdr,
        nullptr, nullptr, nullptr, &tcpHdr, nullptr, nullptr, nullptr, nullptr, nullptr);
    
    if (tcpHdr == nullptr) {
        // 不是 TCP 包，直接放行
        WinDivertSend(handle_, packet, packetLen, nullptr, addr);
        
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.packetsAllowed++;
        return;
    }
    
    // 获取源/目标地址和端口
    UINT32 srcAddr = 0, dstAddr = 0;
    UINT16 srcPort = 0, dstPort = 0;
    bool isIPv6 = false;
    
    if (ipHdr != nullptr) {
        srcAddr = ipHdr->SrcAddr;
        dstAddr = ipHdr->DstAddr;
    } else if (ipv6Hdr != nullptr) {
        // IPv6 简化处理
        srcAddr = ipv6Hdr->SrcAddr[0];
        dstAddr = ipv6Hdr->DstAddr[0];
        isIPv6 = true;
    }
    
    srcPort = WinDivertHelperNtohs(tcpHdr->SrcPort);
    dstPort = WinDivertHelperNtohs(tcpHdr->DstPort);
    
    // 检查是否是到本地代理的连接（避免循环）
    if (dstAddr == localProxyAddr_ && dstPort == localProxyPort_) {
        WinDivertSend(handle_, packet, packetLen, nullptr, addr);
        
        std::lock_guard<std::mutex> lock(statsMutex_);
        stats_.packetsAllowed++;
        return;
    }
    
    // 生成连接键
    std::string connKey = makeConnectionKey(srcAddr, srcPort, dstAddr, dstPort);
    
    // 查找或创建连接跟踪
    TrackedConnection* conn = getOrCreateConnection(srcAddr, srcPort, dstAddr, dstPort, 6);
    
    // 只在 SYN 包时做决策
    if (tcpHdr->Syn && !tcpHdr->Ack) {
        conn->synSeen = true;
        
        // 查找进程信息
        const ConnectionInfo* flowInfo = processMonitor_->findConnection(
            srcAddr, srcPort, dstAddr, dstPort, 6);
        
        if (flowInfo != nullptr) {
            conn->processId = flowInfo->processId;
            conn->processName = flowInfo->processName;
        }
        
        // 做出拦截决策
        InterceptDecision decision = makeDecision(
            conn->processId, conn->processName,
            dstAddr, dstPort, 6);
        
        conn->action = decision.action;
        conn->proxyServer = decision.proxyServer;
        
        if (decision.action == InterceptAction::REDIRECT && decision.proxyServer != nullptr) {
            // 注册原始目标信息
            proxyServer_->registerOriginalTarget(
                srcAddr, srcPort, dstAddr, dstPort,
                conn->processId, conn->processName,
                decision.proxyServer);
            
            conn->redirected = true;
            
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.connectionsRedirected++;
        } else if (decision.action == InterceptAction::BLOCK) {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.connectionsBlocked++;
        }
        
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.connectionsTracked++;
        }
    }
    
    // 根据决策处理包
    switch (conn->action) {
        case InterceptAction::ALLOW:
            // 直接放行
            WinDivertSend(handle_, packet, packetLen, nullptr, addr);
            
            {
                std::lock_guard<std::mutex> lock(statsMutex_);
                stats_.packetsAllowed++;
            }
            break;
            
        case InterceptAction::REDIRECT:
            // 重定向到本地代理
            if (redirectPacket(packet, packetLen, addr, conn)) {
                std::lock_guard<std::mutex> lock(statsMutex_);
                stats_.packetsRedirected++;
            } else {
                // 重定向失败，放行
                WinDivertSend(handle_, packet, packetLen, nullptr, addr);
                
                std::lock_guard<std::mutex> lock(statsMutex_);
                stats_.packetsAllowed++;
            }
            break;
            
        case InterceptAction::BLOCK:
            // 丢弃包（不发送 RST，静默丢弃）
            {
                std::lock_guard<std::mutex> lock(statsMutex_);
                stats_.packetsBlocked++;
            }
            break;
    }
    
    conn->lastActiveTime = getCurrentTimestamp();
}

InterceptDecision TrafficInterceptor::makeDecision(UINT32 processId, const std::string& processName,
                                                   UINT32 dstAddr, UINT16 dstPort, UINT8 protocol) {
    InterceptDecision decision;
    decision.action = InterceptAction::ALLOW;
    
    if (config_ == nullptr) {
        return decision;
    }
    
    // 转换目标地址为字符串
    std::string dstAddrStr = ipToString(dstAddr);
    
    // 匹配规则
    const Rule* rule = config_->matchRule(processName, dstAddrStr, dstPort);
    
    if (rule != nullptr) {
        decision.matchedRule = rule;
        
        switch (rule->action.type) {
            case ProxyType::DIRECT:
                decision.action = InterceptAction::ALLOW;
                decision.reason = "Rule: " + rule->name + " (Direct)";
                break;
                
            case ProxyType::BLOCK:
                decision.action = InterceptAction::BLOCK;
                decision.reason = "Rule: " + rule->name + " (Block)";
                break;
                
            case ProxyType::SOCKS5:
            case ProxyType::HTTP:
                decision.proxyServer = config_->getProxy(rule->action.proxyId);
                if (decision.proxyServer != nullptr) {
                    decision.action = InterceptAction::REDIRECT;
                    decision.reason = "Rule: " + rule->name + " (Proxy)";
                } else {
                    decision.action = InterceptAction::ALLOW;
                    decision.reason = "Rule: " + rule->name + " (Proxy not found, fallback to direct)";
                }
                break;
        }
    } else {
        decision.reason = "No matching rule, default to direct";
    }
    
    return decision;
}

InterceptDecision TrafficInterceptor::makeDecisionV6(UINT32 processId, const std::string& processName,
                                                     const UINT32* dstAddr, UINT16 dstPort, UINT8 protocol) {
    // IPv6 简化处理
    return makeDecision(processId, processName, dstAddr[0], dstPort, protocol);
}

std::string TrafficInterceptor::makeConnectionKey(UINT32 srcAddr, UINT16 srcPort,
                                                  UINT32 dstAddr, UINT16 dstPort) const {
    std::ostringstream oss;
    oss << std::hex << srcAddr << ":" << srcPort << "-" << dstAddr << ":" << dstPort;
    return oss.str();
}

TrackedConnection* TrafficInterceptor::getOrCreateConnection(UINT32 srcAddr, UINT16 srcPort,
                                                             UINT32 dstAddr, UINT16 dstPort,
                                                             UINT8 protocol) {
    std::string key = makeConnectionKey(srcAddr, srcPort, dstAddr, dstPort);
    
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    auto it = connections_.find(key);
    if (it != connections_.end()) {
        return &it->second;
    }
    
    // 创建新连接
    TrackedConnection conn;
    conn.srcAddr = srcAddr;
    conn.srcPort = srcPort;
    conn.dstAddr = dstAddr;
    conn.dstPort = dstPort;
    conn.createTime = getCurrentTimestamp();
    conn.lastActiveTime = conn.createTime;
    
    connections_[key] = conn;
    return &connections_[key];
}

bool TrafficInterceptor::redirectPacket(void* packet, UINT packetLen, void* addrPtr,
                                        TrackedConnection* conn) {
    WINDIVERT_ADDRESS* addr = static_cast<WINDIVERT_ADDRESS*>(addrPtr);
    
    // 解析包头
    PWINDIVERT_IPHDR ipHdr = nullptr;
    PWINDIVERT_TCPHDR tcpHdr = nullptr;
    
    WinDivertHelperParsePacket(packet, packetLen, &ipHdr, nullptr,
        nullptr, nullptr, nullptr, &tcpHdr, nullptr, nullptr, nullptr, nullptr, nullptr);
    
    if (ipHdr == nullptr || tcpHdr == nullptr) {
        return false;
    }
    
    // 修改目标地址为本地代理
    ipHdr->DstAddr = localProxyAddr_;
    tcpHdr->DstPort = WinDivertHelperHtons(localProxyPort_);
    
    // 重新计算校验和
    WinDivertHelperCalcChecksums(packet, packetLen, addr, 0);
    
    // 发送修改后的包
    return WinDivertSend(handle_, packet, packetLen, nullptr, addr) != FALSE;
}

bool TrafficInterceptor::restorePacket(void* packet, UINT packetLen, void* addrPtr,
                                       TrackedConnection* conn) {
    // 用于处理返回的包（从代理到客户端）
    // 需要将源地址从本地代理改回原始目标地址
    // 这个功能在当前实现中由本地代理服务器处理
    return true;
}

void TrafficInterceptor::cleanupExpiredConnections() {
    INT64 now = getCurrentTimestamp();
    const INT64 maxAge = 300000;  // 5 分钟
    
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    
    for (auto it = connections_.begin(); it != connections_.end(); ) {
        if (now - it->second.lastActiveTime > maxAge) {
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string TrafficInterceptor::ipToString(UINT32 addr) const {
    std::ostringstream oss;
    oss << ((addr >> 0) & 0xFF) << "."
        << ((addr >> 8) & 0xFF) << "."
        << ((addr >> 16) & 0xFF) << "."
        << ((addr >> 24) & 0xFF);
    return oss.str();
}

std::string TrafficInterceptor::ipv6ToString(const UINT32* addr) const {
    // 简化实现
    return "";
}

bool TrafficInterceptor::isLocalAddress(UINT32 addr) const {
    // 127.0.0.0/8
    return (addr & 0xFF) == 127;
}

bool TrafficInterceptor::isLocalAddressV6(const UINT32* addr) const {
    // ::1
    return addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 1;
}

InterceptStats TrafficInterceptor::getStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

std::map<std::string, TrackedConnection> TrafficInterceptor::getTrackedConnections() const {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    return connections_;
}

void TrafficInterceptor::addProcessToProxy(UINT32 pid, const ProxyServer* proxy) {
    std::lock_guard<std::mutex> lock(manualProxyMutex_);
    manualProxyProcesses_[pid] = proxy;
}

void TrafficInterceptor::removeProcessFromProxy(UINT32 pid) {
    std::lock_guard<std::mutex> lock(manualProxyMutex_);
    manualProxyProcesses_.erase(pid);
}

void TrafficInterceptor::setLocalProxyAddress(UINT32 addr, UINT16 port) {
    localProxyAddr_ = addr;
    localProxyPort_ = port;
}

} // namespace proxifier