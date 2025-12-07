/*
 * traffic_interceptor.cpp
 * 流量拦截器实现 - 基于 FLOW 层的进程感知代理
 *
 * 核心原理：
 * 1. 使用 FLOW 层获取连接的进程信息（最可靠的方式）
 * 2. 使用 NETWORK 层拦截和重定向流量
 * 3. 在 FLOW 层连接建立事件中做出代理决策
 * 4. 在 NETWORK 层根据决策重定向 SYN 包
 *
 * 重要：FLOW 层事件可能在 SYN 包之后到达，所以需要：
 * - 在 FLOW 层预先标记需要代理的连接
 * - 在 NETWORK 层检查是否有预先标记的决策
 */

#include "traffic_interceptor.h"
#include "config.h"
#include "process_monitor.h"
#include "proxy_server.h"
#include "windivert_loader.h"
#include "dns_monitor.h"
#include <sstream>
#include <chrono>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <iomanip>

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
    
    // 获取本地代理地址和端口
    localProxyPort_ = proxyServer_->getBindPort();
    if (localProxyPort_ == 0) {
        return false;
    }
    
    // 本地代理地址 127.0.0.1 的网络字节序
    localProxyAddr_ = 0x0100007F;  // 127.0.0.1 in network byte order
    
    printf("[拦截器] 本地代理: 127.0.0.1:%d\n", localProxyPort_);
    
    // 打开 NETWORK 层句柄
    // 拦截出站 TCP 连接，排除回环地址
    char filter[512];
    snprintf(filter, sizeof(filter),
        "outbound and ip and tcp and "
        "ip.DstAddr != 127.0.0.1 and "
        "ip.SrcAddr != 127.0.0.1");
    
    printf("[拦截器] 过滤器: %s\n", filter);
    
    handle_ = WinDivertOpen(
        filter,
        WINDIVERT_LAYER_NETWORK,
        0,  // 优先级
        0   // 标志
    );
    
    if (handle_ == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("[拦截器] 打开 WinDivert 失败，错误码: %lu\n", error);
        return false;
    }
    
    // 设置队列参数
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_LENGTH, 16384);
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_TIME, 2000);
    WinDivertSetParam(handle_, WINDIVERT_PARAM_QUEUE_SIZE, 8388608);
    
    running_ = true;
    interceptThread_ = std::thread(&TrafficInterceptor::interceptThread, this);
    
    printf("[拦截器] 启动成功\n");
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
    
    // 生成连接键
    std::string connKey = makeConnectionKey(srcAddr, srcPort, dstAddr, dstPort);
    
    // 查找或创建连接跟踪
    TrackedConnection* conn = getOrCreateConnection(srcAddr, srcPort, dstAddr, dstPort, 6);
    
    // 只在 SYN 包时做决策（新连接）
    if (tcpHdr->Syn && !tcpHdr->Ack) {
        conn->synSeen = true;
        conn->originalDstAddr = dstAddr;
        conn->originalDstPort = dstPort;
        
        // 首先检查是否有 FLOW 层的预先决策
        bool hasPreDecision = false;
        {
            std::lock_guard<std::mutex> lock(preDecisionsMutex_);
            auto preIt = preDecisions_.find(connKey);
            if (preIt != preDecisions_.end()) {
                // 使用预先决策
                conn->action = preIt->second.action;
                conn->proxyServer = preIt->second.proxyServer;
                conn->processId = preIt->second.processId;
                conn->processName = preIt->second.processName;
                hasPreDecision = true;
                
                printf("[SYN-预决策] %s:%d -> %s:%d 进程: %s (PID=%u) 动作=%s\n",
                       ipToString(srcAddr).c_str(), srcPort,
                       ipToString(dstAddr).c_str(), dstPort,
                       conn->processName.c_str(), conn->processId,
                       conn->action == InterceptAction::REDIRECT ? "代理" :
                       (conn->action == InterceptAction::BLOCK ? "阻止" : "直连"));
                
                // 移除已使用的预先决策
                preDecisions_.erase(preIt);
            }
        }
        
        if (!hasPreDecision) {
            // 从 FLOW 层查找进程信息
            const ConnectionInfo* flowInfo = processMonitor_->findConnection(
                srcAddr, srcPort, dstAddr, dstPort, 6);
            
            if (flowInfo != nullptr) {
                conn->processId = flowInfo->processId;
                conn->processName = flowInfo->processName;
            } else {
                // 如果 FLOW 层还没有信息，尝试等待一小段时间
                // 因为 FLOW 层事件可能稍后到达
                for (int retry = 0; retry < 5; retry++) {
                    Sleep(2);  // 等待 2ms
                    flowInfo = processMonitor_->findConnection(
                        srcAddr, srcPort, dstAddr, dstPort, 6);
                    if (flowInfo != nullptr) {
                        conn->processId = flowInfo->processId;
                        conn->processName = flowInfo->processName;
                        break;
                    }
                    
                    // 同时检查预先决策是否到达
                    {
                        std::lock_guard<std::mutex> lock(preDecisionsMutex_);
                        auto preIt = preDecisions_.find(connKey);
                        if (preIt != preDecisions_.end()) {
                            conn->action = preIt->second.action;
                            conn->proxyServer = preIt->second.proxyServer;
                            conn->processId = preIt->second.processId;
                            conn->processName = preIt->second.processName;
                            hasPreDecision = true;
                            preDecisions_.erase(preIt);
                            break;
                        }
                    }
                }
                
                if (!hasPreDecision && flowInfo == nullptr) {
                    // 仍然没有信息，设置为 pending
                    conn->processId = 0;
                    conn->processName = "<pending>";
                }
            }
            
            if (!hasPreDecision) {
                // 调试输出
                printf("[SYN] %s:%d -> %s:%d 进程: %s (PID=%u)\n",
                       ipToString(srcAddr).c_str(), srcPort,
                       ipToString(dstAddr).c_str(), dstPort,
                       conn->processName.c_str(), conn->processId);
                
                // 做出拦截决策
                InterceptDecision decision = makeDecision(
                    conn->processId, conn->processName,
                    dstAddr, dstPort, 6);
                
                conn->action = decision.action;
                conn->proxyServer = decision.proxyServer;
            }
        }
        
        // 处理重定向或阻止
        if (conn->action == InterceptAction::REDIRECT && conn->proxyServer != nullptr) {
            // 注册原始目标信息到本地代理服务器
            proxyServer_->registerOriginalTarget(
                srcAddr, srcPort, dstAddr, dstPort,
                conn->processId, conn->processName,
                conn->proxyServer);
            
            conn->redirected = true;
            
            printf("[重定向] %s (PID=%u) %s:%d -> 代理 %s:%d\n",
                   conn->processName.c_str(), conn->processId,
                   ipToString(dstAddr).c_str(), dstPort,
                   conn->proxyServer->address.c_str(), conn->proxyServer->port);
            
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.connectionsRedirected++;
        } else if (conn->action == InterceptAction::BLOCK) {
            printf("[阻止] %s (PID=%u) -> %s:%d\n",
                   conn->processName.c_str(), conn->processId,
                   ipToString(dstAddr).c_str(), dstPort);
            
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
    
    // 尝试从 DNS 监控获取域名
    DnsMonitor& dnsMonitor = getDnsMonitor();
    std::string domain = dnsMonitor.findDomainByIp(dstAddr);
    
    // 如果找到域名，优先使用域名进行匹配
    std::string targetForMatch = domain.empty() ? dstAddrStr : domain;
    
    // 如果进程名为空或 pending，尝试从进程 ID 获取
    std::string effectiveProcessName = processName;
    if (effectiveProcessName.empty() || effectiveProcessName == "<pending>" || effectiveProcessName == "<unknown>") {
        if (processId != 0 && processId != 4) {
            // 尝试获取进程名
            effectiveProcessName = processMonitor_->getProcessName(processId);
        }
    }
    
    // 匹配规则 - 先用域名匹配，如果没有域名则用 IP 匹配
    const Rule* rule = config_->matchRule(effectiveProcessName, targetForMatch, dstPort);
    
    // 如果域名匹配失败，再尝试用 IP 地址匹配
    if (rule == nullptr && !domain.empty()) {
        rule = config_->matchRule(effectiveProcessName, dstAddrStr, dstPort);
    }
    
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
                printf("[规则匹配] %s (PID=%u) -> %s:%d 匹配规则 '%s' -> 阻止\n",
                       effectiveProcessName.c_str(), processId, dstAddrStr.c_str(), dstPort, rule->name.c_str());
                break;
                
            case ProxyType::SOCKS5:
            case ProxyType::HTTP:
                decision.proxyServer = config_->getProxy(rule->action.proxyId);
                if (decision.proxyServer != nullptr) {
                    decision.action = InterceptAction::REDIRECT;
                    decision.reason = "Rule: " + rule->name + " (Proxy)";
                    printf("[规则匹配] %s (PID=%u) -> %s:%d 匹配规则 '%s' -> 代理 %s:%d\n",
                           effectiveProcessName.c_str(), processId, dstAddrStr.c_str(), dstPort, rule->name.c_str(),
                           decision.proxyServer->address.c_str(), decision.proxyServer->port);
                } else {
                    decision.action = InterceptAction::ALLOW;
                    decision.reason = "Rule: " + rule->name + " (Proxy not found, fallback to direct)";
                    printf("[规则匹配] %s -> %s:%d 匹配规则 '%s' -> 代理未找到，直连\n",
                           effectiveProcessName.c_str(), dstAddrStr.c_str(), dstPort, rule->name.c_str());
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
    // 使用与 ProcessMonitor 相同的格式（但不包含协议，因为我们只处理 TCP）
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << srcAddr << ":"
        << std::setw(4) << srcPort << "-"
        << std::setw(8) << dstAddr << ":"
        << std::setw(4) << dstPort;
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
    
    // 保存原始目标地址（用于调试）
    UINT32 origDstAddr = ipHdr->DstAddr;
    UINT16 origDstPort = WinDivertHelperNtohs(tcpHdr->DstPort);
    
    // 修改目标地址为本地代理
    ipHdr->DstAddr = localProxyAddr_;
    tcpHdr->DstPort = WinDivertHelperHtons(localProxyPort_);
    
    // 重新计算校验和
    WinDivertHelperCalcChecksums(packet, packetLen, addr, 0);
    
    // 发送修改后的包
    BOOL result = WinDivertSend(handle_, packet, packetLen, nullptr, addr);
    
    if (!result) {
        DWORD error = GetLastError();
        printf("[重定向] 发送失败，错误码: %lu\n", error);
        return false;
    }
    
    return true;
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
    // WinDivert 返回的 IP 地址是网络字节序（大端）
    // 需要按照大端方式解析：高字节在前
    std::ostringstream oss;
    oss << ((addr >> 24) & 0xFF) << "."
        << ((addr >> 16) & 0xFF) << "."
        << ((addr >> 8) & 0xFF) << "."
        << ((addr >> 0) & 0xFF);
    return oss.str();
}

std::string TrafficInterceptor::ipv6ToString(const UINT32* addr) const {
    // 简化实现
    return "";
}

bool TrafficInterceptor::isLocalAddress(UINT32 addr) const {
    // 127.0.0.0/8 - 网络字节序，高字节在最高位
    return ((addr >> 24) & 0xFF) == 127;
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

void TrafficInterceptor::onFlowEstablished(UINT32 processId, const std::string& processName,
                                           UINT32 localAddr, UINT16 localPort,
                                           UINT32 remoteAddr, UINT16 remotePort,
                                           UINT8 protocol) {
    // 只处理 TCP 出站连接
    if (protocol != 6) return;
    
    // 忽略回环地址 - 网络字节序，高字节在最高位
    if (((localAddr >> 24) & 0xFF) == 127 || ((remoteAddr >> 24) & 0xFF) == 127) return;
    
    // 做出代理决策
    InterceptDecision decision = makeDecision(processId, processName, remoteAddr, remotePort, protocol);
    
    // 如果需要代理或阻止，保存预先决策
    if (decision.action != InterceptAction::ALLOW) {
        std::string key = makeConnectionKey(localAddr, localPort, remoteAddr, remotePort);
        
        PreDecision preDec;
        preDec.action = decision.action;
        preDec.proxyServer = decision.proxyServer;
        preDec.processId = processId;
        preDec.processName = processName;
        preDec.timestamp = getCurrentTimestamp();
        
        {
            std::lock_guard<std::mutex> lock(preDecisionsMutex_);
            preDecisions_[key] = preDec;
            
            // 清理过期的预先决策（超过 10 秒）
            INT64 now = getCurrentTimestamp();
            for (auto it = preDecisions_.begin(); it != preDecisions_.end(); ) {
                if (now - it->second.timestamp > 10000) {
                    it = preDecisions_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        
        printf("[FLOW预决策] %s (PID=%u) %s:%d -> %s:%d 动作=%s\n",
               processName.c_str(), processId,
               ipToString(localAddr).c_str(), localPort,
               ipToString(remoteAddr).c_str(), remotePort,
               decision.action == InterceptAction::REDIRECT ? "代理" : "阻止");
    }
}

} // namespace proxifier