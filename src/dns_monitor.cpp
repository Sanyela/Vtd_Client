/*
 * dns_monitor.cpp
 * DNS 监控模块实现
 */

#include "dns_monitor.h"
#include "windivert_loader.h"
#include <cstdio>
#include <cstring>
#include <sstream>

namespace proxifier {

// 全局 DNS 监控器实例
static DnsMonitor g_dnsMonitor;
DnsMonitor& getDnsMonitor() { return g_dnsMonitor; }

// DNS 头部结构
#pragma pack(push, 1)
struct DnsHeader {
    UINT16 id;          // 标识
    UINT16 flags;       // 标志
    UINT16 qdcount;     // 问题数
    UINT16 ancount;     // 回答数
    UINT16 nscount;     // 授权数
    UINT16 arcount;     // 附加数
};
#pragma pack(pop)

// DNS 记录类型
#define DNS_TYPE_A      1   // IPv4 地址
#define DNS_TYPE_AAAA   28  // IPv6 地址
#define DNS_TYPE_CNAME  5   // 别名

DnsMonitor::DnsMonitor() {}

DnsMonitor::~DnsMonitor() {
    stop();
}

bool DnsMonitor::start() {
    if (running_) return true;
    
    // 打开 WinDivert 句柄，拦截 DNS 响应（UDP 端口 53）
    // 使用 SNIFF 模式，不修改数据包
    const char* filter = "udp.SrcPort == 53";
    
    handle_ = WinDivertOpen(
        filter,
        WINDIVERT_LAYER_NETWORK,
        -100,  // 低优先级，不影响其他拦截
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY
    );
    
    if (handle_ == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        printf("[DNS监控] 打开 WinDivert 失败，错误码: %lu\n", error);
        return false;
    }
    
    running_ = true;
    monitorThread_ = std::thread(&DnsMonitor::monitorThread, this);
    
    printf("[DNS监控] 启动成功\n");
    return true;
}

void DnsMonitor::stop() {
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
    
    printf("[DNS监控] 已停止\n");
}

void DnsMonitor::monitorThread() {
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
        
        processDnsPacket(packet, packetLen, true);
    }
}

void DnsMonitor::processDnsPacket(const void* packet, UINT packetLen, bool isResponse) {
    // 解析 IP 和 UDP 头部
    PWINDIVERT_IPHDR ipHdr = nullptr;
    PWINDIVERT_UDPHDR udpHdr = nullptr;
    PVOID payload = nullptr;
    UINT payloadLen = 0;
    
    WinDivertHelperParsePacket(
        const_cast<void*>(packet), packetLen,
        &ipHdr, nullptr, nullptr, nullptr, nullptr, nullptr,
        &udpHdr, &payload, &payloadLen, nullptr, nullptr
    );
    
    if (udpHdr == nullptr || payload == nullptr || payloadLen < sizeof(DnsHeader)) {
        return;
    }
    
    // 解析 DNS 响应
    std::string domain;
    std::vector<UINT32> ips;
    
    if (parseDnsResponse(static_cast<const unsigned char*>(payload), payloadLen, domain, ips)) {
        if (!domain.empty() && !ips.empty()) {
            // 添加映射
            std::lock_guard<std::mutex> lock(mappingMutex_);
            
            for (UINT32 ip : ips) {
                DnsRecord record;
                record.domain = domain;
                record.ipAddresses = ips;
                record.timestamp = std::chrono::steady_clock::now();
                record.ttl = defaultTtl_;
                
                // 检查是否已存在相同域名的记录
                auto& records = ipToDomains_[ip];
                bool found = false;
                for (auto& r : records) {
                    if (r.domain == domain) {
                        r = record;  // 更新记录
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    records.push_back(record);
                }
                
                // 调试输出（仅首次添加时）
                if (!found) {
                    printf("[DNS] %s -> %s\n", domain.c_str(), ipToString(ip).c_str());
                }
            }
        }
    }
}

bool DnsMonitor::parseDnsResponse(const unsigned char* data, int len,
                                   std::string& domain, std::vector<UINT32>& ips) {
    if (len < (int)sizeof(DnsHeader)) {
        return false;
    }
    
    const DnsHeader* header = reinterpret_cast<const DnsHeader*>(data);
    
    // 检查是否是响应（QR 位为 1）
    UINT16 flags = ntohs(header->flags);
    if ((flags & 0x8000) == 0) {
        return false;  // 不是响应
    }
    
    // 检查是否有回答
    UINT16 ancount = ntohs(header->ancount);
    if (ancount == 0) {
        return false;
    }
    
    UINT16 qdcount = ntohs(header->qdcount);
    
    int offset = sizeof(DnsHeader);
    
    // 跳过问题部分，同时提取查询的域名
    for (int i = 0; i < qdcount && offset < len; i++) {
        std::string qname = parseDnsName(data, len, offset);
        if (domain.empty()) {
            domain = qname;
        }
        
        // 跳过 QTYPE 和 QCLASS（各 2 字节）
        offset += 4;
    }
    
    // 解析回答部分
    for (int i = 0; i < ancount && offset < len; i++) {
        // 解析名称（可能是压缩指针）
        std::string name = parseDnsName(data, len, offset);
        
        if (offset + 10 > len) break;
        
        // 读取类型、类、TTL、数据长度
        UINT16 type = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        UINT16 cls = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        UINT32 ttl = (data[offset] << 24) | (data[offset + 1] << 16) |
                     (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        
        UINT16 rdlength = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        if (offset + rdlength > len) break;
        
        // 处理 A 记录（IPv4 地址）
        if (type == DNS_TYPE_A && rdlength == 4) {
            // IP 地址已经是网络字节序
            UINT32 ip = (data[offset] << 24) | (data[offset + 1] << 16) |
                        (data[offset + 2] << 8) | data[offset + 3];
            ips.push_back(ip);
        }
        // 处理 CNAME 记录
        else if (type == DNS_TYPE_CNAME) {
            int cnameOffset = offset;
            std::string cname = parseDnsName(data, len, cnameOffset);
            // CNAME 记录可以用来更新域名
        }
        
        offset += rdlength;
    }
    
    return !ips.empty();
}

std::string DnsMonitor::parseDnsName(const unsigned char* data, int len, int& offset) {
    std::string name;
    bool jumped = false;
    int jumpOffset = 0;
    int maxJumps = 10;  // 防止无限循环
    int jumps = 0;
    
    while (offset < len && jumps < maxJumps) {
        unsigned char labelLen = data[offset];
        
        // 检查是否是压缩指针
        if ((labelLen & 0xC0) == 0xC0) {
            if (offset + 1 >= len) break;
            
            // 计算指针偏移
            int ptr = ((labelLen & 0x3F) << 8) | data[offset + 1];
            
            if (!jumped) {
                jumpOffset = offset + 2;
            }
            
            offset = ptr;
            jumped = true;
            jumps++;
            continue;
        }
        
        // 检查是否是结束标记
        if (labelLen == 0) {
            offset++;
            break;
        }
        
        offset++;
        
        // 读取标签
        if (offset + labelLen > len) break;
        
        if (!name.empty()) {
            name += ".";
        }
        name.append(reinterpret_cast<const char*>(data + offset), labelLen);
        
        offset += labelLen;
    }
    
    // 如果发生了跳转，恢复原始偏移
    if (jumped) {
        offset = jumpOffset;
    }
    
    return name;
}

std::string DnsMonitor::findDomainByIp(UINT32 ipAddr) const {
    std::lock_guard<std::mutex> lock(mappingMutex_);
    
    auto it = ipToDomains_.find(ipAddr);
    if (it != ipToDomains_.end() && !it->second.empty()) {
        // 返回最近的记录
        return it->second.back().domain;
    }
    
    return "";
}

std::vector<std::string> DnsMonitor::findAllDomainsByIp(UINT32 ipAddr) const {
    std::vector<std::string> domains;
    
    std::lock_guard<std::mutex> lock(mappingMutex_);
    
    auto it = ipToDomains_.find(ipAddr);
    if (it != ipToDomains_.end()) {
        for (const auto& record : it->second) {
            domains.push_back(record.domain);
        }
    }
    
    return domains;
}

void DnsMonitor::addMapping(UINT32 ipAddr, const std::string& domain) {
    std::lock_guard<std::mutex> lock(mappingMutex_);
    
    DnsRecord record;
    record.domain = domain;
    record.ipAddresses.push_back(ipAddr);
    record.timestamp = std::chrono::steady_clock::now();
    record.ttl = defaultTtl_;
    
    ipToDomains_[ipAddr].push_back(record);
}

void DnsMonitor::cleanupExpiredRecords() {
    std::lock_guard<std::mutex> lock(mappingMutex_);
    
    auto now = std::chrono::steady_clock::now();
    
    for (auto it = ipToDomains_.begin(); it != ipToDomains_.end(); ) {
        auto& records = it->second;
        
        // 移除过期记录
        records.erase(
            std::remove_if(records.begin(), records.end(),
                [&now](const DnsRecord& r) {
                    auto age = std::chrono::duration_cast<std::chrono::seconds>(
                        now - r.timestamp).count();
                    return age > r.ttl;
                }),
            records.end()
        );
        
        // 如果没有记录了，移除整个条目
        if (records.empty()) {
            it = ipToDomains_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t DnsMonitor::getMappingCount() const {
    std::lock_guard<std::mutex> lock(mappingMutex_);
    return ipToDomains_.size();
}

std::string DnsMonitor::ipToString(UINT32 addr) const {
    // 网络字节序，高字节在最高位
    std::ostringstream oss;
    oss << ((addr >> 24) & 0xFF) << "."
        << ((addr >> 16) & 0xFF) << "."
        << ((addr >> 8) & 0xFF) << "."
        << ((addr >> 0) & 0xFF);
    return oss.str();
}

} // namespace proxifier