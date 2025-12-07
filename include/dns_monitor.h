/*
 * dns_monitor.h
 * DNS 监控模块 - 用于建立 IP 到域名的映射
 *
 * 功能：
 * - 拦截 DNS 响应包
 * - 解析 DNS 数据，提取域名和 IP 地址
 * - 维护 IP 到域名的映射表
 * - 提供 IP 反查域名的功能
 */

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <thread>
#include <chrono>

namespace proxifier {

// DNS 记录
struct DnsRecord {
    std::string domain;                     // 域名
    std::vector<UINT32> ipAddresses;        // 解析到的 IP 地址列表
    std::chrono::steady_clock::time_point timestamp;  // 记录时间
    int ttl;                                // TTL（秒）
};

// DNS 监控器
class DnsMonitor {
public:
    DnsMonitor();
    ~DnsMonitor();
    
    // 启动/停止监控
    bool start();
    void stop();
    
    // 根据 IP 地址查找域名
    // 返回空字符串表示未找到
    std::string findDomainByIp(UINT32 ipAddr) const;
    
    // 根据 IP 地址查找所有关联的域名
    std::vector<std::string> findAllDomainsByIp(UINT32 ipAddr) const;
    
    // 手动添加 IP 到域名的映射（用于测试或预设）
    void addMapping(UINT32 ipAddr, const std::string& domain);
    
    // 清理过期记录
    void cleanupExpiredRecords();
    
    // 获取统计信息
    size_t getMappingCount() const;
    
    // 设置记录过期时间（秒）
    void setRecordTtl(int ttl) { defaultTtl_ = ttl; }
    
private:
    // DNS 监控线程
    void monitorThread();
    
    // 处理 DNS 数据包
    void processDnsPacket(const void* packet, UINT packetLen, bool isResponse);
    
    // 解析 DNS 响应
    bool parseDnsResponse(const unsigned char* data, int len, 
                          std::string& domain, std::vector<UINT32>& ips);
    
    // 解析 DNS 域名（处理压缩指针）
    std::string parseDnsName(const unsigned char* data, int len, int& offset);
    
    // IP 地址转字符串（用于调试）
    std::string ipToString(UINT32 addr) const;
    
private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::thread monitorThread_;
    bool running_ = false;
    
    // IP 到域名的映射表
    // key: IP 地址（网络字节序）
    // value: 域名列表（一个 IP 可能对应多个域名，如 CDN）
    mutable std::mutex mappingMutex_;
    std::map<UINT32, std::vector<DnsRecord>> ipToDomains_;
    
    // 默认 TTL（秒）
    int defaultTtl_ = 300;  // 5 分钟
};

// 全局 DNS 监控器实例
DnsMonitor& getDnsMonitor();

} // namespace proxifier

#endif // DNS_MONITOR_H