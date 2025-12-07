/*
 * socks5_client.h
 * SOCKS5 客户端实现
 */

#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <memory>

namespace proxifier {

// SOCKS5 认证方法
enum class Socks5AuthMethod : UINT8 {
    NO_AUTH = 0x00,
    GSSAPI = 0x01,
    USERNAME_PASSWORD = 0x02,
    NO_ACCEPTABLE = 0xFF
};

// SOCKS5 命令
enum class Socks5Command : UINT8 {
    CONNECT = 0x01,
    BIND = 0x02,
    UDP_ASSOCIATE = 0x03
};

// SOCKS5 地址类型
enum class Socks5AddrType : UINT8 {
    IPV4 = 0x01,
    DOMAIN = 0x03,
    IPV6 = 0x04
};

// SOCKS5 回复状态
enum class Socks5Reply : UINT8 {
    SUCCEEDED = 0x00,
    GENERAL_FAILURE = 0x01,
    CONNECTION_NOT_ALLOWED = 0x02,
    NETWORK_UNREACHABLE = 0x03,
    HOST_UNREACHABLE = 0x04,
    CONNECTION_REFUSED = 0x05,
    TTL_EXPIRED = 0x06,
    COMMAND_NOT_SUPPORTED = 0x07,
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08
};

// SOCKS5 连接结果
struct Socks5ConnectResult {
    bool success = false;
    Socks5Reply reply = Socks5Reply::GENERAL_FAILURE;
    std::string errorMessage;
    
    // 绑定地址（服务器返回）
    std::string boundAddr;
    UINT16 boundPort = 0;
};

// SOCKS5 客户端类
class Socks5Client {
public:
    Socks5Client();
    ~Socks5Client();
    
    // 设置代理服务器
    void setProxy(const std::string& host, int port);
    void setAuth(const std::string& username, const std::string& password);
    
    // 连接到代理服务器
    bool connectToProxy();
    
    // 通过代理连接到目标
    Socks5ConnectResult connectToTarget(const std::string& targetHost, int targetPort);
    Socks5ConnectResult connectToTarget(UINT32 targetIP, int targetPort);
    Socks5ConnectResult connectToTargetIPv6(const UINT32* targetIP, int targetPort);
    
    // 获取底层 socket
    SOCKET getSocket() const { return socket_; }
    SOCKET releaseSocket();  // 释放 socket 所有权
    
    // 关闭连接
    void close();
    
    // 检查是否已连接
    bool isConnected() const { return connected_; }
    
    // 设置超时
    void setTimeout(int connectTimeoutMs, int readWriteTimeoutMs);
    
    // 获取错误信息
    const std::string& getLastError() const { return lastError_; }

private:
    bool performHandshake();
    bool performAuth();
    Socks5ConnectResult sendConnectRequest(Socks5AddrType addrType, 
                                           const void* addr, 
                                           size_t addrLen,
                                           UINT16 port);
    
    bool sendAll(const void* data, size_t len);
    bool recvAll(void* data, size_t len);

private:
    SOCKET socket_ = INVALID_SOCKET;
    bool connected_ = false;
    
    std::string proxyHost_;
    int proxyPort_ = 1080;
    
    bool authEnabled_ = false;
    std::string username_;
    std::string password_;
    
    int connectTimeout_ = 10000;  // 10秒
    int rwTimeout_ = 30000;       // 30秒
    
    std::string lastError_;
};

// SOCKS5 工具函数
namespace socks5 {
    // 初始化 Winsock
    bool initWinsock();
    void cleanupWinsock();
    
    // IP 地址转换
    std::string ipv4ToString(UINT32 addr);
    std::string ipv6ToString(const UINT32* addr);
    UINT32 stringToIPv4(const std::string& str);
    bool stringToIPv6(const std::string& str, UINT32* addr);
    
    // 获取错误描述
    std::string getReplyDescription(Socks5Reply reply);
}

} // namespace proxifier

#endif // SOCKS5_CLIENT_H