/*
 * socks5_client.cpp
 * SOCKS5 客户端实现
 */

#include "socks5_client.h"
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

namespace proxifier {

// Winsock 初始化计数
static int g_wsaInitCount = 0;

namespace socks5 {

bool initWinsock() {
    if (g_wsaInitCount == 0) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }
    }
    g_wsaInitCount++;
    return true;
}

void cleanupWinsock() {
    if (g_wsaInitCount > 0) {
        g_wsaInitCount--;
        if (g_wsaInitCount == 0) {
            WSACleanup();
        }
    }
}

std::string ipv4ToString(UINT32 addr) {
    std::ostringstream oss;
    oss << ((addr >> 0) & 0xFF) << "."
        << ((addr >> 8) & 0xFF) << "."
        << ((addr >> 16) & 0xFF) << "."
        << ((addr >> 24) & 0xFF);
    return oss.str();
}

std::string ipv6ToString(const UINT32* addr) {
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, buffer, sizeof(buffer));
    return buffer;
}

UINT32 stringToIPv4(const std::string& str) {
    UINT32 addr = 0;
    inet_pton(AF_INET, str.c_str(), &addr);
    return addr;
}

bool stringToIPv6(const std::string& str, UINT32* addr) {
    return inet_pton(AF_INET6, str.c_str(), addr) == 1;
}

std::string getReplyDescription(Socks5Reply reply) {
    switch (reply) {
        case Socks5Reply::SUCCEEDED:
            return "Succeeded";
        case Socks5Reply::GENERAL_FAILURE:
            return "General SOCKS server failure";
        case Socks5Reply::CONNECTION_NOT_ALLOWED:
            return "Connection not allowed by ruleset";
        case Socks5Reply::NETWORK_UNREACHABLE:
            return "Network unreachable";
        case Socks5Reply::HOST_UNREACHABLE:
            return "Host unreachable";
        case Socks5Reply::CONNECTION_REFUSED:
            return "Connection refused";
        case Socks5Reply::TTL_EXPIRED:
            return "TTL expired";
        case Socks5Reply::COMMAND_NOT_SUPPORTED:
            return "Command not supported";
        case Socks5Reply::ADDRESS_TYPE_NOT_SUPPORTED:
            return "Address type not supported";
        default:
            return "Unknown error";
    }
}

} // namespace socks5

Socks5Client::Socks5Client() {
    socks5::initWinsock();
}

Socks5Client::~Socks5Client() {
    close();
    socks5::cleanupWinsock();
}

void Socks5Client::setProxy(const std::string& host, int port) {
    proxyHost_ = host;
    proxyPort_ = port;
}

void Socks5Client::setAuth(const std::string& username, const std::string& password) {
    authEnabled_ = true;
    username_ = username;
    password_ = password;
}

void Socks5Client::setTimeout(int connectTimeoutMs, int readWriteTimeoutMs) {
    connectTimeout_ = connectTimeoutMs;
    rwTimeout_ = readWriteTimeoutMs;
}

bool Socks5Client::connectToProxy() {
    if (connected_) {
        close();
    }
    
    // 创建 socket
    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        lastError_ = "Failed to create socket";
        return false;
    }
    
    // 设置超时
    DWORD timeout = rwTimeout_;
    setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    
    // 解析代理地址
    struct sockaddr_in proxyAddr;
    memset(&proxyAddr, 0, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(proxyPort_);
    
    // 尝试直接解析 IP
    if (inet_pton(AF_INET, proxyHost_.c_str(), &proxyAddr.sin_addr) != 1) {
        // 尝试 DNS 解析
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(proxyHost_.c_str(), NULL, &hints, &result) != 0) {
            lastError_ = "Failed to resolve proxy host: " + proxyHost_;
            closesocket(socket_);
            socket_ = INVALID_SOCKET;
            return false;
        }
        
        proxyAddr.sin_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    }
    
    // 连接到代理服务器
    if (connect(socket_, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr)) == SOCKET_ERROR) {
        lastError_ = "Failed to connect to proxy server";
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        return false;
    }
    
    // 执行 SOCKS5 握手
    if (!performHandshake()) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
        return false;
    }
    
    connected_ = true;
    return true;
}

bool Socks5Client::performHandshake() {
    // 发送认证方法协商请求
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    
    UINT8 request[4];
    request[0] = 0x05;  // SOCKS5 版本
    
    if (authEnabled_) {
        request[1] = 2;  // 2 种方法
        request[2] = (UINT8)Socks5AuthMethod::NO_AUTH;
        request[3] = (UINT8)Socks5AuthMethod::USERNAME_PASSWORD;
        if (!sendAll(request, 4)) {
            lastError_ = "Failed to send handshake request";
            return false;
        }
    } else {
        request[1] = 1;  // 1 种方法
        request[2] = (UINT8)Socks5AuthMethod::NO_AUTH;
        if (!sendAll(request, 3)) {
            lastError_ = "Failed to send handshake request";
            return false;
        }
    }
    
    // 接收服务器响应
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    
    UINT8 response[2];
    if (!recvAll(response, 2)) {
        lastError_ = "Failed to receive handshake response";
        return false;
    }
    
    if (response[0] != 0x05) {
        lastError_ = "Invalid SOCKS version in response";
        return false;
    }
    
    Socks5AuthMethod method = (Socks5AuthMethod)response[1];
    
    if (method == Socks5AuthMethod::NO_ACCEPTABLE) {
        lastError_ = "No acceptable authentication method";
        return false;
    }
    
    if (method == Socks5AuthMethod::USERNAME_PASSWORD) {
        if (!performAuth()) {
            return false;
        }
    } else if (method != Socks5AuthMethod::NO_AUTH) {
        lastError_ = "Unsupported authentication method";
        return false;
    }
    
    return true;
}

bool Socks5Client::performAuth() {
    // 用户名/密码认证
    // +----+------+----------+------+----------+
    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    // +----+------+----------+------+----------+
    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    // +----+------+----------+------+----------+
    
    if (username_.length() > 255 || password_.length() > 255) {
        lastError_ = "Username or password too long";
        return false;
    }
    
    std::vector<UINT8> request;
    request.push_back(0x01);  // 认证子协议版本
    request.push_back((UINT8)username_.length());
    request.insert(request.end(), username_.begin(), username_.end());
    request.push_back((UINT8)password_.length());
    request.insert(request.end(), password_.begin(), password_.end());
    
    if (!sendAll(request.data(), request.size())) {
        lastError_ = "Failed to send authentication request";
        return false;
    }
    
    // 接收认证响应
    // +----+--------+
    // |VER | STATUS |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    
    UINT8 response[2];
    if (!recvAll(response, 2)) {
        lastError_ = "Failed to receive authentication response";
        return false;
    }
    
    if (response[1] != 0x00) {
        lastError_ = "Authentication failed";
        return false;
    }
    
    return true;
}

Socks5ConnectResult Socks5Client::connectToTarget(const std::string& targetHost, int targetPort) {
    // 检查是否是 IP 地址
    UINT32 ipv4Addr;
    UINT32 ipv6Addr[4];
    
    if (inet_pton(AF_INET, targetHost.c_str(), &ipv4Addr) == 1) {
        return connectToTarget(ipv4Addr, targetPort);
    } else if (inet_pton(AF_INET6, targetHost.c_str(), ipv6Addr) == 1) {
        return connectToTargetIPv6(ipv6Addr, targetPort);
    }
    
    // 域名
    return sendConnectRequest(Socks5AddrType::DOMAINNAME,
                              targetHost.c_str(),
                              targetHost.length(),
                              (UINT16)targetPort);
}

Socks5ConnectResult Socks5Client::connectToTarget(UINT32 targetIP, int targetPort) {
    return sendConnectRequest(Socks5AddrType::IPV4, 
                              &targetIP, 
                              4,
                              (UINT16)targetPort);
}

Socks5ConnectResult Socks5Client::connectToTargetIPv6(const UINT32* targetIP, int targetPort) {
    return sendConnectRequest(Socks5AddrType::IPV6, 
                              targetIP, 
                              16,
                              (UINT16)targetPort);
}

Socks5ConnectResult Socks5Client::sendConnectRequest(Socks5AddrType addrType, 
                                                      const void* addr, 
                                                      size_t addrLen,
                                                      UINT16 port) {
    Socks5ConnectResult result;
    
    if (!connected_) {
        if (!connectToProxy()) {
            result.errorMessage = lastError_;
            return result;
        }
    }
    
    // 发送连接请求
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    
    std::vector<UINT8> request;
    request.push_back(0x05);  // SOCKS5 版本
    request.push_back((UINT8)Socks5Command::CONNECT);
    request.push_back(0x00);  // 保留
    request.push_back((UINT8)addrType);
    
    if (addrType == Socks5AddrType::DOMAINNAME) {
        // 域名格式: 长度(1字节) + 域名
        request.push_back((UINT8)addrLen);
        const char* domain = static_cast<const char*>(addr);
        request.insert(request.end(), domain, domain + addrLen);
    } else {
        // IP 地址
        const UINT8* addrBytes = static_cast<const UINT8*>(addr);
        request.insert(request.end(), addrBytes, addrBytes + addrLen);
    }
    
    // 端口（网络字节序）
    request.push_back((port >> 8) & 0xFF);
    request.push_back(port & 0xFF);
    
    if (!sendAll(request.data(), request.size())) {
        result.errorMessage = "Failed to send connect request";
        return result;
    }
    
    // 接收响应
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    
    UINT8 response[4];
    if (!recvAll(response, 4)) {
        result.errorMessage = "Failed to receive connect response";
        return result;
    }
    
    if (response[0] != 0x05) {
        result.errorMessage = "Invalid SOCKS version in response";
        return result;
    }
    
    result.reply = (Socks5Reply)response[1];
    
    if (result.reply != Socks5Reply::SUCCEEDED) {
        result.errorMessage = socks5::getReplyDescription(result.reply);
        return result;
    }
    
    // 读取绑定地址
    Socks5AddrType boundAddrType = (Socks5AddrType)response[3];
    
    if (boundAddrType == Socks5AddrType::IPV4) {
        UINT8 boundAddr[4];
        if (!recvAll(boundAddr, 4)) {
            result.errorMessage = "Failed to receive bound address";
            return result;
        }
        result.boundAddr = socks5::ipv4ToString(*(UINT32*)boundAddr);
    } else if (boundAddrType == Socks5AddrType::IPV6) {
        UINT32 boundAddr[4];
        if (!recvAll(boundAddr, 16)) {
            result.errorMessage = "Failed to receive bound address";
            return result;
        }
        result.boundAddr = socks5::ipv6ToString(boundAddr);
    } else if (boundAddrType == Socks5AddrType::DOMAINNAME) {
        UINT8 domainLen;
        if (!recvAll(&domainLen, 1)) {
            result.errorMessage = "Failed to receive domain length";
            return result;
        }
        std::vector<char> domain(domainLen + 1, 0);
        if (!recvAll(domain.data(), domainLen)) {
            result.errorMessage = "Failed to receive domain";
            return result;
        }
        result.boundAddr = domain.data();
    }
    
    // 读取绑定端口
    UINT8 portBytes[2];
    if (!recvAll(portBytes, 2)) {
        result.errorMessage = "Failed to receive bound port";
        return result;
    }
    result.boundPort = (portBytes[0] << 8) | portBytes[1];
    
    result.success = true;
    return result;
}

SOCKET Socks5Client::releaseSocket() {
    SOCKET s = socket_;
    socket_ = INVALID_SOCKET;
    connected_ = false;
    return s;
}

void Socks5Client::close() {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    connected_ = false;
}

bool Socks5Client::sendAll(const void* data, size_t len) {
    const char* ptr = static_cast<const char*>(data);
    size_t remaining = len;
    
    while (remaining > 0) {
        int sent = send(socket_, ptr, (int)remaining, 0);
        if (sent <= 0) {
            return false;
        }
        ptr += sent;
        remaining -= sent;
    }
    
    return true;
}

bool Socks5Client::recvAll(void* data, size_t len) {
    char* ptr = static_cast<char*>(data);
    size_t remaining = len;
    
    while (remaining > 0) {
        int received = recv(socket_, ptr, (int)remaining, 0);
        if (received <= 0) {
            return false;
        }
        ptr += received;
        remaining -= received;
    }
    
    return true;
}

namespace socks5 {

Socks5TestResult testProxyConnection(
    const std::string& proxyHost,
    int proxyPort,
    const std::string& username,
    const std::string& password,
    int timeoutMs) {
    
    Socks5TestResult result;
    
    // 记录开始时间
    LARGE_INTEGER frequency, startTime, endTime;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&startTime);
    
    // 创建 SOCKS5 客户端
    Socks5Client client;
    client.setProxy(proxyHost, proxyPort);
    client.setTimeout(timeoutMs, timeoutMs);
    
    // 如果有认证信息，设置认证
    if (!username.empty() || !password.empty()) {
        client.setAuth(username, password);
    }
    
    // 尝试连接到代理服务器并完成握手
    if (!client.connectToProxy()) {
        result.success = false;
        result.errorMessage = client.getLastError();
        return result;
    }
    
    // 计算延迟
    QueryPerformanceCounter(&endTime);
    result.latencyMs = (int)((endTime.QuadPart - startTime.QuadPart) * 1000 / frequency.QuadPart);
    
    result.success = true;
    result.errorMessage = "连接成功";
    
    // 关闭连接
    client.close();
    
    return result;
}

} // namespace socks5

} // namespace proxifier