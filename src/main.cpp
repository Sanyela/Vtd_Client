/*
 * main.cpp
 * WinDivert Proxifier - 进程级别 SOCKS5 代理
 *
 * 功能：
 * - 根据配置文件规则，将指定进程的网络流量重定向到 SOCKS5 代理
 * - 支持进程名、目标地址、端口匹配
 * - 支持 SOCKS5 认证
 *
 * 用法: proxifier.exe [config_file]
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string>
#include <iostream>
#include <algorithm>
#include <conio.h>  // 用于 _getch()

#include "config.h"
#include "process_monitor.h"
#include "proxy_server.h"
#include "traffic_interceptor.h"
#include "socks5_client.h"
#include "windivert_loader.h"
#include "dns_monitor.h"

using namespace proxifier;

// 全局运行标志
static volatile bool g_running = true;

// 信号处理
void signalHandler(int sig) {
    printf("\n收到退出信号，正在停止...\n");
    g_running = false;
}

// 打印帮助信息
void printUsage(const char* program) {
    printf("用法: %s [选项] [配置文件]\n", program);
    printf("\n");
    printf("选项:\n");
    printf("  -h, --help     显示帮助信息\n");
    printf("  -v, --version  显示版本信息\n");
    printf("  -t, --test     测试配置文件\n");
    printf("\n");
    printf("示例:\n");
    printf("  %s config.xml           使用指定配置文件\n", program);
    printf("  %s -t config.xml        测试配置文件\n", program);
    printf("\n");
    printf("配置文件格式支持 Proxifier 的 XML 格式。\n");
}

// 打印版本信息
void printVersion() {
    printf("WinDivert Proxifier v1.0.0\n");
    printf("基于 WinDivert 2.2 的进程级别 SOCKS5 代理\n");
}

// 打印配置信息
void printConfig(const Config& config) {
    printf("\n=== 配置信息 ===\n");
    
    printf("\n代理服务器:\n");
    for (const auto& proxy : config.getProxies()) {
        printf("  [%d] %s:%d", proxy.id, proxy.address.c_str(), proxy.port);
        if (proxy.isDirectRedirect) {
            printf(" (直接重定向)");
        } else if (proxy.authEnabled) {
            if (!proxy.username.empty()) {
                printf(" (认证: 用户=%s)", proxy.username.c_str());
            } else {
                printf(" (需要认证)");
            }
        }
        printf("\n");
    }
    
    printf("\n规则列表:\n");
    int ruleNum = 1;
    for (const auto& rule : config.getRules()) {
        printf("  %d. %s [%s]\n", ruleNum++, rule.name.c_str(),
               rule.enabled ? "启用" : "禁用");
        
        if (!rule.applications.empty()) {
            printf("     应用: ");
            for (size_t i = 0; i < rule.applications.size(); i++) {
                if (i > 0) printf(", ");
                printf("%s", rule.applications[i].c_str());
            }
            printf("\n");
        }
        
        if (!rule.targets.empty()) {
            printf("     目标: ");
            for (size_t i = 0; i < rule.targets.size(); i++) {
                if (i > 0) printf(", ");
                printf("%s", rule.targets[i].c_str());
            }
            printf("\n");
        }
        
        if (!rule.ports.empty()) {
            printf("     端口: ");
            for (size_t i = 0; i < rule.ports.size(); i++) {
                if (i > 0) printf(", ");
                printf("%d", rule.ports[i]);
            }
            printf("\n");
        }
        
        const char* actionStr = "未知";
        switch (rule.action.type) {
            case ProxyType::DIRECT: actionStr = "直连"; break;
            case ProxyType::BLOCK: actionStr = "阻止"; break;
            case ProxyType::SOCKS5: actionStr = "代理"; break;
            case ProxyType::HTTP: actionStr = "HTTP代理"; break;
        }
        printf("     动作: %s", actionStr);
        if (rule.action.type == ProxyType::SOCKS5 || rule.action.type == ProxyType::HTTP) {
            printf(" (ID=%d)", rule.action.proxyId);
        }
        printf("\n");
    }
    
    printf("\n================\n");
}

// 安全地读取密码（不显示输入）
std::string readPassword() {
    std::string password;
    char ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == '\b') {  // 退格键
            if (!password.empty()) {
                password.pop_back();
                printf("\b \b");  // 删除显示的星号
            }
        } else if (ch >= 32 && ch <= 126) {  // 可打印字符
            password += ch;
            printf("*");
        }
    }
    printf("\n");
    return password;
}

// 处理代理凭据
// 返回 true 表示凭据已准备好，false 表示用户取消
bool handleProxyCredentials(Config& config) {
    // 尝试从文件加载已保存的凭据
    std::vector<ProxyCredentials> savedCredentials;
    if (credentialsFileExists() && loadCredentials(savedCredentials)) {
        printf("发现已保存的凭据，正在加载...\n");
        for (const auto& cred : savedCredentials) {
            config.updateProxyCredentials(cred.proxyId, cred.username, cred.password);
        }
    }
    
    // 检查是否还有需要凭据的代理（排除直接重定向类型）
    auto proxiesNeedingCreds = config.getProxiesNeedingCredentials();
    
    // 过滤掉直接重定向类型的代理
    proxiesNeedingCreds.erase(
        std::remove_if(proxiesNeedingCreds.begin(), proxiesNeedingCreds.end(),
            [](const ProxyServer* p) { return p->isDirectRedirect; }),
        proxiesNeedingCreds.end());
    
    if (proxiesNeedingCreds.empty()) {
        return true;  // 所有代理都有凭据
    }
    
    printf("\n=== 代理认证配置 ===\n");
    printf("以下代理需要输入账号密码：\n\n");
    
    std::vector<ProxyCredentials> newCredentials;
    
    for (auto* proxy : proxiesNeedingCreds) {
        printf("代理 [ID=%d]: %s:%d\n", proxy->id, proxy->address.c_str(), proxy->port);
        
        // 输入用户名
        printf("  用户名: ");
        std::string username;
        std::getline(std::cin, username);
        
        if (username.empty()) {
            printf("  用户名不能为空，跳过此代理\n");
            continue;
        }
        
        // 输入密码
        printf("  密码: ");
        std::string password = readPassword();
        
        if (password.empty()) {
            printf("  密码不能为空，跳过此代理\n");
            continue;
        }
        
        // 测试连接
        printf("  正在测试连接...");
        fflush(stdout);
        
        auto testResult = socks5::testProxyConnection(
            proxy->address, proxy->port, username, password, 10000);
        
        if (testResult.success) {
            printf(" 成功! (延迟: %dms)\n", testResult.latencyMs);
            
            // 更新配置
            config.updateProxyCredentials(proxy->id, username, password);
            
            // 保存凭据
            ProxyCredentials cred;
            cred.proxyId = proxy->id;
            cred.username = username;
            cred.password = password;
            newCredentials.push_back(cred);
        } else {
            printf(" 失败!\n");
            printf("  错误: %s\n", testResult.errorMessage.c_str());
            
            // 询问是否重试
            printf("  是否重试? (y/n): ");
            char choice;
            std::cin >> choice;
            std::cin.ignore();  // 清除换行符
            
            if (choice == 'y' || choice == 'Y') {
                // 重新处理这个代理（通过递归调用）
                proxiesNeedingCreds.clear();
                proxiesNeedingCreds.push_back(proxy);
                
                // 简单重试一次
                printf("  用户名: ");
                std::getline(std::cin, username);
                printf("  密码: ");
                password = readPassword();
                
                printf("  正在测试连接...");
                fflush(stdout);
                
                testResult = socks5::testProxyConnection(
                    proxy->address, proxy->port, username, password, 10000);
                
                if (testResult.success) {
                    printf(" 成功! (延迟: %dms)\n", testResult.latencyMs);
                    config.updateProxyCredentials(proxy->id, username, password);
                    
                    ProxyCredentials cred;
                    cred.proxyId = proxy->id;
                    cred.username = username;
                    cred.password = password;
                    newCredentials.push_back(cred);
                } else {
                    printf(" 失败: %s\n", testResult.errorMessage.c_str());
                    printf("  警告: 代理 %d 认证失败，将跳过\n", proxy->id);
                }
            }
        }
        printf("\n");
    }
    
    // 保存新凭据
    if (!newCredentials.empty()) {
        // 合并已有凭据和新凭据
        for (const auto& newCred : newCredentials) {
            bool found = false;
            for (auto& saved : savedCredentials) {
                if (saved.proxyId == newCred.proxyId) {
                    saved = newCred;
                    found = true;
                    break;
                }
            }
            if (!found) {
                savedCredentials.push_back(newCred);
            }
        }
        
        printf("是否保存凭据以便下次自动登录? (y/n): ");
        char saveChoice;
        std::cin >> saveChoice;
        std::cin.ignore();
        
        if (saveChoice == 'y' || saveChoice == 'Y') {
            if (saveCredentials(savedCredentials)) {
                printf("凭据已保存到 credentials.dat\n");
            } else {
                printf("警告: 无法保存凭据\n");
            }
        }
    }
    
    printf("======================\n\n");
    return true;
}

// 验证所有需要认证的代理，如果失败则提示用户重新输入
bool verifyAllProxyConnections(Config& config) {
    printf("\n正在验证代理连接...\n");
    
    bool allSuccess = true;
    bool hasProxyToTest = false;
    std::vector<ProxyCredentials> updatedCredentials;
    
    for (auto& proxy : config.getProxies()) {
        // 跳过直接重定向类型的代理（它们不使用 SOCKS5 协议）
        if (proxy.isDirectRedirect) {
            printf("  代理 [ID=%d] %s:%d - 直接重定向，跳过验证\n",
                   proxy.id, proxy.address.c_str(), proxy.port);
            continue;
        }
        
        // 只处理需要认证的代理
        if (!proxy.authEnabled) {
            printf("  代理 [ID=%d] %s:%d - 无需认证\n",
                   proxy.id, proxy.address.c_str(), proxy.port);
            continue;
        }
        
        hasProxyToTest = true;
        
        // 如果凭据为空，先提示用户输入
        if (proxy.username.empty() || proxy.password.empty()) {
            printf("  代理 [ID=%d] %s:%d 需要输入凭据:\n",
                   proxy.id, proxy.address.c_str(), proxy.port);
            
            printf("    用户名: ");
            std::string username;
            std::getline(std::cin, username);
            
            if (username.empty()) {
                printf("    用户名不能为空，跳过此代理\n");
                allSuccess = false;
                continue;
            }
            
            printf("    密码: ");
            std::string password = readPassword();
            
            if (password.empty()) {
                printf("    密码不能为空，跳过此代理\n");
                allSuccess = false;
                continue;
            }
            
            // 更新配置
            config.updateProxyCredentials(proxy.id, username, password);
            
            // 重新获取代理信息（因为我们更新了凭据）
            const ProxyServer* updatedProxy = config.getProxy(proxy.id);
            if (updatedProxy) {
                proxy.username = updatedProxy->username;
                proxy.password = updatedProxy->password;
            }
            
            // 保存到更新列表
            ProxyCredentials cred;
            cred.proxyId = proxy.id;
            cred.username = username;
            cred.password = password;
            updatedCredentials.push_back(cred);
        }
        
        // 测试连接
        printf("  测试代理 [ID=%d] %s:%d ... ",
               proxy.id, proxy.address.c_str(), proxy.port);
        fflush(stdout);
        
        auto result = socks5::testProxyConnection(
            proxy.address, proxy.port,
            proxy.username, proxy.password, 10000);
        
        if (result.success) {
            printf("成功 (延迟: %dms)\n", result.latencyMs);
        } else {
            printf("失败: %s\n", result.errorMessage.c_str());
            
            // 凭据验证失败，提示用户重新输入
            printf("\n  代理 [ID=%d] 认证失败，请重新输入凭据:\n", proxy.id);
                
                bool retrySuccess = false;
                for (int retry = 0; retry < 3 && !retrySuccess; retry++) {
                    printf("    用户名: ");
                    std::string username;
                    std::getline(std::cin, username);
                    
                    if (username.empty()) {
                        printf("    用户名不能为空\n");
                        continue;
                    }
                    
                    printf("    密码: ");
                    std::string password = readPassword();
                    
                    if (password.empty()) {
                        printf("    密码不能为空\n");
                        continue;
                    }
                    
                    printf("    正在测试连接...");
                    fflush(stdout);
                    
                    result = socks5::testProxyConnection(
                        proxy.address, proxy.port, username, password, 10000);
                    
                    if (result.success) {
                        printf(" 成功! (延迟: %dms)\n", result.latencyMs);
                        
                        // 更新配置中的凭据
                        config.updateProxyCredentials(proxy.id, username, password);
                        
                        // 保存到更新列表
                        ProxyCredentials cred;
                        cred.proxyId = proxy.id;
                        cred.username = username;
                        cred.password = password;
                        updatedCredentials.push_back(cred);
                        
                        retrySuccess = true;
                    } else {
                        printf(" 失败: %s\n", result.errorMessage.c_str());
                        if (retry < 2) {
                            printf("    请重试 (%d/3)\n", retry + 2);
                        }
                    }
                }
                
                if (!retrySuccess) {
                    printf("  警告: 代理 %d 认证失败，将跳过\n", proxy.id);
                    allSuccess = false;
                }
            }
        }
    }
    
    if (!hasProxyToTest) {
        printf("  没有需要验证的 SOCKS5 代理\n");
    }
    
    // 如果有更新的凭据，询问是否保存
    if (!updatedCredentials.empty()) {
        printf("\n是否保存更新的凭据以便下次自动登录? (y/n): ");
        char saveChoice;
        std::cin >> saveChoice;
        std::cin.ignore();
        
        if (saveChoice == 'y' || saveChoice == 'Y') {
            // 加载现有凭据
            std::vector<ProxyCredentials> savedCredentials;
            if (credentialsFileExists()) {
                loadCredentials(savedCredentials);
            }
            
            // 合并更新
            for (const auto& newCred : updatedCredentials) {
                bool found = false;
                for (auto& saved : savedCredentials) {
                    if (saved.proxyId == newCred.proxyId) {
                        saved = newCred;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    savedCredentials.push_back(newCred);
                }
            }
            
            if (saveCredentials(savedCredentials)) {
                printf("凭据已保存到 credentials.dat\n");
            } else {
                printf("警告: 无法保存凭据\n");
            }
        }
    }
    
    return allSuccess;
}

// 进程监控回调
void onConnectionEvent(ConnectionEvent event, const ConnectionInfo& info) {
    const char* eventStr = (event == ConnectionEvent::ESTABLISHED) ? "建立" : "关闭";
    
    printf("[FLOW] 连接%s: %s (PID=%u) ", eventStr, info.processName.c_str(), info.processId);
    
    // 打印地址信息
    // WinDivert FLOW 层返回的 IP 地址是网络字节序（大端），高字节在最高位
    if (!info.isIPv6) {
        UINT32 local = info.localAddr[0];
        UINT32 remote = info.remoteAddr[0];
        printf("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
            (local >> 24) & 0xFF, (local >> 16) & 0xFF,
            (local >> 8) & 0xFF, (local >> 0) & 0xFF,
            info.localPort,
            (remote >> 24) & 0xFF, (remote >> 16) & 0xFF,
            (remote >> 8) & 0xFF, (remote >> 0) & 0xFF,
            info.remotePort);
    }
    
    printf(" [%s]\n", info.protocol == 6 ? "TCP" : "UDP");
    
    // 在连接建立时，通知流量拦截器做出预先决策
    if (event == ConnectionEvent::ESTABLISHED && info.outbound && !info.isIPv6) {
        TrafficInterceptor& interceptor = getTrafficInterceptor();
        interceptor.onFlowEstablished(
            info.processId, info.processName,
            info.localAddr[0], info.localPort,
            info.remoteAddr[0], info.remotePort,
            info.protocol);
    }
}

// 会话回调
void onSessionEvent(ProxySession* session, const std::string& event) {
    if (event == "started") {
        // WinDivert 返回的 IP 地址是网络字节序（大端），高字节在最高位
        printf("[PROXY] 新会话: %s (PID=%u) -> %u.%u.%u.%u:%u\n",
            session->processName.c_str(), session->processId,
            (session->originalDstAddr >> 24) & 0xFF,
            (session->originalDstAddr >> 16) & 0xFF,
            (session->originalDstAddr >> 8) & 0xFF,
            (session->originalDstAddr >> 0) & 0xFF,
            session->originalDstPort);
    } else if (event == "connected") {
        printf("[PROXY] 会话已连接: %llu\n", session->sessionId);
    } else if (event == "connect_failed") {
        printf("[PROXY] 会话连接失败: %llu\n", session->sessionId);
    } else if (event == "closed") {
        printf("[PROXY] 会话关闭: %llu (发送=%llu, 接收=%llu)\n",
            session->sessionId, session->bytesSent, session->bytesReceived);
    }
}

int main(int argc, char* argv[]) {
    // 设置控制台编码
    SetConsoleOutputCP(CP_UTF8);
    
    // 解析命令行参数
    std::string configFile = "config.xml";
    bool testMode = false;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            printVersion();
            return 0;
        } else if (arg == "-t" || arg == "--test") {
            testMode = true;
        } else if (arg[0] != '-') {
            configFile = arg;
        }
    }
    
    printf("===========================================\n");
    printf("  WinDivert Proxifier - 进程级别代理\n");
    printf("===========================================\n");
    
    // 初始化 WinDivert 动态加载器
    printf("初始化 WinDivert...\n");
    if (!WinDivertLoaderInit()) {
        fprintf(stderr, "错误: 无法加载 WinDivert.dll\n");
        fprintf(stderr, "请确保 WinDivert.dll 和驱动文件在程序目录下\n");
        return 1;
    }
    printf("WinDivert 加载成功\n");
    
    // 初始化 Winsock
    if (!socks5::initWinsock()) {
        fprintf(stderr, "错误: 无法初始化 Winsock\n");
        WinDivertLoaderCleanup();
        return 1;
    }
    
    // 加载配置
    Config& config = getConfig();
    printf("加载配置文件: %s\n", configFile.c_str());
    
    if (!config.loadFromFile(configFile)) {
        fprintf(stderr, "错误: 无法加载配置文件 %s\n", configFile.c_str());
        
        // 如果没有配置文件，创建默认配置
        printf("使用默认配置...\n");
        
        // 添加默认代理
        ProxyServer proxy;
        proxy.id = 100;
        proxy.type = ProxyType::SOCKS5;
        proxy.address = "127.0.0.1";
        proxy.port = 1080;
        proxy.authEnabled = false;
        config.addProxy(proxy);
        
        // 添加默认规则：localhost 直连
        Rule localhostRule;
        localhostRule.name = "Localhost";
        localhostRule.enabled = true;
        localhostRule.action.type = ProxyType::DIRECT;
        localhostRule.targets = {"localhost", "127.0.0.1", "::1"};
        config.addRule(localhostRule);
        
        // 添加默认规则：其他流量直连
        Rule defaultRule;
        defaultRule.name = "Default";
        defaultRule.enabled = true;
        defaultRule.action.type = ProxyType::DIRECT;
        config.addRule(defaultRule);
    }
    
    printConfig(config);
    
    if (testMode) {
        printf("\n配置文件测试通过！\n");
        return 0;
    }
    
    // 处理代理凭据（检查、加载、输入、验证）
    if (!handleProxyCredentials(config)) {
        printf("凭据配置已取消\n");
        socks5::cleanupWinsock();
        WinDivertLoaderCleanup();
        return 1;
    }
    
    // 验证所有代理连接
    if (!verifyAllProxyConnections(config)) {
        printf("\n警告: 部分代理连接验证失败\n");
        printf("是否继续启动? (y/n): ");
        char choice;
        std::cin >> choice;
        std::cin.ignore();
        if (choice != 'y' && choice != 'Y') {
            printf("用户取消启动\n");
            socks5::cleanupWinsock();
            WinDivertLoaderCleanup();
            return 1;
        }
    }
    
    // 检查管理员权限
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    if (!isAdmin) {
        fprintf(stderr, "警告: 程序需要管理员权限才能正常工作\n");
        fprintf(stderr, "请右键点击程序，选择\"以管理员身份运行\"\n");
    }
    
    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // 启动本地代理服务器
    LocalProxyServer& proxyServer = getLocalProxyServer();
    proxyServer.setSessionCallback(onSessionEvent);
    
    printf("\n启动本地代理服务器...\n");
    if (!proxyServer.start("127.0.0.1", 0)) {
        fprintf(stderr, "错误: 无法启动本地代理服务器\n");
        return 1;
    }
    printf("本地代理服务器已启动: %s:%d\n", 
           proxyServer.getBindAddress().c_str(), proxyServer.getBindPort());
    
    // 启动进程监控
    ProcessMonitor& processMonitor = getProcessMonitor();
    processMonitor.setCallback(onConnectionEvent);
    
    printf("启动进程监控...\n");
    if (!processMonitor.start()) {
        DWORD error = GetLastError();
        fprintf(stderr, "错误: 无法启动进程监控 (错误码=%lu)\n", error);
        
        // 根据错误码给出更详细的提示
        switch (error) {
            case 2:  // ERROR_FILE_NOT_FOUND
                fprintf(stderr, "  -> WinDivert 驱动文件未找到\n");
                fprintf(stderr, "  -> 请确保 WinDivert64.sys 或 WinDivert32.sys 在程序目录下\n");
                break;
            case 5:  // ERROR_ACCESS_DENIED
                fprintf(stderr, "  -> 访问被拒绝，请以管理员身份运行程序\n");
                break;
            case 577:  // ERROR_INVALID_IMAGE_HASH
                fprintf(stderr, "  -> 驱动签名验证失败\n");
                fprintf(stderr, "  -> 可能需要禁用驱动签名强制或使用签名的驱动\n");
                break;
            case 1275:  // ERROR_DRIVER_BLOCKED
                fprintf(stderr, "  -> 驱动被阻止加载\n");
                fprintf(stderr, "  -> 可能被安全软件阻止，请检查杀毒软件设置\n");
                break;
            case 1058:  // ERROR_SERVICE_DISABLED
                fprintf(stderr, "  -> 服务被禁用\n");
                break;
            case 87:  // ERROR_INVALID_PARAMETER
                fprintf(stderr, "  -> 无效参数，可能是过滤器语法错误\n");
                break;
            default:
                fprintf(stderr, "  -> 请确保以管理员身份运行，并且 WinDivert 驱动文件存在\n");
                break;
        }
        
        proxyServer.stop();
        WinDivertLoaderCleanup();
        return 1;
    }
    printf("进程监控已启动\n");
    
    // 启动 DNS 监控（用于域名匹配）
    DnsMonitor& dnsMonitor = getDnsMonitor();
    printf("启动 DNS 监控...\n");
    if (!dnsMonitor.start()) {
        printf("警告: DNS 监控启动失败，域名匹配功能将不可用\n");
        printf("       规则将只能匹配 IP 地址\n");
    } else {
        printf("DNS 监控已启动\n");
    }
    
    // 启动流量拦截器
    TrafficInterceptor& interceptor = getTrafficInterceptor();
    interceptor.setConfig(&config);
    interceptor.setProcessMonitor(&processMonitor);
    interceptor.setLocalProxyServer(&proxyServer);
    
    printf("启动流量拦截器...\n");
    if (!interceptor.start()) {
        DWORD error = GetLastError();
        fprintf(stderr, "错误: 无法启动流量拦截器 (错误码=%lu)\n", error);
        
        // 根据错误码给出更详细的提示
        switch (error) {
            case 2:  // ERROR_FILE_NOT_FOUND
                fprintf(stderr, "  -> WinDivert 驱动文件未找到\n");
                fprintf(stderr, "  -> 请确保 WinDivert64.sys 或 WinDivert32.sys 在程序目录下\n");
                break;
            case 5:  // ERROR_ACCESS_DENIED
                fprintf(stderr, "  -> 访问被拒绝，请以管理员身份运行程序\n");
                break;
            case 577:  // ERROR_INVALID_IMAGE_HASH
                fprintf(stderr, "  -> 驱动签名验证失败\n");
                fprintf(stderr, "  -> 可能需要禁用驱动签名强制或使用签名的驱动\n");
                break;
            case 1275:  // ERROR_DRIVER_BLOCKED
                fprintf(stderr, "  -> 驱动被阻止加载\n");
                fprintf(stderr, "  -> 可能被安全软件阻止，请检查杀毒软件设置\n");
                break;
            case 1058:  // ERROR_SERVICE_DISABLED
                fprintf(stderr, "  -> 服务被禁用\n");
                break;
            case 87:  // ERROR_INVALID_PARAMETER
                fprintf(stderr, "  -> 无效参数，可能是过滤器语法错误\n");
                break;
            default:
                fprintf(stderr, "  -> 请确保以管理员身份运行，并且 WinDivert 驱动文件存在\n");
                break;
        }
        
        processMonitor.stop();
        proxyServer.stop();
        WinDivertLoaderCleanup();
        return 1;
    }
    printf("流量拦截器已启动\n");
    
    printf("\n-------------------------------------------\n");
    printf("代理服务已启动，按 Ctrl+C 退出\n");
    printf("-------------------------------------------\n\n");
    
    // 主循环
    while (g_running) {
        Sleep(1000);
        
        // 定期打印统计信息
        static int counter = 0;
        if (++counter >= 30) {  // 每 30 秒
            counter = 0;
            
            InterceptStats stats = interceptor.getStats();
            printf("\n[统计] 包: 接收=%llu, 放行=%llu, 重定向=%llu, 阻止=%llu\n",
                stats.packetsReceived, stats.packetsAllowed,
                stats.packetsRedirected, stats.packetsBlocked);
            printf("[统计] 连接: 跟踪=%llu, 重定向=%llu, 阻止=%llu\n",
                stats.connectionsTracked, stats.connectionsRedirected,
                stats.connectionsBlocked);
            printf("[统计] 会话: 总数=%llu, 活动=%llu\n",
                proxyServer.getTotalSessions(), proxyServer.getActiveSessionCount());
            printf("[统计] DNS映射: %zu 条\n", dnsMonitor.getMappingCount());
            
            // 定期清理过期的 DNS 记录
            dnsMonitor.cleanupExpiredRecords();
        }
    }
    
    // 停止所有组件
    printf("\n正在停止服务...\n");
    
    interceptor.stop();
    printf("流量拦截器已停止\n");
    
    dnsMonitor.stop();
    printf("DNS 监控已停止\n");
    
    processMonitor.stop();
    printf("进程监控已停止\n");
    
    proxyServer.stop();
    printf("本地代理服务器已停止\n");
    
    // 清理 Winsock
    socks5::cleanupWinsock();
    
    // 清理 WinDivert
    WinDivertLoaderCleanup();
    
    printf("\n程序已退出\n");
    return 0;
}