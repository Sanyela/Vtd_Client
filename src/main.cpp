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

#include "config.h"
#include "process_monitor.h"
#include "proxy_server.h"
#include "traffic_interceptor.h"
#include "socks5_client.h"

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
        if (proxy.authEnabled) {
            printf(" (认证: %s)", proxy.username.c_str());
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

// 进程监控回调
void onConnectionEvent(ConnectionEvent event, const ConnectionInfo& info) {
    const char* eventStr = (event == ConnectionEvent::ESTABLISHED) ? "建立" : "关闭";
    
    printf("[FLOW] 连接%s: %s (PID=%u) ", eventStr, info.processName.c_str(), info.processId);
    
    // 打印地址信息
    if (!info.isIPv6) {
        UINT32 local = info.localAddr[0];
        UINT32 remote = info.remoteAddr[0];
        printf("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u",
            (local >> 0) & 0xFF, (local >> 8) & 0xFF,
            (local >> 16) & 0xFF, (local >> 24) & 0xFF,
            info.localPort,
            (remote >> 0) & 0xFF, (remote >> 8) & 0xFF,
            (remote >> 16) & 0xFF, (remote >> 24) & 0xFF,
            info.remotePort);
    }
    
    printf(" [%s]\n", info.protocol == 6 ? "TCP" : "UDP");
}

// 会话回调
void onSessionEvent(ProxySession* session, const std::string& event) {
    if (event == "started") {
        printf("[PROXY] 新会话: %s (PID=%u) -> %u.%u.%u.%u:%u\n",
            session->processName.c_str(), session->processId,
            (session->originalDstAddr >> 0) & 0xFF,
            (session->originalDstAddr >> 8) & 0xFF,
            (session->originalDstAddr >> 16) & 0xFF,
            (session->originalDstAddr >> 24) & 0xFF,
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
    
    // 初始化 Winsock
    if (!socks5::initWinsock()) {
        fprintf(stderr, "错误: 无法初始化 Winsock\n");
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
        fprintf(stderr, "错误: 无法启动进程监控 (错误码=%lu)\n", GetLastError());
        fprintf(stderr, "请确保以管理员身份运行，并且 WinDivert 驱动文件存在\n");
        proxyServer.stop();
        return 1;
    }
    printf("进程监控已启动\n");
    
    // 启动流量拦截器
    TrafficInterceptor& interceptor = getTrafficInterceptor();
    interceptor.setConfig(&config);
    interceptor.setProcessMonitor(&processMonitor);
    interceptor.setLocalProxyServer(&proxyServer);
    
    printf("启动流量拦截器...\n");
    if (!interceptor.start()) {
        fprintf(stderr, "错误: 无法启动流量拦截器 (错误码=%lu)\n", GetLastError());
        processMonitor.stop();
        proxyServer.stop();
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
        }
    }
    
    // 停止所有组件
    printf("\n正在停止服务...\n");
    
    interceptor.stop();
    printf("流量拦截器已停止\n");
    
    processMonitor.stop();
    printf("进程监控已停止\n");
    
    proxyServer.stop();
    printf("本地代理服务器已停止\n");
    
    // 清理 Winsock
    socks5::cleanupWinsock();
    
    printf("\n程序已退出\n");
    return 0;
}