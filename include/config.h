/*
 * config.h
 * 配置文件解析和规则定义
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <regex>

namespace proxifier {

// 凭据信息结构
struct ProxyCredentials {
    int proxyId = 0;
    std::string username;
    std::string password;
};

// 代理类型
enum class ProxyType {
    DIRECT,     // 直连
    BLOCK,      // 阻止
    SOCKS5,     // SOCKS5 代理
    HTTP,       // HTTP 代理（暂不实现）
    REDIRECT    // 直接重定向/端口转发（不使用代理协议）
};

// 代理服务器配置
struct ProxyServer {
    int id = 0;
    ProxyType type = ProxyType::SOCKS5;
    std::string address;
    int port = 1080;
    bool authEnabled = false;
    std::string username;
    std::string password;
    bool isDirectRedirect = false;  // 是否为直接重定向（不使用SOCKS5协议）
};

// 规则动作
struct RuleAction {
    ProxyType type = ProxyType::DIRECT;
    int proxyId = 0;  // 如果是代理，指向代理服务器ID
};

// 规则定义
struct Rule {
    bool enabled = true;
    std::string name;
    RuleAction action;
    
    // 匹配条件
    std::vector<std::string> applications;  // 进程名列表
    std::vector<std::string> targets;       // 目标地址/域名列表
    std::vector<int> ports;                 // 端口列表
    
    // 编译后的正则表达式（用于通配符匹配）
    std::vector<std::regex> targetPatterns;
    std::vector<std::regex> appPatterns;
};

// 配置类
class Config {
public:
    Config();
    ~Config();
    
    // 加载配置
    bool loadFromFile(const std::string& filename);
    bool loadFromXml(const std::string& xmlContent);
    bool loadFromJson(const std::string& jsonContent);
    
    // 保存配置
    bool saveToFile(const std::string& filename);
    
    // 获取代理服务器
    const ProxyServer* getProxy(int id) const;
    const std::vector<ProxyServer>& getProxies() const { return proxies_; }
    
    // 获取规则
    const std::vector<Rule>& getRules() const { return rules_; }
    
    // 匹配规则
    const Rule* matchRule(const std::string& processName, 
                          const std::string& targetAddr, 
                          int targetPort) const;
    
    // 设置默认代理
    void setDefaultProxy(int proxyId) { defaultProxyId_ = proxyId; }
    int getDefaultProxyId() const { return defaultProxyId_; }
    
    // 添加代理
    void addProxy(const ProxyServer& proxy);
    
    // 添加规则
    void addRule(const Rule& rule);
    
    // 清空配置
    void clear();
    
    // 更新代理凭据
    bool updateProxyCredentials(int proxyId, const std::string& username, const std::string& password);
    
    // 获取需要认证但凭据为空的代理列表
    std::vector<ProxyServer*> getProxiesNeedingCredentials();

private:
    std::vector<ProxyServer> proxies_;
    std::vector<Rule> rules_;
    int defaultProxyId_ = 0;
    
    // 辅助函数
    bool matchWildcard(const std::string& pattern, const std::string& str) const;
    std::regex wildcardToRegex(const std::string& pattern) const;
    void compileRulePatterns(Rule& rule);
};

// 全局配置实例
Config& getConfig();

// 凭据文件管理函数
bool saveCredentials(const std::vector<ProxyCredentials>& credentials);
bool loadCredentials(std::vector<ProxyCredentials>& credentials);
bool credentialsFileExists();
bool deleteCredentialsFile();

} // namespace proxifier

#endif // CONFIG_H