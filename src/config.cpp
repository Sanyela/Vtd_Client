/*
 * config.cpp
 * 配置文件解析实现
 */

#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <windows.h>

// 凭据文件名
static const char* CREDENTIALS_FILE = "credentials.dat";

namespace proxifier {

// 全局配置实例
static Config g_config;
Config& getConfig() { return g_config; }

// 辅助函数：去除字符串两端空白
static std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

// 辅助函数：分割字符串
static std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        token = trim(token);
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

// 辅助函数：转小写
static std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// 简单的 XML 解析辅助函数
static std::string getXmlTagContent(const std::string& xml, const std::string& tag) {
    std::string startTag = "<" + tag + ">";
    std::string endTag = "</" + tag + ">";
    
    size_t start = xml.find(startTag);
    if (start == std::string::npos) {
        // 尝试带属性的标签
        startTag = "<" + tag + " ";
        start = xml.find(startTag);
        if (start == std::string::npos) return "";
        start = xml.find(">", start);
        if (start == std::string::npos) return "";
        start++;
    } else {
        start += startTag.length();
    }
    
    size_t end = xml.find(endTag, start);
    if (end == std::string::npos) return "";
    
    return xml.substr(start, end - start);
}

static std::string getXmlAttribute(const std::string& xml, const std::string& tag, const std::string& attr) {
    std::string startTag = "<" + tag + " ";
    size_t tagStart = xml.find(startTag);
    if (tagStart == std::string::npos) {
        startTag = "<" + tag + ">";
        tagStart = xml.find(startTag);
        if (tagStart == std::string::npos) return "";
    }
    
    size_t tagEnd = xml.find(">", tagStart);
    if (tagEnd == std::string::npos) return "";
    
    std::string tagContent = xml.substr(tagStart, tagEnd - tagStart);
    
    std::string attrSearch = attr + "=\"";
    size_t attrStart = tagContent.find(attrSearch);
    if (attrStart == std::string::npos) return "";
    
    attrStart += attrSearch.length();
    size_t attrEnd = tagContent.find("\"", attrStart);
    if (attrEnd == std::string::npos) return "";
    
    return tagContent.substr(attrStart, attrEnd - attrStart);
}

// 查找所有匹配的标签
static std::vector<std::string> findAllXmlTags(const std::string& xml, const std::string& tag) {
    std::vector<std::string> results;
    std::string startTag1 = "<" + tag + ">";
    std::string startTag2 = "<" + tag + " ";
    std::string endTag = "</" + tag + ">";
    
    size_t pos = 0;
    while (pos < xml.length()) {
        size_t start1 = xml.find(startTag1, pos);
        size_t start2 = xml.find(startTag2, pos);
        size_t start = std::min(start1, start2);
        
        if (start == std::string::npos) break;
        
        size_t contentStart;
        if (start == start1) {
            contentStart = start + startTag1.length();
        } else {
            contentStart = xml.find(">", start);
            if (contentStart == std::string::npos) break;
            contentStart++;
        }
        
        size_t end = xml.find(endTag, contentStart);
        if (end == std::string::npos) break;
        
        // 包含完整标签
        results.push_back(xml.substr(start, end + endTag.length() - start));
        pos = end + endTag.length();
    }
    
    return results;
}

Config::Config() {}
Config::~Config() {}

bool Config::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    // 检测文件类型
    if (content.find("<?xml") != std::string::npos || 
        content.find("<ProxifierProfile") != std::string::npos) {
        return loadFromXml(content);
    } else if (content.find("{") != std::string::npos) {
        return loadFromJson(content);
    }
    
    return false;
}

bool Config::loadFromXml(const std::string& xmlContent) {
    clear();
    
    // 解析代理列表
    std::string proxyList = getXmlTagContent(xmlContent, "ProxyList");
    auto proxyTags = findAllXmlTags(proxyList, "Proxy");
    
    for (const auto& proxyXml : proxyTags) {
        ProxyServer proxy;
        
        std::string idStr = getXmlAttribute(proxyXml, "Proxy", "id");
        if (!idStr.empty()) {
            proxy.id = std::stoi(idStr);
        }
        
        std::string typeStr = getXmlAttribute(proxyXml, "Proxy", "type");
        if (typeStr == "SOCKS5") {
            proxy.type = ProxyType::SOCKS5;
        } else if (typeStr == "HTTP") {
            proxy.type = ProxyType::HTTP;
        } else if (typeStr == "DIRECT") {
            // 直接端口转发类型 - 不使用 SOCKS5 协议
            proxy.type = ProxyType::DIRECT;
            proxy.isDirectRedirect = true;
        }
        
        proxy.address = getXmlTagContent(proxyXml, "Address");
        
        std::string portStr = getXmlTagContent(proxyXml, "Port");
        if (!portStr.empty()) {
            proxy.port = std::stoi(portStr);
        }
        
        // 认证信息
        std::string authEnabled = getXmlAttribute(proxyXml, "Authentication", "enabled");
        proxy.authEnabled = (authEnabled == "true");
        
        // 解析用户名和密码
        std::string authSection = getXmlTagContent(proxyXml, "Authentication");
        if (!authSection.empty()) {
            proxy.username = trim(getXmlTagContent(authSection, "Username"));
            proxy.password = trim(getXmlTagContent(authSection, "Password"));
        }
        
        // 调试输出
        printf("[配置] 代理 %d: 地址=%s:%d, 认证=%s, 用户名='%s', 密码长度=%zu\n",
               proxy.id, proxy.address.c_str(), proxy.port,
               proxy.authEnabled ? "是" : "否",
               proxy.username.c_str(), proxy.password.length());
        
        // 不再自动检测直接重定向
        // 用户需要在配置中明确指定，或者通过代理 ID 来区分
        // 默认所有代理都是 SOCKS5 代理
        proxy.isDirectRedirect = false;
        
        addProxy(proxy);
    }
    
    // 解析规则列表
    std::string ruleList = getXmlTagContent(xmlContent, "RuleList");
    auto ruleTags = findAllXmlTags(ruleList, "Rule");
    
    for (const auto& ruleXml : ruleTags) {
        Rule rule;
        
        std::string enabledStr = getXmlAttribute(ruleXml, "Rule", "enabled");
        rule.enabled = (enabledStr != "false");
        
        rule.name = getXmlTagContent(ruleXml, "Name");
        
        // 解析动作
        std::string actionType = getXmlAttribute(ruleXml, "Action", "type");
        if (actionType == "Direct") {
            rule.action.type = ProxyType::DIRECT;
        } else if (actionType == "Block") {
            rule.action.type = ProxyType::BLOCK;
        } else if (actionType == "Proxy") {
            rule.action.type = ProxyType::SOCKS5;
            std::string actionContent = getXmlTagContent(ruleXml, "Action");
            if (!actionContent.empty()) {
                rule.action.proxyId = std::stoi(actionContent);
            }
        }
        
        // 解析应用程序列表
        std::string apps = getXmlTagContent(ruleXml, "Applications");
        if (!apps.empty()) {
            rule.applications = split(apps, ';');
        }
        
        // 解析目标地址列表
        std::string targets = getXmlTagContent(ruleXml, "Targets");
        if (!targets.empty()) {
            rule.targets = split(targets, ';');
        }
        
        // 解析端口列表
        std::string ports = getXmlTagContent(ruleXml, "Ports");
        if (!ports.empty()) {
            auto portStrs = split(ports, ';');
            for (const auto& p : portStrs) {
                rule.ports.push_back(std::stoi(p));
            }
        }
        
        addRule(rule);
    }
    
    return true;
}

bool Config::loadFromJson(const std::string& jsonContent) {
    // 简化的 JSON 解析（实际项目中应使用 nlohmann/json 等库）
    // 这里只实现基本功能
    clear();
    
    // TODO: 实现 JSON 解析
    return false;
}

bool Config::saveToFile(const std::string& filename) {
    // TODO: 实现保存功能
    return false;
}

const ProxyServer* Config::getProxy(int id) const {
    for (const auto& proxy : proxies_) {
        if (proxy.id == id) {
            return &proxy;
        }
    }
    return nullptr;
}

void Config::addProxy(const ProxyServer& proxy) {
    proxies_.push_back(proxy);
}

void Config::addRule(const Rule& rule) {
    Rule r = rule;
    compileRulePatterns(r);
    rules_.push_back(r);
}

void Config::clear() {
    proxies_.clear();
    rules_.clear();
    defaultProxyId_ = 0;
}

bool Config::updateProxyCredentials(int proxyId, const std::string& username, const std::string& password) {
    for (auto& proxy : proxies_) {
        if (proxy.id == proxyId) {
            proxy.username = username;
            proxy.password = password;
            return true;
        }
    }
    return false;
}

std::vector<ProxyServer*> Config::getProxiesNeedingCredentials() {
    std::vector<ProxyServer*> result;
    for (auto& proxy : proxies_) {
        if (proxy.authEnabled && (proxy.username.empty() || proxy.password.empty())) {
            result.push_back(&proxy);
        }
    }
    return result;
}

// ============ 凭据文件管理 ============

// 简单的 XOR 加密（仅用于基本混淆，不是真正的安全加密）
static std::string xorEncrypt(const std::string& data, const std::string& key) {
    std::string result = data;
    for (size_t i = 0; i < result.size(); i++) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

// 保存凭据到文件
bool saveCredentials(const std::vector<ProxyCredentials>& credentials) {
    std::ofstream file(CREDENTIALS_FILE, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // 简单的加密密钥（实际应用中应该使用更安全的方式）
    std::string key = "WinDivertProxifier2024";
    
    // 写入凭据数量
    uint32_t count = (uint32_t)credentials.size();
    file.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    for (const auto& cred : credentials) {
        // 写入代理ID
        file.write(reinterpret_cast<const char*>(&cred.proxyId), sizeof(cred.proxyId));
        
        // 加密并写入用户名
        std::string encUsername = xorEncrypt(cred.username, key);
        uint32_t usernameLen = (uint32_t)encUsername.size();
        file.write(reinterpret_cast<const char*>(&usernameLen), sizeof(usernameLen));
        file.write(encUsername.c_str(), usernameLen);
        
        // 加密并写入密码
        std::string encPassword = xorEncrypt(cred.password, key);
        uint32_t passwordLen = (uint32_t)encPassword.size();
        file.write(reinterpret_cast<const char*>(&passwordLen), sizeof(passwordLen));
        file.write(encPassword.c_str(), passwordLen);
    }
    
    file.close();
    return true;
}

// 从文件加载凭据
bool loadCredentials(std::vector<ProxyCredentials>& credentials) {
    std::ifstream file(CREDENTIALS_FILE, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::string key = "WinDivertProxifier2024";
    
    // 读取凭据数量
    uint32_t count = 0;
    file.read(reinterpret_cast<char*>(&count), sizeof(count));
    
    if (count > 100) {  // 安全检查
        file.close();
        return false;
    }
    
    credentials.clear();
    
    for (uint32_t i = 0; i < count; i++) {
        ProxyCredentials cred;
        
        // 读取代理ID
        file.read(reinterpret_cast<char*>(&cred.proxyId), sizeof(cred.proxyId));
        
        // 读取并解密用户名
        uint32_t usernameLen = 0;
        file.read(reinterpret_cast<char*>(&usernameLen), sizeof(usernameLen));
        if (usernameLen > 256) {  // 安全检查
            file.close();
            return false;
        }
        std::string encUsername(usernameLen, '\0');
        file.read(&encUsername[0], usernameLen);
        cred.username = xorEncrypt(encUsername, key);
        
        // 读取并解密密码
        uint32_t passwordLen = 0;
        file.read(reinterpret_cast<char*>(&passwordLen), sizeof(passwordLen));
        if (passwordLen > 256) {  // 安全检查
            file.close();
            return false;
        }
        std::string encPassword(passwordLen, '\0');
        file.read(&encPassword[0], passwordLen);
        cred.password = xorEncrypt(encPassword, key);
        
        credentials.push_back(cred);
    }
    
    file.close();
    return true;
}

// 检查凭据文件是否存在
bool credentialsFileExists() {
    std::ifstream file(CREDENTIALS_FILE);
    return file.good();
}

// 删除凭据文件
bool deleteCredentialsFile() {
    return DeleteFileA(CREDENTIALS_FILE) != 0;
}

void Config::compileRulePatterns(Rule& rule) {
    // 编译目标地址模式
    for (const auto& target : rule.targets) {
        try {
            rule.targetPatterns.push_back(wildcardToRegex(target));
        } catch (...) {
            // 忽略无效的模式
        }
    }
    
    // 编译应用程序模式
    for (const auto& app : rule.applications) {
        try {
            rule.appPatterns.push_back(wildcardToRegex(app));
        } catch (...) {
            // 忽略无效的模式
        }
    }
}

std::regex Config::wildcardToRegex(const std::string& pattern) const {
    std::string regexStr;
    regexStr.reserve(pattern.length() * 2);
    
    for (char c : pattern) {
        switch (c) {
            case '*':
                regexStr += ".*";
                break;
            case '?':
                regexStr += ".";
                break;
            case '.':
            case '+':
            case '^':
            case '$':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
            case '|':
            case '\\':
                regexStr += '\\';
                regexStr += c;
                break;
            default:
                regexStr += c;
                break;
        }
    }
    
    return std::regex(regexStr, std::regex::icase);
}

bool Config::matchWildcard(const std::string& pattern, const std::string& str) const {
    try {
        std::regex re = wildcardToRegex(pattern);
        return std::regex_match(str, re);
    } catch (...) {
        return false;
    }
}

const Rule* Config::matchRule(const std::string& processName,
                              const std::string& targetAddr,
                              int targetPort) const {
    std::string procNameLower = toLower(processName);
    std::string targetLower = toLower(targetAddr);
    
    // 调试输出
    static int debugCounter = 0;
    bool shouldDebug = (++debugCounter % 100 == 1);  // 每100次输出一次
    
    for (const auto& rule : rules_) {
        if (!rule.enabled) continue;
        
        bool appMatch = true;
        bool targetMatch = true;
        bool portMatch = true;
        
        // 检查应用程序匹配
        if (!rule.applications.empty()) {
            appMatch = false;
            
            // 如果进程名为空或未知，跳过需要进程匹配的规则
            if (procNameLower.empty() || procNameLower == "<pending>" || procNameLower == "<unknown>") {
                continue;  // 跳过这条规则，尝试下一条
            }
            
            for (size_t i = 0; i < rule.appPatterns.size(); i++) {
                try {
                    if (std::regex_match(procNameLower, rule.appPatterns[i])) {
                        appMatch = true;
                        break;
                    }
                } catch (const std::exception& e) {
                    // 忽略正则异常
                }
            }
            
            // 如果应用程序不匹配，跳过这条规则
            if (!appMatch) continue;
        }
        
        // 检查目标地址匹配
        if (!rule.targets.empty()) {
            targetMatch = false;
            for (size_t i = 0; i < rule.targetPatterns.size(); i++) {
                try {
                    if (std::regex_match(targetLower, rule.targetPatterns[i])) {
                        targetMatch = true;
                        break;
                    }
                } catch (const std::exception& e) {
                    // 忽略正则异常
                }
            }
            
            // 如果目标地址不匹配，跳过这条规则
            if (!targetMatch) continue;
        }
        
        // 检查端口匹配
        if (!rule.ports.empty()) {
            portMatch = false;
            for (int p : rule.ports) {
                if (p == targetPort) {
                    portMatch = true;
                    break;
                }
            }
            
            // 如果端口不匹配，跳过这条规则
            if (!portMatch) continue;
        }
        
        // 所有条件都匹配
        return &rule;
    }
    
    return nullptr;
}

} // namespace proxifier