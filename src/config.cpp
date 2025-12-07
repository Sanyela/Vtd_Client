/*
 * config.cpp
 * 配置文件解析实现
 */

#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

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
        }
        
        proxy.address = getXmlTagContent(proxyXml, "Address");
        
        std::string portStr = getXmlTagContent(proxyXml, "Port");
        if (!portStr.empty()) {
            proxy.port = std::stoi(portStr);
        }
        
        // 认证信息
        std::string authEnabled = getXmlAttribute(proxyXml, "Authentication", "enabled");
        proxy.authEnabled = (authEnabled == "true");
        
        if (proxy.authEnabled) {
            proxy.username = getXmlTagContent(proxyXml, "Username");
            proxy.password = getXmlTagContent(proxyXml, "Password");
        }
        
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
    
    for (const auto& rule : rules_) {
        if (!rule.enabled) continue;
        
        bool appMatch = true;
        bool targetMatch = true;
        bool portMatch = true;
        
        // 检查应用程序匹配
        if (!rule.applications.empty()) {
            appMatch = false;
            for (size_t i = 0; i < rule.appPatterns.size(); i++) {
                if (std::regex_match(procNameLower, rule.appPatterns[i])) {
                    appMatch = true;
                    break;
                }
            }
        }
        
        // 检查目标地址匹配
        if (!rule.targets.empty()) {
            targetMatch = false;
            for (size_t i = 0; i < rule.targetPatterns.size(); i++) {
                if (std::regex_match(targetLower, rule.targetPatterns[i])) {
                    targetMatch = true;
                    break;
                }
            }
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
        }
        
        // 所有条件都匹配
        if (appMatch && targetMatch && portMatch) {
            return &rule;
        }
    }
    
    return nullptr;
}

} // namespace proxifier