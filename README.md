# WinDivert Proxifier

基于 WinDivert 的进程级别 SOCKS5 代理工具，使用 C++ 编写。

## 功能特性

- **进程级别代理**：根据进程名将特定应用的流量重定向到 SOCKS5 代理
- **规则匹配**：支持进程名、目标地址（含通配符）、端口匹配
- **SOCKS5 支持**：完整的 SOCKS5 协议支持，包括用户名/密码认证
- **Proxifier 兼容**：支持 Proxifier 的 XML 配置文件格式
- **多种动作**：支持直连、代理、阻止三种动作
- **实时监控**：显示连接状态和流量统计

## 系统要求

- Windows 10/11 或 Windows Server 2016+
- 管理员权限（运行时需要）
- Visual Studio 2019+ 或 MinGW-w64（编译时需要）

## 项目结构

```
WinDivert-Proxifier/
├── .github/
│   └── workflows/
│       └── build.yml          # GitHub Actions 自动构建
├── include/
│   ├── windivert.h            # WinDivert API 头文件
│   ├── config.h               # 配置解析
│   ├── process_monitor.h      # 进程监控
│   ├── socks5_client.h        # SOCKS5 客户端
│   ├── proxy_server.h         # 本地代理服务器
│   └── traffic_interceptor.h  # 流量拦截器
├── src/
│   ├── main.cpp               # 主程序
│   ├── config.cpp             # 配置解析实现
│   ├── process_monitor.cpp    # 进程监控实现
│   ├── socks5_client.cpp      # SOCKS5 客户端实现
│   ├── proxy_server.cpp       # 本地代理服务器实现
│   └── traffic_interceptor.cpp # 流量拦截器实现
├── x64/                       # 64位 WinDivert 文件
│   ├── WinDivert.dll
│   └── WinDivert64.sys
├── x86/                       # 32位 WinDivert 文件
│   ├── WinDivert.dll
│   ├── WinDivert32.sys
│   └── WinDivert64.sys
├── CMakeLists.txt             # CMake 构建配置
├── config.xml                 # 示例配置文件
└── README.md                  # 本文件
```

## 工作原理

```
┌─────────────────────────────────────────────────────────────────┐
│                        WinDivert Proxifier                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   进程监控    │    │   规则匹配    │    │   配置解析    │       │
│  │ (FLOW 层)    │───▶│   引擎       │◀───│   (XML)      │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                   │                                    │
│         ▼                   ▼                                    │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              流量拦截器 (NETWORK 层)                   │       │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐              │       │
│  │  │  直连   │  │  代理   │  │  阻止   │              │       │
│  │  └─────────┘  └────┬────┘  └─────────┘              │       │
│  └────────────────────┼─────────────────────────────────┘       │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              本地代理服务器                            │       │
│  │  ┌─────────────────────────────────────────────┐    │       │
│  │  │           SOCKS5 客户端                      │    │       │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐     │    │       │
│  │  │  │  握手   │─▶│  认证   │─▶│  连接   │     │    │       │
│  │  │  └─────────┘  └─────────┘  └─────────┘     │    │       │
│  │  └─────────────────────────────────────────────┘    │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 编译方法

### 方法一：使用 GitHub Actions（推荐）

1. Fork 或 Push 代码到 GitHub
2. GitHub Actions 会自动编译 x64 和 x86 版本
3. 在 Actions 页面下载编译好的 artifacts
4. 创建 tag（如 `v1.0.0`）会自动生成 Release

### 方法二：本地编译（使用 Visual Studio）

```powershell
# 创建构建目录
mkdir build
cd build

# 配置（64位）
cmake .. -A x64

# 或配置（32位）
cmake .. -A Win32

# 编译
cmake --build . --config Release

# 输出文件在 build/bin/Release/ 目录
```

### 方法三：本地编译（使用 MinGW）

```bash
# 创建构建目录
mkdir build
cd build

# 配置
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release

# 编译
cmake --build .

# 输出文件在 build/bin/ 目录
```

## 使用方法

### 基本用法

```powershell
# 以管理员身份运行 PowerShell 或 CMD

# 使用默认配置文件 (config.xml)
proxifier.exe

# 使用指定配置文件
proxifier.exe myconfig.xml

# 测试配置文件
proxifier.exe -t config.xml

# 显示帮助
proxifier.exe -h
```

### 配置文件格式

配置文件使用 Proxifier 的 XML 格式：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ProxifierProfile>
    <ProxyList>
        <Proxy id="100" type="SOCKS5">
            <Address>127.0.0.1</Address>
            <Port>1080</Port>
            <Authentication enabled="true">
                <Username>user</Username>
                <Password>pass</Password>
            </Authentication>
        </Proxy>
    </ProxyList>
    <RuleList>
        <!-- 本地地址直连 -->
        <Rule enabled="true">
            <Name>Localhost</Name>
            <Targets>localhost; 127.0.0.1; ::1</Targets>
            <Action type="Direct" />
        </Rule>
        
        <!-- 指定进程走代理 -->
        <Rule enabled="true">
            <Name>Game Proxy</Name>
            <Applications>game.exe; launcher.exe</Applications>
            <Ports>10012</Ports>
            <Action type="Proxy">100</Action>
        </Rule>
        
        <!-- 阻止特定流量 -->
        <Rule enabled="true">
            <Name>Block HTTP</Name>
            <Applications>game.exe</Applications>
            <Ports>80;443</Ports>
            <Action type="Block" />
        </Rule>
        
        <!-- 默认规则 -->
        <Rule enabled="true">
            <Name>Default</Name>
            <Action type="Direct" />
        </Rule>
    </RuleList>
</ProxifierProfile>
```

### 规则匹配

规则按顺序匹配，第一个匹配的规则生效：

| 条件 | 说明 | 示例 |
|------|------|------|
| `Applications` | 进程名（支持通配符） | `game.exe; *.exe` |
| `Targets` | 目标地址/域名（支持通配符） | `*.google.com; 192.168.*` |
| `Ports` | 目标端口 | `80;443;8080` |

### 动作类型

| 动作 | 说明 |
|------|------|
| `Direct` | 直接连接，不经过代理 |
| `Proxy` | 通过指定代理连接 |
| `Block` | 阻止连接 |

## 常见问题

### 错误码说明

| 错误码 | 说明 | 解决方法 |
|--------|------|----------|
| 2 | 找不到驱动文件 | 确保 WinDivert.dll 和 .sys 文件在程序目录 |
| 5 | 访问被拒绝 | 以管理员身份运行 |
| 577 | 驱动签名无效 | 禁用驱动签名验证或使用已签名驱动 |
| 1275 | 驱动被阻止 | 检查安全软件设置 |

### 禁用驱动签名验证（测试用）

```powershell
# 以管理员身份运行
bcdedit /set testsigning on
# 重启电脑
```

### 恢复驱动签名验证

```powershell
bcdedit /set testsigning off
# 重启电脑
```

## 技术细节

### WinDivert 层使用

- **FLOW 层**：监控进程的网络连接，获取进程 ID 和进程名
- **NETWORK 层**：拦截和重定向网络数据包

### 数据流程

1. **连接建立**：FLOW 层捕获连接事件，记录进程信息
2. **规则匹配**：根据进程名、目标地址、端口匹配规则
3. **流量拦截**：NETWORK 层拦截 TCP SYN 包
4. **重定向**：修改目标地址为本地代理服务器
5. **代理转发**：本地代理服务器通过 SOCKS5 连接到真实目标

## 限制和已知问题

1. **仅支持 TCP**：当前版本不支持 UDP 代理
2. **IPv6 支持有限**：IPv6 支持尚不完整
3. **DNS 解析**：不支持通过代理进行 DNS 解析
4. **性能**：高流量场景下可能有性能影响

## 许可证

- WinDivert: LGPL v3 / GPL v2
- 本项目代码: MIT

## 相关链接

- [WinDivert 官网](https://reqrypt.org/windivert.html)
- [WinDivert GitHub](https://github.com/basil00/Divert)
- [WinDivert 文档](https://reqrypt.org/windivert-doc.html)
- [Proxifier](https://www.proxifier.com/)

## 致谢

- [WinDivert](https://github.com/basil00/Divert) - 强大的 Windows 网络包拦截库
- [Proxifier](https://www.proxifier.com/) - 配置文件格式参考