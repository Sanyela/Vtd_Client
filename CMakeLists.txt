cmake_minimum_required(VERSION 3.15)
project(WinDivertProxifier VERSION 1.0.0 LANGUAGES CXX)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows 特定设置
if(WIN32)
    # 设置 Windows SDK 版本
    set(CMAKE_SYSTEM_VERSION 10.0)
    
    # 添加 Windows 定义
    add_definitions(-D_WIN32_WINNT=0x0A00)  # Windows 10
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-DNOMINMAX)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# 设置输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)

# 根据架构选择正确的库目录
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64位
    set(WINDIVERT_ARCH "x64")
    set(WINDIVERT_LIB_DIR ${CMAKE_SOURCE_DIR}/x64)
else()
    # 32位
    set(WINDIVERT_ARCH "x86")
    set(WINDIVERT_LIB_DIR ${CMAKE_SOURCE_DIR}/x86)
endif()

message(STATUS "Building for architecture: ${WINDIVERT_ARCH}")
message(STATUS "WinDivert library directory: ${WINDIVERT_LIB_DIR}")

# 源文件
set(SOURCES
    src/main.cpp
    src/config.cpp
    src/process_monitor.cpp
    src/socks5_client.cpp
    src/proxy_server.cpp
    src/traffic_interceptor.cpp
    src/windivert_loader.cpp
)

# 头文件
set(HEADERS
    include/windivert.h
    include/windivert_loader.h
    include/config.h
    include/process_monitor.h
    include/socks5_client.h
    include/proxy_server.h
    include/traffic_interceptor.h
)

# 创建可执行文件
add_executable(proxifier ${SOURCES} ${HEADERS})

# 链接库 - 使用动态加载，不直接链接 WinDivert.dll
target_link_libraries(proxifier
    ws2_32
    psapi
)

# 复制 WinDivert 文件到输出目录
add_custom_command(TARGET proxifier POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${WINDIVERT_LIB_DIR}/WinDivert.dll
        $<TARGET_FILE_DIR:proxifier>
    COMMENT "Copying WinDivert.dll to output directory"
)

# 复制驱动文件
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 64位只需要 WinDivert64.sys
    add_custom_command(TARGET proxifier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${WINDIVERT_LIB_DIR}/WinDivert64.sys
            $<TARGET_FILE_DIR:proxifier>
        COMMENT "Copying WinDivert64.sys to output directory"
    )
else()
    # 32位需要 WinDivert32.sys 和 WinDivert64.sys（用于在64位系统上运行）
    add_custom_command(TARGET proxifier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${WINDIVERT_LIB_DIR}/WinDivert32.sys
            $<TARGET_FILE_DIR:proxifier>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${WINDIVERT_LIB_DIR}/WinDivert64.sys
            $<TARGET_FILE_DIR:proxifier>
        COMMENT "Copying WinDivert driver files to output directory"
    )
endif()

# 复制示例配置文件
if(EXISTS ${CMAKE_SOURCE_DIR}/config.xml)
    add_custom_command(TARGET proxifier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/config.xml
            $<TARGET_FILE_DIR:proxifier>
        COMMENT "Copying config.xml to output directory"
    )
endif()

# 安装目标
install(TARGETS proxifier DESTINATION bin)
install(FILES 
    ${WINDIVERT_LIB_DIR}/WinDivert.dll
    DESTINATION bin
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(FILES ${WINDIVERT_LIB_DIR}/WinDivert64.sys DESTINATION bin)
else()
    install(FILES 
        ${WINDIVERT_LIB_DIR}/WinDivert32.sys
        ${WINDIVERT_LIB_DIR}/WinDivert64.sys
        DESTINATION bin
    )
endif()

# 打印配置信息
message(STATUS "")
message(STATUS "=== WinDivert Proxifier Configuration ===")
message(STATUS "Architecture: ${WINDIVERT_ARCH}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output Directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "=========================================")
message(STATUS "")