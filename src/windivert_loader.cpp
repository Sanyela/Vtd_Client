/*
 * windivert_loader.cpp
 * WinDivert 动态加载包装器实现
 */

#include "windivert_loader.h"
#include <stdio.h>

// 全局变量
static HMODULE g_hWinDivert = NULL;

// 函数指针
static PFN_WinDivertOpen pfnWinDivertOpen = NULL;
static PFN_WinDivertRecv pfnWinDivertRecv = NULL;
static PFN_WinDivertRecvEx pfnWinDivertRecvEx = NULL;
static PFN_WinDivertSend pfnWinDivertSend = NULL;
static PFN_WinDivertSendEx pfnWinDivertSendEx = NULL;
static PFN_WinDivertShutdown pfnWinDivertShutdown = NULL;
static PFN_WinDivertClose pfnWinDivertClose = NULL;
static PFN_WinDivertSetParam pfnWinDivertSetParam = NULL;
static PFN_WinDivertGetParam pfnWinDivertGetParam = NULL;
static PFN_WinDivertHelperParsePacket pfnWinDivertHelperParsePacket = NULL;
static PFN_WinDivertHelperCalcChecksums pfnWinDivertHelperCalcChecksums = NULL;
static PFN_WinDivertHelperNtohs pfnWinDivertHelperNtohs = NULL;
static PFN_WinDivertHelperHtons pfnWinDivertHelperHtons = NULL;
static PFN_WinDivertHelperNtohl pfnWinDivertHelperNtohl = NULL;
static PFN_WinDivertHelperHtonl pfnWinDivertHelperHtonl = NULL;

BOOL WinDivertLoaderInit(void) {
    if (g_hWinDivert != NULL) {
        return TRUE; // 已加载
    }

    // 尝试多个路径加载 WinDivert.dll
    const char* dllPaths[] = {
        "WinDivert.dll",           // 当前目录
        ".\\WinDivert.dll",        // 当前目录
        "x64\\WinDivert.dll",      // x64 子目录
        "x86\\WinDivert.dll",      // x86 子目录
        ".\\x64\\WinDivert.dll",
        ".\\x86\\WinDivert.dll",
        NULL
    };

    for (int i = 0; dllPaths[i] != NULL; i++) {
        g_hWinDivert = LoadLibraryA(dllPaths[i]);
        if (g_hWinDivert != NULL) {
            printf("[WinDivertLoader] Loaded from: %s\n", dllPaths[i]);
            break;
        }
    }

    if (g_hWinDivert == NULL) {
        printf("[WinDivertLoader] Failed to load WinDivert.dll, error: %lu\n", GetLastError());
        return FALSE;
    }

    // 获取函数指针
    pfnWinDivertOpen = (PFN_WinDivertOpen)GetProcAddress(g_hWinDivert, "WinDivertOpen");
    pfnWinDivertRecv = (PFN_WinDivertRecv)GetProcAddress(g_hWinDivert, "WinDivertRecv");
    pfnWinDivertRecvEx = (PFN_WinDivertRecvEx)GetProcAddress(g_hWinDivert, "WinDivertRecvEx");
    pfnWinDivertSend = (PFN_WinDivertSend)GetProcAddress(g_hWinDivert, "WinDivertSend");
    pfnWinDivertSendEx = (PFN_WinDivertSendEx)GetProcAddress(g_hWinDivert, "WinDivertSendEx");
    pfnWinDivertShutdown = (PFN_WinDivertShutdown)GetProcAddress(g_hWinDivert, "WinDivertShutdown");
    pfnWinDivertClose = (PFN_WinDivertClose)GetProcAddress(g_hWinDivert, "WinDivertClose");
    pfnWinDivertSetParam = (PFN_WinDivertSetParam)GetProcAddress(g_hWinDivert, "WinDivertSetParam");
    pfnWinDivertGetParam = (PFN_WinDivertGetParam)GetProcAddress(g_hWinDivert, "WinDivertGetParam");
    pfnWinDivertHelperParsePacket = (PFN_WinDivertHelperParsePacket)GetProcAddress(g_hWinDivert, "WinDivertHelperParsePacket");
    pfnWinDivertHelperCalcChecksums = (PFN_WinDivertHelperCalcChecksums)GetProcAddress(g_hWinDivert, "WinDivertHelperCalcChecksums");
    pfnWinDivertHelperNtohs = (PFN_WinDivertHelperNtohs)GetProcAddress(g_hWinDivert, "WinDivertHelperNtohs");
    pfnWinDivertHelperHtons = (PFN_WinDivertHelperHtons)GetProcAddress(g_hWinDivert, "WinDivertHelperHtons");
    pfnWinDivertHelperNtohl = (PFN_WinDivertHelperNtohl)GetProcAddress(g_hWinDivert, "WinDivertHelperNtohl");
    pfnWinDivertHelperHtonl = (PFN_WinDivertHelperHtonl)GetProcAddress(g_hWinDivert, "WinDivertHelperHtonl");

    // 检查必要的函数是否加载成功
    if (pfnWinDivertOpen == NULL || pfnWinDivertRecv == NULL || 
        pfnWinDivertSend == NULL || pfnWinDivertClose == NULL) {
        printf("[WinDivertLoader] Failed to get required function pointers\n");
        WinDivertLoaderCleanup();
        return FALSE;
    }

    printf("[WinDivertLoader] Successfully initialized\n");
    return TRUE;
}

void WinDivertLoaderCleanup(void) {
    if (g_hWinDivert != NULL) {
        FreeLibrary(g_hWinDivert);
        g_hWinDivert = NULL;
    }

    pfnWinDivertOpen = NULL;
    pfnWinDivertRecv = NULL;
    pfnWinDivertRecvEx = NULL;
    pfnWinDivertSend = NULL;
    pfnWinDivertSendEx = NULL;
    pfnWinDivertShutdown = NULL;
    pfnWinDivertClose = NULL;
    pfnWinDivertSetParam = NULL;
    pfnWinDivertGetParam = NULL;
    pfnWinDivertHelperParsePacket = NULL;
    pfnWinDivertHelperCalcChecksums = NULL;
    pfnWinDivertHelperNtohs = NULL;
    pfnWinDivertHelperHtons = NULL;
    pfnWinDivertHelperNtohl = NULL;
    pfnWinDivertHelperHtonl = NULL;

    printf("[WinDivertLoader] Cleaned up\n");
}

BOOL WinDivertLoaderIsLoaded(void) {
    return g_hWinDivert != NULL;
}

// WinDivert API 包装函数实现

HANDLE WinDivertOpen(
    const char *filter,
    WINDIVERT_LAYER layer,
    INT16 priority,
    UINT64 flags) {
    if (pfnWinDivertOpen == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return pfnWinDivertOpen(filter, layer, priority, flags);
}

BOOL WinDivertRecv(
    HANDLE handle,
    PVOID pPacket,
    UINT packetLen,
    UINT *pRecvLen,
    WINDIVERT_ADDRESS *pAddr) {
    if (pfnWinDivertRecv == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertRecv(handle, pPacket, packetLen, pRecvLen, pAddr);
}

BOOL WinDivertRecvEx(
    HANDLE handle,
    PVOID pPacket,
    UINT packetLen,
    UINT *pRecvLen,
    UINT64 flags,
    WINDIVERT_ADDRESS *pAddr,
    UINT *pAddrLen,
    LPOVERLAPPED lpOverlapped) {
    if (pfnWinDivertRecvEx == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertRecvEx(handle, pPacket, packetLen, pRecvLen, flags, pAddr, pAddrLen, lpOverlapped);
}

BOOL WinDivertSend(
    HANDLE handle,
    const VOID *pPacket,
    UINT packetLen,
    UINT *pSendLen,
    const WINDIVERT_ADDRESS *pAddr) {
    if (pfnWinDivertSend == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertSend(handle, pPacket, packetLen, pSendLen, pAddr);
}

BOOL WinDivertSendEx(
    HANDLE handle,
    const VOID *pPacket,
    UINT packetLen,
    UINT *pSendLen,
    UINT64 flags,
    const WINDIVERT_ADDRESS *pAddr,
    UINT addrLen,
    LPOVERLAPPED lpOverlapped) {
    if (pfnWinDivertSendEx == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertSendEx(handle, pPacket, packetLen, pSendLen, flags, pAddr, addrLen, lpOverlapped);
}

BOOL WinDivertShutdown(
    HANDLE handle,
    WINDIVERT_SHUTDOWN how) {
    if (pfnWinDivertShutdown == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertShutdown(handle, how);
}

BOOL WinDivertClose(
    HANDLE handle) {
    if (pfnWinDivertClose == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertClose(handle);
}

BOOL WinDivertSetParam(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64 value) {
    if (pfnWinDivertSetParam == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertSetParam(handle, param, value);
}

BOOL WinDivertGetParam(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64 *pValue) {
    if (pfnWinDivertGetParam == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertGetParam(handle, param, pValue);
}

BOOL WinDivertHelperParsePacket(
    const VOID *pPacket,
    UINT packetLen,
    PWINDIVERT_IPHDR *ppIpHdr,
    PWINDIVERT_IPV6HDR *ppIpv6Hdr,
    UINT8 *pProtocol,
    PWINDIVERT_ICMPHDR *ppIcmpHdr,
    PWINDIVERT_ICMPV6HDR *ppIcmpv6Hdr,
    PWINDIVERT_TCPHDR *ppTcpHdr,
    PWINDIVERT_UDPHDR *ppUdpHdr,
    PVOID *ppData,
    UINT *pDataLen,
    PVOID *ppNext,
    UINT *pNextLen) {
    if (pfnWinDivertHelperParsePacket == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertHelperParsePacket(pPacket, packetLen, ppIpHdr, ppIpv6Hdr, 
        pProtocol, ppIcmpHdr, ppIcmpv6Hdr, ppTcpHdr, ppUdpHdr, ppData, pDataLen, ppNext, pNextLen);
}

BOOL WinDivertHelperCalcChecksums(
    VOID *pPacket,
    UINT packetLen,
    WINDIVERT_ADDRESS *pAddr,
    UINT64 flags) {
    if (pfnWinDivertHelperCalcChecksums == NULL) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }
    return pfnWinDivertHelperCalcChecksums(pPacket, packetLen, pAddr, flags);
}

UINT16 WinDivertHelperNtohs(UINT16 x) {
    if (pfnWinDivertHelperNtohs == NULL) {
        // 回退实现
        return ((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8);
    }
    return pfnWinDivertHelperNtohs(x);
}

UINT16 WinDivertHelperHtons(UINT16 x) {
    if (pfnWinDivertHelperHtons == NULL) {
        // 回退实现
        return ((x & 0xFF00) >> 8) | ((x & 0x00FF) << 8);
    }
    return pfnWinDivertHelperHtons(x);
}

UINT32 WinDivertHelperNtohl(UINT32 x) {
    if (pfnWinDivertHelperNtohl == NULL) {
        // 回退实现
        return ((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) |
               ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24);
    }
    return pfnWinDivertHelperNtohl(x);
}

UINT32 WinDivertHelperHtonl(UINT32 x) {
    if (pfnWinDivertHelperHtonl == NULL) {
        // 回退实现
        return ((x & 0xFF000000) >> 24) | ((x & 0x00FF0000) >> 8) |
               ((x & 0x0000FF00) << 8) | ((x & 0x000000FF) << 24);
    }
    return pfnWinDivertHelperHtonl(x);
}