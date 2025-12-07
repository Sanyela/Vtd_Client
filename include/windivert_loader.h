/*
 * windivert_loader.h
 * WinDivert 动态加载包装器
 */

#ifndef WINDIVERT_LOADER_H
#define WINDIVERT_LOADER_H

#include <windows.h>

// 定义 WinDivert 类型和常量（从 windivert.h 复制必要的定义）
typedef enum {
    WINDIVERT_LAYER_NETWORK = 0,
    WINDIVERT_LAYER_NETWORK_FORWARD = 1,
    WINDIVERT_LAYER_FLOW = 2,
    WINDIVERT_LAYER_SOCKET = 3,
    WINDIVERT_LAYER_REFLECT = 4,
} WINDIVERT_LAYER;

typedef enum {
    WINDIVERT_EVENT_NETWORK_PACKET = 0,
    WINDIVERT_EVENT_FLOW_ESTABLISHED = 1,
    WINDIVERT_EVENT_FLOW_DELETED = 2,
    WINDIVERT_EVENT_SOCKET_BIND = 3,
    WINDIVERT_EVENT_SOCKET_CONNECT = 4,
    WINDIVERT_EVENT_SOCKET_LISTEN = 5,
    WINDIVERT_EVENT_SOCKET_ACCEPT = 6,
    WINDIVERT_EVENT_SOCKET_CLOSE = 7,
    WINDIVERT_EVENT_REFLECT_OPEN = 8,
    WINDIVERT_EVENT_REFLECT_CLOSE = 9,
} WINDIVERT_EVENT;

typedef enum {
    WINDIVERT_SHUTDOWN_RECV = 0x1,
    WINDIVERT_SHUTDOWN_SEND = 0x2,
    WINDIVERT_SHUTDOWN_BOTH = 0x3,
} WINDIVERT_SHUTDOWN;

typedef enum {
    WINDIVERT_PARAM_QUEUE_LENGTH = 0,
    WINDIVERT_PARAM_QUEUE_TIME = 1,
    WINDIVERT_PARAM_QUEUE_SIZE = 2,
    WINDIVERT_PARAM_VERSION_MAJOR = 3,
    WINDIVERT_PARAM_VERSION_MINOR = 4,
} WINDIVERT_PARAM;

#define WINDIVERT_FLAG_SNIFF            0x0001
#define WINDIVERT_FLAG_DROP             0x0002
#define WINDIVERT_FLAG_RECV_ONLY        0x0004
#define WINDIVERT_FLAG_SEND_ONLY        0x0008
#define WINDIVERT_FLAG_NO_INSTALL       0x0010
#define WINDIVERT_FLAG_FRAGMENTS        0x0020

typedef struct {
    INT64  Timestamp;
    UINT32 Layer:8;
    UINT32 Event:8;
    UINT32 Sniffed:1;
    UINT32 Outbound:1;
    UINT32 Loopback:1;
    UINT32 Impostor:1;
    UINT32 IPv6:1;
    UINT32 IPChecksum:1;
    UINT32 TCPChecksum:1;
    UINT32 UDPChecksum:1;
    UINT32 Reserved1:8;
    UINT32 Reserved2;
    union {
        struct {
            UINT32 IfIdx;
            UINT32 SubIfIdx;
        } Network;
        struct {
            UINT64 EndpointId;
            UINT64 ParentEndpointId;
            UINT32 ProcessId;
            UINT32 LocalAddr[4];
            UINT32 RemoteAddr[4];
            UINT16 LocalPort;
            UINT16 RemotePort;
            UINT8  Protocol;
        } Flow;
        struct {
            UINT64 EndpointId;
            UINT64 ParentEndpointId;
            UINT32 ProcessId;
            UINT32 LocalAddr[4];
            UINT32 RemoteAddr[4];
            UINT16 LocalPort;
            UINT16 RemotePort;
            UINT8  Protocol;
        } Socket;
        struct {
            INT64  Timestamp;
            UINT32 ProcessId;
            UINT32 Layer:8;
            UINT32 Reserved1:24;
            UINT64 Flags;
            INT16  Priority;
        } Reflect;
        UINT8 Reserved3[64];
    };
} WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

typedef struct {
    UINT8  HdrLength:4;
    UINT8  Version:4;
    UINT8  TOS;
    UINT16 Length;
    UINT16 Id;
    UINT16 FragOff0;
    UINT8  TTL;
    UINT8  Protocol;
    UINT16 Checksum;
    UINT32 SrcAddr;
    UINT32 DstAddr;
} WINDIVERT_IPHDR, *PWINDIVERT_IPHDR;

typedef struct {
    UINT8  TrafficClass0:4;
    UINT8  Version:4;
    UINT8  FlowLabel0:4;
    UINT8  TrafficClass1:4;
    UINT16 FlowLabel1;
    UINT16 Length;
    UINT8  NextHdr;
    UINT8  HopLimit;
    UINT32 SrcAddr[4];
    UINT32 DstAddr[4];
} WINDIVERT_IPV6HDR, *PWINDIVERT_IPV6HDR;

typedef struct {
    UINT8  Type;
    UINT8  Code;
    UINT16 Checksum;
    UINT32 Body;
} WINDIVERT_ICMPHDR, *PWINDIVERT_ICMPHDR;

typedef struct {
    UINT8  Type;
    UINT8  Code;
    UINT16 Checksum;
    UINT32 Body;
} WINDIVERT_ICMPV6HDR, *PWINDIVERT_ICMPV6HDR;

typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT32 SeqNum;
    UINT32 AckNum;
    UINT16 Reserved1:4;
    UINT16 HdrLength:4;
    UINT16 Fin:1;
    UINT16 Syn:1;
    UINT16 Rst:1;
    UINT16 Psh:1;
    UINT16 Ack:1;
    UINT16 Urg:1;
    UINT16 Reserved2:2;
    UINT16 Window;
    UINT16 Checksum;
    UINT16 UrgPtr;
} WINDIVERT_TCPHDR, *PWINDIVERT_TCPHDR;

typedef struct {
    UINT16 SrcPort;
    UINT16 DstPort;
    UINT16 Length;
    UINT16 Checksum;
} WINDIVERT_UDPHDR, *PWINDIVERT_UDPHDR;

// 函数指针类型定义
typedef HANDLE (WINAPI *PFN_WinDivertOpen)(
    const char *filter,
    WINDIVERT_LAYER layer,
    INT16 priority,
    UINT64 flags);

typedef BOOL (WINAPI *PFN_WinDivertRecv)(
    HANDLE handle,
    PVOID pPacket,
    UINT packetLen,
    UINT *pRecvLen,
    WINDIVERT_ADDRESS *pAddr);

typedef BOOL (WINAPI *PFN_WinDivertRecvEx)(
    HANDLE handle,
    PVOID pPacket,
    UINT packetLen,
    UINT *pRecvLen,
    UINT64 flags,
    WINDIVERT_ADDRESS *pAddr,
    UINT *pAddrLen,
    LPOVERLAPPED lpOverlapped);

typedef BOOL (WINAPI *PFN_WinDivertSend)(
    HANDLE handle,
    const VOID *pPacket,
    UINT packetLen,
    UINT *pSendLen,
    const WINDIVERT_ADDRESS *pAddr);

typedef BOOL (WINAPI *PFN_WinDivertSendEx)(
    HANDLE handle,
    const VOID *pPacket,
    UINT packetLen,
    UINT *pSendLen,
    UINT64 flags,
    const WINDIVERT_ADDRESS *pAddr,
    UINT addrLen,
    LPOVERLAPPED lpOverlapped);

typedef BOOL (WINAPI *PFN_WinDivertShutdown)(
    HANDLE handle,
    WINDIVERT_SHUTDOWN how);

typedef BOOL (WINAPI *PFN_WinDivertClose)(
    HANDLE handle);

typedef BOOL (WINAPI *PFN_WinDivertSetParam)(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64 value);

typedef BOOL (WINAPI *PFN_WinDivertGetParam)(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64 *pValue);

typedef BOOL (WINAPI *PFN_WinDivertHelperParsePacket)(
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
    UINT *pNextLen);

typedef BOOL (WINAPI *PFN_WinDivertHelperCalcChecksums)(
    VOID *pPacket,
    UINT packetLen,
    WINDIVERT_ADDRESS *pAddr,
    UINT64 flags);

typedef UINT16 (WINAPI *PFN_WinDivertHelperNtohs)(UINT16 x);
typedef UINT16 (WINAPI *PFN_WinDivertHelperHtons)(UINT16 x);
typedef UINT32 (WINAPI *PFN_WinDivertHelperNtohl)(UINT32 x);
typedef UINT32 (WINAPI *PFN_WinDivertHelperHtonl)(UINT32 x);

#ifdef __cplusplus
extern "C" {
#endif

// 加载/卸载 WinDivert
BOOL WinDivertLoaderInit(void);
void WinDivertLoaderCleanup(void);
BOOL WinDivertLoaderIsLoaded(void);

// WinDivert API 包装函数
HANDLE WinDivertOpen(
    const char *filter,
    WINDIVERT_LAYER layer,
    INT16 priority,
    UINT64 flags);

BOOL WinDivertRecv(
    HANDLE handle,
    PVOID pPacket,
    UINT packetLen,
    UINT *pRecvLen,
    WINDIVERT_ADDRESS *pAddr);

BOOL WinDivertRecvEx(
    HANDLE handle,
    PVOID pPacket,
    UINT packetLen,
    UINT *pRecvLen,
    UINT64 flags,
    WINDIVERT_ADDRESS *pAddr,
    UINT *pAddrLen,
    LPOVERLAPPED lpOverlapped);

BOOL WinDivertSend(
    HANDLE handle,
    const VOID *pPacket,
    UINT packetLen,
    UINT *pSendLen,
    const WINDIVERT_ADDRESS *pAddr);

BOOL WinDivertSendEx(
    HANDLE handle,
    const VOID *pPacket,
    UINT packetLen,
    UINT *pSendLen,
    UINT64 flags,
    const WINDIVERT_ADDRESS *pAddr,
    UINT addrLen,
    LPOVERLAPPED lpOverlapped);

BOOL WinDivertShutdown(
    HANDLE handle,
    WINDIVERT_SHUTDOWN how);

BOOL WinDivertClose(
    HANDLE handle);

BOOL WinDivertSetParam(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64 value);

BOOL WinDivertGetParam(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64 *pValue);

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
    UINT *pNextLen);

BOOL WinDivertHelperCalcChecksums(
    VOID *pPacket,
    UINT packetLen,
    WINDIVERT_ADDRESS *pAddr,
    UINT64 flags);

UINT16 WinDivertHelperNtohs(UINT16 x);
UINT16 WinDivertHelperHtons(UINT16 x);
UINT32 WinDivertHelperNtohl(UINT32 x);
UINT32 WinDivertHelperHtonl(UINT32 x);

#ifdef __cplusplus
}
#endif

#endif // WINDIVERT_LOADER_H