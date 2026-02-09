#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
//#pragma comment(lib, "icmp.lib") 





//오류 메세지 출력
static void die(const char* msg) 
{
    printf("ERROR: %s (GetLastError=%lu)\n", msg, GetLastError());
}
// IPv4 주소 구조체를 uint32_t 빅엔디언 값으로 변환
static uint32_t ipv4_to_u32_be(const IN_ADDR* a) 
{
    return a->S_un.S_addr;
}

// 빅엔디언 <-> 호스트 엔디언 변환 [CPU 개별에 따라 다름]
static uint32_t u32_be_to_host(uint32_t be) {
    return ntohl(be);
}


static uint32_t host_to_u32_be(uint32_t host) 
{
    return htonl(host);
}

static void ip_to_str(uint32_t ip_be, char* out, size_t outsz) {
    IN_ADDR a;
    a.S_un.S_addr = ip_be;
    inet_ntop(AF_INET, &a, out, (socklen_t)outsz);
}

static int is_usable_subnet(uint32_t ip_host, uint32_t mask_host) {
    // 너무 작은/이상한 마스크는 스킵 (예: /32, /31)
    if (mask_host == 0 || mask_host == 0xFFFFFFFFu) return 0;

    // 169.254.x.x(링크로컬)도 보통 제외
    uint8_t b1 = (uint8_t)((ip_host >> 24) & 0xFF);
    uint8_t b2 = (uint8_t)((ip_host >> 16) & 0xFF);
    if (b1 == 169 && b2 == 254) return 0;

    return 1;
}

static void print_mac(const BYTE* mac, ULONG macLen) {
    if (macLen == 0) { printf("-"); return; }
    for (ULONG i = 0; i < macLen; i++) {
        if (i) printf("-");
        printf("%02X", mac[i]);
    }
}

static int reverse_dns_hostname(DWORD ip_be, char* host, size_t hostsz)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_be; // 네트워크 바이트 오더 그대로

    // NI_NAMEREQD: 이름이 없으면 실패 처리 (IP 문자열로 대체하지 않음)
    // NI_NOFQDN: FQDN이더라도 호스트 부분만 원할 때 사용 가능(옵션)
    int flags = NI_NAMEREQD; // | NI_NOFQDN;

    int r = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
        host, (DWORD)hostsz,
        NULL, 0,
        flags);
    return (r == 0) ? 1 : 0;
}

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        die("WSAStartup failed");
        return 1;
    }

    // ICMP 핸들 
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        die("IcmpCreateFile failed");  
        WSACleanup();
        return 1;
    }

    // 어댑터 목록 조회 (IPv4만)
    ULONG bufLen = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |GAA_FLAG_SKIP_DNS_SERVER, NULL, NULL, &bufLen);

    IP_ADAPTER_ADDRESSES* addrs = (IP_ADAPTER_ADDRESSES*)malloc(bufLen);
    if (!addrs) {
        die("malloc failed");
        IcmpCloseHandle(hIcmp);
        WSACleanup();
        return 1;
    }

    DWORD ga = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |GAA_FLAG_SKIP_DNS_SERVER, NULL, addrs, &bufLen);
    if (ga != NO_ERROR) {
        printf("ERROR: GetAdaptersAddresses failed (ret=%lu)\n", ga);
        free(addrs);
        IcmpCloseHandle(hIcmp);
        WSACleanup();
        return 1;
    }

    // 각 NIC / 각 IPv4 주소별로 서브넷 스캔

    for (IP_ADAPTER_ADDRESSES* aa = addrs; aa; aa = aa->Next) {
        // 다운된 어댑터 스킵
        if (aa->OperStatus != IfOperStatusUp) continue;

        // Loopback 스킵
        if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (IP_ADAPTER_UNICAST_ADDRESS* ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr) continue;
            if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;

            SOCKADDR_IN* sin = (SOCKADDR_IN*)ua->Address.lpSockaddr;
            IN_ADDR ip = sin->sin_addr;

            // PrefixLength -> mask 계산
            ULONG prefix = ua->OnLinkPrefixLength; // 0~32
            if (prefix > 32) continue;
            uint32_t mask_host = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
            uint32_t ip_host = u32_be_to_host(ipv4_to_u32_be(&ip));

            if (!is_usable_subnet(ip_host, mask_host)) continue;

            uint32_t net_host = ip_host & mask_host;
            uint32_t bcast_host = net_host | (~mask_host);

            // 스캔 크기 제한 (너무 큰 대역은 폭주 방지)
            uint32_t hostCount = (bcast_host - net_host + 1);
            if (hostCount > 4096) {
                char ipStr[32];
                IN_ADDR a; a.S_un.S_addr = host_to_u32_be(ip_host);
                inet_ntop(AF_INET, &a, ipStr, sizeof(ipStr));
                printf("\n[NIC] %S\n", aa->FriendlyName);
                printf("  - IP=%s /%lu : subnet too large (%u addrs) -> skip\n",
                    ipStr, prefix, hostCount);
                continue;
            }

            char ipStr[32], maskStr[32];
            ip_to_str(host_to_u32_be(ip_host), ipStr, sizeof(ipStr));
            IN_ADDR m; m.S_un.S_addr = host_to_u32_be(mask_host);
            inet_ntop(AF_INET, &m, maskStr, sizeof(maskStr));

            printf("\n[NIC] %S\n", aa->FriendlyName);
            printf("  - IP=%s  MASK=%s  /%lu\n", ipStr, maskStr, prefix);

            // ICMP 요청 준비
            const char sendData[] = "scan";
            BYTE replyBuf[sizeof(ICMP_ECHO_REPLY) + 64] = { 0 };
            DWORD timeoutMs = 250; // 짧게

            // 네트워크/브로드캐스트/자기자신 제외하고 스캔
            for (uint32_t h = net_host + 1; h <= bcast_host - 1; h++) {
                if (h == ip_host) continue;

                DWORD ip_be = host_to_u32_be(h);

                DWORD ret = IcmpSendEcho(
                    hIcmp,
                    ip_be,
                    (LPVOID)sendData,
                    (WORD)sizeof(sendData) - 1,
                    NULL,
                    replyBuf,
                    sizeof(replyBuf),
                    timeoutMs
                );

                if (ret == 0) {
                    // timeout / filtered
                    continue;
                }

                PICMP_ECHO_REPLY rep = (PICMP_ECHO_REPLY)replyBuf;
                if (rep->Status != IP_SUCCESS) continue;

                // ARP로 MAC 조회
                ULONG macLen = 6;
                BYTE mac[8] = { 0 };
                DWORD arp = SendARP(rep->Address, 0, mac, &macLen);

                char foundIp[32];
                ip_to_str(rep->Address, foundIp, sizeof(foundIp));

                char host[256];
                int hasHost = reverse_dns_hostname(rep->Address, host, sizeof(host));


                printf("[UP ] %s  rtt=%lums  host=%s                           mac=", foundIp, rep->RoundTripTime, hasHost ? host : "-");
                    
                if (arp == NO_ERROR) print_mac(mac, macLen);
                else printf("(arp fail:%lu)", arp);
                printf("\n");
            }
        }
    }

    free(addrs);
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    return 0;
}
	
	

	
	

