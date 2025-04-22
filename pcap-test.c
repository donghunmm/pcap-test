#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

// 필요한 상수 정의
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
#define IPPROTO_TCP 6

// Ethernet 헤더 구조체
struct libnet_ethernet_hdr {
    u_int8_t ether_dhost[ETHER_ADDR_LEN]; //dst
    u_int8_t ether_shost[ETHER_ADDR_LEN]; //src
    u_int16_t ether_type;
};

// IPv4 헤더 구조체
struct libnet_ipv4_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u_int8_t ip_hl:4,      //header length
        ip_v:4;
#else
    u_int8_t ip_v:4,
        ip_hl:4;
#endif
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

// TCP 헤더 구조체
struct libnet_tcp_hdr {
    u_int16_t th_sport;
    u_int16_t th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    u_int8_t th_x2:4,
        th_off:4;
#else
    u_int8_t th_off:4,
        th_x2:4;
#endif
    u_int8_t th_flags;
    u_int16_t th_win;
    u_int16_t th_sum;
    u_int16_t th_urp;
};

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

// MAC 주소 출력 함수
void print_mac(const uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i != 5) printf(":");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // Ethernet 헤더 파싱
        struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*)packet;

        // IP 패킷인지 확인
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            continue;

        // IP 헤더 파싱
        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));

        // TCP 패킷인지 확인
        if (ip->ip_p != IPPROTO_TCP)
            continue;

        // IP 헤더 길이 계산 (4바이트 단위)
        int ip_header_len = (ip->ip_hl & 0x0f) * 4;

        // TCP 헤더 파싱
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)((u_char*)ip + ip_header_len);

        // TCP 헤더 길이 계산 (4바이트 단위)
        int tcp_header_len = ((tcp->th_off & 0x0f) * 4);

        // 페이로드 위치 계산
        u_char* payload = (u_char*)tcp + tcp_header_len;

        // 페이로드 길이 계산
        int ip_total_len = ntohs(ip->ip_len);
        int payload_len = ip_total_len - ip_header_len - tcp_header_len;

        // 패킷 정보 출력
        printf("=======================================\n");

        // 1. Ethernet 헤더 정보 출력
        printf("Ethernet Src MAC: ");
        print_mac(eth->ether_shost);
        printf("\nEthernet Dst MAC: ");
        print_mac(eth->ether_dhost);
        printf("\n");

        // 2. IP 헤더 정보 출력
        printf("IP Src: %s\n", inet_ntoa(ip->ip_src));
        printf("IP Dst: %s\n", inet_ntoa(ip->ip_dst));

        // 3. TCP 헤더 정보 출력
        printf("TCP Src Port: %d\n", ntohs(tcp->th_sport));
        printf("TCP Dst Port: %d\n", ntohs(tcp->th_dport));

        // 4. 페이로드 데이터 출력 (최대 20바이트)
        printf("Payload (Max 20 bytes): ");
        for (int i = 0; i < payload_len && i < 20; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    }

    pcap_close(pcap);
    return 0;
}
