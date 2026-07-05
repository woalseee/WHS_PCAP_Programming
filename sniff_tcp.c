#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // IP 타입인지 확인
    struct ipheader *ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));

    int ip_header_len = ip->iph_ihl * 4;

    printf("=======================================\n");
    printf(" Ethernet Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf(" Ethernet Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("       IP From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("         IP To: %s\n", inet_ntoa(ip->iph_destip));

    if (ip->iph_protocol != IPPROTO_TCP) {
        return;   // TCP만 처리, 나머지는 무시
    }
    printf("      Protocol: TCP\n");

    struct tcpheader *tcp = (struct tcpheader *)
                             ((u_char *)ip + ip_header_len);

    int tcp_header_len = TH_OFF(tcp) * 4;

    printf("     Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("     Dst Port: %d\n", ntohs(tcp->tcp_dport));

    int ip_total_len = ntohs(ip->iph_len);
    int http_len = ip_total_len - ip_header_len - tcp_header_len;

    if (http_len > 0) {
        char *http_msg = (char *)tcp + tcp_header_len;
        printf(" HTTP Message (%d bytes):\n", http_len);
        char buf[2048];
        int copy_len = http_len < 2047 ? http_len : 2047;
        memcpy(buf, http_msg, copy_len);
        buf[copy_len] = '\0';
        printf("%s\n", buf);
    } else {
        printf(" HTTP Message: (없음, TCP 제어 패킷으로 추정)\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp port 80";
  bpf_u_int32 net = 0;

  handle = pcap_open_live("enp0s8", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      fprintf(stderr, "장치를 열 수 없습니다: %s\n", errbuf);
      exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      pcap_perror(handle, "필터 컴파일 실패");
      exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) != 0) {
      pcap_perror(handle, "필터 적용 실패");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);
  return 0;
}