#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

#define IP_TEMP_SIZE 0x40
typedef struct ether_header eth;
typedef struct mac_addr{
  uint8_t bytes[6];
}mac_addr;
struct ip{
  uint8_t bytes[4];
};
typedef struct ip_header{
  uint8_t version_IHL;
  uint8_t tos; // Type of Service
  uint16_t total_length;
  uint16_t identi;
  uint16_t dummy; // IP Flag + Fragmnent Offset
  uint8_t ttl; // Time To Live
  uint8_t protocol;
  uint16_t checksum;
  struct ip source_ip;
  struct ip dest_ip;
  uint32_t ip_option;
}ip_header;
typedef struct tcp_header{
  uint16_t source_port;
  uint16_t dest_port;
  uint32_t seq_number;
  uint32_t ack_number;
  uint16_t dummy; // Offset + Reserved + TCP Flags
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_p;
  uint32_t tcp_option;
}tcp_header;
typedef struct udp_header{
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
}udp_header;
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data);
void print_mac(mac_addr * dat);
void print_ip(struct ip dat);
int main(int argc, char *argv[])
{
  pcap_t *handle;     /* Session handle */
  char *dev;      /* The device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
  struct bpf_program fp;    /* The compiled filter */
  char filter_exp[] = "port 80";  /* The filter expression */
  bpf_u_int32 mask;   /* Our netmask */
  bpf_u_int32 net;    /* Our IP */
  struct pcap_pkthdr header;  /* The header that pcap gives us */
  const u_char *packet;   /* The actual packet */
  /* Open the session in promiscuous mode */
  handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return(2);
  }
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }
  /* Grab a packet */
  pcap_loop(handle, atoi(argv[2]), packet_handler, NULL);
  pcap_close(handle);
  return 0;
}
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data){
  eth* eptr = (eth*) pkt_data;
  char * ip_tmp1 = (char *)malloc(IP_TEMP_SIZE);
  char * ip_tmp2 = (char *)malloc(IP_TEMP_SIZE);
  if(ntohs(eptr->ether_type) == ETHERTYPE_IP){
    ip_header * ip = (ip_header*) (pkt_data + 14);
    uint8_t ip_length = (ip->version_IHL&0xf)<<2;
    mac_addr * source_mac = (mac_addr *)(pkt_data);
    mac_addr * dest_mac = (mac_addr *)(pkt_data + 6);
    printf("=========================\n");
    printf("Source MAC :");
    print_mac(source_mac);
    printf("Dest MAC :");
    print_mac(dest_mac);
    if(ip->protocol == 6){ // TCP
      tcp_header * tcp = (tcp_header*)(ip+ip_length);
      printf("Source IP :");
      inet_ntop(AF_INET,(void*)(&ip->source_ip),ip_tmp1,IP_TEMP_SIZE);
      printf("%s",ip_tmp1);
      printf(":%d\n",ntohs(tcp->source_port));  
      printf("Dest IP :");
      inet_ntop(AF_INET,(void*)(&ip->dest_ip),ip_tmp2,IP_TEMP_SIZE);
      printf("%s",ip_tmp2);
      printf(":%d\n",ntohs(tcp->dest_port));
      uint8_t i;
      pkt_data += sizeof(eth) + sizeof(ip_header) + sizeof(tcp_header);
      for(i=0; (i<header->len+1); i++){
           if((pkt_data[i]>=33) && (pkt_data[i]<=126)) // 아스키코드만 출력
                printf(" %c", pkt_data[i]);
           else
                printf(".");
      }
      puts("\n");
    }
    printf("=========================\n");
  }
  free(ip_tmp1);
  free(ip_tmp2);
}
void print_mac(mac_addr * dat){
  printf("%x:%x:%x:%x:%x:%x",dat->bytes[0],dat->bytes[1],dat->bytes[2],dat->bytes[3],dat->bytes[4],dat->bytes[5]);
  puts("\n");
  return;
}
