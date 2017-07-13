#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
typedef struct ether_header{
  uint8_t eth_dest[16];
  uint8_t eth_source[16];
  uint16_t ether_type;
}eth;
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

  /* Define the device */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return(2);
  }
  /* Find the properties for the device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }
  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
  pcap_loop(handle, 1, packet_handler, NULL);
  pcap_close(handle);
  return 0;
}
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data){
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
    print_ip((struct ip)(ip->source_ip));
    printf(":%d\n",ntohs(tcp->source_port));  
    printf("Dest IP :");
    print_ip((struct ip)(ip->dest_ip));
    printf(":%d\n",ntohs(tcp->dest_port));
    uint8_t i;
    for(i=55; (i<header->caplen+1); i++){
         if((pkt_data[i-1]>=33) && (pkt_data[i-1]<=126)) // 아스키코드만 출력
              printf(" %c", pkt_data[i-1]);
         else
              printf(".");
    }
    puts("\n");
  }
  printf("=========================\n");
}
void print_mac(mac_addr * dat){
  printf("%x:%x:%x:%x:%x:%x",dat->bytes[0],dat->bytes[1],dat->bytes[2],dat->bytes[3],dat->bytes[4],dat->bytes[5]);
  puts("\n");
  return;
}
void print_ip(struct ip dat){
  printf("%d.%d.%d.%d",dat.bytes[0],dat.bytes[1],dat.bytes[2],dat.bytes[3]);
  return;
}
