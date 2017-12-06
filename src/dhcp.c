#ifndef __DHCP_C__
#define __DHCP_C__

#include <type.h>
#include <common.h>
#include <transport.h>
#include <dhcp.h>

/*global instance creation*/
dhcp_ctx_t dhcp_ctx_g;


typedef int (*pFn) (int fd, unsigned char *pPacket, unsigned int packet_len);

/********************************************************************
 * Extern Declaration
 ********************************************************************/
extern int db_init(char  *db_conn_info[]);

extern int db_connect(void);

extern int db_exec_query(char  *sql_query);

extern int db_process_query_result(int32_t  *row_count, 
                                   int32_t  *column_count, 
                                   char     ***result);

extern int write_eth_frame (int fd,
                            unsigned char *dst_mac,
                            unsigned char *packet, 
                            unsigned int packet_len);

extern int open_eth(char *eth_name);

extern int hex_dump(uint8_t  *packet, 
                    uint16_t packet_len);

extern int net_main(pFn recv_cb, 
                    uint32_t time_in_sec, 
                    uint32_t time_in_ms);

extern int32_t net_setaddr(uint8_t *interface_name,
                           uint32_t ip_addr, 
                           uint32_t netmask_addr);

extern int dns_process_query(int16_t fd, 
                             uint8_t *packet_ptr, 
                             uint16_t packet_length);

extern uint32_t dns_init(uint8_t *table_name);

extern uint32_t arp_init(uint8_t *table_name, 
                         uint32_t dns1, 
                         uint32_t dns2);

extern uint32_t arp_process_ARP(int16_t fd, 
                                uint8_t *packet_ptr, 
                                uint16_t packet_length);

extern int32_t tun_main(uint8_t *src_ip_str, 
                        uint8_t *dest_ip_str, 
                        uint8_t *net_mask_str);

extern int32_t tun_get_tun_devname(uint8_t *tun_devname);

extern uint32_t dns_ip_to_ip_str(uint32_t ip_addr, uint8_t *ip_str);

extern int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length);

extern int32_t tun_read(uint8_t *packet_ptr, uint16_t *packet_length);

extern int32_t icmp_init(uint32_t dhcp_listen_addr, uint32_t next_hop_addr);

extern int32_t icmp_main(int16_t fd, uint8_t *packet_ptr, uint16_t packet_length);

extern int32_t nat_nat_init(uint8_t *interface_name,
                            uint32_t dhcp_server_ip,
                            uint32_t dns1,
                            uint32_t dns2);
/********************************************************************
 * Function Definition 
 ********************************************************************/
unsigned short dhcp_cksum(void *pkt_ptr, size_t pkt_len) {
  unsigned int sum = 0;
  const unsigned short *ipl = (unsigned short *)pkt_ptr;

  while(pkt_len > 1) {
    sum += *ipl++;

    if(sum & 0x80000000) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }

    pkt_len -= 2;
  }

  /*pkt_len is an odd*/ 
  if(pkt_len) {
    sum += (unsigned int) *(unsigned char *)ipl;
  }

  /*wrapping up into 2 bytes*/
  while(sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  /*1's complement*/ 
  return (~sum);
}/*dhcp_cksum*/

int dhcp_process_eth_frame(int fd, 
                           unsigned char *packet_ptr, 
                           unsigned int packet_length) {

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  /*broadcast MAC*/
  char bmac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  /*Pointer to IP Packet*/
  struct iphdr *iphdr_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];
  /*protocol could have any of value - 1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP*/
  struct udphdr *udphdr_ptr = (struct udphdr *)&packet_ptr[sizeof(struct eth) + 
                                                           sizeof(struct iphdr)];

  /*Pointer to Ethernet Packet*/
  struct eth *eth_hdr_ptr = (struct eth *)packet_ptr;
  if(ETH_P_IP == ntohs(eth_hdr_ptr->h_proto)) {

    /*Ethernet packet is followed by IP Packet*/
    if(!memcmp(eth_hdr_ptr->h_dest, bmac, ETH_ALEN)) {
      /*It's a broadcast Packet*/
      if(IP_UDP == iphdr_ptr->ip_proto) {

        /*Check whether it's DHCP packet or not based on destination port*/
        if((DHCP_SERVER_PORT == ntohs(udphdr_ptr->udp_dest_port)) &&
           (DHCP_CLIENT_PORT == ntohs(udphdr_ptr->udp_src_port))) {

          dhcp_packet_t *dhcp_ptr = (dhcp_packet_t *)&packet_ptr[sizeof(struct eth) + 
                                     sizeof(struct iphdr) + 
                                     sizeof(struct udphdr)];
          dhcp_option_t dhcp_option;
          /*subtracting the fixed part of DHCP header*/
          dhcp_option.len = ntohs(udphdr_ptr->udp_len) - sizeof(dhcp_packet_t);
          dhcp_option.option = (char *)malloc(dhcp_option.len);
           
          if(NULL == dhcp_option.option) {
            fprintf(stderr, "\nMalloc failed to allocate the memory");
            exit(0);
          }
     
          memset((void *)dhcp_option.option, 0, dhcp_option.len);
           
          dhcp_option.option =  (char *)&packet_ptr[sizeof(struct eth) + 
                                sizeof(struct iphdr)  + 
                                sizeof(struct udphdr) + 
                                sizeof(dhcp_packet_t) + 4 /*DHCP Cookie*/];

          dhcp_process_option(packet_ptr, 
                              packet_length, 
                              dhcp_option.option, 
                              dhcp_option.len);

          dhcp_process_request(fd, packet_ptr, packet_length);

        }
      } else if (IP_TCP == ntohs(iphdr_ptr->ip_proto)) {
        fprintf(stderr, "\nGot the TCP Packet\n");
        //dhcp_process_tcp_packet(packet_ptr, packet_length); 
      }
    } else if (!memcmp(eth_hdr_ptr->h_dest, pDhcpCtx->dhcp_server_mac, ETH_ALEN)) {

      if(IP_UDP == iphdr_ptr->ip_proto) {
        if(53 /*DNS PORT*/ == ntohs(udphdr_ptr->udp_dest_port)) {
          /*DNS Request*/
          dns_process_query(fd, packet_ptr, packet_length);
        } else {
          fprintf(stderr, "\nUDP Packet\n");
          //hex_dump(packet_ptr, packet_length);
          fprintf(stderr, "\n");
        }

      } else if(IP_TCP == iphdr_ptr->ip_proto) {
        fprintf(stderr, "TCP Packet has arrived\n");
        hex_dump(packet_ptr, packet_length);
        fprintf(stderr, "\n");

      } else if(IP_ICMP == iphdr_ptr->ip_proto) {
        /*PING Request*/
        fprintf(stderr, "Got the ICMP Packet\n");
        icmp_main(fd, packet_ptr, packet_length);
      }
    } else {
      /*Check for TCP Packets*/
      fprintf(stderr, "\npacket for Other MAC = %X:%X:%X:%X:%X:%X\n", 
                       eth_hdr_ptr->h_dest[0],
                       eth_hdr_ptr->h_dest[1],
                       eth_hdr_ptr->h_dest[2],
                       eth_hdr_ptr->h_dest[3],
                       eth_hdr_ptr->h_dest[4],
                       eth_hdr_ptr->h_dest[5]);
    }
  } else if (ETH_P_ARP == ntohs(eth_hdr_ptr->h_proto)) {
    arp_process_ARP(fd, packet_ptr, packet_length); 
  }
  
}/*dhcp_process_eth_frame*/


int dhcp_init(unsigned char *eth_name, unsigned char *dhcp_listen_ip) {
 
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  int fd = -1;
  struct ifreq ifr;

  strncpy(pDhcpCtx->dhcp_eth_name, eth_name, 16);
  memcpy((void *)pDhcpCtx->dhcp_server_ip.addr, dhcp_listen_ip, 4);

  memset((void *)&ifr, 0, sizeof(struct ifreq));
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, eth_name, IFNAMSIZ);

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  if(fd < 0) {
    fprintf(stderr, "Creation of fd failed\n");
    perror("fd:");
  }

  /*Retrieving MAC Address*/
  if(ioctl(fd, SIOCGIFHWADDR, &ifr)) {
    fprintf(stderr, "Getting MAC failed\n");
    perror("MAC:");
  }

  memcpy(pDhcpCtx->dhcp_server_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

  /*Remove ip configured to this interface*/
  net_setaddr(eth_name, 0, 0);
#if 0
  /*Retrieving IP Address*/
  if(ioctl(fd, SIOCGIFADDR, &ifr)) {
    fprintf(stderr, "Getting IP Address Failed\n");
    perror("IP ADDR:");
  }
  pDhcpCtx->dhcp_server_ip.ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
#endif

  close(fd);
  return(0);
     
}/*dhcp_init*/

unsigned int ip_str_to_int(char *record) {

  unsigned char ip_str[8][8];
  dhcp_ipaddr_t ip_addr;

  sscanf((const char *)record, 
          "%[^.].%[^.].%[^.].%s", 
          ip_str[0],
          ip_str[1],
          ip_str[2],
          ip_str[3]);

  ip_addr.addr[0] = (unsigned char)atoi(ip_str[0]);
  ip_addr.addr[1] = (unsigned char)atoi(ip_str[1]);
  ip_addr.addr[2] = (unsigned char)atoi(ip_str[2]);
  ip_addr.addr[3] = (unsigned char)atoi(ip_str[3]);

  return(ip_addr.ip_addr);
}/*ip_str_to_int*/

int dhcp_pre_init(char *mysql_server_ip, 
                  char *mysql_server_port, 
                  char *db_name, 
                  char *user_id, 
                  char *password) {

  char *mysql_info[] = {mysql_server_ip, db_name, user_id, password, mysql_server_port};
  int ret = -1;
  char sql_query[256];
  char record[2][16][32];
  int  row = 0;
  int  col = 0;

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  if(db_init(mysql_info)) {
    fprintf(stderr, "\ndb init failed");
    exit(0);
  }

  /*connecting to mysql server*/
  if(db_connect()) {
    fprintf(stderr, "\nmysql connection failed");
    exit(0);
  }

  /*executing the SQL Query for dhcp configuration*/
  memset((void *)&sql_query, 0, sizeof(sql_query));
  strcpy(sql_query, "SELECT * FROM dhcp_conf_table");
  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\nFailed to execute the SQL Query %s->", sql_query);
    exit(0);
  }

  memset((void *)record, 0, (2 * 16 * 32 * sizeof(char)));

  if(db_process_query_result(&row, &col, (char ***)record)) {
    fprintf(stderr, "\nSQL Query Result is unsuccessful");
    exit(0);
  }

  if(row) {
   memcpy((void *)&pDhcpCtx->dhcp_eth_name,    (void *)record[0][0], strlen((const char *)record[0][0]));
   memcpy((void *)&pDhcpCtx->dhcp_server_port, (void *)record[0][2], strlen((const char *)record[0][2]));
   pDhcpCtx->dhcp_server_ip.ip_addr = ip_str_to_int(record[0][1]);
  }

  /*executing the SQL Query for dhcp generic parameters)*/
  memset((void *)&sql_query, 0, sizeof(sql_query));
  strcpy(sql_query, "SELECT * FROM dhcp_generic_param_table");

  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\nFailed to execute the SQL Query %s->", sql_query);
    exit(0);
  }
 
  memset((void *)record, 0, (2 * 16 * 32 * sizeof(char)));

  if(db_process_query_result(&row, &col, (char ***)record)) {
    fprintf(stderr, "\nSQL Query Result is unsuccessful");
    exit(0);
  }

  if(row) {
    pDhcpCtx->subnet_mask.ip_addr    = ip_str_to_int(record[0][0]);
    pDhcpCtx->dhcp_gw_ip.ip_addr     = ip_str_to_int(record[0][1]);
    pDhcpCtx->dns1.ip_addr           = ip_str_to_int(record[0][2]);
    pDhcpCtx->dns2.ip_addr           = ip_str_to_int(record[0][3]);
    pDhcpCtx->time_server_ip.ip_addr = ip_str_to_int(record[0][4]);
    pDhcpCtx->ntp_server_ip.ip_addr  = ip_str_to_int(record[0][5]);

    memcpy((void *)pDhcpCtx->host_name,   (void *)record[0][6], strlen((const char *)record[0][6]));
    memcpy((void *)pDhcpCtx->domain_name, (void *)record[0][7], strlen((const char *)record[0][7]));
  }

  return(0);
}/*dhcp_pre_init*/




int dhcp_process_option(char *packet_ptr, 
                        unsigned int packet_length, 
                        unsigned char *option_ptr, 
                        int   option_len) {
  int offset             = 0;
  unsigned int idx       = 0;
  unsigned short int len = 0;

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  while (option_len > 0) {

    switch (option_ptr[offset]) {
      case DHCP_OPTION_END:
        /*Optional tag ends here and exit the while loop*/
        option_len = 0;
        break;

      default:
        pDhcpCtx->opt_tag.tag[idx].tag = option_ptr[offset++];
        pDhcpCtx->opt_tag.tag[idx].len = option_ptr[offset++];
        /*Value Part*/
        memcpy((void *)pDhcpCtx->opt_tag.tag[idx].value, (void *)&option_ptr[offset], pDhcpCtx->opt_tag.tag[idx].len);
        offset += pDhcpCtx->opt_tag.tag[idx].len;

        option_len -= (1/*1 octet for tag*/ + 
                       1/*1 octet for len*/ + 
                       pDhcpCtx->opt_tag.tag[idx].len /* number of octets in value*/);
        idx += 1;
        break;
    }
  }

  /*Total number of optional tags present*/
  pDhcpCtx->opt_tag.tag_count = idx;

  /*success*/
  return(idx); 
}/*dhcp_process_option*/

char dhcp_is_two_way_handshake(void) {
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  int idx = 0;

  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {
    if(DHCP_OPTION_RAPID_COMMIT == pDhcpCtx->opt_tag.tag[idx].tag) {
      return(1);
    }
  }
  return(0);

}/*dhcp_is_two_way_handshake*/


int dhcp_process_request(int fd, 
                         unsigned char *packet_ptr, 
                         unsigned int packet_length) {
  int idx = 0;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  for (idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    switch (pDhcpCtx->opt_tag.tag[idx].tag) {
      case DHCP_OPTION_MESSAGE_TYPE:

        if(DHCPDISCOVER == pDhcpCtx->opt_tag.tag[idx].value[0]) {

          if(dhcp_is_two_way_handshake()) {
            /*Prepare DHCPACK message*/
            dhcp_ACK(fd, packet_ptr, packet_length);
          } else {
            /*Prepare DHCPOFFER message*/
            dhcp_OFFER(fd, packet_ptr, packet_length);
          }
 
        } else if (DHCPREQUEST == pDhcpCtx->opt_tag.tag[idx].value[0]) {
          /*Prepare DHCPACK message*/
          dhcp_ACK(fd, packet_ptr, packet_length);

        } else if (DHCPDECLINE == pDhcpCtx->opt_tag.tag[idx].value[0]) {
          /*Prepare DHCPACK message*/
          dhcp_ACK(fd, packet_ptr, packet_length);
        } 
      break;

      case DHCP_OPTION_END:
      default:
        /*Controlling the for loop*/
        idx = pDhcpCtx->opt_tag.tag_count;
        break;
    } 
  }

  return(idx); 
}/*dhcp_process_request*/


int dhcp_OFFER (int fd, unsigned char *packet_ptr, unsigned int packet_length) {
  int rsp_len = -1;
  unsigned char rsp_buffer[1500];
  unsigned char dhcp_message_type = (unsigned char)DHCPOFFER;
  
  memset((void *)rsp_buffer, 0, 1500);
  rsp_len = dhcp_build_rsp(dhcp_message_type, rsp_buffer, packet_ptr, packet_length);
  
  if (rsp_len > 0) {
    rsp_len = write_eth_frame(fd, 
                              (unsigned char *)((struct eth *)rsp_buffer)->h_dest, 
                              rsp_buffer, 
                              rsp_len); 
  }
  
  return(rsp_len);
}/*dhcp_OFFER*/


int dhcp_ACK (int fd, unsigned char *packet_ptr, unsigned int packet_length) {
  int rsp_len = -1;
  unsigned char rsp_buffer[1500];
  unsigned char dhcp_message_type = (unsigned char)DHCPACK;
  
  memset((void *)rsp_buffer, 0, 1500);

  rsp_len = dhcp_build_rsp(dhcp_message_type, rsp_buffer, packet_ptr, packet_length);

  hex_dump(rsp_buffer, rsp_len);
 
  if (rsp_len > 0) {
    rsp_len = write_eth_frame(fd, 
                              (unsigned char *)((struct eth *)rsp_buffer)->h_dest, 
                              rsp_buffer,
                              rsp_len); 
  }
  
  return(rsp_len);
}/*dhcp_ACK*/


int dhcp_NACK (int fd, unsigned char *packet_ptr, unsigned int packet_length) {
  int rsp_len = -1;
  unsigned char rsp_buffer[1500];
  unsigned char dhcp_message_type = (unsigned char)DHCPNACK;
  
  memset((void *)rsp_buffer, 0, 1500);

  rsp_len = dhcp_build_rsp(dhcp_message_type, rsp_buffer, packet_ptr, packet_length);
 
  if (rsp_len > 0) {
    rsp_len = write_eth_frame(fd,
                              (unsigned char *)((struct eth *)rsp_buffer)->h_dest, 
                              rsp_buffer, 
                              rsp_len); 
  }
  
  return(rsp_len);
}/*dhcp_NACK*/


int dhcp_populate_dhcp_options(char dhcp_message_type, 
                               char *rsp_ptr, 
                               unsigned int dhcp_option_offset) {

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  int idx = 0;
  int inner_idx = 0;
  unsigned char dhcp_cookie[] = {0x63, 0x82, 0x53, 0x63};

  /*Fill DHCP Cookie*/
  memcpy((void *)&rsp_ptr[dhcp_option_offset], dhcp_cookie, 4);
  dhcp_option_offset += 4; 

  /*Fill Message Type*/
  rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_MESSAGE_TYPE;
  rsp_ptr[dhcp_option_offset++] = 1;
  rsp_ptr[dhcp_option_offset++] = dhcp_message_type;
  
  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    switch(pDhcpCtx->opt_tag.tag[idx].tag) {

      case DHCP_OPTION_PARAMETER_REQUEST_LIST: 

        for(inner_idx = 0; inner_idx < pDhcpCtx->opt_tag.tag[idx].len; inner_idx++) {

          switch(pDhcpCtx->opt_tag.tag[idx].value[inner_idx]) {

            case DHCP_OPTION_SUBNET_MASK:
              rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_SUBNET_MASK;
              rsp_ptr[dhcp_option_offset++] = 4;
              memcpy((void *)&rsp_ptr[dhcp_option_offset], (void *)&pDhcpCtx->subnet_mask.addr, 4);
              dhcp_option_offset += 4;
            break;

            case DHCP_OPTION_ROUTER:
              rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_ROUTER;
              rsp_ptr[dhcp_option_offset++] = 4;
              memcpy((void *)&rsp_ptr[dhcp_option_offset], (void *)&pDhcpCtx->dhcp_gw_ip.addr, 4);
              dhcp_option_offset += 4;
            break;

            case DHCP_OPTION_TIME_SERVER:
            break;

            case DHCP_OPTION_DOMAIN_NAME_SERVER:
              rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_DOMAIN_NAME_SERVER;
              rsp_ptr[dhcp_option_offset++] = 4;
              memcpy((void *)&rsp_ptr[dhcp_option_offset], pDhcpCtx->dhcp_server_ip.addr, 4);
              dhcp_option_offset += 4;
              #if 0
              memcpy((void *)&rsp_ptr[dhcp_option_offset], (void *)&pDhcpCtx->dns1.addr, 4);
              dhcp_option_offset += 4;
              memcpy((void *)&rsp_ptr[dhcp_option_offset], (void *)&pDhcpCtx->dns2.addr, 4);
              dhcp_option_offset += 4;
              #endif
            break;

            case DHCP_OPTION_HOST_NAME:
              rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_HOST_NAME;
              rsp_ptr[dhcp_option_offset++] = strlen(pDhcpCtx->dhcp_server_name);
              memcpy((void *)&rsp_ptr[dhcp_option_offset], (void *)&pDhcpCtx->dhcp_server_name, strlen(pDhcpCtx->dhcp_server_name));
              dhcp_option_offset += strlen(pDhcpCtx->dhcp_server_name);
            break;

            case DHCP_OPTION_DOMAIN_NAME:
              rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_DOMAIN_NAME;
              rsp_ptr[dhcp_option_offset++] = strlen(pDhcpCtx->domain_name);
              memcpy((void *)&rsp_ptr[dhcp_option_offset], (void *)&pDhcpCtx->domain_name, strlen(pDhcpCtx->domain_name));
              dhcp_option_offset += strlen(pDhcpCtx->domain_name);
            break;

            case DHCP_OPTION_INTERFACE_MTU:
              rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_INTERFACE_MTU;
              rsp_ptr[dhcp_option_offset++] = 2;
              rsp_ptr[dhcp_option_offset++] = (1500 >> 8) & 0xFF;
              rsp_ptr[dhcp_option_offset++] = 1500  & 0xFF;
            break;

            case DHCP_OPTION_BROADCAST_ADDRESS:
            break;
            case DHCP_OPTION_NIS_DOMAIN:
            break;

            case DHCP_OPTION_NTP_SERVER:
              rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_NTP_SERVER;
              rsp_ptr[dhcp_option_offset++] = 4;
              memcpy((void *)&rsp_ptr[dhcp_option_offset], (void *)&pDhcpCtx->ntp_server_ip.addr, 4);
              dhcp_option_offset += 4;
            break;

            case DHCP_OPTION_REQUESTED_IP_ADDRESS:
            break;
            case DHCP_OPTION_IP_LEASE_TIME:
            break;
            case DHCP_OPTION_OPTION_OVERLOAD:
            break;
            case DHCP_OPTION_SERVER_IDENTIFIER:
            break;

            default:
            break;
          }
        }
      case DHCP_OPTION_AUTO_CONFIGURE:
        rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_AUTO_CONFIGURE;
        rsp_ptr[dhcp_option_offset++] = 1;
        rsp_ptr[dhcp_option_offset++] = 0x00;
      break;
        
      default:
      break;
    }       
  }

  rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_IP_LEASE_TIME;
  rsp_ptr[dhcp_option_offset++] = 4;
  rsp_ptr[dhcp_option_offset++] = 0x00;
  rsp_ptr[dhcp_option_offset++] = 0x00;
  rsp_ptr[dhcp_option_offset++] = 0xFF;
  rsp_ptr[dhcp_option_offset++] = 0xFF;

  rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_INTERFACE_MTU;
  rsp_ptr[dhcp_option_offset++] = 2;
  rsp_ptr[dhcp_option_offset++] = (1500 >> 8) & 0xFF;
  rsp_ptr[dhcp_option_offset++] = 1500  & 0xFF;

  rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_SERVER_IDENTIFIER;
  rsp_ptr[dhcp_option_offset++] = 4;
  memcpy((void *)&rsp_ptr[dhcp_option_offset], pDhcpCtx->dhcp_server_ip.addr, 4);
  dhcp_option_offset += 4;
  
  rsp_ptr[dhcp_option_offset++] = DHCP_OPTION_END;

  return (dhcp_option_offset); 
}/*dhcp_populate_dhcp_options*/

uint32_t dhcp_get_host_name(uint8_t *host_name) {
  uint32_t idx = 0;
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    if(DHCP_OPTION_HOST_NAME == pDhcpCtx->opt_tag.tag[idx].tag) {
      memcpy((void *)host_name, 
             (void *)pDhcpCtx->opt_tag.tag[idx].value, 
             pDhcpCtx->opt_tag.tag[idx].len);
      break;
    }
  }
 
  return(idx == pDhcpCtx->opt_tag.tag_count ? 0:1); 
}/*dhcp_get_host_name*/


uint32_t dhcp_is_dhcpc_requested_ip(uint32_t xid, uint8_t *mac_str, uint8_t *ip_str) {
  
  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  uint8_t  sql_query[512];
  int8_t   record[2][16][32]; 
  int32_t  row = 0;
  int32_t  col = 0;
  uint32_t idx = 0;
  uint8_t  ip_addr[4];
  uint8_t  host_name[255];

  memset((void *)ip_addr, 0, sizeof(ip_addr));
  for(idx = 0; idx < pDhcpCtx->opt_tag.tag_count; idx++) {

    if(DHCP_OPTION_REQUESTED_IP_ADDRESS == pDhcpCtx->opt_tag.tag[idx].tag) {
      memcpy((void *)ip_addr, 
             (void *)pDhcpCtx->opt_tag.tag[idx].value, 
             pDhcpCtx->opt_tag.tag[idx].len);
      break;
    }
  }
 
  /*did it hit the end*/ 
  if(idx == pDhcpCtx->opt_tag.tag_count) {
    return(0);
  }

  sprintf(ip_str, "%d.%d.%d.%d", 
                  ip_addr[0],
                  ip_addr[1],
                  ip_addr[2],
                  ip_addr[3]);

  memset((void *)&sql_query, 0, sizeof(sql_query));
  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "SELECT * FROM dhcp_ip_allocation_table WHERE (c_mac ="
           "%s%s%s%s%s",
           "'",
           mac_str,
           "') AND (c_ip_address ='",
           ip_str,
           "')");

  if(!db_exec_query(sql_query)) {
    
    memset((void *)record, 0, (2*16*32));
    /*Query is executed successfully*/
    if(db_process_query_result(&row, &col, (char ***)record)) {
      fprintf(stderr, "\nprocess query result is failed");
      exit(0);
    }
    
    if(row > 0) {
      /*Requested IP address can be allocated, proceed to it*/

       memset((void *)host_name, 0, sizeof(host_name));
       dhcp_get_host_name(host_name);

      /*Update the xid received from dhcp client*/
      memset((void *)sql_query, 0, sizeof(sql_query));
      snprintf((char *)sql_query,  
               sizeof(sql_query),  
               "UPDATE dhcp_ip_allocation_table SET "
               "%s%X%s%s%s%s%s",
               "c_xid='",
               xid,
               "',c_host_name = '",
               host_name,
               "', ip_assigned_status=\'ASSIGNED\' WHERE c_ip_address ='",
               record[0][2],
               "'");

      if(db_exec_query(sql_query)) {
        fprintf(stderr, "\nExecution of SQL query failed");
        exit(0);
      }

      return(1);
    }
  }

  /*Requested IP address can not be allocated*/
  return(0);
}/*dhcp_is_dhcpc_requested_ip*/

uint32_t dhcp_get_client_ip(uint32_t xid, uint8_t mac[6]) {

  char sql_query[512];
  char record[2][16][32]; 
  int  row = 0;
  int  col = 0;
  dhcp_ipaddr_t c_ip_addr;
  uint8_t mac_str[32];
  uint8_t ip_str[32];
  uint8_t host_name[255];


  memset((void *)record, 0, (2*16*32));

  memset((void *)mac_str, 0, sizeof(mac_str));
  snprintf((char *)mac_str, 
           sizeof(mac_str), 
           "%.2X%s%.2X%s%.2X%s%.2X%s%.2X%s%.2X",
           mac[0],
           ":",
           mac[1],
           ":",
           mac[2],
           ":",
           mac[3],
           ":",
           mac[4],
           ":",
           mac[5]);

  memset((void *)&ip_str, 0, sizeof(ip_str));

  /*check dhcpc - dhcp client has requested for specific IP address*/
  if(dhcp_is_dhcpc_requested_ip(xid, mac_str, (uint8_t *)ip_str)) {
    c_ip_addr.ip_addr = ip_str_to_int(ip_str);
    return(c_ip_addr.ip_addr);
  }
 
  memset((void *)&sql_query, 0, sizeof(sql_query));
  snprintf((char *)sql_query, 
           sizeof(sql_query),
           "SELECT * FROM dhcp_ip_allocation_table WHERE c_mac ="
           "%s%s%s",
           "'",
           mac_str,
           "' ");
             
  if(!db_exec_query(sql_query)) {

    /*Query is executed successfully*/
    if(db_process_query_result(&row, &col, (char ***)record)) {
      fprintf(stderr, "\nprocess query result is failed");
      exit(0);
    }
    
    if(row > 0) {
      /*A record is found*/
      c_ip_addr.ip_addr = ip_str_to_int(record[0][2]);
      return(c_ip_addr.ip_addr);
      
    }

    /*No result found for given query. Allocate the IP address now*/
    memset((void *)sql_query, 0, sizeof(sql_query));
    strcpy(sql_query, "SELECT * FROM dhcp_ip_allocation_table WHERE ip_assigned_status = \'FREED\'");

    if(db_exec_query(sql_query)) {
      fprintf(stderr, "\nExecution of query is failed - %s", sql_query);
      exit(0);  
    }

    memset((void *)record, 0, (2*16*32));

    if(db_process_query_result(&row, &col, (char ***)record)) {
      fprintf(stderr, "\nprocess query result is failed");
      exit(0);
    }

    /*Result is successful*/
    if(row > 0) {
      /*DHCP Client Host Name*/
      memset((void *)host_name, 0, sizeof(host_name));
      dhcp_get_host_name(host_name);

      /*Freed IP Address is found*/
      c_ip_addr.ip_addr = ip_str_to_int(record[0][2]);
     
     /*Table to mark that this ip address is allocated to dhcp client*/ 
      memset((void *)sql_query, 0, sizeof(sql_query));
      snprintf((char *)sql_query, 
               sizeof(sql_query), 
               "UPDATE dhcp_ip_allocation_table SET "
               "%s%s%s%s%X%s%s%s%s%s%s",
               "c_mac='",
               mac_str,
               "',",
               " c_xid='",
               xid,
               "',",
               " c_host_name='",
               host_name,
               "' , ip_assigned_status=\'ASSIGNED\' WHERE c_ip_address ='",
               record[0][2],
               "'");

      if(db_exec_query(sql_query)) {
        fprintf(stderr, "\nExecution of SQL query failed");
        exit(0);
      } 
      /*Return the allocated dhcp client ip address*/ 
      return(c_ip_addr.ip_addr);
    } 
  }
  return(-1);

}/*dhcp_get_client_ip*/


/*-----------------------------
 *|ethhdr|iphdr|udphdr|dhcphdr|
 *-----------------------------
 */
int dhcp_build_rsp (unsigned char  dhcp_message_type, 
                    unsigned char *rsp_ptr, 
                    unsigned char *packet_ptr, 
                    unsigned int   packet_length) {

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;
  unsigned int dhcp_option_offset = 0;
  int rsp_len = -1;
  unsigned char bmac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  unsigned char *pseudo_ptr = NULL;

  struct eth     *eth_ptr   = (struct eth  *)rsp_ptr;
  struct iphdr   *ip_ptr    = (struct iphdr   *)&rsp_ptr[sizeof(struct eth)];
  struct udphdr  *udp_ptr   = (struct udphdr  *)&rsp_ptr[sizeof(struct eth) + 
                                                         sizeof(struct iphdr)];
  struct dhcphdr *dhcp_ptr  = (struct dhcphdr *)&rsp_ptr[sizeof(struct udphdr) + 
                                                         sizeof(struct iphdr) + 
                                                         sizeof(struct eth)];

  /*dhcp request ptr*/
  struct dhcphdr *dhcp_req_ptr  = (struct dhcphdr *)&packet_ptr[sizeof(struct udphdr) + 
                                                                sizeof(struct iphdr) + 
                                                                sizeof(struct eth)];
  
  /*Fill MAC Header Data*/
  /*Response shall be Unicast*/
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)packet_ptr)->h_source, ETH_ALEN);
  memcpy((void *)eth_ptr->h_source, pDhcpCtx->dhcp_server_mac, ETH_ALEN);
  eth_ptr->h_proto = htons(ETH_P_IP);

  /*Fill IP Header*/
  ip_ptr->ip_ver     = 0x4;
  /*Length shall be multiple of 4. i.e. 5 X 4 = 20 bytes Header*/
  ip_ptr->ip_len     = 0x5;
  /*Type of service*/  
  ip_ptr->ip_tos     = 0x00;
  /*Value shall be Header Len + payload Len*/
  ip_ptr->ip_tot_len = 0x00;
  ip_ptr->ip_id      = htons(random()%65535);
  /*bit0 - R (Reserved), bit1 - DF (Don't Fragment), bit2 - MF (More Fragment)*/
  ip_ptr->ip_flag_offset     = htons(0x1 << 14);
  /*Maximum Number of Hops, At each hop, It's decremented by 1*/
  ip_ptr->ip_ttl     = 0x10;
  /*1 = ICMP; 2= IGMP; 6 = TCP; 17= UDP*/
  ip_ptr->ip_proto   = 0x11;
  /*Checksum will be computed latter*/
  ip_ptr->ip_chksum  = 0x00;
  /*Source IP Address*/
  ip_ptr->ip_src_ip  = pDhcpCtx->dhcp_server_ip.ip_addr;
  /*Destination IP Address*/
  
  if(0 == ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_src_ip) {

    memcpy((void *)&ip_ptr->ip_dest_ip, bmac, 4);
  } else {

    ip_ptr->ip_dest_ip = htonl(((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_src_ip);
  }
 
  /*Fill UDP Header*/
  udp_ptr->udp_src_port  = htons(67);
  udp_ptr->udp_dest_port = htons(68);
  udp_ptr->udp_len       = 0x00;
  udp_ptr->udp_chksum    = 0x00;  
  
  /*Preparing response based on requested options*/
   
  /*Fill DHCP Header*/
  /*1 = BOOTREQUEST, 2 = BOOTREPLY*/
  dhcp_ptr->dhcp_op     = 0x02;
  dhcp_ptr->dhcp_htype  = ETHERNET_10Mb;
  /*length of MAC address of ethernet*/
  dhcp_ptr->dhcp_hlen   = 0x6;

  /*after reaching at 5th router, this message is discarded*/
  dhcp_ptr->dhcp_hops   = 0x5;
  dhcp_ptr->dhcp_xid    = dhcp_req_ptr->dhcp_xid;
  dhcp_ptr->dhcp_secs   = 0x00;
  dhcp_ptr->dhcp_flags  = 0x00;

  /*This field will be filled by dhcp client*/
  dhcp_ptr->dhcp_ciaddr = htonl(0x00);

  /*Retrieve dhcp client IP assignment*/
  dhcp_ptr->dhcp_yiaddr = dhcp_get_client_ip(ntohl(dhcp_req_ptr->dhcp_xid), ((struct eth *)packet_ptr)->h_source);
  dhcp_ptr->dhcp_siaddr = 0x00;
  dhcp_ptr->dhcp_giaddr = 0x00;
  dhcp_ptr->dhcp_siaddr = pDhcpCtx->dhcp_server_ip.ip_addr;
  //dhcp_ptr->dhcp_giaddr = pDhcpCtx->dhcp_gw_ip.ip_addr;

  /*Copy Client MAC address*/
  memset((void *)&dhcp_ptr->dhcp_chaddr, 0, 16);
  memcpy((void *)&dhcp_ptr->dhcp_chaddr, ((struct eth *)packet_ptr)->h_source, ETH_ALEN);

  memset((void *)&dhcp_ptr->dhcp_sname, 0, 64);
  gethostname((char *)pDhcpCtx->dhcp_server_name, 64);
  memcpy((void *)dhcp_ptr->dhcp_sname, pDhcpCtx->dhcp_server_name, strlen(pDhcpCtx->dhcp_server_name));

  memset((void *)&dhcp_ptr->dhcp_file, 0, 128);

  /*Populating Options field of DHCP*/
  dhcp_option_offset = sizeof(struct dhcphdr) + 
                       sizeof(struct udphdr)  + 
                       sizeof(struct iphdr)   + 
                       sizeof(struct eth);

  /*dhcp message type*/ 
  rsp_len = dhcp_populate_dhcp_options(dhcp_message_type, 
                                       rsp_ptr, 
                                       dhcp_option_offset);

  /*Populating IP Header + payload Length and it's payload length*/
  ip_ptr->ip_tot_len = htons(rsp_len - sizeof(struct ethhdr));

  /*UDP Header + Payload length*/
  udp_ptr->udp_len    = htons(rsp_len - 
                              (sizeof(struct eth) + 
                               sizeof(struct iphdr)));
 
  ip_ptr->ip_chksum   = dhcp_cksum((void *)ip_ptr,  (sizeof(unsigned int) * ip_ptr->ip_len)); 

  /*Populating pseudo header for UDP csum calculation*/
  pseudo_ptr = (unsigned char *)malloc(rsp_len + 12);
  memset((void *)pseudo_ptr, 0, (rsp_len + 12));
  
  memcpy((void *)&pseudo_ptr[0], (void *)&ip_ptr->ip_dest_ip, 4);
  memcpy((void *)&pseudo_ptr[4], (void *)&ip_ptr->ip_src_ip, 4);

  /*It's padded with zero*/
  pseudo_ptr[8]  = 0;

  /*Protocol is UDP*/
  pseudo_ptr[9]  = 17;

  /*Length of UDP Header + it's payload (DHCP's Header + DHCP Options)*/
  pseudo_ptr[10] = (ntohs(udp_ptr->udp_len) >> 8) & 0xFF;
  pseudo_ptr[11] = ntohs(udp_ptr->udp_len) & 0xFF;

  memcpy((void *)&pseudo_ptr[12], 
         (void *)&rsp_ptr[sizeof(struct eth) + sizeof(struct iphdr)], 
         ((rsp_len + 12) - (sizeof(struct eth) + sizeof(struct iphdr))));
 
  udp_ptr->udp_chksum = dhcp_cksum((void *)pseudo_ptr, ((rsp_len + 12) - (sizeof(struct eth) + sizeof(struct iphdr))));

  free(pseudo_ptr);
  pseudo_ptr = NULL;

  return(rsp_len);
}/*dhcp_build_rsp*/


int dhcp_main(char *argv[]) {
  uint8_t ip_str[16];

  dhcp_ctx_t *pDhcpCtx = &dhcp_ctx_g;

  /*<START>*/
  /*MYSQL Database Connectivity and population of generic configuration*/
  dhcp_pre_init(argv[0] /*mysql_server_ip*/, 
                argv[1] /*mysql_server_port*/, 
                argv[2] /*db_name*/, 
                argv[3] /*user_id*/, 
                argv[4] /*password*/);

  dhcp_init(pDhcpCtx->dhcp_eth_name, 
            pDhcpCtx->dhcp_server_ip.addr);
  /*<END>*/

  /*<START>*/
  nat_nat_init(pDhcpCtx->dhcp_eth_name, 
               pDhcpCtx->dhcp_server_ip.ip_addr,
               pDhcpCtx->dns1.ip_addr,
               pDhcpCtx->dns2.ip_addr);
  /*<END>*/

  /*DHCP <--> TUN <--> WAN Interface*/
  memset((void *)&ip_str, 0, sizeof(ip_str));
  dns_ip_to_ip_str(pDhcpCtx->dhcp_server_ip.ip_addr, ip_str);
  tun_main(ip_str, ip_str, "255.255.255.0");

  /*<START>*/
  dns_init("dhcp_generic_param_table");
  /*<END>*/

  /*<START>*/
  /*Socket Interface*/
  open_eth(pDhcpCtx->dhcp_eth_name);

  /*<START>*/
  arp_init("dhcp_conf_table", 
           pDhcpCtx->dns1.ip_addr, 
           pDhcpCtx->dns2.ip_addr);
  /*<END>*/
  icmp_init(pDhcpCtx->dhcp_server_ip.ip_addr, ip_str_to_int("255.255.255.0"));
  /*Main Loop*/
  net_main(dhcp_process_eth_frame, 2, 0);  
  /*<END>*/

  return(0);
}/*dhcp_main*/

int main(int argc, char *argv[]) {
  dhcp_main((char **)&argv[1]);

  return(0);

}/*main*/

#endif
