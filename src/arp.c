#ifndef __ARP_C__
#define __ARP_C__

#include <common.h>
#include <transport.h>
#include <arp.h>

typedef int32_t (*arp_req_timeout_callback_t)(void *context_data);

arp_ctx_t arp_ctx_g;

/********************************************************************
 * Extern Declaration
 *******************************************************************/
extern int32_t  db_exec_query(int8_t *sql_query);

extern int32_t  db_process_query_result(int32_t *row_count, 
                                        int32_t *column_count, 
                                        int8_t ***result);

extern uint32_t ip_str_to_int(int8_t *record);

extern int32_t   hex_dump(uint8_t *packet, uint32_t packet_len);

extern int write_eth_frame (int fd,
                            unsigned char *dst_mac,
                            unsigned char *packet, 
                            unsigned int packet_len);

extern uint32_t timer_set_timer(uint32_t sec, 
                                uint32_t micro_sec, 
                                void *ctx_data, 
                                timer_t tid);

extern timer_t timer_create_timer(arp_req_timeout_callback_t timeout_handler);

extern uint32_t dns_ip_to_ip_str(uint32_t ip_addr, uint8_t *ip_str);

extern int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length);

/********************************************************************
 * Function Definition
 ********************************************************************/
int32_t arp_request_timeout_callback(void *context_data) {

  arp_ctx_t *pArpCtx = &arp_ctx_g;
  fprintf(stderr, "Timer of 2sec expired\n");

  if(!memcmp(context_data, "INIT", 4)) {
    /*Build Request for ARP for getting MAC for provided DNS*/
    /*build and send ARP Request*/
    fprintf(stderr, "Sending ARP Request\n");
    arp_build_ARP_request(htonl(ip_str_to_int(pArpCtx->dns2_str))); 

  } else if (!memcmp(context_data, pArpCtx->dns1_str, strlen(pArpCtx->dns1_str))){
    /*Build and broadcast Destination not Rechable*/
    
  } else if(!memcmp(context_data, pArpCtx->dns2_str, strlen(pArpCtx->dns2_str))) {
    
  } else {
    /*Exception Handling*/
  }
 

}/*arp_request_timeout_callback*/


uint32_t arp_get_mac(uint8_t *eth_name, uint8_t *mac) {

  int16_t fd = -1;
  struct ifreq ifr;

  strncpy(ifr.ifr_name, eth_name, IFNAMSIZ);

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(ioctl(fd, SIOCGIFHWADDR, &ifr)) {
    fprintf(stderr, "%s:%d Getting MAC Failed\n", __FILE__, __LINE__);
  }

  memcpy((void *)mac, ifr.ifr_hwaddr.sa_data, 6);
  close(fd);
 
  return(strlen(mac));
}/*arp_get_mac*/

uint32_t arp_init(uint8_t *table_name, uint32_t dns1, uint32_t dns2) {

  arp_ctx_t *pArpCtx = &arp_ctx_g;
  uint8_t sql_query[256];
  int8_t record[2][16][32];
  int32_t row = 0;
  int32_t col = 0;


  memset((void *)&sql_query, 0, sizeof(sql_query));
  memset((void *)&record, 0, sizeof(record));

  snprintf(sql_query,
           sizeof(sql_query),
           "%s%s",
           "SELECT * FROM ",
           table_name);

  if(!db_exec_query(sql_query)) {

    if(!db_process_query_result(&row, &col, (int8_t ***)record)) {

      if(row) {
        memcpy((void *)pArpCtx->eth_name, record[0][0], strlen(record[0][0]));
        memcpy((void *)pArpCtx->ip_str,   record[0][1], strlen(record[0][1]));
        /*Get the MAC Address*/
        arp_get_mac(pArpCtx->eth_name, pArpCtx->mac);
        pArpCtx->ip_addr = ntohl(ip_str_to_int((int8_t *)pArpCtx->ip_str));
      }      
    }
  }

  dns_ip_to_ip_str(dns1, pArpCtx->dns1_str);
  dns_ip_to_ip_str(dns2, pArpCtx->dns2_str);
 
#if 0 
  /*Create the Timer*/
  pArpCtx->arp_req_tid = timer_create_timer(arp_request_timeout_callback);

  timer_set_timer(20/*seconds*/, 
                  0/*nano seconds*/, 
                  "INIT" /*Context*/, 
                  pArpCtx->arp_req_tid);
#endif
}/*arp_init*/

uint32_t arp_process_ARP_reply(uint32_t fd, 
                               uint8_t *packet_ptr, 
                               uint16_t packet_length) {
  uint8_t sql_query[256];
  uint8_t record[2][16][32];
  int32_t row;
  int32_t col;

  uint8_t mac_str[16];
  uint8_t ip_str[16];
  uint32_t ip_addr;
  

  struct eth *eth_ptr = (struct eth *)packet_ptr;
  struct arp *arp_ptr = (struct arp *)&packet_ptr[sizeof(struct eth)];

  ip_addr = arp_ptr->ar_sender_ip;

  snprintf(ip_str,
           sizeof(ip_str),
           "%d.%d.%d.%d", 
           (ip_addr & 0xFF),
           (ip_addr >>  8) & 0xFF,
           (ip_addr >> 16) & 0xFF,
           (ip_addr >> 24) & 0xFF);
  
  snprintf(mac_str,
           sizeof(mac_str),
           "%X:%X:%X:%X:%X:%X",
           eth_ptr->h_source[0],
           eth_ptr->h_source[1],
           eth_ptr->h_source[2],
           eth_ptr->h_source[3],
           eth_ptr->h_source[4],
           eth_ptr->h_source[5]);

  snprintf(sql_query,
           sizeof(sql_query),
           "%s%s%s%s%s%s%s",
           "SELECT * from arp_cache_table WHERE (ip='",
           ip_str,
           "'",
           " AND ",
           "mac='",
           mac_str,
           "')"); 

  if(!db_exec_query(sql_query)) {
  
    memset((void *)record, 0, sizeof(record));
    if(!db_process_query_result(&row, &col, (int8_t ***)record)) {

      if(!row) {
        memset((void *)&sql_query, 0, sizeof(sql_query));
        
        snprintf(sql_query, 
                 sizeof(sql_query),
                 "%s%s%s%s%s%s%s",
                 "INSERT INTO arp_cache_table (ip, mac, ttl, time_stamp) VALUES ('",
                 ip_str,
                 "','",
                 mac_str,
                 "','",
                 "120',",
                 "NULL)");
       
        if(db_exec_query(sql_query)) {
          fprintf(stderr, "Failed to execute the Query %s\n", sql_query);
          exit(0);
        }
      }
    }
  }
  
}/*arp_process_ARP_reply*/


uint32_t arp_build_ARP_request(uint32_t dest_ip) {

  int32_t  fd;
  uint8_t  packet[500];
  uint16_t packet_length;
  int32_t  ret = -1;

  arp_ctx_t *pArpCtx = &arp_ctx_g;

  //uint8_t  bmac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  //uint8_t  bmac[6] = {0x60, 0x67, 0x20, 0x40, 0xFC, 0xE2};
  uint8_t  bmac[6] = {0x76, 0x4e, 0x90, 0x1A, 0x88, 0x64};
  struct eth *eth_rsp_ptr = (struct eth *)packet;
  struct arp *arp_rsp_ptr = (struct arp *)&packet[sizeof(struct eth)];

  packet_length = sizeof(struct eth) + sizeof(struct arp);

  /*RAW ethernet Socket*/ 
  fd = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL));

  /*Destination MAC*/
  memcpy((void *)eth_rsp_ptr->h_dest, bmac, 6);
  /*Source MAC*/
  memcpy((void *)eth_rsp_ptr->h_source, pArpCtx->mac, 6);
 
  /*Ether Net Protocol*/
  eth_rsp_ptr->h_proto = htons(ETH_P_ARP); 
  
  /*ARP Header*/
  arp_rsp_ptr->ar_pro    = htons(0x0800);
  arp_rsp_ptr->ar_hrd    = htons(0x0001);
  arp_rsp_ptr->ar_opcode = htons(ARP_REQUEST);
  arp_rsp_ptr->ar_plen   = 4;
  arp_rsp_ptr->ar_hlen   = 6;

  memcpy((void *)arp_rsp_ptr->ar_sender_ha, pArpCtx->mac, 6);
  arp_rsp_ptr->ar_sender_ip = htonl(pArpCtx->ip_addr);

  memset((void *)arp_rsp_ptr->ar_target_ha, 0, 6) ;
  arp_rsp_ptr->ar_target_ip = htonl(dest_ip);

  fprintf(stderr, "This is ARP REQUEST\n");
  hex_dump(packet, packet_length);

  ret = write_eth_frame(fd, 
                        (unsigned char *)eth_rsp_ptr->h_dest, 
                        packet, 
                        packet_length);
  //ret = tun_write(packet, packet_length);

  if(ret < 0) {
    fprintf(stderr, "tun_write error ret is %d\n", ret);
    perror("The Error is ");
  }
  close(fd);
  
}/*arp_build_ARP_request*/

int arp_process_ARP_request(int32_t fd, char *packet_ptr, unsigned int packet_length) {

  arp_ctx_t *pArpCtx = &arp_ctx_g;
  uint8_t  packet[1500];
  uint8_t mac[6];
  
  memset((void *)packet, 0, sizeof(packet));
  memset((void *)mac, 0, sizeof(mac));

  struct eth *eth_rsp_ptr = (struct eth *)packet;
  struct arp *arp_rsp_ptr = (struct arp *)&packet[sizeof(struct eth)];

  struct arp *arp_ptr = (struct arp *)&packet_ptr[sizeof(struct eth)];
  struct eth *eth_ptr = (struct eth *)packet_ptr;
   
  /*destination MAC*/  
  memcpy((void *)eth_rsp_ptr->h_dest,   eth_ptr->h_source, arp_ptr->ar_hlen);
  /*source MAC*/
  memcpy((void *)eth_rsp_ptr->h_source, pArpCtx->mac, arp_ptr->ar_hlen);

  /*proto of ethernet, i.e. ARP*/
  eth_rsp_ptr->h_proto = eth_ptr->h_proto;

  
  /*ARP Header Preparation*/

  /*HDR - Hardware Type*/
  arp_rsp_ptr->ar_pro    = arp_ptr->ar_pro;
  arp_rsp_ptr->ar_hrd    = arp_ptr->ar_hrd;
  arp_rsp_ptr->ar_opcode = htons(ARP_REPLY);
  arp_rsp_ptr->ar_plen   = arp_ptr->ar_plen;
  arp_rsp_ptr->ar_hlen   = arp_ptr->ar_hlen;
  

  /*SHA - Source Hardware Address*/
  memcpy((void *)arp_rsp_ptr->ar_sender_ha, pArpCtx->mac, arp_ptr->ar_hlen);
  /*SPA - Source Protocol Address (IP Address)*/
  arp_rsp_ptr->ar_sender_ip = htonl(pArpCtx->ip_addr);

  /*THA - Target Hardware Address*/
  memcpy((void *)arp_rsp_ptr->ar_target_ha, eth_ptr->h_source, arp_ptr->ar_hlen);

  /*TPA - Target Protocol Address (IP Address)*/
  arp_rsp_ptr->ar_target_ip = arp_ptr->ar_sender_ip;

  /*Sending Packet to the peer*/ 
  write_eth_frame(fd, (unsigned char *)eth_rsp_ptr->h_dest, packet, packet_length);
 
}/*arp_process_ARP_request*/

uint32_t arp_process_ARP(int32_t fd, 
                         int8_t *packet_ptr, 
                         uint16_t packet_length) {

  arp_ctx_t *pArpCtx = &arp_ctx_g;

  /*Is ARP is for our Machine, check the destination IP*/
  struct arp *arphdr_ptr = (struct arp *)&packet_ptr[sizeof(struct eth)];

  if (ARP_REQUEST == ntohs(arphdr_ptr->ar_opcode)) {
    /*Is ARP for our IP*/
    if (ntohl(arphdr_ptr->ar_target_ip) == pArpCtx->ip_addr) {
      /*Prepare ARP Reply*/
      arp_process_ARP_request(fd, packet_ptr, packet_length);
       
    } else if(!memcmp((void *)arphdr_ptr->ar_sender_ha, (void *)pArpCtx->mac, 6)) {
      /*Pass it on*/ 
      fprintf(stderr, "\nSelf Broadcast ARP Packet is Received (Ignore) for other"
                      " IP Addr is 0x%X\n", 
                      ntohl(arphdr_ptr->ar_target_ip));
    } 
  } else if(ARP_REPLY == ntohs(arphdr_ptr->ar_opcode)) {
    fprintf(stderr, "\n Got the ARP Reply"); 
    arp_process_ARP_reply(fd, packet_ptr, packet_length);
  } 
}/*arp_process_ARP*/

#endif
