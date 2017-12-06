#ifndef __NAT_C__
#define __NAT_C__

#include <type.h>
#include <transport.h>
#include <common.h>
#include <nat.h>

/********************************************************************
 *
 *Extern Declaration
 ********************************************************************/
extern int db_process_query_result(int32_t *row_count, 
                                   int32_t *column_count, 
                                   int8_t ***result);

extern int db_exec_query(int8_t *sql_query);

extern unsigned short dhcp_cksum(void *pkt_ptr, size_t pkt_len);

extern int hex_dump(uint8_t  *packet, 
                    uint16_t packet_len);

/********************************************************************
 *
 * Global Instance
 ********************************************************************/
nat_ctx_t nat_ctx_g;

/********************************************************************
 *
 *Function Definition
 ********************************************************************/
int32_t nat_ip_to_ipstr(uint32_t ip_addr, uint8_t *ipaddr_str) {
  uint8_t tmp_buffer[32];
  int32_t ret = -1;

  memset((void *)tmp_buffer, 0, sizeof(tmp_buffer));

  ret = snprintf(tmp_buffer, sizeof(tmp_buffer),
                       "%d.%d.%d.%d",
                       (ip_addr >> 24) & 0xFF,
                       (ip_addr >> 16) & 0xFF,
                       (ip_addr >>  8) & 0xFF,
                       (ip_addr >>  0) & 0xFF);

  memcpy((void *)ipaddr_str, tmp_buffer, ret);
  //strcpy(ipaddr_str, tmp_buffer);
  return(0);

}/*nat_ip_to_ipstr*/

int32_t nat_ipstr_to_ip(uint8_t *ipaddr_str, uint32_t *ip_addr) {
  
  uint8_t tmp_buffer[4][8];
  int32_t ret = -1;

  memset((void *)tmp_buffer, 0, (4 * 8));

  sscanf(ipaddr_str, 
         "%[^.].%[^.].%[^.].%s",
         tmp_buffer[0],
         tmp_buffer[1],
         tmp_buffer[2],
         tmp_buffer[3]);

  *ip_addr = (atoi(tmp_buffer[0]) << 24) |
             (atoi(tmp_buffer[1]) << 16) |
             (atoi(tmp_buffer[2]) <<  8) |
             (atoi(tmp_buffer[3]) <<  0);
             
  return(0);

}/*nat_ipstr_to_ip*/

int32_t nat_mac_to_macstr(uint8_t *mac, uint8_t *mac_str) {
  uint8_t tmp_buffer[32];
  int32_t ret = -1;
 
  memset((void *)tmp_buffer, 0, sizeof(tmp_buffer)); 
  ret = snprintf(tmp_buffer, sizeof(tmp_buffer),
                 "%X:%X:%X:%X:%X:%X",
                 mac[0],
                 mac[1],
                 mac[2],
                 mac[3],
                 mac[4],
                 mac[5]);
             
   //memcpy((void *)mac_str, tmp_buffer, ret);
   strcpy(mac_str, tmp_buffer);
   return(0);
 
}/*nat_mac_to_macstr*/

int32_t nat_macstr_to_mac(uint8_t *mac_str, uint8_t *mac) {
  int32_t ret = -1;
 
  ret = sscanf(mac_str,
               "%X:%X:%X:%X:%X:%X",
               (uint32_t *)&mac[0],
               (uint32_t *)&mac[1],
               (uint32_t *)&mac[2],
               (uint32_t *)&mac[3],
               (uint32_t *)&mac[4],
               (uint32_t *)&mac[5]);
             
   return(0);
 
}/*nat_macstr_to_mac*/

int32_t nat_nat_init(uint8_t *interface_name,
                     uint32_t dhcp_server_ip,
                     uint32_t dns1,
                     uint32_t dns2) {

  int32_t fd;
  struct ifreq ifr;
  nat_ctx_t *pNatCtx = &nat_ctx_g;
 
  strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(fd < 0) {
    perror("creation of socket failed\n");
    return(-1);
  }

  /*Retrieving MAC Address*/
  if(ioctl(fd, SIOCGIFHWADDR, &ifr)) {
    perror("\nFailed while retrieving MAC Address\n");
    return(-2); 
  }
  memcpy((void *)pNatCtx->mac_addr, ifr.ifr_hwaddr.sa_data, 6);

  //pNatCtx->ip_addr = (uint32_t)((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr; 
  pNatCtx->ip_addr = dhcp_server_ip;
  nat_ip_to_ipstr(pNatCtx->ip_addr, (uint8_t *)pNatCtx->ip_addr_str);
  nat_mac_to_macstr(pNatCtx->mac_addr, pNatCtx->mac_str);
  strncpy(pNatCtx->interface_name, ifr.ifr_name, sizeof(pNatCtx->interface_name));
  pNatCtx->dns1 = dns1;
  pNatCtx->dns2 = dns2;
    
  return(0);
}/*nat_nat_init*/

int32_t nat_delete_from_cache(uint16_t nat_port) {
  uint8_t sql_query[255];
  int32_t ret = -1;

  ret = snprintf(sql_query, 
                 sizeof(sql_query), 
                 "DELETE FROM nat_cache_table where nat_port=%d",
                 nat_port);

  if(db_exec_query(sql_query)) {
    fprintf(stderr, "\n%s:%d::Deletion of entry failed\n", __FILE__, __LINE__);
    return(-1);
  }
  return(0);

}/*nat_delete_from_cache*/

int32_t nat_update_cache(uint32_t ipaddr, 
                         uint8_t *mac_addr, 
                         uint16_t src_port, 
                         uint16_t nat_port) {
  int32_t ret = -1;
  uint8_t sql_query[256];
  int32_t row;
  int32_t col;
  int8_t  record[2][16][32];
  uint8_t mac_str[32];
  uint8_t ipaddr_str[32];

  memset((void *)mac_str, 0, sizeof(mac_str));
  memset((void *)ipaddr_str, 0, sizeof(ipaddr_str));

  nat_ip_to_ipstr(ipaddr, ipaddr_str);
  nat_mac_to_macstr(mac_addr, mac_str);

 ret = snprintf(sql_query, 
                sizeof(sql_query),
                "SELECT * from nat_cache_table where (ip_address ='"
                "%s"
                "' AND mac_address ='"
                "%s"
                "' AND src_port ="
                "%d"
                " AND nat_port ="
                "%d"
                ")",
                ipaddr_str,
                mac_str,
                src_port,
                nat_port);

  if(db_exec_query((int8_t *)sql_query)) {
    fprintf(stderr, "\n%s:%d Execution of SQL Query Failed\n", __FILE__, __LINE__);
    return(-1);
  }

  memset((void *)&record, 0, 2*16*32);
  if(!db_process_query_result(&row, &col, (int8_t ***)record)) {

    /*Process The Reqult*/
    if(!row) {
      /*No Record found , Insert it*/
      memset((void *)&sql_query, 0, sizeof(sql_query));

      ret = snprintf(sql_query,
                    sizeof(sql_query),
                    "INSERT INTO nat_cache_table (ip_address, mac_address, src_port, nat_port) VALUES ("
                    "\'%s\',\'%s\',%d,%d"
                    ")",
                    ipaddr_str,
                    mac_str,
                    src_port,
                    nat_port);
      if(db_exec_query((int8_t *)sql_query)) {
        fprintf(stderr, "\n%s:%d Insertion to Database failed\n", __FILE__, __LINE__);
        return(-3);
      }
    }
  }
                
}/*nat_update_cache*/

int32_t nat_query_cache(uint16_t nat_port, 
                        uint32_t *ip_addr, 
                        uint8_t *mac_addr, 
                        uint16_t *src_port) {

  int32_t ret = -1;
  int32_t row;
  int32_t col;
  uint8_t record[2][16][32];
  uint8_t sql_query[256];
  uint8_t num_str[8];
  uint32_t tmp_port; 

  memset((void *)&sql_query, 0, sizeof(sql_query));

  ret = snprintf(sql_query, 
                 sizeof(sql_query),
                 "SELECT * from nat_cache_table where nat_port = %d",
                 nat_port);

  if(!db_exec_query((int8_t *)sql_query)) {
    
    memset((void *)&record, 0, 2*16*32);
    if(!db_process_query_result(&row, &col, (int8_t ***)record)) {
      if(row) {
        nat_ipstr_to_ip(record[0][0], ip_addr);
        nat_macstr_to_mac(record[0][1], mac_addr);
        memset((void *)num_str, 0, sizeof(num_str));
        strncpy(num_str, record[0][2], sizeof(num_str));
        sscanf((const char *)num_str, "%d", &tmp_port);
        *src_port = (uint16_t )tmp_port;
      }
    }
  }
  return(0);

}/*nat_query_cache*/


int32_t nat_perform_snat(uint8_t  *packet_ptr, 
                         uint16_t packet_length, 
                         uint8_t  *snat_ptr, 
                         uint16_t *snat_length) {

  uint8_t *pseudo_ptr = NULL;
  struct iphdr  *ip_ptr  = NULL;
  struct udphdr *udp_ptr = NULL;
  struct dnshdr *dns_ptr = NULL;
  struct icmphdr *icmp_hdr = NULL;
  uint16_t nat_port = 0x0000;
  uint16_t tmp_src_port = 0x0000;
  uint16_t ip_header_len = 0x0000;
  uint16_t ip_payload_len = 0x0000;

  nat_ctx_t *pNatCtx = &nat_ctx_g;

  struct eth *eth_ptr = (struct eth *)packet_ptr;

  /*what protocol is this? - what type of frame is followed the Ethernet Header*/
  if(0x0800 == htons(eth_ptr->h_proto)) {
    
    ip_ptr = (struct iphdr *)&packet_ptr[sizeof(struct eth)];

    switch(ip_ptr->ip_proto) {

      case IP_ICMP:
        nat_port = (1 << 15) | ((NAT_PROTO_ICMP & 0x1F) << 10) | (random() % (2 << 10));

        ip_payload_len = ntohs(ip_ptr->ip_tot_len) + 2;

        ip_header_len = 4 * ip_ptr->ip_len;

        /*copy ip header*/
        memcpy((void *)snat_ptr, (void *)&packet_ptr[sizeof(struct eth)], ip_header_len);
        ((struct iphdr *)snat_ptr)->ip_tot_len = htons(ip_payload_len);

        /*copy icmp header*/
        memcpy((void *)&snat_ptr[ip_header_len], 
               (void *)&packet_ptr[sizeof(struct eth) + ip_header_len], 
               sizeof(struct icmphdr));

        /*Adding two bytes of proprietary payload*/
        *((uint16_t *)&snat_ptr[ip_header_len + sizeof(struct icmphdr)]) = htons(nat_port);

        /*copy icmp Payload*/
        memcpy((void *)&snat_ptr[ip_header_len + sizeof(struct icmphdr) + 2/*nat_port*/], 
               (void *)&packet_ptr[sizeof(struct eth) + ip_header_len + sizeof(struct icmphdr)],
               (packet_length - (sizeof(struct eth) + ip_header_len + sizeof(struct icmphdr))));

        packet_length += 2;

        *snat_length = (packet_length - sizeof(struct eth));

        /*calculate the ip header check sum*/
        ((struct iphdr *)snat_ptr)->ip_chksum = 0;
        ((struct iphdr *)snat_ptr)->ip_src_ip = pNatCtx->ip_addr;
        //((struct iphdr *)snat_ptr)->ip_dest_ip = 0;

        ((struct iphdr *)snat_ptr)->ip_chksum = dhcp_cksum((void *)snat_ptr, ip_header_len);

        /*calculate the icmp header check sum*/
        ((struct icmphdr *)&snat_ptr[ip_header_len])->cksum = 0;

        ((struct icmphdr *)&snat_ptr[ip_header_len])->cksum = dhcp_cksum((void *)&snat_ptr[ip_header_len], 
                                                        (*snat_length - ip_header_len));
      
        /*Update the cache while preparing the request*/
        nat_update_cache(ntohl(ip_ptr->ip_src_ip), 
                               eth_ptr->h_source, 
                               0x00, 
                               nat_port);

      break;

      case IP_IGMP:
        nat_port = (1 << 15) | ((NAT_PROTO_IGMP & 0x1F) << 10) | (random() % (2 << 10)); 
      break;
      case IP_TCP:
        nat_port = (1 << 15) | ((NAT_PROTO_TCP & 0x1F) << 10) | (random() % (2 << 10)); 
      break;

      case IP_UDP:
      {
        nat_port = (1 << 15) | 
                   ((NAT_PROTO_UDP & 0x1F) << 10) | 
                   (random() % (2 << 10));

        ip_header_len = 4 * ip_ptr->ip_len;

        struct udphdr *udp_ptr = (struct udphdr *)&packet_ptr[sizeof(struct eth) + ip_header_len];
        /*copy the IP Packet*/
        memcpy((void *)snat_ptr, 
               (void *)&packet_ptr[sizeof(struct eth)], 
               ntohs(ip_ptr->ip_tot_len));

        struct iphdr *snat_iphdr_ptr = (struct iphdr *)snat_ptr;
        struct udphdr *snat_udphdr_ptr = (struct udphdr *)&snat_ptr[ip_header_len];

        /*Message structure is based on destination UDP Port*/
        if(53 == ntohs(udp_ptr->udp_dest_port)) {
          /*DNS Query*/
          tmp_src_port = ntohs(udp_ptr->udp_src_port);

          /*Store above extracted in database and will be used while sending response*/
          nat_update_cache(ntohl(ip_ptr->ip_src_ip), 
                           eth_ptr->h_source , 
                           tmp_src_port, 
                           nat_port);


          /*Change the source ip-address*/
          //snat_iphdr_ptr->ip_src_ip = pNatCtx->ip_addr;
          /*Change the destination ip-address*/
          //snat_iphdr_ptr->ip_dest_ip = pNatCtx->dns1;
          
          snat_iphdr_ptr->ip_chksum = 0;

          snat_iphdr_ptr->ip_chksum = dhcp_cksum((void *)snat_iphdr_ptr, ip_header_len);
 
          /*Populating pseudo header for UDP csum calculation*/
          pseudo_ptr = (uint8_t *)malloc(ntohs(snat_udphdr_ptr->udp_len) + 20);
          memset((void *)pseudo_ptr, 0, (ntohs(snat_udphdr_ptr->udp_len) + 20));
  
          *((uint32_t *)&pseudo_ptr[0]) = snat_iphdr_ptr->ip_src_ip;
          *((uint32_t *)&pseudo_ptr[4]) = snat_iphdr_ptr->ip_dest_ip;

          /*It's padded with zero*/
          pseudo_ptr[8]  = 0;

          /*Protocol is UDP*/
          pseudo_ptr[9]  = 17;

          /*Length of UDP Header + it's payload*/
          *((uint16_t *)&pseudo_ptr[10]) = snat_udphdr_ptr->udp_len;

          /*Change the source udp port*/
          snat_udphdr_ptr->udp_src_port = htons(nat_port);
          snat_udphdr_ptr->udp_chksum = 0;

          memcpy((void *)&pseudo_ptr[12], 
                 (void *)&snat_ptr[ip_header_len], 
                 ntohs(snat_udphdr_ptr->udp_len));

          snat_udphdr_ptr->udp_chksum = dhcp_cksum((void *)pseudo_ptr, 
                                                   (ntohs(snat_udphdr_ptr->udp_len) + 12));
          *snat_length = ntohs(ip_ptr->ip_tot_len);

          free(pseudo_ptr);
          pseudo_ptr = NULL;
        }
      }
      break;

      default:
      break; 
    }
  }
  return(0);

}/*dns_perform_snat*/

int32_t nat_perform_dnat(uint8_t *packet_ptr, 
                         uint16_t packet_length,
                         uint8_t *dnat_ptr,
                         uint16_t *dnat_length) {

  uint8_t  *pseudo_ptr = NULL;
  uint16_t ip_header_len = 0x00;
  uint16_t nat_port = 0x00;
  uint16_t src_port = 0x00;

  nat_ctx_t *pNatCtx = &nat_ctx_g;

  struct iphdr *iphdr_ptr = (struct iphdr *)packet_ptr;

  ip_header_len = 4 * iphdr_ptr->ip_len;

  /*copy the received ip packet into dnat_ptr*/
  memcpy((void *)&dnat_ptr[sizeof(struct eth)], packet_ptr, packet_length);
 
  struct eth *dnat_eth_ptr = (struct eth *)dnat_ptr;

  struct iphdr *dnat_iphdr_ptr = (struct iphdr *)&dnat_ptr[sizeof(struct eth)];

  memcpy((void *)dnat_eth_ptr->h_source, (void *)pNatCtx->mac_addr, 6);
  dnat_eth_ptr->h_proto = htons(0x0800);
      
  //dnat_iphdr_ptr->ip_src_ip = pNatCtx->ip_addr;
  //dnat_iphdr_ptr->ip_dest_ip = dnat_iphdr_ptr->ip_dest_ip;

  switch(iphdr_ptr->ip_proto) {
    case IP_ICMP:
    {
      /*ICMP Reply received*/

      nat_port = ntohs(*((uint16_t *)&packet_ptr[ip_header_len + sizeof(struct icmphdr)]));
      fprintf(stderr, "\nnat_port 0x%X from icmp request is\n",nat_port);
      
      /*Retrieve the IP, MAC from cache based on nat_port*/
      nat_query_cache(nat_port, 
                      (uint32_t *)&dnat_iphdr_ptr->ip_dest_ip,
                      (uint8_t *)dnat_eth_ptr->h_dest,
                      (uint16_t *)&src_port);

      /*nat_src port is of 2 bytes*/
      dnat_iphdr_ptr->ip_tot_len = htons(ntohs(dnat_iphdr_ptr->ip_tot_len) - 2);

      /*copy icmp response header*/
      struct icmphdr *dnat_icmphdr_ptr = (struct icmphdr *)&dnat_ptr[sizeof(struct eth) + ip_header_len];
      memcpy((void *)dnat_icmphdr_ptr, (void *)&packet_ptr[ip_header_len], ip_header_len);

      /*copy icmp payload*/
      memcpy((void *)&dnat_ptr[sizeof(struct eth) + ip_header_len + sizeof(struct icmphdr)], 
             (void *)&packet_ptr[ip_header_len + sizeof(struct icmphdr) + 2],
             (packet_length - (ip_header_len + sizeof(struct icmphdr) + 2)));

      /*IP Header checksum*/
      dnat_iphdr_ptr->ip_chksum = 0;
      dnat_iphdr_ptr->ip_chksum = dhcp_cksum((void *)dnat_iphdr_ptr, ip_header_len);
  
      /*icmp header check sum*/
      dnat_icmphdr_ptr->cksum = dhcp_cksum((void *)dnat_icmphdr_ptr, (dnat_iphdr_ptr->ip_tot_len - ip_header_len));
 
      *dnat_length = (packet_length + sizeof(struct eth)) - 2;
    }
    break;
    case IP_IGMP:
    break;
    case IP_TCP:
    break;
    case IP_UDP:
    {
      struct udphdr *dnat_udphdr_ptr = (struct udphdr *)&dnat_ptr[sizeof(struct eth) + ip_header_len];
      struct udphdr *udphdr_ptr = (struct udphdr *)&packet_ptr[ip_header_len];

      nat_port = ntohs(dnat_udphdr_ptr->udp_dest_port);
  
      /*Retrieve the IP, MAC from cache based on nat_port*/
      nat_query_cache(nat_port, 
                      (uint32_t *)&dnat_iphdr_ptr->ip_dest_ip,
                      (uint8_t *)dnat_eth_ptr->h_dest,
                      (uint16_t *)&src_port);

      /*Change the source ip-address*/
      //dnat_iphdr_ptr->ip_src_ip = pNatCtx->ip_addr;
      dnat_iphdr_ptr->ip_dest_ip = htonl(dnat_iphdr_ptr->ip_dest_ip);
      
      /*let the source udp port remain same*/
      dnat_udphdr_ptr->udp_dest_port = htons(src_port);

      /*IP Header checksum*/
      dnat_iphdr_ptr->ip_chksum = 0;
      dnat_iphdr_ptr->ip_chksum = dhcp_cksum((void *)dnat_iphdr_ptr, ip_header_len);
 
      /*Populating pseudo header for UDP csum calculation*/
      pseudo_ptr = (uint8_t *)malloc(ntohs(udphdr_ptr->udp_len) + 12);
      memset((void *)pseudo_ptr, 0, (ntohs(udphdr_ptr->udp_len) + 12));

      *((uint32_t *)&pseudo_ptr[0]) = dnat_iphdr_ptr->ip_dest_ip;
      *((uint32_t *)&pseudo_ptr[4]) = dnat_iphdr_ptr->ip_src_ip;

      #if 0
      memcpy((void *)&pseudo_ptr[0], (void *)&dnat_iphdr_ptr->ip_dest_ip, 4);
      memcpy((void *)&pseudo_ptr[4], (void *)&dnat_iphdr_ptr->ip_src_ip, 4);
      #endif
      /*It's padded with zero*/
      pseudo_ptr[8]  = 0;

      /*Protocol is UDP*/
      pseudo_ptr[9]  = 17;

      /*Length of UDP Header + it's payload*/
      *((uint16_t *)&pseudo_ptr[10]) = dnat_udphdr_ptr->udp_len;

      #if 0
      pseudo_ptr[10] = (ntohs(dnat_udphdr_ptr->udp_len) >> 8) & 0xFF;
      pseudo_ptr[11] = ntohs(dnat_udphdr_ptr->udp_len) & 0xFF;
      #endif

      dnat_udphdr_ptr->udp_chksum = 0;
      
      memcpy((void *)&pseudo_ptr[12],
         (void *)&dnat_ptr[sizeof(struct eth) + ip_header_len],
         ntohs(udphdr_ptr->udp_len));

      dnat_udphdr_ptr->udp_chksum = dhcp_cksum((void *)pseudo_ptr, 
                                               (ntohs(dnat_udphdr_ptr->udp_len) + 12));

      *dnat_length = sizeof(struct eth) + ntohs(iphdr_ptr->ip_tot_len); 

      free(pseudo_ptr);
      pseudo_ptr = NULL;
      nat_delete_from_cache(nat_port);
    }
    break;

    default:

    break;
  }
  return(0);

}/*dns_perform_dnat*/


#endif /*__NAT_C__*/
