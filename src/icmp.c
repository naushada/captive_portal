#ifndef __ICMP_C__
#define __ICMP_C__

#include <type.h>
#include <transport.h>
#include <common.h>

#include <icmp.h>

/********************************************************************
 *Global Instance Variable
 ********************************************************************/
icmp_ctx_t icmp_ctx_g;

/*********************************************************************
 * Extern Declaration
 ********************************************************************/
extern unsigned short dhcp_cksum(void *pkt_ptr, size_t pkt_len);

extern int write_eth_frame (int fd,
                            unsigned char *dst_mac,
                            unsigned char *packet, 
                            unsigned int packet_len);

extern int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length);

extern int32_t nat_perform_snat(uint8_t *packet_ptr, 
                                uint16_t packet_length, 
                                uint8_t *snat_ptr, 
                                uint16_t *snat_length);
/*********************************************************************
 * Function Definition
 ********************************************************************/

int32_t icmp_build_common_header(uint8_t *rsp_ptr, 
                                 uint16_t *len, 
                                 uint8_t *packet_ptr, 
                                 uint16_t packet_length) {
  uint8_t tmp_mac[6];
  uint32_t tmp_ip;
  struct eth *eth_ptr;
  struct iphdr *iphdr_ptr;

  eth_ptr = (struct eth *)rsp_ptr;
  iphdr_ptr = (struct iphdr *)&rsp_ptr[sizeof(struct eth)];

  /*Populating MAC Header*/
  memcpy((void *)tmp_mac, ((struct eth *)packet_ptr)->h_dest, sizeof(tmp_mac));
  memcpy((void *)eth_ptr->h_dest, ((struct eth *)packet_ptr)->h_source, 6);
  memcpy((void *)eth_ptr->h_source, tmp_mac, 6);
  eth_ptr->h_proto = ((struct eth *)packet_ptr)->h_proto;

  /*Populating IP Header*/
  tmp_ip = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_dest_ip;
  iphdr_ptr->ip_dest_ip = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_src_ip;
  iphdr_ptr->ip_src_ip = tmp_ip;
  iphdr_ptr->ip_chksum = 0;
  iphdr_ptr->ip_len = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_len;
  iphdr_ptr->ip_ver = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_ver;
  iphdr_ptr->ip_flag_offset = htons(0x1 << 14);
  iphdr_ptr->ip_ttl = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_ttl;
  iphdr_ptr->ip_tos = 0;
  iphdr_ptr->ip_proto = IP_ICMP;
  
  *len = sizeof(struct eth) + (4 * iphdr_ptr->ip_len);
  return(0);
}/*icmp_build_header*/


int32_t icmp_build_echo_reply(int16_t fd, 
                              uint8_t *packet_ptr, 
                              uint16_t packet_length) {

  uint8_t rsp_buffer[1500];
  uint16_t len = 0;
  int32_t ret = -1;
  struct icmphdr *icmphdr_ptr = NULL;

  memset((void *)&rsp_buffer, 0, sizeof(rsp_buffer));
  /*This will build the MAC Header + IP HEADER*/
  icmp_build_common_header((uint8_t *)rsp_buffer, &len, packet_ptr, packet_length);

  icmphdr_ptr = (struct icmphdr *)&rsp_buffer[len];
 
  icmphdr_ptr->type = (uint8_t )ICMP_ECHO_REPLY;
  icmphdr_ptr->code = 0;
  /*Will be calculated later*/
  icmphdr_ptr->cksum = 0;

  icmphdr_ptr->id = ((struct icmphdr *)&packet_ptr[sizeof(struct eth) + 
                    sizeof(struct iphdr)])->id;

  icmphdr_ptr->seq_number = ((struct icmphdr *)&packet_ptr[sizeof(struct eth) + 
                            sizeof(struct iphdr)])->seq_number;

  len += sizeof(struct icmphdr);

  /*Is there any payload in request? if so then it must be copied back to ECHO REPLY*/ 
  if(packet_length > len) {
    memcpy((void *)&rsp_buffer[len], 
           (void *)&packet_ptr[sizeof(struct eth) + 
           (((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_len * 4) + 
            sizeof(struct icmphdr)],
           (packet_length - len));
    len += (packet_length - len);
  }

  /*Updating total length in IP Header*/
  ((struct iphdr *)&rsp_buffer[sizeof(struct eth)])->ip_tot_len = htons(len - sizeof(struct eth));

  /*Populating IP Header check sum*/
  ((struct iphdr *)&rsp_buffer[sizeof(struct eth)])->ip_chksum = 
                  dhcp_cksum((void *)&rsp_buffer[sizeof(struct eth)], 
                             ((struct iphdr *)&rsp_buffer[sizeof(struct eth)])->ip_len * 4);

  /*Populating ICMP Header check sum (Header's payload to be included 
   *while calculating check sum. 
   */
  icmphdr_ptr->cksum = dhcp_cksum((void *)&rsp_buffer[sizeof(struct eth) + 
                                  ((struct iphdr *)&rsp_buffer[sizeof(struct eth)])->ip_len * 4],
                                  len - (sizeof(struct eth) + ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_len * 4));
  ret = write_eth_frame(fd, 
                       (unsigned char *)((struct eth *)rsp_buffer)->h_dest, 
                       rsp_buffer, 
                       len);
  if(ret < 0) {
    perror("ICMP ECHO REPLY:");
    return(-1);
  }

  return(0);
}/*icmp_build_echo_reply*/

int32_t icmp_build_response(uint8_t type, 
                            int16_t fd, 
                            uint8_t *packet_ptr, 
                            uint16_t packet_length) {

  switch(type) {
    case ICMP_ECHO_REPLY:
      icmp_build_echo_reply(fd, packet_ptr, packet_length);
    break;

    default:
    break; 
  }/*end of switch*/

}/*icmp_build_response*/

int32_t icmp_init(uint32_t dhcp_listen_addr, uint32_t dhcp_listen_mask) {
  icmp_ctx_t *pIcmpCtx = &icmp_ctx_g;
  pIcmpCtx->dhcp_ip_addr = dhcp_listen_addr;
  pIcmpCtx->dhcp_listen_mask = dhcp_listen_mask;

}/*icmp_init*/

int32_t icmp_main(int16_t fd, uint8_t *packet_ptr, uint16_t packet_length) {
  icmp_ctx_t *pIcmpCtx = &icmp_ctx_g;
  int32_t ret = -1;
  uint8_t buffer[1500];
  uint16_t buffer_length;
  uint32_t ipaddr = ((struct iphdr *)&packet_ptr[sizeof(struct eth)])->ip_dest_ip;

  ipaddr = ntohl(ipaddr);
  fprintf(stderr, "\ndhcp listen ip %X dhcp_listen mask %X ipaddr %X\n",
         ntohl(pIcmpCtx->dhcp_ip_addr), ntohl(pIcmpCtx->dhcp_listen_mask), ipaddr);

  if((ntohl(pIcmpCtx->dhcp_ip_addr) & ntohl(pIcmpCtx->dhcp_listen_mask)) != (ipaddr & htonl(pIcmpCtx->dhcp_listen_mask))) {
    /*Ping Request is for other Network*/
    fprintf(stderr, "Ping Request to be sent via tunnel\n");
    nat_perform_snat(packet_ptr, packet_length, buffer, &buffer_length);

    ret = tun_write(buffer, buffer_length);
  } else {
    
    icmp_build_response((uint8_t)ICMP_ECHO_REPLY, 
                        fd, 
                        packet_ptr, 
                        packet_length);
  }
  return(0);

}/*icmp_main*/


#endif /*__ICMP_C__*/
