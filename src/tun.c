#ifndef __TUN_C__
#define __TUN_C__

#include <type.h>
#include <transport.h>
#include <common.h>
#include <string.h>
#include <linux/if_tun.h>

#include <tun.h>

tun_ctx_t tun_ctx_g;

/********************************************************************
 *  Extern Declaration
 ********************************************************************/
extern int ndelay_on(int fd);

extern int coe(int fd);

extern uint32_t  ip_str_to_int(int8_t  *record);

extern int32_t net_get_dhcp_fd(void);

extern int32_t write_eth_frame (int32_t fd,
                                uint8_t *dst_mac,
                                uint8_t *packet, 
                                uint32_t packet_len);

extern int32_t net_get_dhcp_fd(void);

extern int32_t nat_perform_dnat(uint8_t *packet_ptr, 
                                uint16_t packet_length,
                                uint8_t *dnat_ptr,
                                uint16_t *dnat_length);

/********************************************************************
 * Function Definition starts
 ********************************************************************/
int32_t tun_read(uint8_t *packet_ptr, uint16_t *packet_length) {
  int32_t ret = -1;
  size_t  max_bytes = sizeof(uint16_t);
 
  tun_ctx_t *pTunCtx = &tun_ctx_g;

  do {
    ret = read(pTunCtx->tun_fd, packet_ptr, max_bytes);
  }while(ret == -1 && errno == EINTR);
 
  *packet_length = (uint16_t)ret;
  return(0); 
}/*tun_read*/

int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length) {
  tun_ctx_t *pTunCtx = &tun_ctx_g;
  int32_t ret = -1;

  do {
    ret = write(pTunCtx->tun_fd, packet_ptr, packet_length);
  } while (ret == -1 && errno == EINTR);

  return(ret);
}/*tun_write*/

int32_t tun_get_tun_devname(uint8_t *tun_devname) {
  
  tun_ctx_t *pTunCtx = &tun_ctx_g;
  strncpy(tun_devname, pTunCtx->tun_devname, strlen(pTunCtx->tun_devname));

  return(0);
}/*tun_get_tun_devname*/

int32_t tun_get_tun_fd(void) {
  tun_ctx_t *pTunCtx = &tun_ctx_g;
  return(pTunCtx->tun_fd);

}/*tun_get_tun_fd*/


int32_t tun_set_flags(uint32_t flags) {
  struct ifreq ifr;
  int32_t fd;

  tun_ctx_t *pTunCtx = &tun_ctx_g;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;

  strncpy(ifr.ifr_name, pTunCtx->tun_devname, IFNAMSIZ);

  if(ioctl(fd, SIOCSIFFLAGS, &ifr)) {
    perror("Setting of Flags Failed");
    return(-1);
  }
  
  close(fd);

  return(0);
}/*tun_set_flags*/


int32_t tun_setaddr(uint8_t *ip_addr_ptr, 
                    uint8_t *dst_addr_ptr, 
                    uint8_t *netmask_addr_ptr) {
  int32_t fd;
  struct ifreq ifr;
  tun_ctx_t *pTunCtx = &tun_ctx_g;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  strncpy(ifr.ifr_name, pTunCtx->tun_devname, IFNAMSIZ);

  ifr.ifr_addr.sa_family = AF_INET;
  ifr.ifr_dstaddr.sa_family = AF_INET;
  ifr.ifr_netmask.sa_family = AF_INET;

  /*Make sure to null terminate*/
  ifr.ifr_name[IFNAMSIZ-1] = 0;

  if(ip_addr_ptr) {
    ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr = ip_str_to_int((int8_t *)ip_addr_ptr);

    if (ioctl(fd, SIOCSIFADDR, (void *) &ifr) < 0) {
     fprintf(stderr, "Setting of interface address failed\n");
     return(-1);
    }
  }

  if(dst_addr_ptr) {
    ((struct sockaddr_in *)&ifr.ifr_dstaddr)->sin_addr.s_addr = ip_str_to_int((int8_t *)dst_addr_ptr);

    if(ioctl(fd, SIOCSIFDSTADDR, (void *) &ifr) < 0) {
     fprintf(stderr, "Setting of interface DESTINATION IP FAILED failed\n");
     return(-1);
    }
  }
  
  if(netmask_addr_ptr) {
    ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr = ip_str_to_int((int8_t *)netmask_addr_ptr);

    if(ioctl(fd, SIOCSIFNETMASK, (void *) &ifr) < 0) {
     fprintf(stderr, "Setting of interface NETMASK failed\n");
     return(-1);
    }
  }
  close(fd);

  if(tun_set_flags((IFF_UP | IFF_RUNNING))) {
    perror("setting of flags failed");
    return(-1);
  }

  return(0);

}/*tun_setaddr*/

int32_t tun_open_tun(void) {
  
  struct ifreq ifr;
  int32_t fd;
  struct ifreq nifr;

  tun_ctx_t *pTunCtx = &tun_ctx_g;

  pTunCtx->tun_fd = open(TUN_DEV_PATH, O_RDWR);

  if(pTunCtx->tun_fd < 0) {
    fprintf(stderr, "Opening of Virtual Device Failed\n");
    perror("tun:");
    return(-1);
  }
  
  ndelay_on(pTunCtx->tun_fd);
  coe(pTunCtx->tun_fd);

  memset((void *)&ifr, 0, sizeof(struct ifreq));

  ifr.ifr_flags = IFF_TUN       | 
                  IFF_NO_PI     | 
                  IFF_MULTICAST |
                  IFF_BROADCAST | 
                  IFF_PROMISC   |
                  IFF_ONE_QUEUE;

  if(ioctl(pTunCtx->tun_fd, TUNSETIFF, (void *) &ifr) < 0) {
    perror("ioctl failed");
    return(-1);
  }

  strncpy(pTunCtx->tun_devname, ifr.ifr_name, IFNAMSIZ);
  fprintf(stderr, "clone devname is %s\n", pTunCtx->tun_devname); 
  /*Set Transmit Queue Length*/ 
  memset((void *)&nifr, 0, sizeof(struct ifreq));

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  if(fd < 0) {
    perror("socket Creation Failed");
    return(-1);
  }
  strncpy(nifr.ifr_name, ifr.ifr_name, IFNAMSIZ);
  nifr.ifr_qlen = 100;

  if(ioctl(fd, SIOCSIFTXQLEN, (void *) &nifr)) {
    perror("Setting of TXQLEN Failed\n");
    return(-1);
  }
  
  strncpy(pTunCtx->tun_devname, ifr.ifr_name, IFNAMSIZ);
  ioctl(pTunCtx->tun_fd, TUNSETNOCSUM, 1); /* Disable checksums */ 

  /*Set the MTU*/
  memset((void *)&nifr, 0, sizeof(struct ifreq));
  strncpy(nifr.ifr_name, pTunCtx->tun_devname, sizeof(nifr.ifr_name));
  ifr.ifr_mtu = 1500;

  if(ioctl(fd, SIOCSIFMTU, &ifr) < 0) {
    perror("ioctl Failed:");
    return(-1);
  }
 
  close(fd);
  return(0);
 
}/*tun_open_tun*/

int32_t tun_process_response(uint8_t *packet_ptr, uint16_t packet_length) {
  uint8_t  buffer[1500];
  uint16_t buffer_length;
  uint8_t  dst_mac[6];
  int32_t  raw_fd = -1;
  
  memset((void *)buffer, 0, sizeof(buffer));
  buffer_length = 0;
 
  nat_perform_dnat(packet_ptr, packet_length, buffer, &buffer_length);
  memset((void *)dst_mac, 0, sizeof(dst_mac));
    
  memcpy((void *)dst_mac, (void *)buffer, sizeof(dst_mac));
  raw_fd = net_get_dhcp_fd();
  write_eth_frame(raw_fd, dst_mac, buffer, buffer_length);

  return(0);
}/*tun_process_response*/


int32_t tun_main(uint8_t *src_ip_str, uint8_t *dest_ip_str, uint8_t *net_mask_str) {
  tun_open_tun();
  tun_setaddr(src_ip_str, dest_ip_str, net_mask_str);
  
}/*tun_main*/

#endif /*__TUN_C__*/
