#ifndef __TUN_H__
#define __TUN_H__

#include <type.h>

#define TUN_DEV_PATH "/dev/net/tun"

typedef struct {
  int32_t tun_fd;
  uint8_t tun_devname[16];
  uint8_t tun_ipaddr_str[16];
  uint8_t tun_netmask_str[16];
  uint8_t tun_gw_str[16];


}tun_ctx_t;




int32_t tun_main(uint8_t *src_ip_str, uint8_t *dest_ip_str, uint8_t *net_mask_str);

int32_t tun_open_tun(void);

int32_t tun_setaddr(uint8_t *ip_addr_ptr, 
                    uint8_t *dst_addr_ptr, 
                    uint8_t *netmask_addr_ptr);

int32_t tun_set_flags(uint32_t flags);

int32_t tun_get_tun_devname(uint8_t *tun_devname);

int32_t tun_write(uint8_t *packet_ptr, uint16_t packet_length);

int32_t tun_read(uint8_t *packet_ptr, uint16_t *packet_length);
#endif /*__TUN_H__*/
