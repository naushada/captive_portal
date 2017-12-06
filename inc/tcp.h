#ifndef __TCP_H__
#define __TCP_H__

typedef struct {
  uint32_t ip_addr;
  uint32_t ip_mask;
  uint32_t uam_ip;
  uint16_t uam_port;
  uint32_t radius_ip;
  uint16_t radius_port;

}tcp_ctx_t;

#endif /*__TCP_H__*/
