#ifndef __TCP_C__
#define __TCP_C__

#include <transport.h>
#include <common.h>
#include <type.h>

#include <tcp.h>

/********************************************************************
 *Extern Declaration
 *
 ********************************************************************/


/********************************************************************
 *Global Definition
 *
 ********************************************************************/
tcp_ctx_t tcp_ctx_g;

/********************************************************************
 *Function Definitions
 *
 ********************************************************************/
int32_t tcp_init(uint32_t ip_addr, 
                 uint32_t ip_mask,
                 uint32_t uam_ip,
                 uint16_t uam_port,
                 uint32_t radius_ip,
                 uint16_t radius_port) {
  
}/*tcp_init*/
#endif /*__TCP_C__*/
