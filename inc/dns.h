#ifndef __DNS_H__
#define __DNS_H__

#include <common.h>

#define DNS_PORT 53


typedef enum {
  DNS_QUERY,
  DNS_INVERSE_QUERY,
  DNS_STATUS

}dns_opcode_t;

typedef enum {
  DNS_NO_ERROR,
  DNS_FORMAT_ERROR,
  DNS_SERVER_FAILURE,
  DNS_NAME_ERROR,
  DNS_NOT_IMPLEMENTED,
  DNS_REFUSED

}dns_rcode_t;

typedef enum {
  /*A host address*/
  A = 1,
  NS,
  MD,
  MF,
  CNAME,
  SOA,
  MB,
  MG,
  MR,
  WKS = 11,
  PTR,
  HINFO,
  MX,
  TXT,
  ALL_RECORD = 255
}dns_rr_type_t;

typedef enum {
  IN = 1,
  CS,
  CH,
  HS,
  AXFR = 252,
  MAILB,
  MAILA,
  ANY_CLASS = 255
}dns_rr_class_t;

/*-------------------------------------------------------------------------
 * Refer to RFC1035 Note on bit position 
 * Bit Numbering:
 *   IETF Standard 
 *     bits starts from left to right and left and  MSB labeled with bit0.
 *     -----------------
 *     |0|1|2|3|4|5|6|7|
 *     -----------------
 *  ITU Standard
 *    nits starts from right to left and MSB labeled with bit7.
 *    ----------------- 
 *    |7|6|5|4|3|2|1|0|
 *    -----------------
 *-----------------------------------------------------------------------*/
struct dnshdr {
  uint16_t  xid;       /*unique transaction id to map request into response*/

  uint8_t   rd:1;      /*Recursion Desired*/
  uint8_t   tc:1;      /*TrunCation - Is message truncated?*/
  uint8_t   aa:1;      /*Is it authoritative Answer*/
  uint8_t   opcode:4;  /*query type*/
  uint8_t   qr:1;      /*signifies whether it's request(0) or reply/response(1)*/

  uint8_t   rcode:4;   /*Response Code - */
  uint8_t   z:3;       /*Reserved for Future Use - RFU*/
  uint8_t   ra:1;      /*Recursion Available - Recursive query to be supported or not*/

  uint16_t  qdcount;   /*Number of entries in the query section*/
  uint16_t  ancount;   /*Speficy number of RR (Resource Record) in Answer section*/
  uint16_t  nscount;   /*Specify the number of name server records in the authority record*/
  uint16_t  arcount;   /*specify the number of resource records in the additional records section*/
}__attribute__((packed));

typedef struct {
  uint8_t  len;
  /*variable length value*/
  uint8_t   value[255];
}domain_name_list_t;

typedef struct {
   uint8_t  qname_count;
  /*An array of Domain Name List*/
  domain_name_list_t qname[255];
  /*Two octet code which specifies the type of query*/
  uint16_t   qtype;
  /*Type of query*/
  uint16_t   qclass;
  
}dns_qddata_t;

typedef struct {
  uint16_t name_count;
  /*Domain Name*/
  domain_name_list_t name[255];
  /*contains RR type codes*/
  uint16_t type;
  /*specify the class of data in the RDATA files*/
  uint16_t rdata_class;
  /*specify time interval (in seconds) that the RR record may be cached 
    before it should be discarded*/
  uint32_t ttl;
  /*length in the RDATA filed*/
  uint16_t rdlength;
  /*variable length RDATA*/
  uint8_t  rdata[255];
}dns_andata_t;

typedef union {
  uint32_t  addr;
  uint8_t   addr_c[4];
}dns_ip_addr_t;

typedef struct {
  dns_qddata_t  qdata;
  dns_andata_t  andata;
  uint8_t       domain_name[255];
  uint8_t       ns1_ip[32];
  uint8_t       ns1_name[255];
  uint8_t       host_name[255];
  uint8_t       host_ip[32];
  uint8_t       dns1[32];
  uint8_t       dns2[32];
  dns_ip_addr_t ns_ipaddr;
  /*Timerid for SNAT Request*/
  timer_t       snat_tid;

}dns_ctx_t;

#endif

