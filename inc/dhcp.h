#ifndef __DHCP_H__
#define __DHCP_H__

typedef enum {
  DHCP_SERVER_PORT = 67,
  DHCP_CLIENT_PORT = 68
}udp_port_t;

typedef union {
  unsigned int ip_addr;
  unsigned char addr[4];
}dhcp_ipaddr_t;


typedef struct dhcphdr {
  unsigned char      dhcp_op;                   /* packet type */
  unsigned char      dhcp_htype;                /* type of hardware address for this machine (Ethernet, etc) */
  unsigned char      dhcp_hlen;                 /* length of hardware address (of this machine) */
  unsigned char      dhcp_hops;                 /* hops */
  unsigned int       dhcp_xid;                  /* random transaction id number - chosen by this machine */
  unsigned short int dhcp_secs;                 /* seconds used in timing */
  unsigned short int dhcp_flags;                /* flags */
  unsigned int       dhcp_ciaddr;               /* IP address of this machine (if we already have one) */
  unsigned int       dhcp_yiaddr;               /* IP address of this machine (offered by the DHCP server) */
  unsigned int       dhcp_siaddr;               /* IP address of DHCP server */
  unsigned int       dhcp_giaddr;               /* IP address of DHCP relay */
  unsigned char      dhcp_chaddr[16];           /* hardware address of this machine */
  unsigned char      dhcp_sname[64];            /* name of DHCP server */
  unsigned char      dhcp_file[128];            /* boot file name (used for diskless booting?) */
}__attribute__((packed)) dhcp_packet_t;

typedef struct {
  int  len;
  char *option;
}dhcp_option_t;

typedef struct {
  /*tag of one octet*/
  unsigned char tag;
  /*length can be of 1 octet*/
  unsigned char len;
  /*value part of the option*/
  unsigned char value[255];
}dhcp_tag_t;

typedef struct {
  unsigned char tag_count;
  dhcp_tag_t    tag[23];
}dhcp_tag_present_t;


typedef enum {
  DHCPUNKNOWN  = 0,
  DHCPDISCOVER = 1,
  DHCPOFFER    = 2,
  DHCPREQUEST  = 3,
  DHCPDECLINE  = 4,
  DHCPACK      = 5,
  DHCPNACK     = 6,
  DHCPRELEASE  = 7

}dhcp_message_type_t;


typedef enum {
  DHCP_OPTION_PAD                        = 0,
  DHCP_OPTION_SUBNET_MASK                = 1,
  DHCP_OPTION_ROUTER                     = 3,
  DHCP_OPTION_TIME_SERVER                = 4,
  DHCP_OPTION_NAME_SERVER                = 5,
  DHCP_OPTION_DOMAIN_NAME_SERVER         = 6,
  DHCP_OPTION_LOG_SERVER                 = 7,
  DHCP_OPTION_QUOTE_SERVER               = 8,
  DHCP_OPTION_IMPRESS_SERVER             = 10,
  DHCP_OPTION_ROUTER_LOCATION_SERVER     = 11,
  DHCP_OPTION_HOST_NAME                  = 12,
  DHCP_OPTION_DOMAIN_NAME                = 15,
  
  DHCP_OPTION_INTERFACE_MTU              = 26,
  DHCP_OPTION_BROADCAST_ADDRESS          = 28,
  /* Network Information Server Domain */
  DHCP_OPTION_NIS_DOMAIN                 = 40,
  /* Network Information Server */
  DHCP_OPTION_NIS                         = 41,
  DHCP_OPTION_NTP_SERVER                  = 42,
  DHCP_OPTION_VENDOR_SPECIFIC_INFO        = 43,
  DHCP_OPTION_REQUESTED_IP_ADDRESS        = 50,
  DHCP_OPTION_IP_LEASE_TIME               = 51,
  DHCP_OPTION_OPTION_OVERLOAD             = 52,
  DHCP_OPTION_MESSAGE_TYPE                = 53,
  DHCP_OPTION_SERVER_IDENTIFIER           = 54,
  DHCP_OPTION_PARAMETER_REQUEST_LIST      = 55,
  DHCP_OPTION_MESSAGE                     = 56,
  DHCP_OPTION_MAXIMUM_DHCP_MESSAGE_SIZE   = 57,
  DHCP_OPTION_RENEWAL_TIME_T1             = 58,
  DHCP_OPTION_REBINDING_TIME_T2           = 59,
  DHCP_OPTION_CLASS_IDENTIFIER            = 60,
  DHCP_OPTION_CLIENT_IDENTIFIER           = 61,
  DHCP_OPTION_RAPID_COMMIT                = 80,
  DHCP_OPTION_AUTO_CONFIGURE              = 116,

  DHCP_OPTION_END                         = 255
}dhcp_option_type_t;

typedef enum {
  ETHERNET_10Mb     = 1,
  IEEE_802_NW       = 6
  
}dhcp_arp_hdr_type_t;


typedef struct {
  int fd;
  unsigned char dhcp_server_mac[6];
  unsigned char dhcp_client_mac[6];
  int           packet_type;
  dhcp_ipaddr_t dhcp_server_ip;
  unsigned short dhcp_server_port;
  char          dhcp_eth_name[16];
  dhcp_ipaddr_t dhcp_gw_ip;
  char          dhcp_server_name[32];
  dhcp_ipaddr_t subnet_mask;
  dhcp_ipaddr_t dns1;
  dhcp_ipaddr_t dns2;
  dhcp_ipaddr_t ntp_server_ip;
  dhcp_ipaddr_t time_server_ip;
  char          domain_name[32];
  char          host_name[32];
   
  
  /*List of Optional Tag present in OFFER/REQUEST*/
  dhcp_tag_present_t opt_tag;
}dhcp_ctx_t;

/*Function Prototype*/
int dhcp_init (unsigned char *eth_name, 
               unsigned char *dhcp_listen_ip);

int dhcp_process_eht_frame(int fd, 
                           unsigned char *packet_ptr, 
                           unsigned int packet_length);

int dhcp_reply_ARP(int fd, 
                   char *packet_ptr, 
                   unsigned int packet_length);

int dhcp_process_request(int fd, 
                         unsigned char *packet_ptr, 
                         unsigned int packet_length);

int dhcp_build_rsp (unsigned char  dhcp_message_type, 
                    unsigned char *rsp_ptr, 
                    unsigned char *packet_ptr, 
                    unsigned int   packet_length);

int dhcp_process_option(char         *packet_ptr, 
                        unsigned int  packet_length, 
                        unsigned char         *option_ptr, 
                        int           option_len);

int dhcp_OFFER (int fd, 
                unsigned char *packet_ptr, 
                unsigned int   packet_length);

int dhcp_ACK (int fd, 
              unsigned char *packet_ptr, 
              unsigned int packet_length);

unsigned int ip_str_to_int(char *record);

#endif

