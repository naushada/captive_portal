#!/bin/sh

TUN=tun0
ADDR=192.168.1.1
WAN=wlan0
DHCPIF=eth0
UAMPORT=3990

iptables -I INPUT -i lo -j ACCEPT

#iptables -I INPUT -i $TUN --dst $ADDR -j DROP
iptables -I INPUT -i $TUN -p tcp -m tcp --dport $UAMPORT --dst $ADDR -j ACCEPT
iptables -I INPUT -i $TUN -p udp -d 255.255.255.255 --destination-port 67:68 -j ACCEPT
iptables -I INPUT -i $TUN -p udp -d $ADDR --destination-port 67:68 -j ACCEPT
iptables -I INPUT -i $TUN -p udp --dst $ADDR --dport 53 -j ACCEPT
#iptables -I INPUT -i $TUN -p icmp --dst $ADDR -j ACCEPT
iptables -I INPUT -i $TUN -p icmp -j ACCEPT

iptables -I INPUT -i $DHCPIF -j DROP

iptables -I OUTPUT -o lo -j ACCEPT

#Forwarding Rule
iptables -I FORWARD -i $DHCPIF -j DROP
iptables -I FORWARD -o $DHCPIF -j DROP
iptables -I FORWARD -i $TUN -j ACCEPT
iptables -I FORWARD -o $TUN -j ACCEPT

#iptables -I FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
#iptables -I FORWARD -t mangle -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

iptables -I FORWARD -i $TUN \! -o $WAN -j DROP
iptables -I FORWARD -i $TUN -o $WAN -j ACCEPT
iptables -I POSTROUTING -t nat -o $WAN -j MASQUERADE
