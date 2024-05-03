#pragma once

#include <sys/ioctl.h>
#include <linux/if.h>
#include "ipv4_addr.h"

/*
 * 2 bytes for ether_flags and 2 bytes for ether_type
 * according to tuntap.txt in section 3.2 "Frame format"
 * in this case, "00 00 08 00" is needed for an IP packet
 */
#define PI_LEN 4
#define ETH_FLAGS_OFF 0
#define ETH_TYPE_OFF 2

int tun_open(char *devname, struct ifreq *ifr);
int tun_set_ip(int nic_fd, struct ifreq *ifr, union ipv4_addr *ip_addr,
	       union ipv4_addr *subnet);
