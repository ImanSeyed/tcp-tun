#ifndef __TCP_TUN_TUN_H__
#define __TCP_TUN_TUN_H__

#include <sys/ioctl.h>
#include <linux/if.h>
#include "ipv4_addr.h"

int tun_open(char *devname, struct ifreq *ifr);
int tun_set_ip(int nic_fd, struct ifreq *ifr, union ipv4_addr *ip_addr,
	       union ipv4_addr *subnet);

#endif
