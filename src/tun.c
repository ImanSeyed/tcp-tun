#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "ipv4_addr.h"
#include "tun.h"

int tun_open(char *devname, struct ifreq *ifr)
{
	int nic_fd;

	if ((nic_fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("open /dev/net/tun");
		exit(EXIT_FAILURE);
	}

	ifr->ifr_flags = IFF_TUN;
	strncpy(ifr->ifr_name, devname, IFNAMSIZ);

	if (ioctl(nic_fd, TUNSETIFF, ifr) == -1) {
		perror("ioctl set TUN flag");
		close(nic_fd);
		exit(EXIT_FAILURE);
	}

	return nic_fd;
}

int tun_set_ip(int nic_fd, struct ifreq *ifr, union ipv4_addr *ip_addr,
	       union ipv4_addr *subnet)
{
	assert(nic_fd != -1 && ip_addr != NULL && ip_addr->byte_value != 0);

	int ret;
	int sockfd;
	struct sockaddr_in *addr;
	char *ipv4_addr_str;
	char *ipv4_subnet_str;

	ret = 0;
	sockfd = -1;
	addr = (struct sockaddr_in *)&ifr->ifr_addr;
	ifr->ifr_addr.sa_family = AF_INET;
	ipv4_addr_str = ipv4_addr_to_str(ip_addr);
	ipv4_subnet_str = ipv4_addr_to_str(subnet);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		goto failed;

	inet_pton(AF_INET, ipv4_addr_str, &addr->sin_addr);
	if (ioctl(sockfd, SIOCSIFADDR, (void *)ifr) == -1)
		goto failed;

	inet_pton(AF_INET, ipv4_subnet_str, &addr->sin_addr);
	if (ioctl(sockfd, SIOCSIFNETMASK, ifr) == -1)
		goto failed;

	ifr->ifr_flags |= (IFF_UP | IFF_RUNNING);
	if (ioctl(sockfd, SIOCSIFFLAGS, ifr) == -1)
		goto failed;

	goto out;
failed:
	perror("tun_set_ip");
	ret = -1;
out:
	if (sockfd != -1)
		close(sockfd);

	free(ipv4_addr_str);
	free(ipv4_subnet_str);

	return ret;
}

void tun_close(int fd)
{
	if (fd > 0)
		close(fd);
}
