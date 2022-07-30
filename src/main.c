#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "ipv4_funcs.h"
#include "tcp_funcs.h"
#include "types.h"
#include "endian.h"
#include "print.h"

/* 
 * 2 bytes for ether_flags, 2 bytes for ether_type
 * according to tuntap.txt in Linux kernel documentations 
 * */
#define RAW_OFFSET 4

int tun_open(char *devname)
{
	struct ifreq ifr;
	int fd, error;
	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("open /dev/net/tun");
		exit(EXIT_FAILURE);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	strncpy(ifr.ifr_name, devname, IFNAMSIZ);

	if ((error = ioctl(fd, TUNSETIFF, &ifr)) == -1) {
		perror("ioctl set TUN flag");
		close(fd);
		exit(EXIT_FAILURE);
	}
	return fd;
}

int main()
{
	int nic, nbytes;
	uint8_t buffer[1504];
	uint16_t eth_flags;
	uint16_t eth_type;
	struct ipv4_header input_ipv4_header;
	struct tcp_header input_tcp_header;

	nic = tun_open("tun0");
	for (;;) {
		nbytes = read(nic, buffer, sizeof(buffer));
		eth_flags = convert_from_be16(buffer[0], buffer[1]);
		eth_type = convert_from_be16(buffer[2], buffer[3]);

		/* Ignore everything except IPv4 packets */
		if (eth_type != 0x0800)
			continue;

		parse_ipv4_header(&input_ipv4_header, buffer, RAW_OFFSET);

		/* Ignore everything except TCP packets */
		if (input_ipv4_header.protocol != 0x06)
			continue;

		parse_tcp_header(&input_tcp_header, buffer,
				 RAW_OFFSET + (input_ipv4_header.ihl * 4));

		print_addr(input_ipv4_header.src_addr,
			   input_tcp_header.src_port);
		printf(" -> ");
		print_addr(input_ipv4_header.dest_addr,
			   input_tcp_header.dest_port);
		printf("\n");
		print_bytes(buffer, RAW_OFFSET, nbytes);
	}
}
