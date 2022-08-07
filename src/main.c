#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include "../include/utils/ipv4_utility.h"
#include "../include/utils/tcp_utility.h"
#include "../include/common/endian.h"
#include "../include/common/types.h"
#include "../include/common/print.h"
#include "../include/connections.h"
#include "../include/states.h"

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
	uint16_t eth_type;
	struct ipv4_header input_ipv4_header;
	struct tcp_header input_tcp_header;
	struct connections_hashmap *connections_ht;
	enum tcp_state state;
	nic = tun_open("tun0");
	connections_ht = connections_create();

	for (;;) {
		nbytes = read(nic, buffer, sizeof(buffer));
		/* skipping ethernet flags */
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

		struct connection_quad new_quad;
		new_quad.src.ip = input_ipv4_header.src_addr;
		new_quad.dest.ip = input_ipv4_header.dest_addr;
		new_quad.src.port = input_tcp_header.src_port;
		new_quad.dest.port = input_tcp_header.dest_port;
		state = Listen; /* just a random default state for all network */
		if (connections_entry_is_occupied(connections_ht, &new_quad)) {
			on_packet(nic, &input_ipv4_header, &input_tcp_header);
		} else {
			accept_request(nic, &input_ipv4_header,
				       &input_tcp_header);
			connections_set(connections_ht, &new_quad, state);
		}
		connections_dump(connections_ht);
		printf("==============================\n");
	}
}
