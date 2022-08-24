#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include "utils/ipv4_utility.h"
#include "utils/tcp_utility.h"
#include "common/types.h"
#include "connections.h"
#include "states.h"

int tun_open(char *devname)
{
	struct ifreq ifr;
	int fd;
	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("open /dev/net/tun");
		exit(EXIT_FAILURE);
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, devname, IFNAMSIZ);

	if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		perror("ioctl set TUN flag");
		close(fd);
		exit(EXIT_FAILURE);
	}
	return fd;
}

int main()
{
	int nic;
	uint8_t buffer[1500];
	struct ipv4_header input_ipv4_header;
	struct tcp_header input_tcp_header;
	struct connections_hashmap *connections_ht;
	struct TCB starter;
	nic = tun_open("tun0");
	connections_ht = connections_create();

	for (;;) {
		read(nic, buffer, sizeof(buffer));

		/* Ignore everything except IPv4 packets */
		if (!(buffer[0] >= 0x45 && buffer[0] <= 0x4f))
			continue;

		parse_ipv4_header(&input_ipv4_header, buffer, 0);

		/* Ignore everything except TCP packets */
		if (input_ipv4_header.protocol != TCP_PROTO)
			continue;

		parse_tcp_header(&input_tcp_header, buffer,
				  (input_ipv4_header.ihl * 4));

		struct connection_quad new_quad;
		new_quad.src.ip = input_ipv4_header.src_addr;
		new_quad.dest.ip = input_ipv4_header.dest_addr;
		new_quad.src.port = input_tcp_header.src_port;
		new_quad.dest.port = input_tcp_header.dest_port;

		uint16_t data_offset = input_ipv4_header.total_length -
				       ((input_ipv4_header.ihl +
					 input_tcp_header.data_offset) *
					4);

		if (connections_entry_is_occupied(connections_ht, &new_quad)) {
			on_packet(nic, &input_ipv4_header, &input_tcp_header,
				  &starter, buffer + data_offset);
		} else {
			starter = accept_request(nic, &input_ipv4_header,
						 &input_tcp_header);
			connections_set(connections_ht, &new_quad,
					starter.state);
		}
		connections_dump(connections_ht);
		printf("==============================\n");
	}
}
