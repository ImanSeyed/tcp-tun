#include <unistd.h>
#include <stdio.h>
#include <linux/if.h>
#include "ipv4_addr.h"
#include "ipv4_header.h"
#include "tcp_utility.h"
#include "types.h"
#include "connections.h"
#include "tun.h"
#include "states.h"

int main()
{
	int nic;
	u8 buffer[1500];
	struct ipv4_header input_ipv4_header;
	struct tcp_header input_tcp_header;
	struct connections_hashmap *connections_ht;
	struct TCB starter;
	struct ifreq ifr = { 0 };
	nic = tun_open("tun0", &ifr);
	connections_ht = connections_create();

	union ipv4_addr ipv4, subnet;
	init_ipv4_addr(&ipv4, 192, 168, 20, 1);
	init_ipv4_addr(&subnet, 255, 255, 255, 0);

	tun_set_ip(nic, &ifr, &ipv4, &subnet);

	for (;;) {
		read(nic, buffer, sizeof(buffer));

		/* Ignore everything except IPv4 packets */
		if (!(buffer[0] >= 0x45 && buffer[0] <= 0x4f))
			continue;

		ipv4h_from_buff(&input_ipv4_header, buffer, 0);

		/* Ignore everything except TCP packets */
		if (input_ipv4_header.protocol != TCP_PROTO)
			continue;

		parse_tcp_header(&input_tcp_header, buffer,
				 ((input_ipv4_header.version_and_ihl.ihl) * 4));

		struct connection_quad new_quad;
		new_quad.src.ip = input_ipv4_header.src_addr;
		new_quad.dest.ip = input_ipv4_header.dest_addr;
		new_quad.src.port = input_tcp_header.src_port;
		new_quad.dest.port = input_tcp_header.dest_port;

		u16 data_offset = input_ipv4_header.total_length -
				  (((input_ipv4_header.version_and_ihl.ihl) +
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
