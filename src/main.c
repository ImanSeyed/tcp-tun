#include <unistd.h>
#include <stdio.h>
#include <linux/if.h>
#include "ipv4_addr.h"
#include "ipv4_header.h"
#include "tcp_header.h"
#include "types.h"
#include "connections.h"
#include "tun.h"
#include "states.h"

int main()
{
	int nic_fd;
	u8 packet_with_pi[1504];
	struct ipv4_header incoming_ipv4h;
	struct tcp_header incoming_tcph;
	struct connections_hashmap *connections_ht;
	struct TCB starter;
	struct ifreq ifr = { 0 };
	nic_fd = tun_open("tun%d", &ifr);
	connections_ht = connections_create();

	union ipv4_addr tun_ipv4, tun_subnet;
	init_ipv4_addr(&tun_ipv4, 192, 168, 20, 1);
	init_ipv4_addr(&tun_subnet, 255, 255, 255, 0);

	tun_set_ip(nic_fd, &ifr, &tun_ipv4, &tun_subnet);

	for (;;) {
		read(nic_fd, packet_with_pi, sizeof(packet_with_pi));

		/* Ignore everything except IPv4 packets */
		if (packet_with_pi[ETH_TYPE_OFF] != IPV4_PROTO)
			continue;

		u8 *packet = &packet_with_pi[PI_LEN];
		ipv4h_from_buff(&incoming_ipv4h, packet, 0);

		/* Ignore everything except TCP packets */
		if (incoming_ipv4h.protocol != TCP_PROTO)
			continue;

		tcph_from_buff(&incoming_tcph, packet,
			       ((incoming_ipv4h.version_and_ihl.ihl) * 4));

		struct connection_quad new_quad;
		new_quad.src.ip = incoming_ipv4h.src_addr;
		new_quad.dest.ip = incoming_ipv4h.dest_addr;
		new_quad.src.port = incoming_tcph.src_port;
		new_quad.dest.port = incoming_tcph.dest_port;

		u16 data_offset =
			incoming_ipv4h.total_length -
			(((incoming_ipv4h.version_and_ihl.ihl) +
			  incoming_tcph.flags_and_data_offset.data_offset) *
			 4);

		if (connections_entry_is_occupied(connections_ht, &new_quad)) {
			on_packet(nic_fd, &incoming_ipv4h, &incoming_tcph,
				  &starter, packet + data_offset);
		} else {
			starter = accept_request(nic_fd, &incoming_ipv4h,
						 &incoming_tcph);
			connections_set(connections_ht, &new_quad,
					starter.state);
		}
		connections_dump(connections_ht);
		printf("==============================\n");
	}
}
