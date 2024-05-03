#include <unistd.h>
#include <stdio.h>
#include <linux/if.h>
#include "ipv4_addr.h"
#include "ipv4_header.h"
#include "tcp_header.h"
#include "types.h"
#include "conn_table.h"
#include "tun.h"
#include "states.h"

int main()
{
	int nic_fd;
	u8 *packet;
	u8 packet_with_pi[1504];
	u16 tcp_data_len;
	union ipv4_addr tun_ipv4, tun_subnet;
	struct ipv4_header incoming_ipv4h;
	struct tcp_header incoming_tcph;
	struct conn_table *conn_tbl;
	struct conn_quad current_quad;
	struct ifreq ifr = { 0 };

	nic_fd = tun_open("tun%d", &ifr);
	conn_tbl = init_conn_table();
	init_ipv4_addr(&tun_ipv4, 192, 168, 20, 1);
	init_ipv4_addr(&tun_subnet, 255, 255, 255, 0);
	tun_set_ip(nic_fd, &ifr, &tun_ipv4, &tun_subnet);

	for (;;) {
		read(nic_fd, packet_with_pi, sizeof(packet_with_pi));

		/* Ignore everything except IPv4 packets */
		if (packet_with_pi[ETH_TYPE_OFF] != IPV4_PROTO)
			continue;

		packet = &packet_with_pi[PI_LEN];
		ipv4h_from_buff(&incoming_ipv4h, packet, 0);

		/* Ignore everything except TCP packets */
		if (incoming_ipv4h.protocol != TCP_PROTO)
			continue;

		tcph_from_buff(&incoming_tcph, packet,
			       ipv4h_size(&incoming_ipv4h));

		current_quad = (struct conn_quad){
			.src.ip = incoming_ipv4h.src_addr,
			.dest.ip = incoming_ipv4h.dest_addr,
			.src.port = incoming_tcph.src_port,
			.dest.port = incoming_tcph.dest_port,
		};

		tcp_data_len = data_size(&incoming_ipv4h, &incoming_tcph);

		if (conn_table_key_exist(conn_tbl, &current_quad)) {
			struct TCB *ctrl_block =
				conn_table_get(conn_tbl, &current_quad);
			on_packet(nic_fd, &incoming_ipv4h, &incoming_tcph,
				  ctrl_block, packet + tcp_data_len);
		} else {
			struct TCB *new_ctrl_block = accept_request(
				nic_fd, &incoming_ipv4h, &incoming_tcph);
			conn_table_insert(conn_tbl, &current_quad,
					  new_ctrl_block);
			conn_table_dump(conn_tbl);
			printf("==============================\n");
		}
	}
}
