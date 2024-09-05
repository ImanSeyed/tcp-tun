#include <unistd.h>
#include <stdio.h>
#include <linux/if.h>
#include "ipv4_addr.h"
#include "ipv4_header.h"
#include "tcp_header.h"
#include "conn_table.h"
#include "packet.h"
#include "tun.h"
#include "states.h"

int main()
{
	int nic_fd;
	struct packet *recvd_pkt;
	struct tcp_header *recvd_tcph;
	struct ipv4_header *recvd_ipv4h;
	struct conn_table *conn_tbl;
	struct conn_quad current_quad;
	struct ifreq ifr = { 0 };
	union ipv4_addr tun_ipv4, tun_subnet;

	recvd_pkt = alloc_packet();
	recvd_ipv4h = recvd_pkt->ipv4h;
	recvd_tcph = recvd_pkt->tcph;
	nic_fd = tun_open("tun%d", &ifr);
	conn_tbl = init_conn_table();
	init_ipv4_addr(&tun_ipv4, 192, 168, 20, 1);
	init_ipv4_addr(&tun_subnet, 255, 255, 255, 0);
	tun_set_ip(nic_fd, &ifr, &tun_ipv4, &tun_subnet);

	for (;;) {
		read(nic_fd, recvd_pkt->buff, TUN_MTU + PI_LEN);

		/* Ignore everything except IPv4 packets */
		if (recvd_pkt->buff[ETH_TYPE_OFF] != IPV4_PROTO)
			continue;

		ipv4h_from_buff(recvd_ipv4h, recvd_pkt->pkt_buff, 0);

		/* Ignore everything except TCP packets */
		if (recvd_ipv4h->protocol != TCP_PROTO)
			continue;

		tcph_from_buff(recvd_tcph, recvd_pkt->pkt_buff,
			       ipv4h_size(recvd_ipv4h));

		current_quad = (struct conn_quad){
			.src.ip = recvd_ipv4h->src_addr,
			.dest.ip = recvd_ipv4h->dest_addr,
			.src.port = recvd_tcph->src_port,
			.dest.port = recvd_tcph->dest_port,
		};

		if (conn_table_key_exist(conn_tbl, &current_quad)) {
			struct TCB *ctrl_block =
				conn_table_get(conn_tbl, &current_quad);
			on_packet(nic_fd, recvd_pkt, ctrl_block);
		} else {
			struct TCB *new_ctrl_block =
				accept_request(nic_fd, recvd_pkt);
			conn_table_insert(conn_tbl, &current_quad,
					  new_ctrl_block);
			conn_table_dump(conn_tbl);
			printf("==============================\n");
		}
	}
}
