#include <unistd.h>
#include <stdio.h>
#include "packet.h"
#include "ipv4_header.h"
#include "tcp_header.h"
#include "types.h"
#include "states.h"
#include "send.h"

void send_packet(int nic_fd, struct packet *pkt, struct TCB *ctrl_block)
{
	u16 flags;

	commit_packet(pkt);
	flags = tcph_flags(pkt->tcph);

	if (flags & FIN)
		ctrl_block->send.nxt++;

	/* write the packet info + the packet over the tunnel device */
	if (write(nic_fd, pkt->buff, pkt_size(pkt)) == -1)
		perror("write over tun");

	// TODO: implement a queue to store sent *pkt*s for retransmission
	dealloc_packet(pkt);
}

void send_rst(int nic_fd, struct packet *recvd_pkt, struct TCB *ctrl_block)
{
	struct packet *pkt = alloc_packet();
	struct tcp_header *recvd_tcph;
	struct ipv4_header *recvd_ipv4h;

	recvd_tcph = recvd_pkt->tcph;
	recvd_ipv4h = recvd_pkt->ipv4h;

	init_tcph(pkt->tcph, recvd_tcph->dest_port, recvd_tcph->src_port, RST,
		  ctrl_block->send.nxt, 0, ctrl_block->send.wnd);
	init_ipv4h(pkt->ipv4h, 20 + tcph_size(pkt->tcph), TCP_PROTO,
		   recvd_ipv4h->dest_addr, recvd_ipv4h->src_addr);

	send_packet(nic_fd, pkt, ctrl_block);
}

void shutdown_connection(int nic_fd, struct packet *recvd_pkt,
			 struct TCB *ctrl_block)
{
	struct packet *pkt = alloc_packet();
	struct tcp_header *recvd_tcph;
	struct ipv4_header *recvd_ipv4h;

	recvd_tcph = recvd_pkt->tcph;
	recvd_ipv4h = recvd_pkt->ipv4h;

	init_tcph(pkt->tcph, recvd_tcph->dest_port, recvd_tcph->src_port,
		  FIN | ACK, ctrl_block->send.nxt, ctrl_block->recv.nxt,
		  ctrl_block->send.wnd);
	init_ipv4h(pkt->ipv4h, 20 + tcph_size(pkt->tcph), TCP_PROTO,
		   recvd_ipv4h->dest_addr, recvd_ipv4h->src_addr);

	send_packet(nic_fd, pkt, ctrl_block);
}
