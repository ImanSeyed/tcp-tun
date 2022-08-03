#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "utility/tcp_utility.h"
#include "utility/ipv4_utility.h"
#include "common/types.h"
#include "states.h"

#define TCP_PROTO 0x06

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 uint8_t *buffer)
{
	size_t ipv4h_len = (ipv4h->ihl * 4) + ipv4h->options_len;
	size_t buffer_len = 0;
	buffer_len += dump_ipv4_header(ipv4h, buffer);
	buffer_len += dump_tcp_header(tcph, buffer, ipv4h_len);
	if (write(nic_fd, buffer, buffer_len) == -1)
		perror("write on tun");
}

void accept(int nic_fd, enum tcp_state state, struct ipv4_header *ipv4h,
	    struct tcp_header *tcph)
{
	struct TCB starter = { .state = SynRecvd,
			       .send = { .iss = 0,
					 .una = 0,
					 .nxt = 1,
					 .wnd = 10,
					 .up = false,
					 .wl1 = 0,
					 .wl2 = 0 },
			       .recv = { .irs = tcph->seq_number,
					 .nxt = tcph->seq_number + 1,
					 .wnd = tcph->win_size,
					 .up = false } };

	if (!tcph->is_syn) {
		/* only expected SYN packet */
		return;
	}

	/* start establishing a connection */
	struct tcp_header *syn_ack;
	struct ipv4_header *ip;
	uint8_t buffer[1500];

	/* write out the headers */
	fill_tcp_header(syn_ack, tcph->dest_port, tcph->src_port,
			starter.send.iss, starter.send.wnd);
	syn_ack->ack_number = tcph->seq_number + 1;

	syn_ack->is_syn = true;
	syn_ack->is_ack = true;
	fill_ipv4_header(ip, (syn_ack->data_offset * 4) + syn_ack->options_len,
			 64, TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, ip, syn_ack, buffer);
}

void on_packet(int nic_fd, enum tcp_state state, struct ipv4_header *ipv4h,
	       struct tcp_header *tcph)
{
}
