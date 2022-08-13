#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "utils/tcp_utility.h"
#include "utils/ipv4_utility.h"
#include "common/endian.h"
#include "common/types.h"
#include "states.h"

#define RAW_OFFSET 4
#define TCP_PROTO 0x06

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 uint8_t *buffer)
{
	memset(buffer, 0, 1500);
	convert_into_be16(0x08, &buffer[2], &buffer[3]);
	size_t ipv4h_len = 0, tcph_len = 0, buffer_len = 0;
	ipv4h_len += dump_ipv4_header(ipv4h, buffer, RAW_OFFSET);
	tcph_len += dump_tcp_header(tcph, buffer, ipv4h_len + RAW_OFFSET);
	/* apparently kernel does calculate checksum for us, no need to do that here */
	buffer_len = RAW_OFFSET + ipv4h_len + tcph_len;
	if (write(nic_fd, buffer, buffer_len) == -1)
		perror("write over tun");
}

bool is_between_wrapped(uint32_t start, uint32_t x, uint32_t end)
{
	if (start == x) {
		return false;
	} else if (start < x) {
		if (end >= start && end <= x)
			return false;
	} else if (start > x) {
		if (!(end < start && end > x))
			return false;
	}
	return true;
}

bool is_synchronized(struct TCB *starter)
{
	if (starter->state == SYNRECVD)
		return true;
	else if (starter->state == ESTAB)
		return false;
}

void send_rst(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter)
{
	uint8_t buffer[1504];
	struct ipv4_header rst_ipv4h;
	struct tcp_header rst_tcph;
	/* write out the headers */
	/* TODO: fix sequence numbers */
	fill_tcp_header(&rst_tcph, tcph->dest_port, tcph->src_port, 0,
			starter->send.wnd);
	rst_tcph.ack_number = 0;
	rst_tcph.is_rst = true;
	fill_ipv4_header(&rst_ipv4h,
			 20 + (rst_tcph.data_offset * 4) + rst_tcph.options_len,
			 64, TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &rst_ipv4h, &rst_tcph, buffer);
}

struct TCB accept_request(int nic_fd, struct ipv4_header *ipv4h,
			  struct tcp_header *tcph)
{
	struct TCB starter = {
		.state = SYNRECVD,
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
			  .up = false },
	};

	/* start establishing a connection */
	struct tcp_header syn_ack;
	struct ipv4_header ip;
	uint8_t buffer[1504];

	/* write out the headers */
	fill_tcp_header(&syn_ack, tcph->dest_port, tcph->src_port,
			starter.send.iss, starter.send.wnd);
	syn_ack.ack_number = tcph->seq_number + 1;

	syn_ack.is_syn = true;
	syn_ack.is_ack = true;
	fill_ipv4_header(&ip,
			 20 + (syn_ack.data_offset * 4) + syn_ack.options_len,
			 64, TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &ip, &syn_ack, buffer);

	return starter;
}

void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	       struct TCB *starter)
{
	uint32_t seg_len = tcph->data_offset * 4;
	if (tcph->is_fin)
		++seg_len;
	if (tcph->is_syn)
		++seg_len;
	/* first, check that sequence numbers are valid (RFC 793 3.3) */
	/* acceptable ACK check (SND.UNA < SEG.ACK =< SND.NXT) */
	/* TODO: handle synchronized RST */
	if (!is_between_wrapped(starter->send.una, tcph->ack_number,
				starter->send.nxt + 1))
		return;

	/* zero-length segment has separate rules for acceptance */
	if (seg_len == 0) {
		if (starter->recv.wnd == 0) {
			if (tcph->seq_number != starter->recv.nxt)
				return;
		} else {
			if (!is_between_wrapped(
				    starter->recv.nxt - 1, tcph->seq_number,
				    starter->recv.nxt + starter->recv.wnd))
				return;
		}
	} else {
		if (starter->recv.wnd == 0)
			return;
		/* valid segment check:
		 * RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND) ||
		 * RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
		 * */
		else if (!is_between_wrapped(
				 starter->recv.nxt - 1, tcph->seq_number,
				 starter->recv.nxt + starter->recv.wnd) &&
			 !is_between_wrapped(starter->recv.nxt - 1,
					     tcph->seq_number + seg_len - 1,
					     starter->recv.nxt +
						     starter->recv.wnd))
			return;
	}

	switch (starter->state) {
	case SYNRECVD:
		/* expect to get an ACK for our SYN-ACK */
		if (!tcph->is_ack)
			return;
		starter->state = ESTAB;
		/* now let's terminate the connection */

		break;
	case ESTAB:
		break;
	}
}