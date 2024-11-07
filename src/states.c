#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "ipv4_header.h"
#include "tcp_header.h"
#include "types.h"
#include "states.h"
#include "send.h"

/* 
 * From RFC1323:
 * TCP determines if a data segment is "old" or "new" by testing
 * whether its sequence number is within 2**31 bytes of the left edge
 * of the window, and if it is not, discarding the data as "old".  To
 * insure that new data is never mistakenly considered old and vice-
 * versa, the left edge of the sender's window has to be at most
 * 2**31 away from the right edge of the receiver's window.
 */
static bool wrapping_lt(u32 lhs, u32 rhs)
{
	return (lhs - rhs) > (1u << 31);
}

static bool is_between_wrapped(u32 start, u32 x, u32 end)
{
	return wrapping_lt(start, x) && wrapping_lt(x, end);
}

static u32 get_isn(void)
{
	srand(time(NULL));
	return (u32)rand();
}

struct TCB *accept_request(int nic_fd, struct packet *recvd_pkt)
{
	struct packet *syn_ack;
	struct ipv4_header *recvd_ipv4h;
	struct tcp_header *recvd_tcph;
	struct TCB *ctrl_block;

	syn_ack = alloc_packet();
	recvd_ipv4h = recvd_pkt->ipv4h;
	recvd_tcph = recvd_pkt->tcph;
	ctrl_block = malloc(sizeof(struct TCB));

	*ctrl_block = (struct TCB){
		.state = SYNRECVD,
		.send = {
			.iss = get_isn(),
			.una = 0,
			.nxt = 0,
			.wnd = 10,
			.up = false,
			.wl1 = 0,
			.wl2 = 0,
		},
		.recv = {
			.irs = recvd_tcph->seq_number,
			.nxt = recvd_tcph->seq_number + 1,
			.wnd = recvd_tcph->win_size,
			.up = false,
		},
	};

	ctrl_block->send.nxt = ctrl_block->send.iss + 1;

	set_tcph(syn_ack->tcph, recvd_tcph->dest_port, recvd_tcph->src_port,
		 SYN | ACK, ctrl_block->send.iss, recvd_tcph->seq_number + 1,
		 ctrl_block->send.wnd);
	set_ipv4h(syn_ack->ipv4h, 20 + tcph_size(syn_ack->tcph), TCP_PROTO,
		  recvd_ipv4h->dest_addr, recvd_ipv4h->src_addr);
	send_packet(nic_fd, syn_ack, ctrl_block);

	return ctrl_block;
}

void on_packet(int nic_fd, struct packet *recvd_pkt, struct TCB *ctrl_block)
{
	struct tcp_header *tcph;
	struct ipv4_header *ipv4h;
	u16 data_len, flags;

	tcph = recvd_pkt->tcph;
	ipv4h = recvd_pkt->ipv4h;
	data_len = data_size(ipv4h, tcph);
	flags = tcph_flags(tcph);

	if (flags & FIN)
		++data_len;
	if (flags & SYN)
		++data_len;

	if (data_len == 0) {
		/* zero-length segment has separate rules for acceptance */
		if (ctrl_block->recv.wnd == 0) {
			if (tcph->seq_number != ctrl_block->recv.nxt)
				return;
		} else {
			if (!is_between_wrapped(ctrl_block->recv.nxt - 1,
						tcph->seq_number,
						ctrl_block->recv.nxt +
							ctrl_block->recv.wnd))
				return;
		}
	} else {
		if (ctrl_block->recv.wnd == 0)
			return;
		/* 
                 * valid segment check:
		 * RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND) ||
		 * RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
		 */
		else if (!is_between_wrapped(
				 ctrl_block->recv.nxt - 1, tcph->seq_number,
				 ctrl_block->recv.nxt + ctrl_block->recv.wnd) &&
			 !is_between_wrapped(ctrl_block->recv.nxt - 1,
					     tcph->seq_number + data_len - 1,
					     ctrl_block->recv.nxt +
						     ctrl_block->recv.wnd))
			return;
	}

	if (!(flags & ACK)) {
		if (flags & SYN) {
			assert(data_len == 0);
			++ctrl_block->recv.nxt;
		}
		return;
	}

	ctrl_block->recv.nxt = tcph->seq_number + data_len;

	switch (ctrl_block->state) {
	case SYNRECVD:
		/* expect to get an ACK for our SYN-ACK */
		if (!(flags & ACK))
			return;

		if (is_between_wrapped(ctrl_block->send.una - 1,
				       tcph->ack_number,
				       ctrl_block->send.nxt + 1))
			ctrl_block->state = ESTAB;
		/* fall through */
	case ESTAB:
		ctrl_block->send.una = tcph->ack_number;

		/* terminate the connection immediately */
		shutdown_connection(nic_fd, recvd_pkt, ctrl_block);
		ctrl_block->state = FINWAIT1;
		break;
	case FINWAIT1:
		if (!(flags & FIN)) {
			/* UNIMPLEMENTED */
			break;
		}
		send_rst(nic_fd, recvd_pkt, ctrl_block);
		/* 
                 * must send ACKed our FIN, since we detected at least one ACKed
		 * byte, and we have only sent one byte (the FIN)
                 */
		ctrl_block->state = FINWAIT2;
		break;
	case FINWAIT2:
		if (!(flags & FIN)) {
			/* UNIMPLEMENTED */
		}
		/* 
                 * must send ACKed our FIN, since we detected at least one ACKed
		 * byte, and we have only sent one byte (the FIN)
                 */
		ctrl_block->state = CLOSING;
		break;
	case CLOSING:
		break;
	}
}
