#include <stdbool.h>
#include <stdlib.h>
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

struct TCB *accept_request(int nic_fd, struct ipv4_header *ipv4h,
			   struct tcp_header *tcph)
{
	struct tcp_header syn_ack;
	struct ipv4_header ip;
	struct TCB *ctrl_block = malloc(sizeof(struct TCB));

	*ctrl_block = (struct TCB){
		.state = SYNRECVD,
		.send = {
			.iss = 0,
			.una = 0,
			.nxt = 0,
			.wnd = 10,
			.up = false,
			.wl1 = 0,
			.wl2 = 0,
		},
		.recv = {
			.irs = tcph->seq_number,
			.nxt = tcph->seq_number + 1,
			.wnd = tcph->win_size,
			.up = false,
		},
	};

	ctrl_block->send.nxt = ctrl_block->send.iss + 1;

	init_tcph(&syn_ack, tcph->dest_port, tcph->src_port, SYN | ACK,
		  ctrl_block->send.iss, tcph->seq_number + 1,
		  ctrl_block->send.wnd);
	init_ipv4h(&ip, 20 + tcph_size(&syn_ack), 64, TCP_PROTO,
		   ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &ip, &syn_ack, NULL, ctrl_block);

	return ctrl_block;
}

void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	       struct TCB *ctrl_block, u8 *data)
{
	u16 data_len = data_size(ipv4h, tcph);
	u16 flags = tcph_flags(tcph);

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
		send_fin_ack(nic_fd, ipv4h, tcph, ctrl_block);
		ctrl_block->state = FINWAIT1;
		break;
	case FINWAIT1:
		if (!(flags & FIN)) {
			/* UNIMPLEMENTED */
			break;
		}
		send_rst(nic_fd, ipv4h, tcph, ctrl_block);
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
