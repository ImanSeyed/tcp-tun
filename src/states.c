#include <stdbool.h>
#include <assert.h>
#include "ipv4_header.h"
#include "tcp_header.h"
#include "types.h"
#include "states.h"
#include "send.h"

/* From RFC1323:
 * TCP determines if a data segment is "old" or "new" by testing
 * whether its sequence number is within 2**31 bytes of the left edge
 * of the window, and if it is not, discarding the data as "old".  To
 * insure that new data is never mistakenly considered old and vice-
 * versa, the left edge of the sender's window has to be at most
 * 2**31 away from the right edge of the receiver's window.
 */
static bool wrapping_lt(u32 lhs, u32 rhs)
{
	return (lhs - rhs) > (1 << 31);
}

static bool is_between_wrapped(u32 start, u32 x, u32 end)
{
	return wrapping_lt(start, x) && wrapping_lt(x, end);
}

static bool is_synchronized(const struct TCB *ctrl_block)
{
	return (ctrl_block->state == SYNRECVD) ? false : true;
}

struct TCB accept_request(int nic_fd, struct ipv4_header *ipv4h,
			  struct tcp_header *tcph)
{
	struct TCB ctrl_block = {
		.state = SYNRECVD,
		.send = {
                        .iss = 0,
                        .una = tcph->seq_number,
                        .nxt = ctrl_block.send.una + 1,
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

	ctrl_block.send.nxt = ctrl_block.send.iss;

	/* start establishing a connection */
	struct tcp_header syn_ack;
	struct ipv4_header ip;
	u8 buffer[1500];

	/* write out the headers */
	init_tcph(&syn_ack, tcph->dest_port, tcph->src_port, SYN | ACK,
		  ctrl_block.send.iss, tcph->seq_number + 1,
		  ctrl_block.send.wnd);
	init_ipv4h(&ip, 20 + tcph_size(&syn_ack), 64, TCP_PROTO,
		   ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &ip, &syn_ack, buffer, &ctrl_block);
	return ctrl_block;
}

void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	       struct TCB *ctrl_block, u8 *data)
{
	/* first, check that sequence numbers are valid (RFC 793 S3.3) */
	u32 segment_len = tcph_size(tcph);
	u16 data_len = ipv4h->total_length - (ipv4h_size(ipv4h) + segment_len);
	u16 flags = tcph_flags(tcph);

	if (flags & FIN)
		++segment_len;
	if (flags & SYN)
		++segment_len;

	if (segment_len == 0) {
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
		/* valid segment check:
		 * RCV.NXT =< SEG.SEQ < RCV.NXT + RCV.WND) ||
		 * RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
		 * */
		else if (!is_between_wrapped(
				 ctrl_block->recv.nxt - 1, tcph->seq_number,
				 ctrl_block->recv.nxt + ctrl_block->recv.wnd) &&
			 !is_between_wrapped(ctrl_block->recv.nxt - 1,
					     tcph->seq_number + segment_len - 1,
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

	ctrl_block->recv.nxt = tcph->seq_number + segment_len;

	switch (ctrl_block->state) {
	case SYNRECVD:
		/* expect to get an ACK for our SYN-ACK */
		if (!(flags & ACK))
			return;

		ctrl_block->state = ESTAB;
	case ESTAB:
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
		/* must send ACKed our FIN, since we detected at least one ACKed
		 * byte, and we have only sent one byte (the FIN)
		 * */
		ctrl_block->state = FINWAIT2;
		break;
	case FINWAIT2:
		if (!(flags & FIN)) {
			/* unimplemented */
		}
		/* must send ACKed our FIN, since we detected at least one ACKed
		 * byte, and we have only sent one byte (the FIN)
		 * */
		ctrl_block->state = CLOSING;
		break;
	case CLOSING:
		break;
	default:
		/* MUST NOT be another case */
		assert(false);
	}
}
