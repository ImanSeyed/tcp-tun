#include <stdbool.h>
#include <assert.h>
#include "ipv4_header.h"
#include "tcp_header.h"
#include "types.h"
#include "states.h"
#include "send.h"

bool is_between_wrapped(u32 start, u32 x, u32 end)
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

bool is_synchronized(const struct TCB *starter)
{
	if (starter->state == SYNRECVD)
		return false;
	else
		return true;
}

struct TCB accept_request(int nic_fd, struct ipv4_header *ipv4h,
			  struct tcp_header *tcph)
{
	struct TCB starter = {
		.state = SYNRECVD,
		.send = { .iss = 0,
			  .una = 0,
			  .nxt = 0,
			  .wnd = 10,
			  .up = false,
			  .wl1 = 0,
			  .wl2 = 0 },
		.recv = { .irs = tcph->seq_number,
			  .nxt = tcph->seq_number + 1,
			  .wnd = tcph->win_size,
			  .up = false },
	};

	starter.send.una = starter.send.iss;
	starter.send.nxt = starter.send.iss;

	/* start establishing a connection */
	struct tcp_header syn_ack;
	struct ipv4_header ip;
	u8 buffer[1500];

	/* write out the headers */
	init_tcph(&syn_ack, tcph->dest_port, tcph->src_port, SYN | ACK,
		  starter.send.iss, tcph->seq_number + 1, starter.send.wnd);
	init_ipv4h(&ip, 20 + (syn_ack.flags_and_data_offset.data_offset * 4),
		   64, TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &ip, &syn_ack, buffer);

	return starter;
}

void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	       struct TCB *starter, u8 *data)
{
	/* first, check that sequence numbers are valid (RFC 793 S3.3) */
	u32 segment_len = tcph->flags_and_data_offset.data_offset * 4;
	u16 data_len = ipv4h->total_length -
		       ((ipv4h->version_and_ihl.ihl) * 4) - segment_len;
	u16 tcph_flags = tcph->flags_and_data_offset.flags;
	if (tcph_flags & FIN)
		++segment_len;
	if (tcph_flags & SYN)
		++segment_len;

	if (segment_len == 0) {
		/* zero-length segment has separate rules for acceptance */
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
					     tcph->seq_number + segment_len - 1,
					     starter->recv.nxt +
						     starter->recv.wnd))
			return;
	}

	if (!(tcph_flags & ACK)) {
		if (tcph_flags & SYN) {
			assert(data_len == 0);
			++starter->recv.nxt;
		}
		return;
	}

	/* acceptable ACK check (SND.UNA < SEG.ACK =< SND.NXT) */
	/* TODO: handle synchronized RST */
	if (!is_between_wrapped(starter->send.una, tcph->ack_number,
				starter->send.nxt + 1)) {
		if (!is_synchronized(starter)) {
			/* according to the Reset Generation, we should send RST */
			send_rst(nic_fd, ipv4h, tcph, starter);
		}
		return;
	}

	starter->send.una = tcph->ack_number;

	starter->recv.nxt = tcph->seq_number + segment_len;
	/* TODO: make sure this get ACKed */

	switch (starter->state) {
	case SYNRECVD:
		/* expect to get an ACK for our SYN-ACK */
		if (!(tcph_flags & ACK))
			return;
		/* must have ACKed our SYN, since we detected at least one ACKed
		 * byte, and we have only sent one byte (the SYN)
		 * */
		starter->state = ESTAB;
		/* now let's terminate the connection */
		/* TODO: needs to be stored in the retransmission queue */
		send_fin(nic_fd, ipv4h, tcph, starter);
		starter->state = FINWAIT1;
		break;
	case ESTAB:
		/* UNIMPLEMENTED */
	case FINWAIT1:
		if (!(tcph_flags & FIN)) {
			/* UNIMPLEMENTED */
		}
		/* must send ACKed our FIN, since we detected at least one ACKed
		 * byte, and we have only sent one byte (the FIN)
		 * */
		starter->state = FINWAIT2;
		break;
	case FINWAIT2:
		if (!(tcph_flags & FIN)) {
			/* unimplemented */
		}
		/* must send ACKed our FIN, since we detected at least one ACKed
		 * byte, and we have only sent one byte (the FIN)
		 * */
		starter->state = CLOSING;
		break;
	case CLOSING:
		break;
	default:
		/* MUST NOT be another case */
		assert(false);
	}
}
