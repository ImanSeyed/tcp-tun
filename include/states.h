#pragma once

#include <stdbool.h>
#include "ipv4_header.h"
#include "tcp_header.h"
#include "types.h"

#define ENUMERATE_STATES()              \
	ENUMERATE_STATES_IMPL(SYNRECVD) \
	ENUMERATE_STATES_IMPL(ESTAB)    \
	ENUMERATE_STATES_IMPL(FINWAIT1) \
	ENUMERATE_STATES_IMPL(FINWAIT2) \
	ENUMERATE_STATES_IMPL(CLOSING)

enum tcp_state {
#define ENUMERATE_STATES_IMPL(name) name,
	ENUMERATE_STATES()
#undef ENUMERATE_STATES_IMPL
};

/*  
 *  Send Sequence Space (RFC 793 S3.2 Figure 4)
 *
 *             1         2          3          4
 *        ----------|----------|----------|----------
 *               SND.UNA    SND.NXT    SND.UNA
 *                                    +SND.WND
 *
 *  1 - old sequence numbers which have been acknowledged
 *  2 - sequence numbers of unacknowledged data
 *  3 - sequence numbers allowed for new data transmission
 *  4 - future sequence numbers which are not yet allowed
 */

struct send_sequence_space {
	u32 una; /* send unacknowledged */
	u32 nxt; /* send next */
	u16 wnd; /* send window */
	bool up; /* send urgent pointer */
	size_t wl1; /* segment sequence number used for last window update */
	size_t wl2; /* segment acknowledgment number used for last window update */
	u32 iss; /* initial send sequence number */
};

/*  
 *  Receive Sequence Space (RFC 793 S3.2 Figure 5)
 *
 *            1          2          3
 *        ----------|----------|----------
 *               RCV.NXT    RCV.NXT
 *                         +RCV.WND
 *
 *   1 - old sequence numbers which have been acknowledged
 *   2 - sequence numbers allowed for new reception
 *   3 - future sequence numbers which are not yet allowed
 */

struct recv_sequence_space {
	u32 nxt; /* receive next */
	u16 wnd; /* receive window */
	bool up; /* receive urgent pointer */
	u32 irs; /* initial receive sequence number */
};

struct TCB {
	enum tcp_state state;
	struct send_sequence_space send;
	struct recv_sequence_space recv;
};

struct TCB *accept_request(int nic_fd, struct ipv4_header *ipv4h,
			   struct tcp_header *tcph);
void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	       struct TCB *ctrl_block, u8 *data);
