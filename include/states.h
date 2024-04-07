#ifndef __TCP_TUN_STATES_H__
#define __TCP_TUN_STATES_H__
#include <stdbool.h>
#include "ipv4_header.h"
#include "types.h"

/*  Send Sequence Space (RFC 793 53.2 Figure 4)
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
 *  */

struct send_sequence_space {
	u32 una; /* send unacknowledged */
	u32 nxt; /* send next */
	u16 wnd; /* send window */
	bool up; /* send urgent pointer */
	size_t wl1; /* segment sequence number used for last window update */
	size_t wl2; /* segment acknowledgment number used for last window update */
	u32 iss; /* initial send sequence number */
};

/*  Receive Sequence Space (RFC 793 53.2 Figure 5)
 *
 *            1          2          3
 *        ----------|----------|----------
 *               RCV.NXT    RCV.NXT
 *                         +RCV.WND
 *
 *   1 - old sequence numbers which have been acknowledged
 *   2 - sequence numbers allowed for new reception
 *   3 - future sequence numbers which are not yet allowed
 * */

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

struct TCB accept_request(int nic_fd, struct ipv4_header *ipv4h,
			  struct tcp_header *tcph);
void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	       struct TCB *starter, u8 *data);
bool is_between_wrapped(u32 start, u32 x, u32 end);
bool is_synchronized(const struct TCB *starter);

#endif
