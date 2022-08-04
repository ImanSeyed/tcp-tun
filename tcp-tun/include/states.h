#ifndef __TCP_TUN_STATES_H__
#define __TCP_TUN_STATES_H__
#include <stdbool.h>
#include <stdint.h>
#include "common/types.h"

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
	uint32_t una; /* send unacknowledged */
	uint32_t nxt; /* send next */
	uint16_t wnd; /* send window */
	bool up; /* send urgent pointer */
	size_t wl1; /* segment sequence number used for last window update */
	size_t wl2; /* segment acknowledgment number used for last window update */
	uint32_t iss; /* initial send sequence number */
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
	uint32_t nxt; /* receive next */
	uint16_t wnd; /* receive window */
	bool up; /* receive urgent pointer */
	uint32_t irs; /* initial receive sequence number */
};

struct TCB {
	enum tcp_state state;
	struct send_sequence_space send;
	struct recv_sequence_space recv;
};

void accept(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph);
void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph);
void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 uint8_t *buffer);

#endif
