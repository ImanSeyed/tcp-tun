#ifndef __TCP_TUN_SEND_H__
#define __TCP_TUN_SEND_H__
#include "types.h"
#include "states.h"
#include "tcp_header.h"
#include "ipv4_header.h"

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 u8 *buffer, struct TCB *ctrl_block);
void send_rst(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *ctrl_block);
void send_fin_ack(int nic_fd, struct ipv4_header *ipv4h,
		  struct tcp_header *tcph, struct TCB *ctrl_block);
#endif
