#ifndef TCP_TUN_SEND_H
#define TCP_TUN_SEND_H
#include <stdint.h>
#include "common/types.h"

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 uint8_t *buffer);
void send_rst(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter);
void send_fin(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter);

#endif