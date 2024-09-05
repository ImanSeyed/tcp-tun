#pragma once

#include "states.h"
#include "packet.h"

void send_packet(int nic_fd, struct packet *pkt, struct TCB *ctrl_block);
void send_rst(int nic_fd, struct packet *recvd_pkt, struct TCB *ctrl_block);
void shutdown_connection(int nic_fd, struct packet *recvd_pkt,
			 struct TCB *ctrl_block);
