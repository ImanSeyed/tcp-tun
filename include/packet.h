#pragma once

#include "tun.h"
#include <ipv4_header.h>
#include <tcp_header.h>

struct packet {
	u8 *buff; /* packet info + packet */
	u8 *pkt_buff;
	struct ipv4_header *ipv4h;
	struct tcp_header *tcph;
	u8 *tcph_buff;
	u8 *ipv4h_buff;
	u8 *data;
};

static inline size_t pkt_size(struct packet *pkt)
{
	return pkt->ipv4h->total_length + PI_LEN;
}

struct packet *alloc_packet();
void dealloc_packet(struct packet *pkt);
void commit_packet(struct packet *pkt);
