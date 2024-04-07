#ifndef __TCP_TUN_TCP_UTILITY_H__
#define __TCP_TUN_TCP_UTILITY_H__
#include "types.h"
#include "ipv4_header.h"

void parse_tcp_header(struct tcp_header *header, const u8 *buffer,
		      size_t start);
void fill_tcp_header(struct tcp_header *header, u16 src_port, u16 dest_port,
		     u32 seq_number, u16 win_size);
size_t dump_tcp_header(const struct tcp_header *header, u8 *buffer,
		       size_t start);
u16 tcp_checksum(const struct tcp_header *tcph, const u8 *pseudo_header);
u8 *get_pseudo_header(const struct ipv4_header *header);

#endif
