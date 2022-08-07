#ifndef __TCP_TUN_TCP_UTILITY_H__
#define __TCP_TUN_TCP_UTILITY_H__
#include <sys/types.h>
#include <stdint.h>
#include "../common/types.h"

void parse_tcp_header(struct tcp_header *header, uint8_t *buffer, size_t start);
void fill_tcp_header(struct tcp_header *header, uint16_t src_port,
		     uint16_t dest_port, uint32_t seq_number,
		     uint16_t win_size);
size_t dump_tcp_header(struct tcp_header *header, uint8_t *buffer,
		       size_t start);

#endif
