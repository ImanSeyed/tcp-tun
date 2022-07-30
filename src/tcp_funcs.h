#ifndef __TCP_TUN_TCP_FUNCS_H__
#define __TCP_TUN_TCP_FUNCS_H__
#include <stdint.h>
#include <sys/types.h>
#include "types.h"

void parse_tcp_header(struct tcp_header *header, uint8_t *buffer, size_t start);
void fill_tcp_header(struct tcp_header *header, union ipv4_addr src,
		     union ipv4_addr dest, uint32_t seq_number,
		     uint16_t win_size);
#endif
