#ifndef __TCP_TUN_IPV4_UTILITY_H__
#define __TCP_TUN_IPV4_UTILITY_H__
#include <sys/types.h>
#include <stdint.h>
#include "../common/types.h"

void parse_ipv4_header(struct ipv4_header *header, uint8_t *buffer,
		       size_t start);
void fill_ipv4_header(struct ipv4_header *header, uint16_t total_length,
		      uint8_t time_to_live, uint8_t protocol,
		      union ipv4_addr src_addr, union ipv4_addr dest_addr);
size_t dump_ipv4_header(struct ipv4_header *header, uint8_t *buffer);

#endif
