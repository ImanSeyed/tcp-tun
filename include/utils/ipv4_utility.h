#ifndef __TCP_TUN_IPV4_UTILITY_H__
#define __TCP_TUN_IPV4_UTILITY_H__
#include <sys/types.h>
#include <stdint.h>
#include "common/types.h"

void parse_ipv4_header(struct ipv4_header *header, const u8 *buffer,
		       size_t start);
void fill_ipv4_header(struct ipv4_header *header, u16 total_length,
		      u8 time_to_live, u8 protocol, union ipv4_addr src_addr,
		      union ipv4_addr dest_addr);
size_t dump_ipv4_header(const struct ipv4_header *header, u8 *buffer,
			size_t start);
u16 ipv4_checksum(const u8 *ipv4_ptr, size_t len);
void init_ipv4_addr(union ipv4_addr *addr, u8 a, u8 b, u8 c, u8 d);
char *ipv4_addr_to_str(union ipv4_addr *addr);

#endif
