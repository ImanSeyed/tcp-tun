#ifndef __TCP_TUN_IPV4_UTILITY_H__
#define __TCP_TUN_IPV4_UTILITY_H__
#include <sys/types.h>
#include <stdint.h>
#include "common/types.h"

void parse_ipv4_header(struct ipv4_header *header, const uint8_t *buffer,
		       size_t start);
void fill_ipv4_header(struct ipv4_header *header, uint16_t total_length,
		      uint8_t time_to_live, uint8_t protocol,
		      union ipv4_addr src_addr, union ipv4_addr dest_addr);
size_t dump_ipv4_header(const struct ipv4_header *header, uint8_t *buffer,
			size_t start);
uint16_t ipv4_checksum(const uint8_t *ipv4_ptr, size_t len);
void init_ipv4_addr(union ipv4_addr *addr, uint8_t a, uint8_t b, uint8_t c, uint8_t d);
char *ipv4_addr_to_str(union ipv4_addr *addr);

#endif
