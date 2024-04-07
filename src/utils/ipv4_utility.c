#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils/ipv4_utility.h"
#include "utils/in_cksum.h"
#include "common/endian.h"
#include "common/types.h"

#define IHL_MINIMUM_SIZE 5

void parse_ipv4_header(struct ipv4_header *header, const u8 *buffer,
		       size_t start)
{
	const u8 *header_ptr = buffer + start;
	header->version_and_ihl = header_ptr[0];
	header->type_of_service = header_ptr[1];
	header->total_length = get_toggle_endian16(header_ptr + 2);
	header->identification = get_toggle_endian16(header_ptr + 4);
	header->flags = header_ptr[6] >> 13;
	u16 fragment_offset;
	memcpy(&fragment_offset, header_ptr + 6, sizeof(u16));
	header->fragment_offset = fragment_offset & 0x1fff;
	header->ttl = header_ptr[8];
	header->protocol = header_ptr[9];
	header->checksum = get_toggle_endian16(header_ptr + 10);
	header->src_addr.byte_value =
		get_ipv4addr_toggle_endian32(header_ptr + 12);
	header->dest_addr.byte_value =
		get_ipv4addr_toggle_endian32(header_ptr + 16);

	assert((header->version_and_ihl & 0x0f) >= 5);
}

void fill_ipv4_header(struct ipv4_header *header, u16 total_length,
		      u8 time_to_live, u8 protocol, union ipv4_addr src_addr,
		      union ipv4_addr dest_addr)
{
	header->version_and_ihl = (0x4 << 4) | IHL_MINIMUM_SIZE;
	header->type_of_service = 0;
	header->total_length = total_length;
	header->identification = 0;
	header->flags = 0x2; /* Don't fragment */
	header->fragment_offset = 0;
	header->ttl = time_to_live;
	header->protocol = protocol;
	header->checksum = 0;
	header->src_addr = src_addr;
	header->dest_addr = dest_addr;
}

size_t dump_ipv4_header(const struct ipv4_header *header, u8 *buffer,
			size_t start)
{
	u8 *header_ptr = buffer + start;
	header_ptr[0] = header->version_and_ihl;
	header_ptr[1] = header->type_of_service;
	write_toggle_endian16(header->total_length, header_ptr + 2);
	write_toggle_endian16(header->identification, header_ptr + 4);
	u16 tmp = header->flags;
	tmp = tmp << 13 | header->fragment_offset;
	write_toggle_endian16(tmp, header_ptr + 6);
	header_ptr[8] = header->ttl;
	header_ptr[9] = header->protocol;
	write_ipv4addr_toggle_endian32(header->src_addr.byte_value,
				       header_ptr + 12);
	write_ipv4addr_toggle_endian32(header->dest_addr.byte_value,
				       header_ptr + 16);

	// let's just return 20 for now
	return 20;
}

u16 ipv4_checksum(const u8 *ipv4_ptr, size_t len)
{
	struct cksum_vec vec[1];
	vec[0].ptr = ipv4_ptr;
	vec[0].len = len;
	return __builtin_bswap16(in_cksum(vec, 1));
}

void init_ipv4_addr(union ipv4_addr *addr, u8 a, u8 b, u8 c, u8 d)
{
	assert(addr != NULL);

	addr->first = a;
	addr->second = b;
	addr->third = c;
	addr->fourth = d;
}

char *ipv4_addr_to_str(union ipv4_addr *addr)
{
	assert(addr != NULL);

	char *ipv4_addr_str = calloc(16, sizeof(char));
	if (ipv4_addr_str == NULL) {
		perror("ipv4_addr_to_str");
		return NULL;
	}

	sprintf(ipv4_addr_str, "%u.%u.%u.%u", addr->first, addr->second,
		addr->third, addr->fourth);
	return ipv4_addr_str;
}
