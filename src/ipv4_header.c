#include <string.h>
#include <assert.h>
#include "ipv4_addr.h"
#include "ipv4_header.h"
#include "in_cksum.h"
#include "endian.h"
#include "types.h"

#define IHL_MINIMUM_SIZE 5

void ipv4h_from_buff(struct ipv4_header *header, const u8 *buffer, size_t start)
{
	const u8 *header_ptr = buffer + start;
	header->version_and_ihl.byte_value = header_ptr[VERSION_OFF];
	header->type_of_service = header_ptr[TOS_OFF];
	header->total_length = get_swapped_endian16(&header_ptr[LENGTH_OFF]);
	header->identification = get_swapped_endian16(&header_ptr[IDENT_OFF]);
	header->flags_and_fragment.byte_value =
		get_swapped_endian16(&header_ptr[IP_FLAGS_OFF]);
	header->ttl = header_ptr[TTL_OFF];
	header->protocol = header_ptr[PROTO_OFF];
	header->checksum = get_swapped_endian16(&header_ptr[IP_CHECKSUM_OFF]);
	header->src_addr.byte_value =
		get_ipv4addr_swapped_endian32(&header_ptr[SRC_ADDR_OFF]);
	header->dest_addr.byte_value =
		get_ipv4addr_swapped_endian32(&header_ptr[DST_ADDR_OFF]);

	assert((header->version_and_ihl.ihl) >= 5);
}

void init_ipv4h(struct ipv4_header *header, u16 total_length, u8 time_to_live,
		u8 protocol, union ipv4_addr src_addr,
		union ipv4_addr dest_addr)
{
	header->version_and_ihl.version = 0x4;
	header->version_and_ihl.ihl = IHL_MINIMUM_SIZE;
	header->type_of_service = 0;
	header->total_length = total_length;
	header->identification = 0;
	header->flags_and_fragment.flags = 0x2; /* Don't fragment */
	header->ttl = time_to_live;
	header->protocol = protocol;
	header->checksum = 0;
	header->src_addr = src_addr;
	header->dest_addr = dest_addr;
}

void ipv4h_to_buff(const struct ipv4_header *header, u8 *buffer, size_t start)
{
	u8 *header_ptr = buffer + start;
	header_ptr[VERSION_OFF] = header->version_and_ihl.byte_value;
	header_ptr[TOS_OFF] = header->type_of_service;
	store_swapped_endian16(header->total_length, &header_ptr[LENGTH_OFF]);
	store_swapped_endian16(header->identification, &header_ptr[IDENT_OFF]);
	store_swapped_endian16(header->flags_and_fragment.byte_value,
			       &header_ptr[IP_FLAGS_OFF]);
	header_ptr[TTL_OFF] = header->ttl;
	header_ptr[PROTO_OFF] = header->protocol;
	store_ipv4addr_swapped_endian32(header->src_addr.byte_value,
					&header_ptr[SRC_ADDR_OFF]);
	store_ipv4addr_swapped_endian32(header->dest_addr.byte_value,
					&header_ptr[DST_ADDR_OFF]);
}

u16 ipv4h_checksum(const u8 *ipv4_ptr, size_t len)
{
	struct cksum_vec vec[1];
	vec[0].ptr = ipv4_ptr;
	vec[0].len = len;
	return __builtin_bswap16(in_cksum(vec, 1));
}
