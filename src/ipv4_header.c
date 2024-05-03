#include <string.h>
#include <assert.h>
#include "ipv4_addr.h"
#include "ipv4_header.h"
#include "in_cksum.h"
#include "endian.h"
#include "types.h"

void ipv4h_from_buff(struct ipv4_header *ipv4h, const u8 *buffer, size_t start)
{
	const u8 *header_ptr = buffer + start;

	ipv4h->version_and_ihl.byte_value = header_ptr[VERSION_OFF];
	ipv4h->type_of_service = header_ptr[TOS_OFF];
	ipv4h->total_length = get_swapped_endian16(&header_ptr[LENGTH_OFF]);
	ipv4h->identification = get_swapped_endian16(&header_ptr[IDENT_OFF]);
	ipv4h->flags_and_fragment.byte_value =
		get_swapped_endian16(&header_ptr[IP_FLAGS_OFF]);
	ipv4h->ttl = header_ptr[TTL_OFF];
	ipv4h->protocol = header_ptr[PROTO_OFF];
	ipv4h->checksum = get_swapped_endian16(&header_ptr[IP_CHECKSUM_OFF]);
	ipv4h->src_addr.byte_value =
		get_swapped_endian32(&header_ptr[SRC_ADDR_OFF]);
	ipv4h->dest_addr.byte_value =
		get_swapped_endian32(&header_ptr[DST_ADDR_OFF]);

	assert(ipv4h_size(ipv4h) >= 20);
}

void init_ipv4h(struct ipv4_header *ipv4h, u16 total_length, u8 time_to_live,
		u8 protocol, union ipv4_addr src_addr,
		union ipv4_addr dest_addr)
{
	ipv4h->version_and_ihl.version = 0x4;
	ipv4h->version_and_ihl.ihl = IHL_MINIMUM_SIZE;
	ipv4h->type_of_service = 0;
	ipv4h->total_length = total_length;
	ipv4h->identification = 0;
	ipv4h->flags_and_fragment.flags = 0x2; /* Don't fragment */
	ipv4h->ttl = time_to_live;
	ipv4h->protocol = protocol;
	ipv4h->checksum = 0;
	ipv4h->src_addr = src_addr;
	ipv4h->dest_addr = dest_addr;
}

void ipv4h_to_buff(const struct ipv4_header *ipv4h, u8 *buffer, size_t start)
{
	u8 *header_ptr = buffer + start;

	header_ptr[VERSION_OFF] = ipv4h->version_and_ihl.byte_value;
	header_ptr[TOS_OFF] = ipv4h->type_of_service;
	store_swapped_endian16(ipv4h->total_length, &header_ptr[LENGTH_OFF]);
	store_swapped_endian16(ipv4h->identification, &header_ptr[IDENT_OFF]);
	store_swapped_endian16(ipv4h->flags_and_fragment.byte_value,
			       &header_ptr[IP_FLAGS_OFF]);
	header_ptr[TTL_OFF] = ipv4h->ttl;
	header_ptr[PROTO_OFF] = ipv4h->protocol;
	store_swapped_endian32(ipv4h->src_addr.byte_value,
			       &header_ptr[SRC_ADDR_OFF]);
	store_swapped_endian32(ipv4h->dest_addr.byte_value,
			       &header_ptr[DST_ADDR_OFF]);
}

u16 ipv4h_checksum(const u8 *ipv4_ptr, size_t len)
{
	struct cksum_vec vec[1];

	vec[0].ptr = ipv4_ptr;
	vec[0].len = len;

	return in_cksum(vec, 1);
}
