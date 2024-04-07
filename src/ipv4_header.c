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
	header->version_and_ihl.byte_value = header_ptr[0];
	header->type_of_service = header_ptr[1];
	header->total_length = get_toggle_endian16(header_ptr + 2);
	header->identification = get_toggle_endian16(header_ptr + 4);
	header->flags_and_fragment.byte_value =
		get_toggle_endian16(header_ptr + 6);
	header->ttl = header_ptr[8];
	header->protocol = header_ptr[9];
	header->checksum = get_toggle_endian16(header_ptr + 10);
	header->src_addr.byte_value =
		get_ipv4addr_toggle_endian32(header_ptr + 12);
	header->dest_addr.byte_value =
		get_ipv4addr_toggle_endian32(header_ptr + 16);

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
	header_ptr[0] = header->version_and_ihl.byte_value;
	header_ptr[1] = header->type_of_service;
	write_toggle_endian16(header->total_length, header_ptr + 2);
	write_toggle_endian16(header->identification, header_ptr + 4);
	write_toggle_endian16(header->flags_and_fragment.byte_value,
			      header_ptr + 6);
	header_ptr[8] = header->ttl;
	header_ptr[9] = header->protocol;
	write_ipv4addr_toggle_endian32(header->src_addr.byte_value,
				       header_ptr + 12);
	write_ipv4addr_toggle_endian32(header->dest_addr.byte_value,
				       header_ptr + 16);
}

u16 ipv4h_checksum(const u8 *ipv4_ptr, size_t len)
{
	struct cksum_vec vec[1];
	vec[0].ptr = ipv4_ptr;
	vec[0].len = len;
	return __builtin_bswap16(in_cksum(vec, 1));
}
