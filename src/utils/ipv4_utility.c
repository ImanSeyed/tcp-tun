#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "utils/ipv4_utility.h"
#include "utils/in_cksum.h"
#include "common/endian.h"
#include "common/types.h"

#define IHL_MINIMUM_SIZE 5

void parse_ipv4_header(struct ipv4_header *header, uint8_t *buffer,
		       size_t start)
{
	uint8_t *header_ptr = buffer + start;
	header->version = header_ptr[0] >> 4 & 0xf;
	header->ihl = header_ptr[0] & 0xf;
	header->type_of_service = header_ptr[1];
	header->total_length = convert_from_be16(header_ptr + 2);
	header->identification = convert_from_be16(header_ptr + 4);
	header->flags = header_ptr[6] >> 13;
	uint16_t fragment_offset;
	memcpy(&fragment_offset, header_ptr + 6, sizeof(uint16_t));
	header->fragment_offset = fragment_offset & 0x1fff;
	header->time_to_live = header_ptr[8];
	header->protocol = header_ptr[9];
	header->checksum = convert_from_be16(header_ptr + 10);
	header->src_addr.byte_value =
		convert_ipv4addr_from_be32(header_ptr + 12);
	header->dest_addr.byte_value =
		convert_ipv4addr_from_be32(header_ptr + 16);

	assert(header->ihl >= 5);
	memset(header->options, 0, sizeof(header->options));
	if (header->ihl == 5) {
		header->options_len = 0;
	} else {
		header->options_len =
			(header->ihl * 4) - (IHL_MINIMUM_SIZE * 4);
		uint8_t *options_ptr = header_ptr + 20;
		for (size_t i = 0; i < header->options_len; ++options_ptr, ++i)
			header->options[i] = *options_ptr;
	}
}

void fill_ipv4_header(struct ipv4_header *header, uint16_t total_length,
		      uint8_t time_to_live, uint8_t protocol,
		      union ipv4_addr src_addr, union ipv4_addr dest_addr)
{
	header->version = 0x4;
	header->ihl = IHL_MINIMUM_SIZE;
	header->type_of_service = 0;
	header->total_length = total_length;
	header->identification = 0;
	header->flags = 0x2; /* Don't fragment */
	header->fragment_offset = 0;
	header->time_to_live = time_to_live;
	header->protocol = protocol;
	header->checksum = 0;
	header->src_addr = src_addr;
	header->dest_addr = dest_addr;
	header->options_len = 0;
	memset(header->options, 0, sizeof(header->options));
}

size_t dump_ipv4_header(struct ipv4_header *header, uint8_t *buffer,
			size_t start)
{
	uint8_t *header_ptr = buffer + start;
	header_ptr[0] = header->version << 4 | header->ihl;
	header_ptr[1] = header->type_of_service;
	convert_into_be16(header->total_length, header_ptr + 2);
	convert_into_be16(header->identification, header_ptr + 4);
	uint16_t tmp = header->flags;
	tmp = tmp << 13 | header->fragment_offset;
	convert_into_be16(tmp, header_ptr + 6);
	header_ptr[8] = header->time_to_live;
	header_ptr[9] = header->protocol;
	convert_ipv4addr_into_be32(header->src_addr.byte_value,
				   header_ptr + 12);
	convert_ipv4addr_into_be32(header->dest_addr.byte_value,
				   header_ptr + 16);

	size_t written_bytes = header->options_len + 20;
	for (size_t i = 20, j = 0; i < written_bytes; ++i, ++j)
		header_ptr[i] = header->options[j];

	return written_bytes;
}

uint16_t ipv4_checksum(uint8_t *ipv4_ptr, int len)
{
	struct cksum_vec vec[1];
	vec[0].ptr = ipv4_ptr;
	vec[0].len = len;
	return __builtin_bswap16(in_cksum(vec, 1));
}