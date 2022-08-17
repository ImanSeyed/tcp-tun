#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "common/types.h"
#include "common/endian.h"
#include "utils/ipv4_utility.h"

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
	header->src_addr.byte_value = convert_from_be32(
		header_ptr[15], header_ptr[14], header_ptr[13], header_ptr[12]);
	header->dest_addr.byte_value = convert_from_be32(
		header_ptr[19], header_ptr[18], header_ptr[17], header_ptr[16]);

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
	convert_into_be32(header->src_addr.byte_value, &header_ptr[15],
			  &header_ptr[14], &header_ptr[13], &header_ptr[12]);
	convert_into_be32(header->dest_addr.byte_value, &header_ptr[19],
			  &header_ptr[18], &header_ptr[17], &header_ptr[16]);

	size_t written_bytes = header->options_len + 20;
	for (size_t i = 20, j = 0; i < written_bytes; ++i, ++j)
		header_ptr[i] = header->options[j];

	return written_bytes;
}

uint16_t checksum(void *addr, int count)
{
	uint32_t sum = 0;
	uint16_t *ptr = addr;

	while (count > 1) {
		sum += *ptr++;
		count -= 2;
	}

	if (count > 0)
		sum += *(uint8_t *)ptr;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

uint8_t *get_pseudo_header(struct ipv4_header *header)
{
	uint8_t *buffer = (uint8_t *)malloc(PSEUDO_HEADER_SIZE);
	memset(buffer, 0, PSEUDO_HEADER_SIZE);
	convert_into_be32(header->src_addr.byte_value, &buffer[0], &buffer[1],
			  &buffer[2], &buffer[3]);
	convert_into_be32(header->dest_addr.byte_value, &buffer[4], &buffer[5],
			  &buffer[6], &buffer[7]);
	buffer[9] = header->protocol;
	uint16_t segment_len = header->total_length - (header->ihl * 4);
	convert_into_be16(segment_len, buffer + 10);
	return buffer;
}