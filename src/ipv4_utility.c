#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "types.h"
#include "endian.h"

#define IHL_MINIMUM_SIZE 5

void parse_ipv4_header(struct ipv4_header *header, uint8_t *buffer,
		       size_t start)
{
	header->version = buffer[start] >> 4 & 0xf;
	header->ihl = buffer[start] & 0xf;
	header->type_of_service = buffer[start + 1];
	header->total_length =
		convert_from_be16(buffer[start + 2], buffer[start + 3]);
	header->identification =
		convert_from_be16(buffer[start + 4], buffer[start + 5]);
	header->flags = buffer[start + 6] >> 13;
	uint8_t fragment_offset[2] = { buffer[start + 6] + buffer[start + 7] };
	uint16_t tmp16;
	memcpy(&tmp16, fragment_offset, sizeof(uint16_t));
	header->fragment_offset = tmp16 & 0x1fff;
	header->time_to_live = buffer[start + 8];
	header->protocol = buffer[start + 9];
	header->checksum =
		convert_from_be16(buffer[start + 10], buffer[start + 11]);
	header->src_addr.byte_value =
		convert_from_be32(buffer[start + 15], buffer[start + 14],
				  buffer[start + 13], buffer[start + 12]);
	header->dest_addr.byte_value =
		convert_from_be32(buffer[start + 19], buffer[start + 18],
				  buffer[start + 17], buffer[start + 16]);
	uint8_t options[4] = { buffer[start + 20], buffer[start + 21],
			       buffer[start + 22], buffer[start + 23] };

	assert(header->ihl >= 5);
	memset(header->options, 0, sizeof(header->options));
	if (header->ihl == 5) {
		header->options_len = 0;
	} else {
		header->options_len =
			(header->ihl * 4) - (IHL_MINIMUM_SIZE * 4);
		uint8_t *p = &buffer[start + 20];
		for (int i = 0; i < header->options_len; ++p, ++i)
			header->options[i] = *p;
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
	header->flags = 0x4; /* Don't fragment */
	header->fragment_offset = 0;
	header->time_to_live = time_to_live;
	header->protocol = protocol;
	header->checksum = 0;
	header->src_addr = src_addr;
	header->dest_addr = dest_addr;
	header->options_len = 0;
	memset(header->options, 0, sizeof(header->options));
}
