#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "utils/ipv4_utility.h"
#include "common/endian.h"
#include "common/types.h"

#define TCP_MINIMUM_DATA_OFFSET 5

void parse_tcp_header(struct tcp_header *header, uint8_t *buffer, size_t start)
{
	uint8_t *header_ptr = buffer + start;
	header->src_port = convert_from_be16(header_ptr);
	header->dest_port = convert_from_be16(header_ptr + 2);
	header->seq_number = convert_from_be32(header_ptr[4], header_ptr[5],
					       header_ptr[6], header_ptr[7]);
	header->ack_number = convert_from_be32(header_ptr[8], header_ptr[9],
					       header_ptr[10], header_ptr[11]);
	header->data_offset = header_ptr[12] >> 4 & 0xf;
	header->reserved = 0;
	header->is_urg = header_ptr[13] >> 5 & 0x1;
	header->is_ack = header_ptr[13] >> 4 & 0x1;
	header->is_psh = header_ptr[13] >> 3 & 0x1;
	header->is_rst = header_ptr[13] >> 2 & 0x1;
	header->is_syn = header_ptr[13] >> 1 & 0x1;
	header->is_fin = header_ptr[13] & 0x1;
	header->win_size = convert_from_be16(header_ptr + 14);
	header->checksum = convert_from_be16(header_ptr + 16);
	header->urg_pointer = convert_from_be16(header_ptr + 18);

	assert(header->data_offset >= 5);
	memset(header->options, 0, sizeof(header->options));
	if (header->data_offset == 5) {
		header->options_len = 0;
	} else {
		header->options_len = (header->data_offset * 4) -
				      (TCP_MINIMUM_DATA_OFFSET * 4);
		uint8_t *options_ptr = header_ptr + 20;
		for (size_t i = 0; i < header->options_len; ++options_ptr, ++i)
			header->options[i] = *options_ptr;
	}
}

void fill_tcp_header(struct tcp_header *header, uint16_t src_port,
		     uint16_t dest_port, uint32_t seq_number, uint16_t win_size)
{
	header->src_port = src_port;
	header->dest_port = dest_port;
	header->seq_number = seq_number;
	header->ack_number = 0;
	header->data_offset = TCP_MINIMUM_DATA_OFFSET;
	header->is_urg = false;
	header->is_ack = false;
	header->is_psh = false;
	header->is_rst = false;
	header->is_syn = false;
	header->is_fin = false;
	header->win_size = win_size;
	header->checksum = 0;
	header->urg_pointer = 0;
	header->options_len = 0;
	memset(header->options, 0, sizeof(header->options));
}

size_t dump_tcp_header(struct tcp_header *header, uint8_t *buffer, size_t start)
{
	uint8_t *header_ptr = buffer + start;
	convert_into_be16(header->src_port, header_ptr);
	convert_into_be16(header->dest_port, header_ptr + 2);
	convert_into_be32(header->seq_number, &header_ptr[4], &header_ptr[5],
			  &header_ptr[6], &header_ptr[7]);
	convert_into_be32(header->ack_number, &header_ptr[8], &header_ptr[9],
			  &header_ptr[10], &header_ptr[11]);
	uint16_t tmp = header->data_offset;
	tmp = (tmp << 12 | (header->is_urg << 5) | (header->is_ack << 4) |
	       (header->is_psh << 3) | (header->is_rst << 2) |
	       (header->is_syn << 1) | header->is_fin) &
	      0xf03f;
	convert_into_be16(tmp, header_ptr + 12);
	convert_into_be16(header->win_size, header_ptr + 14);
	convert_into_be16(header->urg_pointer, header_ptr + 18);

	size_t written_bytes = header->options_len + 20;
	for (size_t i = 20, j = 0; i < written_bytes; ++i, ++j)
		header_ptr[i] = header->options[j];

	return written_bytes;
}

uint16_t tcp_checksum(struct tcp_header *tcph, uint8_t *pseudo_header)
{
	size_t len = PSEUDO_HEADER_SIZE + (tcph->data_offset * 4);
	uint8_t combination[len];
	memcpy(combination, pseudo_header, PSEUDO_HEADER_SIZE);
	dump_tcp_header(tcph, combination, PSEUDO_HEADER_SIZE);
	return checksum(combination, len / 2);
}