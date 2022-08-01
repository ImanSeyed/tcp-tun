#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/types.h>
#include "types.h"
#include "endian.h"

#define PADDING 8
#define TCP_MINIMUM_DATA_OFFSET 5

void parse_tcp_header(struct tcp_header *header, uint8_t *buffer, size_t start)
{
	header->src_port = convert_from_be16(buffer[start], buffer[start + 1]);
	header->dest_port =
		convert_from_be16(buffer[start + 2], buffer[start + 3]);
	header->seq_number =
		convert_from_be32(buffer[start + 4], buffer[start + 5],
				  buffer[start + 6], buffer[start + 7]);
	header->ack_number =
		convert_from_be32(buffer[start + 8], buffer[start + 9],
				  buffer[start + 10], buffer[start + 11]);
	header->data_offset = buffer[start + 12] >> 4 & 0xf;
	header->reserved = 0;
	header->is_urg = buffer[start + 13] >> 5 & 0x1;
	header->is_ack = buffer[start + 13] >> 4 & 0x1;
	header->is_psh = buffer[start + 13] >> 3 & 0x1;
	header->is_rst = buffer[start + 13] >> 2 & 0x1;
	header->is_syn = buffer[start + 13] >> 1 & 0x1;
	header->is_fin = buffer[start + 13] & 0x1;
	header->win_size =
		convert_from_be16(buffer[start + 14], buffer[start + 15]);
	header->checksum =
		convert_from_be16(buffer[start + 16], buffer[start + 17]);
	header->urg_pointer =
		convert_from_be16(buffer[start + 18], buffer[start + 19]);

	assert(header->data_offset >= 5);
	memset(header->options, 0, sizeof(header->options));
	if (header->data_offset == 5) {
		header->options_len = 0;
	} else {
		header->options_len = (header->data_offset * 4) -
				      (TCP_MINIMUM_DATA_OFFSET * 4);
		uint8_t *p = &buffer[start + 20];
		for (int i = 0; i < header->options_len; ++p, ++i)
			header->options[i] = *p;
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

size_t dump_tcp_header(struct tcp_header *header, uint8_t *buffer)
{
	convert_into_be16(header->src_port, &buffer[0], &buffer[1]);
	convert_into_be16(header->dest_port, &buffer[2], &buffer[3]);
	convert_into_be32(header->seq_number, &buffer[4], &buffer[5],
			  &buffer[6], &buffer[7]);
	convert_into_be32(header->ack_number, &buffer[8], &buffer[9],
			  &buffer[10], &buffer[11]);
	uint16_t tmp = header->data_offset;
	tmp = tmp << 12 | (header->is_urg << 5) | (header->is_ack << 4) |
	      (header->is_psh << 3) | (header->is_rst << 2) |
	      (header->is_syn << 1) | header->is_fin & 0xf03f;
	convert_into_be16(tmp, &buffer[12], &buffer[13]);
	convert_into_be16(header->win_size, &buffer[14], &buffer[15]);
	convert_into_be16(header->checksum, &buffer[16], &buffer[17]);
	convert_into_be16(header->urg_pointer, &buffer[18], &buffer[19]);

	size_t written_bytes = header->options_len + 20;
	for (int i = 20, j = 0; i < written_bytes; ++i, ++j)
		buffer[i] = header->options[j];

	return written_bytes;
}
