#include <stdint.h>
#include <string.h>
#include <stdbool.h>
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
	header->ack_number =
		convert_from_be16(buffer[start + 4], buffer[start + 5]);
	header->data_offset = buffer[start + 6] >> 4 & 0xf;
	header->reserved = 0;
	header->is_urg = buffer[start + 7] >> 5 & 0x1;
	header->is_ack = buffer[start + 7] >> 4 & 0x1;
	header->is_psh = buffer[start + 7] >> 3 & 0x1;
	header->is_rst = buffer[start + 7] >> 2 & 0x1;
	header->is_syn = buffer[start + 7] >> 1 & 0x1;
	header->is_fin = buffer[start + 7] & 0x1;
	header->win_size =
		convert_from_be16(buffer[start + 8], buffer[start + 9]);
	header->checksum =
		convert_from_be16(buffer[start + 10], buffer[start + 11]);
	header->urg_pointer =
		convert_from_be16(buffer[start + 12], buffer[start + 13]);
	uint8_t options[4] = { buffer[start + 14], buffer[start + 15],
			       buffer[start + 16], buffer[start + 17] };
	uint32_t tmp32;
	memcpy(&tmp32, options, sizeof(uint32_t));
	header->options = tmp32 >> 2 & 0x00ffffff;
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
	header->options = 0;
}
