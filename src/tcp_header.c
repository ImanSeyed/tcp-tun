#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "tcp_header.h"
#include "ipv4_header.h"
#include "in_cksum.h"
#include "endian.h"
#include "types.h"

#define TCP_MINIMUM_DATA_OFFSET 5

void tcph_from_buff(struct tcp_header *header, const u8 *buffer, size_t start)
{
	const u8 *header_ptr = buffer + start;
	header->src_port = get_toggle_endian16(header_ptr);
	header->dest_port = get_toggle_endian16(header_ptr + 2);
	header->seq_number = get_toggle_endian32(header_ptr + 4);
	header->ack_number = get_toggle_endian32(header_ptr + 8);
	header->flags_and_data_offset.byte_value =
		get_toggle_endian16(header_ptr + 12);
	header->win_size = get_toggle_endian16(header_ptr + 14);
	header->checksum = get_toggle_endian16(header_ptr + 16);
	header->urg_pointer = get_toggle_endian16(header_ptr + 18);

	assert(header->flags_and_data_offset.data_offset >= 5);
}

void init_tcph(struct tcp_header *header, u16 src_port, u16 dest_port,
	       u16 flags, u32 seq_number, u32 ack_number, u16 win_size)
{
	header->src_port = src_port;
	header->dest_port = dest_port;
	header->seq_number = seq_number;
	header->ack_number = ack_number;
	header->flags_and_data_offset.byte_value = flags;
	header->flags_and_data_offset.data_offset = TCP_MINIMUM_DATA_OFFSET;
	header->win_size = win_size;
	header->checksum = 0;
	header->urg_pointer = 0;
}

void tcph_to_buff(const struct tcp_header *header, u8 *buffer, size_t start)
{
	u8 *header_ptr = buffer + start;
	write_toggle_endian16(header->src_port, header_ptr);
	write_toggle_endian16(header->dest_port, header_ptr + 2);
	write_toggle_endian32(header->seq_number, header_ptr + 4);
	write_toggle_endian32(header->ack_number, header_ptr + 8);
	write_toggle_endian16(header->flags_and_data_offset.byte_value,
			      header_ptr + 12);
	write_toggle_endian16(header->win_size, header_ptr + 14);
	write_toggle_endian16(header->urg_pointer, header_ptr + 18);
}

u8 *get_pseudo_header(const struct ipv4_header *ipv4h)
{
	u8 *buffer = (u8 *)malloc(PSEUDO_HEADER_SIZE);
	memset(buffer, 0, PSEUDO_HEADER_SIZE);
	write_ipv4addr_toggle_endian32(ipv4h->src_addr.byte_value, buffer);
	write_ipv4addr_toggle_endian32(ipv4h->dest_addr.byte_value, buffer + 4);
	buffer[9] = ipv4h->protocol;
	u16 segment_len =
		ipv4h->total_length - ((ipv4h->version_and_ihl.ihl) * 4);
	write_toggle_endian16(segment_len, buffer + 10);
	return buffer;
}

u16 tcph_checksum(const struct tcp_header *tcph, const u8 *pseudo_header)
{
	struct cksum_vec vec[2];
	int tcph_len = tcph->flags_and_data_offset.data_offset * 4;
	u8 tcph_buff[tcph_len];
	memset(tcph_buff, 0, tcph_len);
	tcph_to_buff(tcph, tcph_buff, 0);
	vec[0].ptr = pseudo_header;
	vec[0].len = PSEUDO_HEADER_SIZE;
	vec[1].ptr = tcph_buff;
	vec[1].len = tcph_len;
	return __builtin_bswap16(in_cksum(vec, 2));
}
