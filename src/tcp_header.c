#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include "tcp_header.h"
#include "ipv4_header.h"
#include "in_cksum.h"
#include "endian.h"
#include "types.h"

void tcph_from_buff(struct tcp_header *tcph, const u8 *buffer, size_t start)
{
	const u8 *header_ptr = buffer + start;

	tcph->src_port = get_swapped_endian16(&header_ptr[SRC_PORT_OFF]);
	tcph->dest_port = get_swapped_endian16(&header_ptr[DST_PORT_OFF]);
	tcph->seq_number = get_swapped_endian32(&header_ptr[SEQ_NUM_OFF]);
	tcph->ack_number = get_swapped_endian32(&header_ptr[ACK_NUM_OFF]);
	tcph->flags_and_data_offset.byte_value =
		get_swapped_endian16(&header_ptr[TCP_FLAGS_OFF]);
	tcph->win_size = get_swapped_endian16(&header_ptr[WIN_SIZ_OFF]);
	tcph->checksum = get_swapped_endian16(&header_ptr[TCP_CHECKSUM_OFF]);
	tcph->urg_pointer = get_swapped_endian16(&header_ptr[URG_PTR_OFF]);

	assert(tcph_size(tcph) >= 20);
}

void init_tcph(struct tcp_header *tcph, u16 src_port, u16 dest_port, u16 flags,
	       u32 seq_number, u32 ack_number, u16 win_size)
{
	tcph->src_port = src_port;
	tcph->dest_port = dest_port;
	tcph->seq_number = seq_number;
	tcph->ack_number = ack_number;
	tcph->flags_and_data_offset.byte_value = flags;
	tcph->flags_and_data_offset.data_offset = TCP_MINIMUM_DATA_OFFSET;
	tcph->win_size = win_size;
	tcph->checksum = 0;
	tcph->urg_pointer = 0;
}

void tcph_to_buff(const struct tcp_header *tcph, u8 *buffer, size_t start)
{
	u8 *header_ptr = buffer + start;

	store_swapped_endian16(tcph->src_port, &header_ptr[SRC_PORT_OFF]);
	store_swapped_endian16(tcph->dest_port, &header_ptr[DST_PORT_OFF]);
	store_swapped_endian32(tcph->seq_number, &header_ptr[SEQ_NUM_OFF]);
	store_swapped_endian32(tcph->ack_number, &header_ptr[ACK_NUM_OFF]);
	store_swapped_endian16(tcph->flags_and_data_offset.byte_value,
			       &header_ptr[TCP_FLAGS_OFF]);
	store_swapped_endian16(tcph->win_size, &header_ptr[WIN_SIZ_OFF]);
	store_swapped_endian16(tcph->urg_pointer, &header_ptr[URG_PTR_OFF]);
}

u8 *get_pseudo_header(const struct ipv4_header *ipv4h)
{
	u16 segment_len = ipv4h->total_length - ipv4h_size(ipv4h);
	u8 *pseudo_header = (u8 *)calloc(PSEUDO_HEADER_SIZE, sizeof(u8));

	store_swapped_endian32(ipv4h->src_addr.byte_value,
			       &pseudo_header[P_SRC_ADDR_OFF]);
	store_swapped_endian32(ipv4h->dest_addr.byte_value,
			       &pseudo_header[P_DST_ADDR_OFF]);
	pseudo_header[P_PROTO_OFF] = ipv4h->protocol;
	store_swapped_endian16(segment_len, &pseudo_header[P_SEG_LEN_OFF]);

	return pseudo_header;
}

u16 tcph_checksum(const u8 *tcph_buff, size_t len, const u8 *pseudo_header)
{
	struct cksum_vec vec[2];

	vec[0].ptr = pseudo_header;
	vec[0].len = PSEUDO_HEADER_SIZE;
	vec[1].ptr = tcph_buff;
	vec[1].len = len;

	return in_cksum(vec, 2);
}
