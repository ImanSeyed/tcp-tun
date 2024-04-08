#ifndef __TCP_TUN_TCP_HEADER_H__
#define __TCP_TUN_TCP_HEADER_H__

#include "types.h"
#include "ipv4_header.h"

#define TCP_PROTO 0x06
#define PSEUDO_HEADER_SIZE 12

enum tcp_flags : u16 {
	FIN = 0x01,
	SYN = 0x02,
	RST = 0x04,
	PSH = 0x08,
	ACK = 0x10,
	URG = 0x20,
};

struct [[gnu::packed]] tcp_header {
	u16 src_port;
	u16 dest_port;
	u32 seq_number;
	u32 ack_number;
	union {
		struct {
			u16 flags : 6;
			u16 reserved : 6;
			u16 data_offset : 4;
		};
		u16 byte_value;
	} flags_and_data_offset;
	u16 win_size;
	u16 checksum;
	u16 urg_pointer;
};

_Static_assert(sizeof(struct tcp_header) == 20, "tcp_header must be 20 bytes.");

void tcph_from_buff(struct tcp_header *header, const u8 *buffer, size_t start);
void init_tcph(struct tcp_header *header, u16 src_port, u16 dest_port,
	       u16 flags, u32 seq_number, u32 ack_number, u16 win_size);
void tcph_to_buff(const struct tcp_header *header, u8 *buffer, size_t start);
u16 tcph_checksum(const struct tcp_header *tcph, const u8 *pseudo_header);
u8 *get_pseudo_header(const struct ipv4_header *header);

#endif
