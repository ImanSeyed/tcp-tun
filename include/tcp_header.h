#pragma once

#include "types.h"
#include "ipv4_header.h"

#define TCP_PROTO 0x06
#define PSEUDO_HEADER_SIZE 12
#define TCP_MINIMUM_DATA_OFFSET 5

/* offset of each field in the TCP header */
#define SRC_PORT_OFF 0
#define DST_PORT_OFF 2
#define SEQ_NUM_OFF 4
#define ACK_NUM_OFF 8
#define TCP_FLAGS_OFF 12
#define WIN_SIZ_OFF 14
#define TCP_CHECKSUM_OFF 16
#define URG_PTR_OFF 18

/* offset of each field in the pseudo header */
#define P_SRC_ADDR_OFF 0
#define P_DST_ADDR_OFF 4
#define P_PROTO_OFF 9
#define P_SEG_LEN_OFF 10

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

static inline u16 tcph_size(const struct tcp_header *tcph)
{
	return tcph->flags_and_data_offset.data_offset * 4;
}

static inline u16 tcph_flags(const struct tcp_header *tcph)
{
	return tcph->flags_and_data_offset.flags;
}

static inline u16 data_size(const struct ipv4_header *ipv4h,
			    const struct tcp_header *tcph)
{
	return ipv4h->total_length - (ipv4h_size(ipv4h) + tcph_size(tcph));
}

void tcph_from_buff(struct tcp_header *tcph, const u8 *buffer, size_t start);
void init_tcph(struct tcp_header *tcph, u16 src_port, u16 dest_port, u16 flags,
	       u32 seq_number, u32 ack_number, u16 win_size);
void tcph_to_buff(const struct tcp_header *tcph, u8 *buffer, size_t start);
u16 tcph_checksum(const u8 *tcph_buff, size_t len, const u8 *pseudo_header);
u8 *get_pseudo_header(const struct ipv4_header *header);
