#ifndef __TCP_TUN_TYPES_H__
#define __TCP_TUN_TYPES_H__
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * 2 bytes for ether_flags, 2 bytes for ether_type
 * according to tuntap.txt in Linux kernel documentations
 * */

#define IPV4_PROTO 0x08
#define TCP_PROTO 0x06
#define PSEUDO_HEADER_SIZE 12

union ipv4_addr {
	struct {
		uint8_t first;
		uint8_t second;
		uint8_t third;
		uint8_t fourth;
	};
	uint32_t byte_value;
};

struct [[gnu::packed]] tcp_header {
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t seq_number;
	uint32_t ack_number;
	uint8_t data_offset : 4;
	uint16_t reserved : 6;
	bool is_urg : 1;
	bool is_ack : 1;
	bool is_psh : 1;
	bool is_rst : 1;
	bool is_syn : 1;
	bool is_fin : 1;
	uint16_t win_size;
	uint16_t checksum;
	uint16_t urg_pointer;
};

_Static_assert(sizeof(struct tcp_header) == 20, "TCP header must be 20 bytes.");

struct [[gnu::packed]] ipv4_header {
	uint8_t version_and_ihl;
	uint8_t type_of_service;
	uint16_t total_length;
	uint16_t identification;
	uint8_t flags : 3;
	uint16_t fragment_offset : 13;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	union ipv4_addr src_addr;
	union ipv4_addr dest_addr;
};

_Static_assert(sizeof(struct ipv4_header) == 20,
	       "IPv4 header must be 20 bytes.");

#define ENUMERATE_STATES()              \
	ENUMERATE_STATES_IMPL(SYNRECVD) \
	ENUMERATE_STATES_IMPL(ESTAB)    \
	ENUMERATE_STATES_IMPL(FINWAIT1) \
	ENUMERATE_STATES_IMPL(FINWAIT2) \
	ENUMERATE_STATES_IMPL(CLOSING)

enum tcp_state {
#define ENUMERATE_STATES_IMPL(name) name,
	ENUMERATE_STATES()
#undef ENUMERATE_STATES_IMPL
};

struct addrress_pair {
	union ipv4_addr ip;
	uint16_t port;
};

struct connection_quad {
	struct addrress_pair src;
	struct addrress_pair dest;
};

struct cksum_vec {
	const uint8_t *ptr;
	size_t len;
};

#endif
