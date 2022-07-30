#ifndef __TCP_TUN_TYPES_H__
#define __TCP_TUN_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
union ipv4_addr {
	struct {
		uint8_t first : 8;
		uint8_t second : 8;
		uint8_t third : 8;
		uint8_t fourth : 8;
	};
	uint32_t byte_value;
};

struct tcp_header {
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t seq_number;
	uint32_t ack_number;
	uint8_t data_offset : 4;
	uint8_t reserved : 6;
	bool is_urg : 1;
	bool is_ack : 1;
	bool is_psh : 1;
	bool is_rst : 1;
	bool is_syn : 1;
	bool is_fin : 1;
	uint16_t win_size;
	uint16_t checksum;
	uint16_t urg_pointer;
	uint32_t options : 24;
};

struct ipv4_header {
	uint8_t version : 4;
	uint8_t ihl : 4;
	uint8_t type_of_service;
	uint16_t total_length;
	uint16_t identification;
	uint8_t flags : 3;
	uint16_t fragment_offset : 13;
	uint8_t time_to_live;
	uint8_t protocol;
	uint16_t checksum;
	union ipv4_addr src_addr;
	union ipv4_addr dest_addr;
	uint32_t options : 24;
};

enum tcp_state {
	Closed,
	Listen,
	SynRecvd,
	Estab,
};

struct addrress_pair {
	union ipv4_addr ip;
	uint16_t port;
};

struct connection_quad {
	struct addrress_pair src;
	struct addrress_pair dest;
};

#endif
