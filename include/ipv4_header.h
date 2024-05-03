#pragma once

#include "ipv4_addr.h"
#include "types.h"

#define IPV4_PROTO 0x08
#define IHL_MINIMUM_SIZE 5

/* offset of each field in the IPv4 header */
#define VERSION_OFF 0
#define TOS_OFF 1
#define LENGTH_OFF 2
#define IDENT_OFF 4
#define IP_FLAGS_OFF 6
#define TTL_OFF 8
#define PROTO_OFF 9
#define IP_CHECKSUM_OFF 10
#define SRC_ADDR_OFF 12
#define DST_ADDR_OFF 16

struct [[gnu::packed]] ipv4_header {
	union {
		struct {
			u8 ihl : 4;
			u8 version : 4;
		};
		u8 byte_value;
	} version_and_ihl;
	u8 type_of_service;
	u16 total_length;
	u16 identification;
	union {
		struct {
			u16 fragment : 13;
			u16 flags : 3;
		};
		u16 byte_value;
	} flags_and_fragment;
	u8 ttl;
	u8 protocol;
	u16 checksum;
	union ipv4_addr src_addr;
	union ipv4_addr dest_addr;
};

_Static_assert(sizeof(struct ipv4_header) == 20,
	       "ipv4_header must be 20 bytes.");

static inline u8 ipv4h_size(const struct ipv4_header *ipv4h)
{
	return ipv4h->version_and_ihl.ihl * 4;
}

static inline u16 ipv4h_flags(const struct ipv4_header *ipv4h)
{
	return ipv4h->flags_and_fragment.flags;
}

static inline u16 ipv4h_fragments(const struct ipv4_header *ipv4h)
{
	return ipv4h->flags_and_fragment.fragment;
}

void ipv4h_from_buff(struct ipv4_header *ipv4h, const u8 *buffer, size_t start);
void init_ipv4h(struct ipv4_header *ipv4h, u16 total_length, u8 time_to_live,
		u8 protocol, union ipv4_addr src_addr,
		union ipv4_addr dest_addr);
void ipv4h_to_buff(const struct ipv4_header *ipv4h, u8 *buffer, size_t start);
u16 ipv4h_checksum(const u8 *ipv4_ptr, size_t len);
