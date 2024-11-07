#pragma once

#include "types.h"

union ipv4_addr {
	struct {
		u8 fourth;
		u8 third;
		u8 second;
		u8 first;
	};
	u32 byte_value;
};

struct endpoint {
	union ipv4_addr ip;
	u16 port;
};

struct conn_quad {
	struct endpoint src;
	struct endpoint dest;
};

void init_ipv4_addr(union ipv4_addr *addr, u8 a, u8 b, u8 c, u8 d);
char *ipv4_addr_to_str(union ipv4_addr *addr);
