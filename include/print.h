#pragma once

#include <sys/types.h>
#include "types.h"
#include "tcp_header.h"
#include "ipv4_header.h"
#include "ipv4_addr.h"
#include "states.h"

void pr_bytes(const u8 *byte, size_t start, size_t end);
void pr_ipv4(union ipv4_addr ip);
void pr_addr(union ipv4_addr ip, u16 port);
void pr_state(enum tcp_state state);
void pr_quad(struct conn_quad quad);
void pr_ipv4_header(const struct ipv4_header *ipv4h);
void pr_tcp_header(const struct tcp_header *tcph);
