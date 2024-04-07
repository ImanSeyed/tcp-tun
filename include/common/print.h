#ifndef __TCP_TUN_PRINT_H__
#define __TCP_TUN_PRINT_H__
#include <sys/types.h>
#include <stdint.h>
#include "types.h"

void print_bytes(const u8 *byte, size_t start, size_t end);
void print_ipv4(union ipv4_addr ip);
void print_addr(union ipv4_addr ip, u16 port);
void print_state(enum tcp_state state);
void print_quad(struct connection_quad quad);
void print_ipv4_header(const struct ipv4_header *ipv4h);
void print_tcp_header(const struct tcp_header *tcph);

#endif
