#ifndef __TCP_TUN_PRINT_H__
#define __TCP_TUN_PRINT_H__
#include <sys/types.h>
#include <stdint.h>
#include "types.h"

void print_bytes(uint8_t *byte, size_t start, size_t end);
void print_ipv4(union ipv4_addr ip);
void print_addr(union ipv4_addr ip, uint16_t port);
void print_state(enum tcp_state state);
void print_quad(struct connection_quad quad);
void print_ipv4_header(struct ipv4_header *ipv4h);
void print_tcp_header(struct tcp_header *tcph);

#endif
