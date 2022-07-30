#ifndef __TCP_TUN_IPV4_FUNCS_H__
#define __TCP_TUN_IPV4_FUNCS_H__
#include <sys/types.h>
#include <stdint.h>
#include "types.h"
void parse_ipv4_header(struct ipv4_header *header, uint8_t *buffer,
		       size_t start);

#endif
