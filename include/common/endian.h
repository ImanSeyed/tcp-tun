#ifndef __TCP_TUN_ENDIAN_H__
#define __TCP_TUN_ENDIAN_H__
#include <stdint.h>

uint16_t convert_from_be16(uint8_t *addr);
uint32_t convert_from_be32(uint8_t *addr);
void convert_into_be16(uint16_t data, uint8_t *addr);
void convert_into_be32(uint32_t data, uint8_t *addr);
uint32_t convert_ipv4addr_from_be32(uint8_t *addr);
void convert_ipv4addr_into_be32(uint32_t data, uint8_t *addr);

#endif
