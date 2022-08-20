#ifndef __TCP_TUN_ENDIAN_H__
#define __TCP_TUN_ENDIAN_H__
#include <stdint.h>

uint16_t get_toggle_endian16(uint8_t *addr);
uint32_t get_toggle_endian32(uint8_t *addr);
void write_toggle_endian16(uint16_t data, uint8_t *addr);
void write_toggle_endian32(uint32_t data, uint8_t *addr);
uint32_t get_ipv4addr_toggle_endian32(uint8_t *addr);
void write_ipv4addr_toggle_endian32(uint32_t data, uint8_t *addr);

#endif
