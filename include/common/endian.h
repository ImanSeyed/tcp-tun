#ifndef __TCP_TUN_ENDIAN_H__
#define __TCP_TUN_ENDIAN_H__
#include <stdint.h>

u16 get_toggle_endian16(const u8 *addr);
u32 get_toggle_endian32(const u8 *addr);
void write_toggle_endian16(u16 data, u8 *addr);
void write_toggle_endian32(u32 data, u8 *addr);
u32 get_ipv4addr_toggle_endian32(const u8 *addr);
void write_ipv4addr_toggle_endian32(u32 data, u8 *addr);

#endif
