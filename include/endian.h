#ifndef __TCP_TUN_ENDIAN_H__
#define __TCP_TUN_ENDIAN_H__
#include "types.h"

u16 get_swapped_endian16(const u8 *addr);
u32 get_swapped_endian32(const u8 *addr);
void store_swapped_endian16(u16 data, u8 *addr);
void store_swapped_endian32(u32 data, u8 *addr);
u32 get_ipv4addr_swapped_endian32(const u8 *addr);
void store_ipv4addr_swapped_endian32(u32 data, u8 *addr);

#endif
