#include <string.h>
#include "types.h"

u16 get_swapped_endian16(const u8 *addr)
{
	u16 dest;
	memcpy(&dest, addr, sizeof(u16));
	return __builtin_bswap16(dest);
}

u32 get_swapped_endian32(const u8 *addr)
{
	u32 dest;
	memcpy(&dest, addr, sizeof(u32));
	return __builtin_bswap32(dest);
}

void store_swapped_endian16(u16 data, u8 *addr)
{
	u16 tmp = __builtin_bswap16(data);
	addr[0] = tmp & 0xff;
	addr[1] = tmp >> 8;
}

void store_swapped_endian32(u32 data, u8 *addr)
{
	u32 tmp = __builtin_bswap32(data);
	addr[0] = tmp & 0xff;
	addr[1] = tmp >> 8;
	addr[2] = tmp >> 16;
	addr[3] = tmp >> 24;
}
