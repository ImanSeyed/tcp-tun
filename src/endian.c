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

u32 get_ipv4addr_swapped_endian32(const u8 *addr)
{
	u8 ip[4];
	for (size_t i = 0, j = 3; i < 4; ++i, j--)
		ip[i] = addr[j];
	return get_swapped_endian32(ip);
}

void store_ipv4addr_swapped_endian32(u32 data, u8 *addr)
{
	u8 ip[4], reverse_ip[4];
	memcpy(ip, &data, sizeof(u32));
	for (size_t i = 0, j = 3; i < 4; ++i, --j)
		reverse_ip[i] = ip[j];
	memcpy(&data, reverse_ip, sizeof(u32));
	store_swapped_endian32(data, addr);
}
