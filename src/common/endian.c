#include <stdint.h>
#include <string.h>
#include "common/endian.h"

u16 get_toggle_endian16(const u8 *addr)
{
	u16 dest;
	memcpy(&dest, addr, sizeof(u16));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap16(dest);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return dest;
#endif
}

u32 get_toggle_endian32(const u8 *addr)
{
	u32 dest;
	memcpy(&dest, addr, sizeof(u32));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap32(dest);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return dest;
#endif
}

void write_toggle_endian16(u16 data, u8 *addr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	u16 tmp = __builtin_bswap16(data);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	u16 tmp = data;
#endif
	addr[0] = tmp & 0xff;
	addr[1] = tmp >> 8;
}

void write_toggle_endian32(u32 data, u8 *addr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	u32 tmp = __builtin_bswap32(data);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	u32 tmp = data;
#endif
	addr[0] = tmp & 0xff;
	addr[1] = tmp >> 8;
	addr[2] = tmp >> 16;
	addr[3] = tmp >> 24;
}

u32 get_ipv4addr_toggle_endian32(const u8 *addr)
{
	u8 ip[4];
	for (size_t i = 0, j = 3; i < 4; ++i, j--)
		ip[i] = addr[j];
	return get_toggle_endian32(ip);
}

void write_ipv4addr_toggle_endian32(u32 data, u8 *addr)
{
	u8 ip[4], reverse_ip[4];
	memcpy(ip, &data, sizeof(u32));
	for (size_t i = 0, j = 3; i < 4; ++i, --j)
		reverse_ip[i] = ip[j];
	memcpy(&data, reverse_ip, sizeof(u32));
	write_toggle_endian32(data, addr);
}