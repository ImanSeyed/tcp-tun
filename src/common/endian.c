#include <stdint.h>
#include <string.h>
#include "common/endian.h"

uint16_t get_toggle_endian16(uint8_t *addr)
{
	uint16_t dest;
	memcpy(&dest, addr, sizeof(uint16_t));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap16(dest);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return dest;
#endif
}

uint32_t get_toggle_endian32(uint8_t *addr)
{
	uint32_t dest;
	memcpy(&dest, addr, sizeof(uint32_t));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap32(dest);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return dest;
#endif
}

void write_toggle_endian16(uint16_t data, uint8_t *addr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint16_t tmp = __builtin_bswap16(data);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint16_t tmp = data;
#endif
	addr[0] = tmp & 0xff;
	addr[1] = tmp >> 8;
}

void write_toggle_endian32(uint32_t data, uint8_t *addr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t tmp = __builtin_bswap32(data);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint32_t tmp = data;
#endif
	addr[0] = tmp & 0xff;
	addr[1] = tmp >> 8;
	addr[2] = tmp >> 16;
	addr[3] = tmp >> 24;
}

uint32_t get_ipv4addr_toggle_endian32(uint8_t *addr)
{
	addr += 3;
	uint8_t ip[4];
	for (size_t i = 0; i < 4; ++i)
		ip[i] = *addr--;
	return get_toggle_endian32(ip);
}

void write_ipv4addr_toggle_endian32(uint32_t data, uint8_t *addr)
{
	uint8_t ip[4], reverse_ip[4];
	memcpy(ip, &data, sizeof(uint32_t));
	for (size_t i = 0, j = 3; i < 4; ++i, --j)
		reverse_ip[i] = ip[j];
	memcpy(&data, reverse_ip, sizeof(uint32_t));
	write_toggle_endian32(data, addr);
}