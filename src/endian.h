#ifndef __TCP_TUN_ENDIAN_H__
#define __TCP_TUN_ENDIAN_H__
#include <stdint.h>

uint16_t convert_from_be16(uint8_t first, uint8_t second);
uint32_t convert_from_be32(uint8_t first, uint8_t second, uint8_t third,
			   uint8_t fourth);
uint16_t convert_into_be16(uint8_t first, uint8_t second);
uint32_t convert_into_be32(uint8_t first, uint8_t second, uint8_t third,
			   uint8_t fourth);
#endif
