#pragma once

#include <stddef.h>
#include <stdint.h>

/* Standard reflected IEEE CRC-32, used by Ethernet's FCS. */
uint32_t crc32(const void* data, size_t data_size);

/* One's-complement checksum over native simulator octet pairs. */
uint16_t checksum16(const void* data, size_t data_size);
