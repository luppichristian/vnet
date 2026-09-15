/*
 * MIT License
 *
 * Copyright (c) 2026 Christian Luppi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <rip.h>

#include <string.h>

bool rip_is_multicast_address(ipv4_address_t address) {
  return address == RIP_MULTICAST_ADDRESS;
}

static bool rip_entry_is_valid(const rip_route_entry_t* entry) {
  return entry->address_family == RIP_ADDRESS_FAMILY_IPV4 && entry->route_tag == 0 && ipv4_mask_is_contiguous(entry->subnet_mask) && (entry->destination & entry->subnet_mask) == entry->destination && entry->metric >= RIP_METRIC_MIN && entry->metric <= RIP_METRIC_INFINITY;
}

bool rip_write_packet(uint8_t command, const rip_route_entry_t* entries, size_t entry_count, uint8_t* bytes, size_t capacity, size_t* byte_count) {
  if (!bytes || !byte_count || (command != RIP_COMMAND_REQUEST && command != RIP_COMMAND_RESPONSE) || entry_count > RIP_MAX_ENTRIES_PER_PACKET || (entry_count > 0 && !entries) || capacity < sizeof(rip_header_t) + entry_count * sizeof(rip_route_entry_t)) {
    return false;
  }
  for (size_t i = 0; i < entry_count; ++i) {
    if (!rip_entry_is_valid(&entries[i])) return false;
  }
  const rip_header_t header = {
      .command = command,
      .version = RIP_VERSION,
  };
  memcpy(bytes, &header, sizeof(header));
  memcpy(bytes + sizeof(header), entries, entry_count * sizeof(*entries));
  *byte_count = sizeof(header) + entry_count * sizeof(*entries);
  return true;
}

bool rip_parse_packet(const uint8_t* bytes, size_t byte_count, rip_packet_view_t* packet) {
  if (!bytes || !packet || byte_count < sizeof(packet->header) || (byte_count - sizeof(packet->header)) % sizeof(rip_route_entry_t) != 0) {
    return false;
  }
  memcpy(&packet->header, bytes, sizeof(packet->header));
  packet->entry_count = (byte_count - sizeof(packet->header)) / sizeof(rip_route_entry_t);
  packet->entries = (const rip_route_entry_t*)(bytes + sizeof(packet->header));
  if ((packet->header.command != RIP_COMMAND_REQUEST && packet->header.command != RIP_COMMAND_RESPONSE) || packet->header.version != RIP_VERSION || packet->header.zero != 0 || packet->entry_count > RIP_MAX_ENTRIES_PER_PACKET) {
    return false;
  }
  for (size_t i = 0; i < packet->entry_count; ++i) {
    if (!rip_entry_is_valid(&packet->entries[i])) return false;
  }
  return true;
}
