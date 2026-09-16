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
#include "route_table.h"

#include <string.h>

static unsigned int prefix_length(ipv4_address_t mask) {
  unsigned int length = 0;
  while (mask != 0) {
    length += mask & 1u;
    mask >>= 1;
  }
  return length;
}

static bool route_is_valid(ipv4_address_t destination, ipv4_address_t mask) {
  return ipv4_mask_is_contiguous(mask) && (destination & mask) == destination;
}

void route_table_init(route_table_t* table, route_entry_t* entries, size_t capacity) {
  *table = (route_table_t) {.entries = entries, .capacity = capacity};
}

static bool route_table_add_source(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric, route_source_t source) {
  if (table->count == table->capacity || !route_is_valid(destination, mask)) {
    return false;
  }
  table->entries[table->count++] = (route_entry_t) {
      .destination = destination,
      .mask = mask,
      .next_hop = next_hop,
      .interface_index = interface_index,
      .metric = metric,
      .source = source,
  };
  return true;
}

bool route_table_add(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric) {
  return route_table_add_source(table, destination, mask, next_hop, interface_index, metric, ROUTE_SOURCE_STATIC);
}

bool route_table_add_connected(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, size_t interface_index) {
  return route_table_add_source(table, destination, mask, 0, interface_index, 0, ROUTE_SOURCE_CONNECTED);
}

const route_entry_t* route_table_lookup(const route_table_t* table, ipv4_address_t destination) {
  const route_entry_t* best = NULL;
  unsigned int best_prefix = 0;
  for (size_t i = 0; i < table->count; ++i) {
    const route_entry_t* route = &table->entries[i];
    const unsigned int prefix = prefix_length(route->mask);
    if ((destination & route->mask) == route->destination && (!best || prefix > best_prefix || (prefix == best_prefix && route->metric < best->metric))) {
      best = route;
      best_prefix = prefix;
    }
  }
  return best;
}

bool route_table_remove(route_table_t* table, size_t index) {
  if (index >= table->count) return false;
  table->entries[index] = table->entries[--table->count];
  return true;
}

const char* route_source_name(route_source_t source) {
  switch (source) {
    case ROUTE_SOURCE_CONNECTED:
      return "connected";
    case ROUTE_SOURCE_STATIC:
      return "static";
  }
  return "unknown";
}
