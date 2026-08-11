#include "route_table.h"

static unsigned int prefix_length(ipv4_address_t mask) {
  unsigned int length = 0;
  while (mask != 0) {
    length += mask & 1u;
    mask >>= 1;
  }
  return length;
}

void route_table_init(route_table_t* table, route_entry_t* entries, size_t capacity) {
  *table = (route_table_t) {.entries = entries, .capacity = capacity};
}

bool route_table_add(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric) {
  if (table->count == table->capacity || !ipv4_mask_is_contiguous(mask) || (destination & mask) != destination) {
    return false;
  }
  table->entries[table->count++] = (route_entry_t) {
      .destination = destination,
      .mask = mask,
      .next_hop = next_hop,
      .interface_index = interface_index,
      .metric = metric,
  };
  return true;
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
