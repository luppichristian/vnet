#include "route_table.h"

#include <limits.h>
#include <string.h>

static unsigned int prefix_length(ipv4_address_t mask) {
  unsigned int length = 0;
  while (mask != 0) {
    length += mask & 1u;
    mask >>= 1;
  }
  return length;
}

static unsigned int administrative_distance(route_source_t source) {
  switch (source) {
    case ROUTE_SOURCE_CONNECTED:
      return 0;
    case ROUTE_SOURCE_STATIC:
      return 1;
    case ROUTE_SOURCE_RIP:
      return 120;
    case ROUTE_SOURCE_OSPF:
      return 110;
  }
  return UINT_MAX;
}

static bool route_is_valid(ipv4_address_t destination, ipv4_address_t mask) {
  return ipv4_mask_is_contiguous(mask) && (destination & mask) == destination;
}

void route_table_init(route_table_t* table, route_entry_t* entries, size_t capacity) {
  *table = (route_table_t) {.entries = entries, .capacity = capacity};
}

static bool route_table_add_source(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric, route_source_t source, uint32_t expires_at) {
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
      .expires_at = expires_at,
  };
  return true;
}

bool route_table_add(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric) {
  return route_table_add_source(table, destination, mask, next_hop, interface_index, metric, ROUTE_SOURCE_STATIC, 0);
}

bool route_table_add_connected(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, size_t interface_index) {
  return route_table_add_source(table, destination, mask, 0, interface_index, 0, ROUTE_SOURCE_CONNECTED, 0);
}

bool route_table_learn_rip(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric, uint32_t expires_at) {
  if (metric == 0 || metric > 16 || !route_is_valid(destination, mask)) {
    return false;
  }
  for (size_t i = 0; i < table->count; ++i) {
    route_entry_t* route = &table->entries[i];
    if (route->source == ROUTE_SOURCE_RIP && route->destination == destination && route->mask == mask && route->next_hop == next_hop && route->interface_index == interface_index) {
      if (metric == 16) {
        route_table_remove(table, i);
      } else {
        route->metric = metric;
        route->expires_at = expires_at;
      }
      return true;
    }
  }
  return metric == 16 || route_table_add_source(table, destination, mask, next_hop, interface_index, metric, ROUTE_SOURCE_RIP, expires_at);
}

bool route_table_learn_ospf(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric, uint32_t expires_at) {
  if (metric == 0 || !route_is_valid(destination, mask)) return false;
  for (size_t i = 0; i < table->count; ++i) {
    route_entry_t* route = &table->entries[i];
    if (route->source == ROUTE_SOURCE_OSPF && route->destination == destination && route->mask == mask && route->next_hop == next_hop && route->interface_index == interface_index) {
      route->metric = metric;
      route->expires_at = expires_at;
      return true;
    }
  }
  return route_table_add_source(table, destination, mask, next_hop, interface_index, metric, ROUTE_SOURCE_OSPF, expires_at);
}

void route_table_remove_ospf(route_table_t* table) {
  for (size_t i = 0; i < table->count;) {
    if (table->entries[i].source == ROUTE_SOURCE_OSPF) route_table_remove(table, i);
    else ++i;
  }
}

void route_table_expire_ospf(route_table_t* table, uint32_t now) {
  for (size_t i = 0; i < table->count;) {
    const route_entry_t* route = &table->entries[i];
    if (route->source == ROUTE_SOURCE_OSPF && route->expires_at <= now) route_table_remove(table, i);
    else ++i;
  }
}

void route_table_remove_rip(route_table_t* table) {
  for (size_t i = 0; i < table->count;) {
    if (table->entries[i].source == ROUTE_SOURCE_RIP) {
      route_table_remove(table, i);
    } else {
      ++i;
    }
  }
}

void route_table_expire_rip(route_table_t* table, uint32_t now) {
  for (size_t i = 0; i < table->count;) {
    const route_entry_t* route = &table->entries[i];
    if (route->source == ROUTE_SOURCE_RIP && route->expires_at <= now) {
      route_table_remove(table, i);
    } else {
      ++i;
    }
  }
}

const route_entry_t* route_table_lookup(const route_table_t* table, ipv4_address_t destination) {
  const route_entry_t* best = NULL;
  unsigned int best_prefix = 0;
  unsigned int best_distance = 0;
  for (size_t i = 0; i < table->count; ++i) {
    const route_entry_t* route = &table->entries[i];
    const unsigned int prefix = prefix_length(route->mask);
    const unsigned int distance = administrative_distance(route->source);
    if ((destination & route->mask) == route->destination && (!best || prefix > best_prefix || (prefix == best_prefix && (distance < best_distance || (distance == best_distance && route->metric < best->metric))))) {
      best = route;
      best_prefix = prefix;
      best_distance = distance;
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
    case ROUTE_SOURCE_RIP:
      return "rip";
    case ROUTE_SOURCE_OSPF:
      return "ospf";
  }
  return "unknown";
}
