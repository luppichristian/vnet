#pragma once

#include <ipv4.h>
#include <stddef.h>
#include <stdint.h>

/*
==================
IPv4 Routing Table
==================
An IPv4 routing table maps destination prefixes to an egress interface and,
for remote networks, a next-hop router. Forwarding selects the matching route
with the longest prefix; when prefix lengths tie, the route with the lower
metric wins. A zero next_hop denotes a directly connected network, where the
destination itself is resolved through ARP.

Real systems distinguish a control-plane routing information base (RIB) from
an optimized forwarding information base (FIB), and populate routes through
connected networks, static configuration, and routing protocols. This table is
a small static FIB-like model: it performs only deterministic lookup and does
not track route origin, administrative distance, recursion, or ECMP.
*/
typedef struct route_entry {
  ipv4_address_t destination;
  ipv4_address_t mask;
  ipv4_address_t next_hop;
  size_t interface_index;
  uint32_t metric;
} route_entry_t;

typedef struct route_table {
  route_entry_t* entries;
  size_t capacity;
  size_t count;
} route_table_t;

/* Binds a caller-owned entry array to an initially empty routing table. */
void route_table_init(route_table_t* table, route_entry_t* entries, size_t capacity);

/* Adds a route. next_hop is zero for a directly connected destination. */
bool route_table_add(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric);

/* Returns the longest-prefix matching route, preferring the lower metric on equal prefixes. */
const route_entry_t* route_table_lookup(const route_table_t* table, ipv4_address_t destination);

/* Removes the route at index, retaining the remaining entries. */
bool route_table_remove(route_table_t* table, size_t index);
