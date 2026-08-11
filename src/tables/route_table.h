#pragma once

#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
==================
IPv4 Routing Table
==================
An IPv4 routing table maps destination prefixes to an egress interface and,
for remote networks, a next-hop router. Forwarding selects the matching route
with the longest prefix; when prefix lengths tie, the lower administrative
distance wins and then the lower metric wins. A zero next_hop denotes a directly
connected network, where the destination itself is resolved through ARP.

Real systems distinguish a control-plane routing information base (RIB) from
an optimized forwarding information base (FIB). This small table retains enough
RIB metadata to model connected, static, RIP, OSPF, and eBGP-learned routes while directly
serving forwarding lookup. It does not model recursion or ECMP.
*/
typedef enum route_source {
  ROUTE_SOURCE_CONNECTED,
  ROUTE_SOURCE_STATIC,
  ROUTE_SOURCE_RIP,
  ROUTE_SOURCE_OSPF,
  ROUTE_SOURCE_BGP,
} route_source_t;

typedef struct route_entry {
  ipv4_address_t destination;
  ipv4_address_t mask;
  ipv4_address_t next_hop;
  size_t interface_index;
  uint32_t metric;
  route_source_t source;
  uint32_t expires_at;
} route_entry_t;

typedef struct route_table {
  route_entry_t* entries;
  size_t capacity;
  size_t count;
} route_table_t;

/* Binds a caller-owned entry array to an initially empty routing table. */
void route_table_init(route_table_t* table, route_entry_t* entries, size_t capacity);

/* Adds a static route. next_hop is zero for a directly connected destination. */
bool route_table_add(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric);

/* Adds a connected interface route with the highest forwarding preference. */
bool route_table_add_connected(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, size_t interface_index);

/* Learns or refreshes one RIP route advertised by next_hop on one interface. */
bool route_table_learn_rip(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric, uint32_t expires_at);

/* Removes all RIP-learned routes, retaining connected and static configuration. */
void route_table_remove_rip(route_table_t* table);

/* Removes RIP-learned routes whose expiry time is no later than now. */
void route_table_expire_rip(route_table_t* table, uint32_t now);

/* Learns or refreshes one OSPF route advertised by next_hop on one interface. */
bool route_table_learn_ospf(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric, uint32_t expires_at);

/* Removes all OSPF-learned routes, retaining connected and static configuration. */
void route_table_remove_ospf(route_table_t* table);

/* Removes OSPF-learned routes whose expiry time is no later than now. */
void route_table_expire_ospf(route_table_t* table, uint32_t now);

/* Learns or refreshes an eBGP route from one configured peer. */
bool route_table_learn_bgp(route_table_t* table, ipv4_address_t destination, ipv4_address_t mask, ipv4_address_t next_hop, size_t interface_index, uint32_t metric);

/* Removes eBGP routes learned from one peer when its session closes. */
void route_table_remove_bgp_peer(route_table_t* table, ipv4_address_t next_hop, size_t interface_index);

/* Returns the longest-prefix matching route, then lowest distance and metric. */
const route_entry_t* route_table_lookup(const route_table_t* table, ipv4_address_t destination);

/* Removes the route at index, retaining the remaining entries. */
bool route_table_remove(route_table_t* table, size_t index);

/* Returns a stable human-readable source name for route-table presentation. */
const char* route_source_name(route_source_t source);
