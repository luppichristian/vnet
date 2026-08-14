#pragma once

#include <ethernet.h>
#include <ipv6.h>

/*
===================
IPv6 Neighbor Cache
===================

IPv6 does not use ARP. Neighbor Discovery resolves an on-link IPv6 next hop to
the Ethernet MAC address needed for transmission. This table stores only the
resolved core mapping for one interface and does not yet model reachability or
timer state.
*/

typedef struct nd_entry {
  size_t interface_index;
  ipv6_address_t ip6;
  mac_address_t mac;
} nd_entry_t;

typedef struct nd_table {
  nd_entry_t* entries;
  size_t capacity;
  size_t count;
} nd_table_t;

void nd_table_init(nd_table_t* table, nd_entry_t* entries, size_t capacity);
nd_entry_t* nd_table_find(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6);
const nd_entry_t* nd_table_find_const(const nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6);
void nd_table_learn(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6, const mac_address_t mac);
bool nd_table_remove(nd_table_t* table, size_t interface_index, const ipv6_address_t* ip6);
