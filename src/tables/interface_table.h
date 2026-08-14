#pragma once

#include <ethernet.h>
#include <ipv4.h>
#include <ipv6.h>
#include <stdbool.h>
#include <stddef.h>
#include <vnet.h>

/*
======================
Router Interface Table
======================
A router forwards between interfaces, not directly between networks. Each
interface supplies a Layer-2 identity (MAC address), a Layer-3 address and
subnet mask, and attachment to one local medium. A forwarding decision selects
an interface from the routing table; ARP then resolves a next hop on that same
interface.

In this file-based simulator, path identifies the VNet medium in place of a
physical port, VLAN subinterface, or operating-system interface index. This
table models one static IPv4 address plus one simulator-derived IPv6 /64 for
basic dual-stack behavior. It still does not represent MTU, link state, or
multiple addresses per interface.
*/
typedef struct interface_entry {
  char path[VNET_PATH_LEN];
  mac_address_t mac;
  ipv4_address_t ip4;
  ipv4_address_t mask;
  ipv6_address_t ip6_link_local;
  ipv6_address_t ip6_global;
  ipv6_address_t ip6_prefix;
  uint8_t ip6_prefix_length;
  bool enabled;
} interface_entry_t;

typedef struct interface_table {
  interface_entry_t* entries;
  size_t capacity;
  size_t count;
} interface_table_t;

/* Binds a caller-owned entry array to an initially empty interface table. */
void interface_table_init(interface_table_t* table, interface_entry_t* entries, size_t capacity);

/* Finds a configured interface by its VNet path or local IPv4 address. */
interface_entry_t* interface_table_find_path(interface_table_t* table, const char* path);
interface_entry_t* interface_table_find_ip4(interface_table_t* table, ipv4_address_t ip4);
const interface_entry_t* interface_table_get(const interface_table_t* table, size_t index);

/* Adds an enabled interface. Returns false for duplicate paths, invalid masks, or a full table. */
bool interface_table_add(interface_table_t* table, const char* path, const mac_address_t mac, ipv4_address_t ip4, ipv4_address_t mask);

/* Changes the administrative state of an existing interface. */
bool interface_table_set_enabled(interface_table_t* table, size_t index, bool enabled);
