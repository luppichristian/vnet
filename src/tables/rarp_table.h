#pragma once

#include <ethernet.h>
#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>

/*
========================
RARP Configuration Table
========================
Reverse ARP answers the inverse question to ARP: a booting client knows its
Ethernet MAC address and asks a RARP server for an administratively assigned
IPv4 address. The server therefore needs an authoritative, configured
MAC-to-IPv4 mapping; it cannot use an ARP cache, whose entries are learned
dynamically in the opposite direction.

RARP predates BOOTP and DHCP and is rarely deployed now, but it remains useful
in this simulator to demonstrate the protocol. Entries here are static and do
not model leases, relay agents, or automatic address allocation.
*/
typedef struct rarp_entry {
  mac_address_t mac;
  ipv4_address_t ip4;
} rarp_entry_t;

typedef struct rarp_table {
  rarp_entry_t* entries;
  size_t capacity;
  size_t count;
} rarp_table_t;

/* Binds a caller-owned entry array to an initially empty RARP configuration table. */
void rarp_table_init(rarp_table_t* table, rarp_entry_t* entries, size_t capacity);

/* Returns the administratively assigned address for mac, or NULL when it is not configured. */
rarp_entry_t* rarp_table_find(rarp_table_t* table, const mac_address_t mac);
const rarp_entry_t* rarp_table_find_const(const rarp_table_t* table, const mac_address_t mac);

/* Adds or replaces a static MAC-to-IPv4 assignment. Returns false for a full table. */
bool rarp_table_set(rarp_table_t* table, const mac_address_t mac, ipv4_address_t ip4);

/* Removes one static MAC-to-IPv4 assignment. */
bool rarp_table_remove(rarp_table_t* table, const mac_address_t mac);
