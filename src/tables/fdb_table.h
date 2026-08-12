#pragma once

#include <ethernet.h>
#include <stdbool.h>
#include <stddef.h>

/*
============================
Bridge Forwarding Database
============================
An Ethernet bridge or Layer-2 switch learns each unicast source MAC address in
its ingress VLAN and records the ingress port. Later unicast traffic can use
that VLAN-local mapping; unknown unicast, broadcast, and multicast flood.

Production switches age dynamic entries and may install static entries. This
fixed-capacity simulator table models VLAN-isolated dynamic learning and
explicit removal when a port disconnects.
*/
typedef struct fdb_entry {
  mac_address_t mac;
  uint16_t vlan_id;
  size_t port;
} fdb_entry_t;

typedef struct fdb_table {
  fdb_entry_t* entries;
  size_t capacity;
  size_t count;
} fdb_table_t;

/* Binds a caller-owned entry array to an initially empty forwarding database. */
void fdb_table_init(fdb_table_t* table, fdb_entry_t* entries, size_t capacity);

/* Returns the learned VLAN-local MAC mapping, or NULL when the destination is unknown. */
fdb_entry_t* fdb_table_find(fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id);
const fdb_entry_t* fdb_table_find_const(const fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id);

/* Learns or refreshes a unicast MAC in VLAN on port. Returns false for group MACs or a full table. */
bool fdb_table_learn(fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id, size_t port);

/* Removes every learned MAC mapping on port. */
void fdb_table_remove_port(fdb_table_t* table, size_t port);

/* Removes one learned unicast MAC mapping from VLAN. Returns false when it is absent. */
bool fdb_table_remove(fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id);
