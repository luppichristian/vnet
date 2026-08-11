#pragma once

#include <ethernet.h>
#include <stdbool.h>
#include <stddef.h>

/*
============================
Bridge Forwarding Database
============================
An Ethernet bridge or Layer-2 switch learns the source MAC address of every
unicast frame it receives and records the ingress port in its forwarding
database (FDB, also called a MAC-address or CAM table). For a later unicast
frame, the switch sends it only to the learned destination port; unknown
unicast, broadcast, and multicast frames are flooded to all other ports.

Production switches age dynamic entries, isolate them by VLAN, and may install
static entries. This fixed-capacity simulator table deliberately models only
dynamic MAC-to-port learning and explicit removal when a port disconnects.
*/
typedef struct fdb_entry {
  mac_address_t mac;
  size_t port;
} fdb_entry_t;

typedef struct fdb_table {
  fdb_entry_t* entries;
  size_t capacity;
  size_t count;
} fdb_table_t;

/* Binds a caller-owned entry array to an initially empty forwarding database. */
void fdb_table_init(fdb_table_t* table, fdb_entry_t* entries, size_t capacity);

/* Returns the learned MAC mapping, or NULL when the destination is unknown. */
fdb_entry_t* fdb_table_find(fdb_table_t* table, const mac_address_t mac);
const fdb_entry_t* fdb_table_find_const(const fdb_table_t* table, const mac_address_t mac);

/* Learns or refreshes a unicast MAC on port. Returns false for group MACs or a full table. */
bool fdb_table_learn(fdb_table_t* table, const mac_address_t mac, size_t port);

/* Removes every learned MAC mapping on port. */
void fdb_table_remove_port(fdb_table_t* table, size_t port);

/* Removes one learned unicast MAC mapping. Returns false when it is absent. */
bool fdb_table_remove(fdb_table_t* table, const mac_address_t mac);
