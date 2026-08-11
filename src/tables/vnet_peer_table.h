#pragma once

#include <ethernet.h>
#include <stdbool.h>
#include <stddef.h>
#include <vnet.h>

/*
===================
VNet Peer Table
===================
VNet is simulator control metadata rather than a real network protocol. This
table records each connected VNet path and, after traffic arrives, the MAC
address learned from that peer. It lets a target explain which simulated file
connection supplied observed Ethernet traffic.

The closest device concept is an interface-neighbor or attachment registry,
but it is not a bridge FDB and must not drive Ethernet forwarding decisions.
Real systems identify peers through physical ports, interface indices, and
link-layer control protocols rather than filesystem paths.
*/
typedef struct vnet_peer_entry {
  mac_address_t mac;
  char path[VNET_PATH_LEN];
  bool has_mac;
} vnet_peer_entry_t;

typedef struct vnet_peer_table {
  vnet_peer_entry_t* entries;
  size_t capacity;
  size_t count;
} vnet_peer_table_t;

/* Binds a caller-owned entry array to an initially empty peer table. */
void vnet_peer_table_init(vnet_peer_table_t* table, vnet_peer_entry_t* entries, size_t capacity);

/* Returns the peer for path or mac, or NULL when no peer matches. */
vnet_peer_entry_t* vnet_peer_table_find_path(vnet_peer_table_t* table, const char* path);
vnet_peer_entry_t* vnet_peer_table_find_mac(vnet_peer_table_t* table, const mac_address_t mac);

/* Adds path when it is not already connected. Returns false when the table is full. */
bool vnet_peer_table_start(vnet_peer_table_t* table, const char* path);

/* Removes the connected peer path when present. */
void vnet_peer_table_end(vnet_peer_table_t* table, const char* path);

/* Associates mac with the most recently added unassigned peer. */
void vnet_peer_table_learn_mac(vnet_peer_table_t* table, const mac_address_t mac);
