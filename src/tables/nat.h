#pragma once

#include <ipv4.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
==========================
IPv4 NAT and PAT Bindings
==========================
NAT is a router-owned translation policy backed by this Layer-3/4 state table;
it is not an on-the-wire protocol. Static NAT maps one inside IPv4 address to
one outside IPv4 address. Dynamic NAT allocates an outside address from the
configured pool. Static PAT forwards a configured outside transport port to an
inside endpoint. Dynamic PAT allocates an outside ephemeral port, allowing
multiple inside transport flows to share the router's outside address.

Dynamic bindings are remote-tuple restricted: replies must match the transport
protocol, translated endpoint, and original remote endpoint. Static mappings
are not restricted to a remote endpoint, which models reachable static NAT and
port forwarding. Only UDP and the simulator's base-header TCP are supported.
*/
#define NAT_EPHEMERAL_PORT_MIN 49152

typedef enum nat_translation_kind {
  NAT_TRANSLATION_NAT,
  NAT_TRANSLATION_PAT,
} nat_translation_kind_t;

typedef struct nat_entry {
  ipv4_address_t inside_address;
  ipv4_address_t outside_address;
  ipv4_address_t remote_address;
  uint16_t inside_port;
  uint16_t outside_port;
  uint16_t remote_port;
  uint8_t protocol;
  nat_translation_kind_t kind;
  bool is_static;
  bool active;
} nat_entry_t;

typedef struct nat_table {
  nat_entry_t* entries;
  ipv4_address_t* pool;
  size_t capacity;
  size_t pool_capacity;
  size_t pool_count;
  size_t next_pool;
  uint16_t next_port;
} nat_table_t;

/* Binds caller-owned binding and dynamic-address-pool storage to an empty table. */
void nat_table_init(nat_table_t* table, nat_entry_t* entries, size_t capacity, ipv4_address_t* pool, size_t pool_capacity, uint16_t first_port);

/* Adds a static one-to-one IPv4 mapping; duplicate inside/outside addresses are rejected. */
bool nat_table_add_static_nat(nat_table_t* table, ipv4_address_t inside_address, ipv4_address_t outside_address);

/* Adds a static UDP or TCP port-forwarding mapping. */
bool nat_table_add_static_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t outside_address, uint16_t outside_port);

/* Adds one outside IPv4 address available for dynamic one-to-one NAT. */
bool nat_table_add_pool(nat_table_t* table, ipv4_address_t outside_address);

/* Reuses or allocates a dynamic one-to-one IPv4 binding from the address pool. */
nat_entry_t* nat_table_open_dynamic_nat(nat_table_t* table, ipv4_address_t inside_address);

/* Reuses or allocates a dynamic UDP/TCP port binding on outside_address. */
nat_entry_t* nat_table_open_dynamic_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t remote_address, uint16_t remote_port, ipv4_address_t outside_address);

/* Finds the applicable outbound address mapping, preferring static NAT over dynamic NAT. */
nat_entry_t* nat_table_find_outbound_nat(nat_table_t* table, ipv4_address_t inside_address, ipv4_address_t remote_address);

/* Finds the applicable inbound address mapping. */
nat_entry_t* nat_table_find_inbound_nat(nat_table_t* table, ipv4_address_t outside_address, ipv4_address_t remote_address);

/* Finds a configured static port mapping for an outbound UDP/TCP endpoint. */
nat_entry_t* nat_table_find_outbound_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t outside_address);

/* Finds the applicable inbound port mapping. */
nat_entry_t* nat_table_find_inbound_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t outside_address, uint16_t outside_port, ipv4_address_t remote_address, uint16_t remote_port);

/* Rewrites a UDP or base-header TCP payload and regenerates its transport checksum. */
bool nat_rewrite_transport(const ipv4_packet_view_t* packet, ipv4_address_t source_address, ipv4_address_t destination_address, uint16_t source_port, uint16_t destination_port, uint8_t* payload, size_t capacity, uint16_t* payload_length);
