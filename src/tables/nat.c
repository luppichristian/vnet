#include "nat.h"

#include <tcp.h>
#include <udp.h>

#include <limits.h>
#include <string.h>

static bool is_transport_protocol(uint8_t protocol) {
  return protocol == UDP_IPV4_PROTOCOL || protocol == TCP_IPV4_PROTOCOL;
}

static nat_entry_t* find_free_entry(nat_table_t* table) {
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    if (!table->entries[i].active) return &table->entries[i];
  }
  return NULL;
}

static bool outside_address_is_available(const nat_table_t* table, ipv4_address_t outside_address) {
  for (size_t i = 0; i < table->capacity; ++i) {
    const nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->kind == NAT_TRANSLATION_NAT && entry->outside_address == outside_address) return false;
  }
  return true;
}

static bool outside_port_is_available(const nat_table_t* table, uint8_t protocol, ipv4_address_t outside_address, uint16_t outside_port) {
  for (size_t i = 0; i < table->capacity; ++i) {
    const nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->kind == NAT_TRANSLATION_PAT && entry->protocol == protocol && entry->outside_address == outside_address && entry->outside_port == outside_port) return false;
  }
  return true;
}

void nat_table_init(nat_table_t* table, nat_entry_t* entries, size_t capacity, ipv4_address_t* pool, size_t pool_capacity, uint16_t first_port) {
  if (!table) return;
  *table = (nat_table_t) {
      .entries = entries,
      .pool = pool,
      .capacity = capacity,
      .pool_capacity = pool_capacity,
      .next_port = first_port < NAT_EPHEMERAL_PORT_MIN ? NAT_EPHEMERAL_PORT_MIN : first_port,
  };
  if (entries) memset(entries, 0, capacity * sizeof(*entries));
  if (pool) memset(pool, 0, pool_capacity * sizeof(*pool));
}

bool nat_table_add_static_nat(nat_table_t* table, ipv4_address_t inside_address, ipv4_address_t outside_address) {
  if (!table || !inside_address || !outside_address || !outside_address_is_available(table, outside_address)) return false;
  for (size_t i = 0; i < table->capacity; ++i) {
    const nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->kind == NAT_TRANSLATION_NAT && entry->inside_address == inside_address) return false;
  }
  nat_entry_t* entry = find_free_entry(table);
  if (!entry) return false;
  *entry = (nat_entry_t) {.inside_address = inside_address, .outside_address = outside_address, .kind = NAT_TRANSLATION_NAT, .is_static = true, .active = true};
  return true;
}

bool nat_table_add_static_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t outside_address, uint16_t outside_port) {
  if (!table || !is_transport_protocol(protocol) || !inside_address || !outside_address || !inside_port || !outside_port || !outside_port_is_available(table, protocol, outside_address, outside_port)) return false;
  nat_entry_t* entry = find_free_entry(table);
  if (!entry) return false;
  *entry = (nat_entry_t) {.inside_address = inside_address, .outside_address = outside_address, .inside_port = inside_port, .outside_port = outside_port, .protocol = protocol, .kind = NAT_TRANSLATION_PAT, .is_static = true, .active = true};
  return true;
}

bool nat_table_add_pool(nat_table_t* table, ipv4_address_t outside_address) {
  if (!table || !outside_address || table->pool_count == table->pool_capacity) return false;
  for (size_t i = 0; i < table->pool_count; ++i) {
    if (table->pool[i] == outside_address) return false;
  }
  table->pool[table->pool_count++] = outside_address;
  return true;
}

nat_entry_t* nat_table_find_outbound_nat(nat_table_t* table, ipv4_address_t inside_address, ipv4_address_t remote_address) {
  (void)remote_address;
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->kind == NAT_TRANSLATION_NAT && entry->inside_address == inside_address) return entry;
  }
  return NULL;
}

nat_entry_t* nat_table_open_dynamic_nat(nat_table_t* table, ipv4_address_t inside_address) {
  nat_entry_t* entry = nat_table_find_outbound_nat(table, inside_address, 0);
  if (entry || !table || !inside_address || !table->pool_count) return entry;
  for (size_t i = 0; i < table->pool_count; ++i) {
    const size_t index = (table->next_pool + i) % table->pool_count;
    if (!outside_address_is_available(table, table->pool[index])) continue;
    entry = find_free_entry(table);
    if (!entry) return NULL;
    *entry = (nat_entry_t) {.inside_address = inside_address, .outside_address = table->pool[index], .kind = NAT_TRANSLATION_NAT, .active = true};
    table->next_pool = (index + 1) % table->pool_count;
    return entry;
  }
  return NULL;
}

nat_entry_t* nat_table_open_dynamic_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t remote_address, uint16_t remote_port, ipv4_address_t outside_address) {
  if (!table || !is_transport_protocol(protocol) || !inside_address || !inside_port || !remote_address || !remote_port || !outside_address) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    nat_entry_t* entry = &table->entries[i];
    if (entry->active && !entry->is_static && entry->kind == NAT_TRANSLATION_PAT && entry->protocol == protocol && entry->inside_address == inside_address && entry->inside_port == inside_port && entry->remote_address == remote_address && entry->remote_port == remote_port && entry->outside_address == outside_address) return entry;
  }
  nat_entry_t* entry = find_free_entry(table);
  if (!entry) return NULL;
  for (uint32_t attempts = 0; attempts <= UINT16_MAX - NAT_EPHEMERAL_PORT_MIN; ++attempts) {
    const uint16_t outside_port = table->next_port;
    table->next_port = outside_port == UINT16_MAX ? NAT_EPHEMERAL_PORT_MIN : outside_port + 1;
    if (!outside_port_is_available(table, protocol, outside_address, outside_port)) continue;
    *entry = (nat_entry_t) {.inside_address = inside_address, .outside_address = outside_address, .remote_address = remote_address, .inside_port = inside_port, .outside_port = outside_port, .remote_port = remote_port, .protocol = protocol, .kind = NAT_TRANSLATION_PAT, .active = true};
    return entry;
  }
  return NULL;
}

nat_entry_t* nat_table_find_inbound_nat(nat_table_t* table, ipv4_address_t outside_address, ipv4_address_t remote_address) {
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->kind == NAT_TRANSLATION_NAT && entry->outside_address == outside_address) return entry;
  }
  return NULL;
}

nat_entry_t* nat_table_find_outbound_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t outside_address) {
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->is_static && entry->kind == NAT_TRANSLATION_PAT && entry->protocol == protocol && entry->inside_address == inside_address && entry->inside_port == inside_port && entry->outside_address == outside_address) return entry;
  }
  return NULL;
}

nat_entry_t* nat_table_find_inbound_pat(nat_table_t* table, uint8_t protocol, ipv4_address_t outside_address, uint16_t outside_port, ipv4_address_t remote_address, uint16_t remote_port) {
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->kind == NAT_TRANSLATION_PAT && entry->protocol == protocol && entry->outside_address == outside_address && entry->outside_port == outside_port && (entry->is_static || (entry->remote_address == remote_address && entry->remote_port == remote_port))) return entry;
  }
  return NULL;
}

bool nat_rewrite_transport(const ipv4_packet_view_t* packet, ipv4_address_t source_address, ipv4_address_t destination_address, uint16_t source_port, uint16_t destination_port, uint8_t* payload, size_t capacity, uint16_t* payload_length) {
  if (!packet || !payload || !payload_length) return false;
  if (packet->header.protocol == UDP_IPV4_PROTOCOL) {
    udp_packet_view_t udp = {0};
    udp_packet_data_t rewritten = {.src_addr = source_address, .dst_addr = destination_address};
    if (!udp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &udp)) return false;
    rewritten.src_port = source_port;
    rewritten.dst_port = destination_port;
    rewritten.data = udp.data;
    rewritten.data_length = udp.data_length;
    return udp_serialize_packet(&rewritten, payload, capacity, payload_length);
  }
  if (packet->header.protocol == TCP_IPV4_PROTOCOL) {
    tcp_packet_view_t tcp = {0};
    tcp_packet_data_t rewritten = {.src_addr = source_address, .dst_addr = destination_address};
    if (!tcp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &tcp)) return false;
    rewritten.src_port = source_port;
    rewritten.dst_port = destination_port;
    rewritten.sequence_number = tcp.header.sequence_number;
    rewritten.acknowledgement_number = tcp.header.acknowledgement_number;
    rewritten.window_size = tcp.header.window_size;
    rewritten.flags = (tcp.header.fin ? TCP_FLAG_FIN : 0) | (tcp.header.syn ? TCP_FLAG_SYN : 0) | (tcp.header.rst ? TCP_FLAG_RST : 0) | (tcp.header.psh ? TCP_FLAG_PSH : 0) | (tcp.header.ack ? TCP_FLAG_ACK : 0) | (tcp.header.urg ? TCP_FLAG_URG : 0) | (tcp.header.ece ? TCP_FLAG_ECE : 0) | (tcp.header.cwr ? TCP_FLAG_CWR : 0) | (tcp.header.ns ? TCP_FLAG_NS : 0);
    rewritten.data = tcp.data;
    rewritten.data_length = tcp.data_length;
    return tcp_serialize_packet(&rewritten, payload, capacity, payload_length);
  }
  return false;
}

