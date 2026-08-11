#include <nat.h>

#include <tcp.h>
#include <udp.h>

#include <limits.h>
#include <string.h>

void nat_table_init(nat_table_t* table, nat_entry_t* entries, size_t capacity, uint16_t first_port) {
  if (!table) return;
  table->entries = entries;
  table->capacity = capacity;
  table->next_port = first_port < NAT_EPHEMERAL_PORT_MIN ? NAT_EPHEMERAL_PORT_MIN : first_port;
  if (entries) memset(entries, 0, capacity * sizeof(*entries));
}

nat_entry_t* nat_table_find_outbound(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t remote_address, uint16_t remote_port) {
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->protocol == protocol && entry->inside_address == inside_address && entry->inside_port == inside_port && entry->remote_address == remote_address && entry->remote_port == remote_port) return entry;
  }
  return NULL;
}

nat_entry_t* nat_table_find_inbound(nat_table_t* table, uint8_t protocol, uint16_t outside_port, ipv4_address_t remote_address, uint16_t remote_port) {
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    nat_entry_t* entry = &table->entries[i];
    if (entry->active && entry->protocol == protocol && entry->outside_port == outside_port && entry->remote_address == remote_address && entry->remote_port == remote_port) return entry;
  }
  return NULL;
}

nat_entry_t* nat_table_open(nat_table_t* table, uint8_t protocol, ipv4_address_t inside_address, uint16_t inside_port, ipv4_address_t remote_address, uint16_t remote_port) {
  nat_entry_t* entry = nat_table_find_outbound(table, protocol, inside_address, inside_port, remote_address, remote_port);
  if (entry) return entry;
  if (!table) return NULL;
  for (size_t i = 0; i < table->capacity; ++i) {
    entry = &table->entries[i];
    if (!entry->active) {
      const uint16_t outside_port = table->next_port;
      table->next_port = outside_port == UINT16_MAX ? NAT_EPHEMERAL_PORT_MIN : outside_port + 1;
      *entry = (nat_entry_t) {.inside_address = inside_address, .inside_port = inside_port, .remote_address = remote_address, .remote_port = remote_port, .outside_port = outside_port, .protocol = protocol, .active = true};
      return entry;
    }
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
