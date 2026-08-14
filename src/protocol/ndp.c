#include <ndp.h>

#include <string.h>

typedef struct ndp_link_layer_option_wire {
  ndp_option_header_t option;
  mac_address_t address;
} ndp_link_layer_option_wire_t;

static size_t append_source_link_layer_option(uint8_t* destination, size_t capacity, uint8_t type, const mac_address_t mac) {
  if (capacity < sizeof(ndp_link_layer_option_wire_t)) return 0;
  ndp_link_layer_option_wire_t option = {.option = {.type = type, .length = 1}};
  memcpy(option.address, mac, sizeof(option.address));
  memcpy(destination, &option, sizeof(option));
  return sizeof(option);
}

static bool write_ndp_message(FILE* destination, const mac_address_t dst_mac, const mac_address_t src_mac, const ipv6_address_t* src_addr, const ipv6_address_t* dst_addr, const uint8_t* message, uint16_t message_length) {
  ipv6_packet_data_t packet = {
      .src_addr = *src_addr,
      .dst_addr = *dst_addr,
      .next_header = IPV6_NEXT_HEADER_ICMPV6,
      .hop_limit = NDP_HOP_LIMIT_REQUIRED,
      .data = message,
      .data_length = message_length,
  };
  memcpy(packet.dst_mac_addr, dst_mac, sizeof(packet.dst_mac_addr));
  memcpy(packet.src_mac_addr, src_mac, sizeof(packet.src_mac_addr));
  return ipv6_write_ethernet_packet(destination, &packet);
}

bool ndp_write_router_solicitation(FILE* destination, const ndp_router_solicitation_data_t* request) {
  uint8_t bytes[sizeof(ndp_router_solicitation_wire_t) + sizeof(ndp_link_layer_option_wire_t)] = {0};
  ndp_router_solicitation_wire_t message = {.header = {.type = ICMPV6_TYPE_ROUTER_SOLICITATION}};
  size_t length = sizeof(message);
  memcpy(bytes, &message, sizeof(message));
  if (request->include_source_link_layer) length += append_source_link_layer_option(bytes + length, sizeof(bytes) - length, NDP_OPTION_SOURCE_LINK_LAYER, request->src_mac_addr);
  ((icmpv6_header_t*)bytes)->checksum = icmpv6_checksum(&request->src_addr, &request->dst_addr, bytes, (uint16_t)length);
  return write_ndp_message(destination, request->dst_mac_addr, request->src_mac_addr, &request->src_addr, &request->dst_addr, bytes, (uint16_t)length);
}

bool ndp_write_router_advertisement(FILE* destination, const ndp_router_advertisement_data_t* advertisement) {
  uint8_t bytes[sizeof(ndp_router_advertisement_wire_t) + sizeof(ndp_link_layer_option_wire_t) + sizeof(ndp_prefix_information_wire_t)] = {0};
  ndp_router_advertisement_wire_t message = {
      .header = {.type = ICMPV6_TYPE_ROUTER_ADVERTISEMENT},
      .current_hop_limit = advertisement->current_hop_limit,
      .flags = advertisement->flags,
      .router_lifetime = advertisement->router_lifetime,
      .reachable_time = advertisement->reachable_time,
      .retrans_timer = advertisement->retrans_timer,
  };
  size_t length = sizeof(message);
  memcpy(bytes, &message, sizeof(message));
  if (advertisement->include_source_link_layer) length += append_source_link_layer_option(bytes + length, sizeof(bytes) - length, NDP_OPTION_SOURCE_LINK_LAYER, advertisement->src_mac_addr);
  if (advertisement->include_prefix_information) {
    if (sizeof(bytes) - length < sizeof(ndp_prefix_information_wire_t)) return false;
    ndp_prefix_information_wire_t option = {
        .option = {.type = NDP_OPTION_PREFIX_INFORMATION, .length = (uint8_t)(sizeof(option) / 8)},
        .prefix_length = advertisement->prefix_length,
        .flags = (uint8_t)((advertisement->on_link ? NDP_ROUTER_FLAG_ON_LINK : 0) | (advertisement->autonomous ? NDP_ROUTER_FLAG_AUTONOMOUS : 0)),
        .valid_lifetime = advertisement->valid_lifetime,
        .preferred_lifetime = advertisement->preferred_lifetime,
        .prefix = advertisement->prefix,
    };
    memcpy(bytes + length, &option, sizeof(option));
    length += sizeof(option);
  }
  ((icmpv6_header_t*)bytes)->checksum = icmpv6_checksum(&advertisement->src_addr, &advertisement->dst_addr, bytes, (uint16_t)length);
  return write_ndp_message(destination, advertisement->dst_mac_addr, advertisement->src_mac_addr, &advertisement->src_addr, &advertisement->dst_addr, bytes, (uint16_t)length);
}

bool ndp_write_neighbor_solicitation(FILE* destination, const ndp_neighbor_solicitation_data_t* solicitation) {
  uint8_t bytes[sizeof(ndp_neighbor_solicitation_wire_t) + sizeof(ndp_link_layer_option_wire_t)] = {0};
  ndp_neighbor_solicitation_wire_t message = {
      .header = {.type = ICMPV6_TYPE_NEIGHBOR_SOLICITATION},
      .target_address = solicitation->target_address,
  };
  size_t length = sizeof(message);
  memcpy(bytes, &message, sizeof(message));
  if (solicitation->include_source_link_layer) length += append_source_link_layer_option(bytes + length, sizeof(bytes) - length, NDP_OPTION_SOURCE_LINK_LAYER, solicitation->src_mac_addr);
  ((icmpv6_header_t*)bytes)->checksum = icmpv6_checksum(&solicitation->src_addr, &solicitation->dst_addr, bytes, (uint16_t)length);
  return write_ndp_message(destination, solicitation->dst_mac_addr, solicitation->src_mac_addr, &solicitation->src_addr, &solicitation->dst_addr, bytes, (uint16_t)length);
}

bool ndp_write_neighbor_advertisement(FILE* destination, const ndp_neighbor_advertisement_data_t* advertisement) {
  uint8_t bytes[sizeof(ndp_neighbor_advertisement_wire_t) + sizeof(ndp_link_layer_option_wire_t)] = {0};
  ndp_neighbor_advertisement_wire_t message = {
      .header = {.type = ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT},
      .flags = advertisement->flags,
      .target_address = advertisement->target_address,
  };
  size_t length = sizeof(message);
  memcpy(bytes, &message, sizeof(message));
  if (advertisement->include_target_link_layer) length += append_source_link_layer_option(bytes + length, sizeof(bytes) - length, NDP_OPTION_TARGET_LINK_LAYER, advertisement->src_mac_addr);
  ((icmpv6_header_t*)bytes)->checksum = icmpv6_checksum(&advertisement->src_addr, &advertisement->dst_addr, bytes, (uint16_t)length);
  return write_ndp_message(destination, advertisement->dst_mac_addr, advertisement->src_mac_addr, &advertisement->src_addr, &advertisement->dst_addr, bytes, (uint16_t)length);
}

static bool parse_link_layer_option(const uint8_t* bytes, size_t byte_count, uint8_t expected_type, bool* present, mac_address_t mac) {
  *present = false;
  for (size_t offset = 0; offset + sizeof(ndp_option_header_t) <= byte_count;) {
    ndp_option_header_t header = {0};
    memcpy(&header, bytes + offset, sizeof(header));
    if (header.length == 0) return false;
    const size_t option_length = (size_t)header.length * 8;
    if (offset + option_length > byte_count) return false;
    if (header.type == expected_type) {
      if (option_length < sizeof(ndp_link_layer_option_wire_t)) return false;
      memcpy(mac, bytes + offset + sizeof(header), sizeof(mac_address_t));
      *present = true;
    }
    offset += option_length;
  }
  return true;
}

bool ndp_parse_router_solicitation(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_router_solicitation_t* solicitation) {
  ndp_router_solicitation_wire_t message = {0};
  if (!solicitation || byte_count < sizeof(message) || !icmpv6_parse_header(bytes, byte_count, source, destination, &message.header) || message.header.type != ICMPV6_TYPE_ROUTER_SOLICITATION || message.header.code != 0) return false;
  memcpy(&message, bytes, sizeof(message));
  return parse_link_layer_option(bytes + sizeof(message), byte_count - sizeof(message), NDP_OPTION_SOURCE_LINK_LAYER, &solicitation->has_source_link_layer, solicitation->source_link_layer);
}

bool ndp_parse_router_advertisement(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_router_advertisement_t* advertisement) {
  ndp_router_advertisement_wire_t message = {0};
  if (!advertisement || byte_count < sizeof(message) || !icmpv6_parse_header(bytes, byte_count, source, destination, &message.header) || message.header.type != ICMPV6_TYPE_ROUTER_ADVERTISEMENT || message.header.code != 0) return false;
  memcpy(&message, bytes, sizeof(message));
  *advertisement = (ndp_router_advertisement_t) {
      .current_hop_limit = message.current_hop_limit,
      .flags = message.flags,
      .router_lifetime = message.router_lifetime,
      .reachable_time = message.reachable_time,
      .retrans_timer = message.retrans_timer,
  };
  size_t offset = sizeof(message);
  while (offset + sizeof(ndp_option_header_t) <= byte_count) {
    ndp_option_header_t header = {0};
    memcpy(&header, bytes + offset, sizeof(header));
    if (header.length == 0) return false;
    const size_t option_length = (size_t)header.length * 8;
    if (offset + option_length > byte_count) return false;
    if (header.type == NDP_OPTION_SOURCE_LINK_LAYER) {
      if (option_length < sizeof(ndp_link_layer_option_wire_t)) return false;
      memcpy(advertisement->source_link_layer, bytes + offset + sizeof(header), sizeof(mac_address_t));
      advertisement->has_source_link_layer = true;
    } else if (header.type == NDP_OPTION_PREFIX_INFORMATION) {
      ndp_prefix_information_wire_t option = {0};
      if (option_length < sizeof(option)) return false;
      memcpy(&option, bytes + offset, sizeof(option));
      advertisement->has_prefix_information = true;
      advertisement->prefix = option.prefix;
      advertisement->prefix_length = option.prefix_length;
      advertisement->on_link = (option.flags & NDP_ROUTER_FLAG_ON_LINK) != 0;
      advertisement->autonomous = (option.flags & NDP_ROUTER_FLAG_AUTONOMOUS) != 0;
      advertisement->valid_lifetime = option.valid_lifetime;
      advertisement->preferred_lifetime = option.preferred_lifetime;
    }
    offset += option_length;
  }
  return true;
}

bool ndp_parse_neighbor_solicitation(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_neighbor_solicitation_t* solicitation) {
  ndp_neighbor_solicitation_wire_t message = {0};
  if (!solicitation || byte_count < sizeof(message) || !icmpv6_parse_header(bytes, byte_count, source, destination, &message.header) || message.header.type != ICMPV6_TYPE_NEIGHBOR_SOLICITATION || message.header.code != 0) return false;
  memcpy(&message, bytes, sizeof(message));
  solicitation->target_address = message.target_address;
  return parse_link_layer_option(bytes + sizeof(message), byte_count - sizeof(message), NDP_OPTION_SOURCE_LINK_LAYER, &solicitation->has_source_link_layer, solicitation->source_link_layer);
}

bool ndp_parse_neighbor_advertisement(const uint8_t* bytes, size_t byte_count, const ipv6_address_t* source, const ipv6_address_t* destination, ndp_neighbor_advertisement_t* advertisement) {
  ndp_neighbor_advertisement_wire_t message = {0};
  if (!advertisement || byte_count < sizeof(message) || !icmpv6_parse_header(bytes, byte_count, source, destination, &message.header) || message.header.type != ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT || message.header.code != 0) return false;
  memcpy(&message, bytes, sizeof(message));
  advertisement->flags = message.flags;
  advertisement->target_address = message.target_address;
  return parse_link_layer_option(bytes + sizeof(message), byte_count - sizeof(message), NDP_OPTION_TARGET_LINK_LAYER, &advertisement->has_target_link_layer, advertisement->target_link_layer);
}
