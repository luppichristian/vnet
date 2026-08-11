#include <ospf.h>

#include <math.h>
#include <string.h>

bool ospf_is_all_spf_routers(ipv4_address_t address) {
  return address == OSPF_ALL_SPF_ROUTERS;
}

static bool ospf_link_is_valid(const ospf_router_link_t* link) {
  return ipv4_mask_is_contiguous(link->mask) && (link->network & link->mask) == link->network && link->metric > 0 && link->reserved == 0;
}

bool ospf_write_router_update(ipv4_address_t router_id, const ospf_router_link_t* links, size_t link_count, uint8_t* bytes, size_t capacity, size_t* byte_count) {
  const size_t length = sizeof(ospf_header_t) + link_count * sizeof(ospf_router_link_t);
  if (!router_id || !bytes || !byte_count || link_count == 0 || link_count > OSPF_MAX_LINKS_PER_PACKET || !links || length > UINT16_MAX || capacity < length) return false;
  for (size_t i = 0; i < link_count; ++i) {
    if (!ospf_link_is_valid(&links[i])) return false;
  }
  ospf_header_t header = {
      .version = OSPF_VERSION,
      .packet_type = OSPF_PACKET_TYPE_LINK_STATE_UPDATE,
      .packet_length = (uint16_t)length,
      .router_id = router_id,
      .area_id = OSPF_AREA_BACKBONE,
  };
  memcpy(bytes, &header, sizeof(header));
  memcpy(bytes + sizeof(header), links, link_count * sizeof(*links));
  ((ospf_header_t*)bytes)->checksum = checksum16(bytes, length);
  *byte_count = length;
  return true;
}

bool ospf_parse_router_update(const uint8_t* bytes, size_t byte_count, ospf_packet_view_t* packet) {
  if (!bytes || !packet || byte_count < sizeof(packet->header)) return false;
  memcpy(&packet->header, bytes, sizeof(packet->header));
  if (packet->header.version != OSPF_VERSION || packet->header.packet_type != OSPF_PACKET_TYPE_LINK_STATE_UPDATE || packet->header.packet_length != byte_count || packet->header.area_id != OSPF_AREA_BACKBONE || packet->header.authentication_type != 0 || memcmp(packet->header.authentication, (uint8_t[8]) {0}, sizeof(packet->header.authentication)) != 0 || checksum16(bytes, byte_count) != 0 || (byte_count - sizeof(packet->header)) % sizeof(ospf_router_link_t) != 0) return false;
  packet->link_count = (byte_count - sizeof(packet->header)) / sizeof(ospf_router_link_t);
  packet->links = (const ospf_router_link_t*)(bytes + sizeof(packet->header));
  if (!packet->header.router_id || packet->link_count == 0 || packet->link_count > OSPF_MAX_LINKS_PER_PACKET) return false;
  for (size_t i = 0; i < packet->link_count; ++i) {
    if (!ospf_link_is_valid(&packet->links[i])) return false;
  }
  return true;
}
