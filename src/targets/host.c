/*
Interactive Ethernet host attached to one append-only VNet traffic file.
OSI/ISO layer: Layer 2 endpoint; optional IPv4 configuration supplies Layer 3 identity.
*/

#include <arp.h>
#include <cmd_app.h>
#include <ethernet.h>
#include <futils.h>
#include <icmp.h>
#include <ipv4.h>
#include <mutex.h>
#include <rarp.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcp.h>
#include <thread.h>
#include <udp.h>
#include <vnet.h>

#define HOST_DEVICE_CAPACITY  64
#define HOST_ARP_CAPACITY     64
#define HOST_BUFFER_SIZE      8192
#define HOST_PENDING_DATA_MAX (ETHERNET_MAX_DATA_LEN - sizeof(ipv4_header_t) - sizeof(tcp_header_t))
#define SLEEP_INTERVAL_MS     5

typedef struct host_device {
  mac_address_t mac;
  char path[VNET_PATH_LEN];
  bool has_mac;
} host_device_t;

typedef struct host_arp_entry {
  ipv4_address_t ip4;
  mac_address_t mac;
} host_arp_entry_t;

typedef enum host_pending_type {
  HOST_PENDING_NONE,
  HOST_PENDING_PING,
  HOST_PENDING_UDP,
  HOST_PENDING_TCP,
} host_pending_type_t;

typedef struct host_pending_packet {
  ipv4_address_t destination;
  ipv4_address_t next_hop;
  host_pending_type_t type;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t sequence_number;
  uint32_t acknowledgement_number;
  uint16_t flags;
  uint16_t window_size;
  uint8_t data[HOST_PENDING_DATA_MAX];
  uint16_t data_length;
  bool active;
} host_pending_packet_t;

typedef struct host_context {
  const char* path;
  mac_address_t mac;
  ipv4_address_t ip4;
  ipv4_address_t mask;
  ipv4_address_t gateway;
  bool has_ip4;
  bool has_gateway;
  uint16_t ping_sequence;
  FILE* source;
  mutex_t mutex;
  cmd_app_t commands;
  host_device_t devices[HOST_DEVICE_CAPACITY];
  size_t device_count;
  host_arp_entry_t arp_entries[HOST_ARP_CAPACITY];
  size_t arp_count;
  host_pending_packet_t pending_packet;
} host_context_t;

static bool ip4_is_local(const host_context_t* context, ipv4_address_t address) {
  return ipv4_addresses_share_subnet(context->ip4, address, context->mask);
}

static host_device_t* device_find_path(host_context_t* context, const char* path) {
  for (size_t i = 0; i < context->device_count; ++i) {
    if (strcmpi(context->devices[i].path, path) == 0) {
      return &context->devices[i];
    }
  }
  return NULL;
}

static host_device_t* device_find_mac(host_context_t* context, const mac_address_t mac) {
  for (size_t i = 0; i < context->device_count; ++i) {
    if (context->devices[i].has_mac && memcmp(context->devices[i].mac, mac, sizeof(mac_address_t)) == 0) {
      return &context->devices[i];
    }
  }
  return NULL;
}

static void device_start(host_context_t* context, const char* path) {
  if (device_find_path(context, path)) {
    return;
  }
  if (context->device_count == HOST_DEVICE_CAPACITY) {
    fprintf(stderr, "Device table is full; ignoring '%s'.\n", path);
    return;
  }
  host_device_t* device = &context->devices[context->device_count++];
  memset(device, 0, sizeof(*device));
  strncpy(device->path, path, sizeof(device->path) - 1);
}

static void device_end(host_context_t* context, const char* path) {
  for (size_t i = 0; i < context->device_count; ++i) {
    if (strcmpi(context->devices[i].path, path) == 0) {
      context->devices[i] = context->devices[--context->device_count];
      return;
    }
  }
}

static void device_learn(host_context_t* context, const mac_address_t mac) {
  host_device_t* device = device_find_mac(context, mac);
  if (!device && context->device_count > 0) {
    device = &context->devices[context->device_count - 1];
  }
  if (device) {
    memcpy(device->mac, mac, sizeof(device->mac));
    device->has_mac = true;
  }
}

static host_arp_entry_t* arp_find(host_context_t* context, ipv4_address_t address) {
  for (size_t i = 0; i < context->arp_count; ++i) {
    if (context->arp_entries[i].ip4 == address) {
      return &context->arp_entries[i];
    }
  }
  return NULL;
}

static void arp_learn(host_context_t* context, ipv4_address_t address, const mac_address_t mac) {
  host_arp_entry_t* entry = arp_find(context, address);
  if (!entry) {
    if (context->arp_count == HOST_ARP_CAPACITY) {
      context->arp_entries[0] = context->arp_entries[--context->arp_count];
    }
    entry = &context->arp_entries[context->arp_count++];
    entry->ip4 = address;
  }
  memcpy(entry->mac, mac, sizeof(entry->mac));
}

static bool write_arp_request(host_context_t* context, ipv4_address_t target) {
  FILE* destination = fopen(context->path, "ab");
  if (!destination) {
    fputs("Could not open the network file for ARP.\n", stderr);
    return false;
  }
  const arp_packet_data_t request = {
      .sender_hardware_address = {context->mac[0], context->mac[1], context->mac[2], context->mac[3], context->mac[4], context->mac[5]},
      .sender_protocol_address = context->ip4,
      .target_protocol_address = target,
  };
  const bool written = arp_write_ethernet_request(destination, &request);
  fclose(destination);
  return written;
}

static bool write_arp_reply(host_context_t* context, const arp_packet_t* request) {
  FILE* destination = fopen(context->path, "ab");
  if (!destination) {
    return false;
  }
  arp_reply_data_t reply = {
      .sender_protocol_address = context->ip4,
      .target_protocol_address = request->sender_protocol_address,
  };
  memcpy(reply.sender_hardware_address, context->mac, sizeof(reply.sender_hardware_address));
  memcpy(reply.target_hardware_address, request->sender_hardware_address, sizeof(reply.target_hardware_address));
  const bool written = arp_write_ethernet_reply(destination, &reply);
  fclose(destination);
  return written;
}

static bool write_rarp_request(host_context_t* context) {
  FILE* destination = fopen(context->path, "ab");
  if (!destination) {
    fputs("Could not open the network file for RARP.\n", stderr);
    return false;
  }
  rarp_request_data_t request = {0};
  memcpy(request.client_hardware_address, context->mac, sizeof(request.client_hardware_address));
  const bool written = rarp_write_ethernet_request(destination, &request);
  fclose(destination);
  return written;
}

static bool write_ping(host_context_t* context, ipv4_address_t destination_ip, const mac_address_t destination_mac) {
  FILE* destination = fopen(context->path, "ab");
  if (!destination) {
    fputs("Could not open the network file for ping.\n", stderr);
    return false;
  }
  const uint8_t data[] = {'v', 'n', 'e', 't'};
  icmp_echo_request_data_t request = {
      .src_addr = context->ip4,
      .dst_addr = destination_ip,
      .identifier = 1,
      .sequence_number = ++context->ping_sequence,
      .data = data,
      .data_length = sizeof(data),
  };
  memcpy(request.dst_mac_addr, destination_mac, sizeof(request.dst_mac_addr));
  memcpy(request.src_mac_addr, context->mac, sizeof(request.src_mac_addr));
  const bool written = icmp_write_ethernet_echo_request(destination, &request);
  fclose(destination);
  return written;
}

static bool write_ping_reply(host_context_t* context, const ethernet_frame_view_t* frame, const ipv4_packet_view_t* ip4, const icmp_echo_header_t* echo, const uint8_t* data, size_t data_length) {
  FILE* destination = fopen(context->path, "ab");
  if (!destination) {
    return false;
  }
  icmp_echo_request_data_t reply = {
      .src_addr = context->ip4,
      .dst_addr = ip4->header.src_addr,
      .identifier = echo->identifier,
      .sequence_number = echo->sequence_number,
      .data = data,
      .data_length = (uint16_t)data_length,
  };
  memcpy(reply.dst_mac_addr, frame->header.src_mac, sizeof(reply.dst_mac_addr));
  memcpy(reply.src_mac_addr, context->mac, sizeof(reply.src_mac_addr));
  const bool written = icmp_write_ethernet_echo_reply(destination, &reply);
  fclose(destination);
  return written;
}

static bool write_udp(host_context_t* context, const host_pending_packet_t* pending, const mac_address_t destination_mac) {
  FILE* destination = fopen(context->path, "ab");
  if (!destination) {
    fputs("Could not open the network file for UDP.\n", stderr);
    return false;
  }
  udp_packet_data_t packet = {
      .src_addr = context->ip4,
      .dst_addr = pending->destination,
      .src_port = pending->src_port,
      .dst_port = pending->dst_port,
      .data = pending->data,
      .data_length = pending->data_length,
  };
  memcpy(packet.dst_mac_addr, destination_mac, sizeof(packet.dst_mac_addr));
  memcpy(packet.src_mac_addr, context->mac, sizeof(packet.src_mac_addr));
  const bool written = udp_write_ethernet_packet(destination, &packet);
  fclose(destination);
  return written;
}

static bool write_tcp(host_context_t* context, const host_pending_packet_t* pending, const mac_address_t destination_mac) {
  FILE* destination = fopen(context->path, "ab");
  if (!destination) {
    fputs("Could not open the network file for TCP.\n", stderr);
    return false;
  }
  tcp_packet_data_t packet = {
      .src_addr = context->ip4,
      .dst_addr = pending->destination,
      .src_port = pending->src_port,
      .dst_port = pending->dst_port,
      .sequence_number = pending->sequence_number,
      .acknowledgement_number = pending->acknowledgement_number,
      .flags = pending->flags,
      .window_size = pending->window_size,
      .data = pending->data,
      .data_length = pending->data_length,
  };
  memcpy(packet.dst_mac_addr, destination_mac, sizeof(packet.dst_mac_addr));
  memcpy(packet.src_mac_addr, context->mac, sizeof(packet.src_mac_addr));
  const bool written = tcp_write_ethernet_packet(destination, &packet);
  fclose(destination);
  return written;
}

static bool send_pending_packet(host_context_t* context, const host_pending_packet_t* pending, const mac_address_t destination_mac) {
  bool written = false;
  if (pending->type == HOST_PENDING_PING) written = write_ping(context, pending->destination, destination_mac);
  else if (pending->type == HOST_PENDING_UDP)
    written = write_udp(context, pending, destination_mac);
  else if (pending->type == HOST_PENDING_TCP)
    written = write_tcp(context, pending, destination_mac);
  if (written) {
    fprintf(stdout, "Sent %s to ", pending->type == HOST_PENDING_PING ? "ping" : pending->type == HOST_PENDING_UDP ? "UDP datagram"
                                                                                                                   : "TCP segment");
    ipv4_address_print(stdout, pending->destination);
    fputs(".\n", stdout);
  }
  return written;
}

static bool route_next_hop(const host_context_t* context, ipv4_address_t destination, ipv4_address_t* next_hop) {
  if (ip4_is_local(context, destination)) {
    *next_hop = destination;
    return true;
  }
  if (context->has_gateway) {
    *next_hop = context->gateway;
    return true;
  }
  return false;
}

static void print_info(host_context_t* context) {
  mutex_lock(&context->mutex);
  fprintf(stdout, "Host file: %s\nHost MAC:  ", context->path);
  ethernet_mac_print(stdout, context->mac);
  fputc('\n', stdout);
  if (context->has_ip4) {
    fputs("Host IPv4: ", stdout);
    ipv4_address_print(stdout, context->ip4);
    fputs("\nSubnet mask: ", stdout);
    ipv4_address_print(stdout, context->mask);
    fputc('\n', stdout);
    if (context->has_gateway) {
      fputs("Default gateway: ", stdout);
      ipv4_address_print(stdout, context->gateway);
      fputc('\n', stdout);
    }
  }
  fprintf(stdout, "ARP cache (%zu):\n", context->arp_count);
  for (size_t i = 0; i < context->arp_count; ++i) {
    fputs("  ", stdout);
    ipv4_address_print(stdout, context->arp_entries[i].ip4);
    fputs("  ", stdout);
    ethernet_mac_print(stdout, context->arp_entries[i].mac);
    fputc('\n', stdout);
  }
  fprintf(stdout, "Devices (%zu):\n", context->device_count);
  for (size_t i = 0; i < context->device_count; ++i) {
    fprintf(stdout, "  %-48s ", context->devices[i].path);
    if (context->devices[i].has_mac) {
      ethernet_mac_print(stdout, context->devices[i].mac);
    } else {
      fputs("(MAC not learned)", stdout);
    }
    fputc('\n', stdout);
  }
  fflush(stdout);
  mutex_unlock(&context->mutex);
}

static void handle_vnet(host_context_t* context, const vnet_frame_header_t* frame) {
  if (strcmpi(frame->destination_path, context->path) != 0) {
    return;
  }
  mutex_lock(&context->mutex);
  if (frame->type == VNET_FRAME_CONNECTION_START) {
    device_start(context, frame->source_path);
    fprintf(stdout, "Connected to '%s'.\n", frame->source_path);
  } else {
    device_end(context, frame->source_path);
    fprintf(stdout, "Disconnected from '%s'.\n", frame->source_path);
  }
  fflush(stdout);
  mutex_unlock(&context->mutex);
}

static void handle_arp(host_context_t* context, const ethernet_frame_view_t* frame) {
  arp_packet_t packet = {0};
  if (!arp_parse_packet(frame->data, sizeof(packet), &packet)) {
    return;
  }
  mutex_lock(&context->mutex);
  arp_learn(context, packet.sender_protocol_address, packet.sender_hardware_address);
  mutex_unlock(&context->mutex);

  if (context->has_ip4 && packet.operation == ARP_OPERATION_REQUEST && packet.target_protocol_address == context->ip4) {
    if (write_arp_reply(context, &packet)) {
      fputs("Replied to ARP request from ", stdout);
      ipv4_address_print(stdout, packet.sender_protocol_address);
      fputs(".\n", stdout);
    }
  }

  host_pending_packet_t pending = {0};
  mutex_lock(&context->mutex);
  if (context->pending_packet.active && context->pending_packet.next_hop == packet.sender_protocol_address) {
    pending = context->pending_packet;
    context->pending_packet.active = false;
  }
  mutex_unlock(&context->mutex);
  if (pending.active) {
    send_pending_packet(context, &pending, packet.sender_hardware_address);
  }
}

static void handle_rarp(host_context_t* context, const ethernet_frame_view_t* frame) {
  rarp_packet_t packet = {0};
  if (!rarp_parse_packet(frame->data, sizeof(packet), &packet)) {
    return;
  }
  if (packet.operation == RARP_OPERATION_REPLY && memcmp(packet.target_hardware_address, context->mac, sizeof(context->mac)) == 0 && packet.target_protocol_address != 0) {
    mutex_lock(&context->mutex);
    context->ip4 = packet.target_protocol_address;
    context->has_ip4 = true;
    mutex_unlock(&context->mutex);
    fputs("Received RARP assignment: ", stdout);
    ipv4_address_print(stdout, packet.target_protocol_address);
    fputs(".\n", stdout);
  }
}

static void handle_ipv4(host_context_t* context, const ethernet_frame_view_t* frame) {
  ipv4_packet_view_t packet = {0};
  if (!context->has_ip4 || !ipv4_parse_packet(frame->data, frame->data_length, &packet) || packet.header.dst_addr != context->ip4 || packet.header.protocol != ICMP_IPV4_PROTOCOL) {
    return;
  }
  icmp_echo_header_t echo = {0};
  const uint8_t* data = NULL;
  size_t data_length = 0;
  if (!icmp_parse_echo_packet(packet.payload, packet.payload_length, &echo, &data, &data_length)) {
    return;
  }
  if (echo.type == ICMP_TYPE_ECHO_REQUEST && write_ping_reply(context, frame, &packet, &echo, data, data_length)) {
    fputs("Replied to ping from ", stdout);
    ipv4_address_print(stdout, packet.header.src_addr);
    fputs(".\n", stdout);
  } else if (echo.type == ICMP_TYPE_ECHO_REPLY) {
    fputs("Ping reply from ", stdout);
    ipv4_address_print(stdout, packet.header.src_addr);
    fprintf(stdout, ": sequence=%u.\n", echo.sequence_number);
  }
}

static void handle_ethernet(host_context_t* context, const uint8_t* bytes, size_t byte_count) {
  ethernet_frame_view_t frame = {0};
  if (!ethernet_parse_frame(bytes, byte_count, &frame)) {
    return;
  }
  const bool group = ethernet_mac_is_group(frame.header.dst_mac);
  if (!group && memcmp(frame.header.dst_mac, context->mac, sizeof(context->mac)) != 0) {
    return;
  }

  mutex_lock(&context->mutex);
  device_learn(context, frame.header.src_mac);
  fputs("Received ", stdout);
  group ? fputs(ethernet_mac_is_broadcast(frame.header.dst_mac) ? "broadcast" : "multicast", stdout) : fputs("unicast", stdout);
  fputs(" frame from ", stdout);
  ethernet_mac_print(stdout, frame.header.src_mac);
  fprintf(stdout, " (%zu bytes).\n", byte_count);
  fflush(stdout);
  mutex_unlock(&context->mutex);

  if (frame.format != ETHERNET_FRAME_FORMAT_II) {
    return;
  }
  if (frame.header.type_or_length == ETHERNET_ETHERTYPE_ARP) {
    handle_arp(context, &frame);
  } else if (frame.header.type_or_length == ETHERNET_ETHERTYPE_RARP) {
    handle_rarp(context, &frame);
  } else if (frame.header.type_or_length == ETHERNET_ETHERTYPE_IPV4) {
    handle_ipv4(context, &frame);
  }
}

static void process_bytes(host_context_t* context, uint8_t* buffer, size_t* buffer_length) {
  size_t offset = 0;
  while (offset < *buffer_length) {
    const size_t remaining = *buffer_length - offset;
    vnet_frame_header_t control = {0};
    if (remaining >= sizeof(control) && vnet_parse_frame(buffer + offset, sizeof(control), &control)) {
      handle_vnet(context, &control);
      offset += sizeof(control);
      continue;
    }
    if (!ethernet_frame_is_start(buffer + offset, remaining)) {
      ++offset;
      continue;
    }
    size_t end = offset + 1;
    while (end < *buffer_length && !ethernet_frame_is_start(buffer + end, *buffer_length - end) && !vnet_frame_has_prefix(buffer + end, *buffer_length - end)) {
      ++end;
    }
    ethernet_frame_view_t frame = {0};
    if (ethernet_parse_frame(buffer + offset, end - offset, &frame)) {
      handle_ethernet(context, buffer + offset, end - offset);
      offset = end;
      continue;
    }
    if (end == *buffer_length && remaining < sizeof(ethernet_header_t) + ETHERNET_MIN_DATA_LEN + sizeof(ethernet_footer_t)) {
      break;
    }
    ++offset;
  }
  if (offset > 0) {
    memmove(buffer, buffer + offset, *buffer_length - offset);
    *buffer_length -= offset;
  }
}

static void receiver_thread(void* argument) {
  host_context_t* context = argument;
  uint8_t buffer[HOST_BUFFER_SIZE] = {0};
  size_t buffer_length = 0;
  while (cmd_app_is_running(&context->commands)) {
    long end = 0;
    const long position = ftell(context->source);
    if (position < 0 || !get_file_end(context->source, &end)) {
      mutex_lock(&context->mutex);
      fputs("Could not read the network file.\n", stderr);
      mutex_unlock(&context->mutex);
      cmd_app_stop(&context->commands);
      break;
    }
    if (position < end) {
      const size_t available = (size_t)(end - position);
      const size_t read_count = available < sizeof(buffer) - buffer_length ? available : sizeof(buffer) - buffer_length;
      if (fread(buffer + buffer_length, 1, read_count, context->source) != read_count) {
        mutex_lock(&context->mutex);
        fputs("Could not read the network file.\n", stderr);
        mutex_unlock(&context->mutex);
        cmd_app_stop(&context->commands);
        break;
      }
      buffer_length += read_count;
      process_bytes(context, buffer, &buffer_length);
    }
    if (buffer_length == sizeof(buffer)) {
      mutex_lock(&context->mutex);
      fputs("Discarding an oversized or incomplete network frame.\n", stderr);
      mutex_unlock(&context->mutex);
      buffer_length = 0;
    }
    thread_sleep(SLEEP_INTERVAL_MS);
  }
}

static void print_usage(void) {
  fputs("Usage: host <file> <mac-address> [-ip4 <address> [-mask <address>] [-gateway <address>] ]\n", stderr);
}

static bool parse_options(host_context_t* context, int argc, char** argv) {
  context->mask = IPV4_ADDRESS(255, 255, 255, 0);
  for (int i = 3; i < argc; i += 2) {
    if (i + 1 >= argc) {
      return false;
    }
    if (strcmpi(argv[i], "-ip4") == 0) {
      if (context->has_ip4 || !ipv4_parse_address(argv[i + 1], &context->ip4)) {
        return false;
      }
      context->has_ip4 = true;
    } else if (strcmpi(argv[i], "-mask") == 0) {
      if (!ipv4_parse_address(argv[i + 1], &context->mask) || !ipv4_mask_is_contiguous(context->mask)) {
        return false;
      }
    } else if (strcmpi(argv[i], "-gateway") == 0) {
      if (context->has_gateway || !ipv4_parse_address(argv[i + 1], &context->gateway)) {
        return false;
      }
      context->has_gateway = true;
    } else {
      return false;
    }
  }
  return context->has_ip4 || (!context->has_gateway && context->mask == IPV4_ADDRESS(255, 255, 255, 0));
}

static void command_info(void* argument, char* arguments) {
  if (!cmd_app_arguments_empty(arguments)) {
    fputs("Usage: info\n", stderr);
    return;
  }
  print_info(argument);
}

static void command_arp(void* context_argument, char* argument) {
  host_context_t* context = context_argument;
  ipv4_address_t destination = 0;
  ipv4_address_t next_hop = 0;
  if (!context->has_ip4) {
    fputs("ARP requires an IPv4 address.\n", stderr);
  } else if (!ipv4_parse_address(argument, &destination)) {
    fputs("Usage: arp <ip-address>\n", stderr);
  } else if (!route_next_hop(context, destination, &next_hop)) {
    fputs("Destination is outside the local subnet and no default gateway is configured.\n", stderr);
  } else if (write_arp_request(context, next_hop)) {
    fputs("Sent ARP request for ", stdout);
    ipv4_address_print(stdout, next_hop);
    if (next_hop != destination) {
      fputs(" (default gateway for ", stdout);
      ipv4_address_print(stdout, destination);
      fputc(')', stdout);
    }
    fputs(".\n", stdout);
  }
}

static void command_rarp(void* context_argument, char* argument) {
  host_context_t* context = context_argument;
  if (!cmd_app_arguments_empty(argument)) {
    fputs("Usage: rarp\n", stderr);
  } else if (context->has_ip4) {
    fputs("RARP requires a host without an IPv4 address.\n", stderr);
  } else if (write_rarp_request(context)) {
    fputs("Sent RARP request for ", stdout);
    ethernet_mac_print(stdout, context->mac);
    fputs(".\n", stdout);
  }
}

static void command_ping(void* context_argument, char* argument) {
  host_context_t* context = context_argument;
  ipv4_address_t destination = 0;
  ipv4_address_t next_hop = 0;
  if (!context->has_ip4) {
    fputs("Ping requires an IPv4 address.\n", stderr);
  } else if (!ipv4_parse_address(argument, &destination)) {
    fputs("Usage: ping <ip-address>\n", stderr);
  } else if (!route_next_hop(context, destination, &next_hop)) {
    fputs("Destination is outside the local subnet and no default gateway is configured.\n", stderr);
  } else {
    mutex_lock(&context->mutex);
    host_arp_entry_t* entry = arp_find(context, next_hop);
    mac_address_t mac = {0};
    if (entry) {
      memcpy(mac, entry->mac, sizeof(mac));
    } else {
      context->pending_packet = (host_pending_packet_t) {
          .destination = destination,
          .next_hop = next_hop,
          .type = HOST_PENDING_PING,
          .active = true,
      };
    }
    mutex_unlock(&context->mutex);
    if (entry) {
      const host_pending_packet_t pending = {.destination = destination, .type = HOST_PENDING_PING};
      send_pending_packet(context, &pending, mac);
    } else if (write_arp_request(context, next_hop)) {
      fputs("Resolving ", stdout);
      ipv4_address_print(stdout, next_hop);
      fputs(" before pinging ", stdout);
      ipv4_address_print(stdout, destination);
      fputs(".\n", stdout);
    }
  }
}

static bool parse_tcp_flags(char* text, uint16_t* flags) {
  *flags = 0;
  char* flag = text;
  while (*flag) {
    char* next = strchr(flag, ',');
    if (next) *next = '\0';
    if (strcmpi(flag, "fin") == 0) *flags |= TCP_FLAG_FIN;
    else if (strcmpi(flag, "syn") == 0)
      *flags |= TCP_FLAG_SYN;
    else if (strcmpi(flag, "rst") == 0)
      *flags |= TCP_FLAG_RST;
    else if (strcmpi(flag, "psh") == 0)
      *flags |= TCP_FLAG_PSH;
    else if (strcmpi(flag, "ack") == 0)
      *flags |= TCP_FLAG_ACK;
    else if (strcmpi(flag, "urg") == 0)
      *flags |= TCP_FLAG_URG;
    else if (strcmpi(flag, "ece") == 0)
      *flags |= TCP_FLAG_ECE;
    else if (strcmpi(flag, "cwr") == 0)
      *flags |= TCP_FLAG_CWR;
    else if (strcmpi(flag, "ns") == 0)
      *flags |= TCP_FLAG_NS;
    else
      return false;
    if (!next) break;
    flag = next + 1;
    if (*flag == '\0') return false;
  }
  return true;
}

static void command_transport(host_context_t* context, host_pending_packet_t* pending) {
  ipv4_address_t next_hop = 0;
  if (!context->has_ip4) {
    fputs("UDP and TCP require an IPv4 address.\n", stderr);
  } else if (!route_next_hop(context, pending->destination, &next_hop)) {
    fputs("Destination is outside the local subnet and no default gateway is configured.\n", stderr);
  } else {
    mutex_lock(&context->mutex);
    host_arp_entry_t* entry = arp_find(context, next_hop);
    mac_address_t mac = {0};
    if (entry) {
      memcpy(mac, entry->mac, sizeof(mac));
    } else {
      pending->next_hop = next_hop;
      pending->active = true;
      context->pending_packet = *pending;
    }
    mutex_unlock(&context->mutex);
    if (entry) {
      send_pending_packet(context, pending, mac);
    } else if (write_arp_request(context, next_hop)) {
      fputs("Resolving ", stdout);
      ipv4_address_print(stdout, next_hop);
      fputs(" before sending a transport packet.\n", stdout);
    }
  }
}

static void command_udp(void* context_argument, char* argument) {
  host_context_t* context = context_argument;
  char* cursor = argument;
  char* src_port = cmd_app_next_argument(&cursor);
  char* dst_port = cmd_app_next_argument(&cursor);
  char* dst_ip = cmd_app_next_argument(&cursor);
  char* data_marker = cmd_app_next_argument(&cursor);
  char* data = cmd_app_next_argument(&cursor);
  if (!src_port || !dst_port || !dst_ip || !data_marker || !data || cmd_app_next_argument(&cursor) || strcmpi(data_marker, "-d") != 0) {
    fputs("Usage: udp <src_port> <dst_port> <dst_ip> -d <data>\n", stderr);
    return;
  }
  host_pending_packet_t pending = {.type = HOST_PENDING_UDP};
  const size_t data_length = strlen(data);
  if (!cmd_app_parse_uint16(src_port, &pending.src_port) || !cmd_app_parse_uint16(dst_port, &pending.dst_port) || !ipv4_parse_address(dst_ip, &pending.destination) || data_length > HOST_PENDING_DATA_MAX) {
    fputs("Invalid UDP ports, destination, or data (maximum 1460 bytes).\n", stderr);
    return;
  }
  memcpy(pending.data, data, data_length);
  pending.data_length = (uint16_t)data_length;
  command_transport(context, &pending);
}

static void command_tcp(void* context_argument, char* argument) {
  host_context_t* context = context_argument;
  char* cursor = argument;
  char* src_port = cmd_app_next_argument(&cursor);
  char* dst_port = cmd_app_next_argument(&cursor);
  char* dst_ip = cmd_app_next_argument(&cursor);
  host_pending_packet_t pending = {.type = HOST_PENDING_TCP, .sequence_number = 1, .window_size = UINT16_MAX, .flags = TCP_FLAG_PSH | TCP_FLAG_ACK};
  char* data = NULL;
  if (!src_port || !dst_port || !dst_ip || !cmd_app_parse_uint16(src_port, &pending.src_port) || !cmd_app_parse_uint16(dst_port, &pending.dst_port) || !ipv4_parse_address(dst_ip, &pending.destination)) goto usage;
  for (char* option = cmd_app_next_argument(&cursor); option; option = cmd_app_next_argument(&cursor)) {
    char* value = cmd_app_next_argument(&cursor);
    if (!value) goto usage;
    if (strcmpi(option, "-d") == 0) data = value;
    else if (strcmpi(option, "-seq") == 0) {
      if (!cmd_app_parse_uint32(value, &pending.sequence_number)) goto usage;
    } else if (strcmpi(option, "-ack") == 0) {
      if (!cmd_app_parse_uint32(value, &pending.acknowledgement_number)) goto usage;
    } else if (strcmpi(option, "-window") == 0) {
      if (!cmd_app_parse_uint16(value, &pending.window_size)) goto usage;
    } else if (strcmpi(option, "-flags") == 0) {
      if (!parse_tcp_flags(value, &pending.flags)) goto usage;
    } else if (strcmpi(option, "-d") != 0)
      goto usage;
  }
  if (!data || strlen(data) > HOST_PENDING_DATA_MAX) goto usage;
  memcpy(pending.data, data, strlen(data));
  pending.data_length = (uint16_t)strlen(data);
  command_transport(context, &pending);
  return;
usage:
  fputs("Usage: tcp <src_port> <dst_port> <dst_ip> -d <data> [-seq <number>] [-ack <number>] [-window <number>] [-flags <syn,ack,...>]\n", stderr);
}

int main(int argc, char** argv) {
  if (argc < 3 || ((argc - 3) % 2) != 0) {
    print_usage();
    return EXIT_FAILURE;
  }
  host_context_t context = {.path = argv[1]};
  if (!ethernet_mac_parse(argv[2], context.mac) || !parse_options(&context, argc, argv) || (context.has_gateway && !ip4_is_local(&context, context.gateway))) {
    print_usage();
    return EXIT_FAILURE;
  }
  context.source = fopen(context.path, "rb");
  if (!context.source || fseek(context.source, 0, SEEK_END) != 0) {
    fprintf(stderr, "Could not open '%s' for reading.\n", context.path);
    if (context.source) fclose(context.source);
    return EXIT_FAILURE;
  }
  if (!mutex_init(&context.mutex)) {
    fputs("Could not initialize the host mutex.\n", stderr);
    fclose(context.source);
    return EXIT_FAILURE;
  }
  cmd_app_init(&context.commands);
  thread_t thread;
  if (!thread_start(&thread, receiver_thread, &context)) {
    fprintf(stderr, "Could not start the packet receiver thread.\n");
    mutex_destroy(&context.mutex);
    fclose(context.source);
    return EXIT_FAILURE;
  }

  if (!cmd_app_register(&context.commands, "info", "Show host, routes, ARP cache, and learned devices.", command_info, &context) || !cmd_app_register(&context.commands, "arp", "Resolve the local destination or next-hop gateway.", command_arp, &context) || !cmd_app_register(&context.commands, "rarp", "Request an IPv4 address for this host MAC.", command_rarp, &context) || !cmd_app_register(&context.commands, "ping", "Send an ICMP Echo Request after ARP resolution.", command_ping, &context) || !cmd_app_register(&context.commands, "udp", "Send a UDP datagram after ARP resolution.", command_udp, &context) || !cmd_app_register(&context.commands, "tcp", "Send a base-header TCP segment after ARP resolution.", command_tcp, &context) || !cmd_app_start(&context.commands)) {
    fputs("Could not start the command application.\n", stderr);
    cmd_app_stop(&context.commands);
    thread_join(&thread);
    mutex_destroy(&context.mutex);
    fclose(context.source);
    return EXIT_FAILURE;
  }

  cmd_app_join(&context.commands);
  cmd_app_stop(&context.commands);
  thread_join(&thread);
  mutex_destroy(&context.mutex);
  fclose(context.source);
  return EXIT_SUCCESS;
}
