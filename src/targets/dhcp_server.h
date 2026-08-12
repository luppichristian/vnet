#pragma once

/* Interactive configurable DHCPv4 service attached to one VNet LAN. */

#include <cmd_app.h>
#include <dhcp.h>
#include <ethernet.h>
#include <futils.h>
#include <mutex.h>
#include <thread.h>
#include <udp.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DHCP_SERVER_BUFFER_SIZE 8192
#define DHCP_SERVER_LEASE_CAPACITY 64

typedef struct dhcp_server_lease {
  mac_address_t client_mac;
  ipv4_address_t address;
  bool reserved;
} dhcp_server_lease_t;

typedef struct dhcp_server_context {
  const char* path;
  mac_address_t mac;
  FILE* source;
  mutex_t mutex;
  cmd_app_t commands;
  dhcp_server_lease_t leases[DHCP_SERVER_LEASE_CAPACITY];
  size_t lease_count;
  ipv4_address_t server_address;
  ipv4_address_t first_address;
  ipv4_address_t last_address;
  ipv4_address_t mask;
  ipv4_address_t gateway;
  ipv4_address_t dns_server;
  bool enabled;
} dhcp_server_context_t;
