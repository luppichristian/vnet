#pragma once

/* Interactive configurable DHCPv4 service attached to one VNet LAN. */

#include <cmd_app.h>
#include <dhcp_service.h>
#include <ethernet.h>
#include <futils.h>
#include <mutex.h>
#include <thread.h>
#include <udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DHCP_SERVER_BUFFER_SIZE 8192
#define DHCP_SERVER_LEASE_CAPACITY 64

typedef struct dhcp_server_context {
  const char* path;
  mac_address_t mac;
  FILE* source;
  mutex_t mutex;
  cmd_app_t commands;
  dhcp_lease_t lease_entries[DHCP_SERVER_LEASE_CAPACITY];
  dhcp_service_t service;
} dhcp_server_context_t;
