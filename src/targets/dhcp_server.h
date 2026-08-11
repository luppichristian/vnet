#pragma once

/* Interactive DHCPv4 server for one configured VNet client lease. */

#include <cmd_app.h>
#include <dhcp.h>
#include <ethernet.h>
#include <futils.h>
#include <ipv4.h>
#include <thread.h>
#include <udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DHCP_SERVER_BUFFER_SIZE 8192

typedef struct dhcp_server_context {
  const char* path;
  mac_address_t mac;
  mac_address_t client_mac;
  ipv4_address_t address;
  ipv4_address_t client_address;
  ipv4_address_t mask;
  ipv4_address_t gateway;
  ipv4_address_t dns_server;
  FILE* source;
  cmd_app_t commands;
} dhcp_server_context_t;
