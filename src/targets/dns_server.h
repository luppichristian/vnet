#pragma once

/* Interactive authoritative DNS A-record server on one VNet Ethernet LAN. */

#include <arp.h>
#include <cmd_app.h>
#include <dns.h>
#include <ethernet.h>
#include <futils.h>
#include <ipv4.h>
#include <thread.h>
#include <udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DNS_SERVER_BUFFER_SIZE 8192

typedef struct dns_server_context {
  const char* path;
  mac_address_t mac;
  ipv4_address_t address;
  char name[DNS_NAME_MAX + 1];
  ipv4_address_t record_address;
  FILE* source;
  cmd_app_t commands;
} dns_server_context_t;
