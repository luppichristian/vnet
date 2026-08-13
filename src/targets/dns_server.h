#pragma once

/* Interactive authoritative DNS A/CNAME server on one VNet Ethernet LAN. */

#include <arp.h>
#include <cmd_app.h>
#include <dns.h>
#include <ethernet.h>
#include <futils.h>
#include <ipv4.h>
#include <mutex.h>
#include <thread.h>
#include <udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DNS_SERVER_BUFFER_SIZE    8192
#define DNS_SERVER_RECORD_CAPACITY 32
#define DNS_SERVER_BLACKLIST_CAPACITY 32

typedef struct dns_server_context {
  const char* path;
  mac_address_t mac;
  ipv4_address_t address;
  dns_record_t records[DNS_SERVER_RECORD_CAPACITY];
  size_t record_count;
  char blacklist[DNS_SERVER_BLACKLIST_CAPACITY][DNS_NAME_MAX + 1];
  size_t blacklist_count;
  FILE* source;
  mutex_t mutex;
  cmd_app_t commands;
} dns_server_context_t;
