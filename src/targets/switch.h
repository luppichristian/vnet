#pragma once

/*
Learning Ethernet switch for append-only VNet traffic files.
OSI/ISO layer: Layer 2 (data link); it learns and forwards by Ethernet MAC address.

An access port accepts untagged ingress for one PVID and emits untagged frames.
A trunk accepts explicitly allowed tagged VLANs and preserves their 802.1Q tags.
Native VLANs and hybrid ports are deliberately not modeled.
*/

#include <cmd_app.h>
#include <ethernet.h>
#include <fdb_table.h>
#include <futils.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <vnet.h>

#define SWITCH_DEVICE_CAPACITY 256
#define SWITCH_BUFFER_SIZE     8192
#define SWITCH_VLAN_COUNT      (ETHERNET_VLAN_ID_MAX + 1)
#define SLEEP_INTERVAL_MS      5

typedef enum switch_port_mode {
  SWITCH_PORT_ACCESS,
  SWITCH_PORT_TRUNK,
} switch_port_mode_t;

typedef struct switch_port {
  const char* path;
  FILE* source;
  FILE* destination;
  bool started;
  switch_port_mode_t mode;
  uint16_t access_vlan_id;
  bool allowed_vlans[SWITCH_VLAN_COUNT];
  uint8_t buffer[SWITCH_BUFFER_SIZE];
  size_t buffer_length;
} switch_port_t;

typedef struct switch_context {
  const char* path;
  const switch_port_t* ports;
  size_t port_count;
  fdb_table_t* devices;
} switch_context_t;
