/*
 * MIT License
 *
 * Copyright (c) 2026 Christian Luppi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

/*
Learning Ethernet switch for append-only VNet traffic files.
OSI/ISO layer: Layer 2 (data link); it learns and forwards by Ethernet MAC address.

An access port accepts untagged ingress for one PVID and emits untagged frames.
A trunk accepts explicitly allowed tagged VLANs and preserves their 802.1Q tags.
Native VLANs and hybrid ports are deliberately not modeled.

This target now includes an explicit IEEE 802.1D-style spanning-tree subset.
Each switch has one bridge ID (priority + MAC address), emits and receives
untagged configuration BPDUs on every connected port, elects one root bridge,
assigns root/designated/alternate roles, and blocks alternate ports from MAC
learning and data forwarding. A topology change flushes the dynamic FDB.
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
#define SWITCH_STP_DEFAULT_PRIORITY 32768u
#define SWITCH_STP_DEFAULT_PATH_COST 4u
#define SWITCH_STP_HELLO_TIME_MS    1000u
#define SWITCH_STP_MAX_AGE_MS       3000u
#define SWITCH_STP_TC_WINDOW_MS     2000u

typedef uint64_t switch_bridge_id_t;

typedef enum switch_port_mode {
  SWITCH_PORT_ACCESS,
  SWITCH_PORT_TRUNK,
} switch_port_mode_t;

typedef enum switch_stp_port_role {
  SWITCH_STP_PORT_ROLE_DISABLED,
  SWITCH_STP_PORT_ROLE_ROOT,
  SWITCH_STP_PORT_ROLE_DESIGNATED,
  SWITCH_STP_PORT_ROLE_ALTERNATE,
} switch_stp_port_role_t;

typedef enum switch_stp_port_state {
  SWITCH_STP_PORT_STATE_DISABLED,
  SWITCH_STP_PORT_STATE_BLOCKING,
  SWITCH_STP_PORT_STATE_FORWARDING,
} switch_stp_port_state_t;

#pragma pack(push, 1)

typedef struct switch_stp_bpdu {
  uint8_t llc_dsap;
  uint8_t llc_ssap;
  uint8_t llc_control;
  uint16_t protocol_id;
  uint8_t version;
  uint8_t type;
  uint8_t flags;
  switch_bridge_id_t root_id;
  uint32_t root_path_cost;
  switch_bridge_id_t bridge_id;
  uint16_t port_id;
} switch_stp_bpdu_t;

#pragma pack(pop)

typedef struct switch_stp_neighbor {
  bool valid;
  switch_bridge_id_t root_id;
  uint32_t root_path_cost;
  switch_bridge_id_t bridge_id;
  uint16_t port_id;
  bool topology_change;
  uint32_t last_seen_ms;
} switch_stp_neighbor_t;

typedef struct switch_port {
  const char* path;
  FILE* source;
  FILE* destination;
  bool started;
  switch_port_mode_t mode;
  uint16_t access_vlan_id;
  bool allowed_vlans[SWITCH_VLAN_COUNT];
  uint32_t stp_path_cost;
  uint16_t stp_port_id;
  switch_stp_port_role_t stp_role;
  switch_stp_port_state_t stp_state;
  switch_stp_neighbor_t stp_neighbor;
  uint32_t stp_rx_bpdus;
  uint32_t stp_tx_bpdus;
  uint8_t buffer[SWITCH_BUFFER_SIZE];
  size_t buffer_length;
} switch_port_t;

typedef struct switch_context {
  const char* path;
  switch_port_t* ports;
  size_t port_count;
  fdb_table_t* devices;
  switch_bridge_id_t bridge_id;
  switch_bridge_id_t root_id;
  uint32_t root_path_cost;
  size_t root_port;
  uint32_t topology_change_count;
  uint32_t topology_change_until_ms;
} switch_context_t;
