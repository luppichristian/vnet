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
