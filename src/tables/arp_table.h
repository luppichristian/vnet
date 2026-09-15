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

#include <ethernet.h>
#include <ipv4.h>
#include <stddef.h>

/*
==================
ARP Neighbor Cache
==================
IPv4 routing first selects an egress interface and a next-hop IPv4 address.
ARP then resolves that next hop to the Ethernet MAC address required to send
the frame on that interface. The interface is part of the key because identical
IPv4 addresses can exist on independent Layer-2 networks.

Real operating systems call this a neighbor cache and track reachability,
timeouts, retry state, and queued packets while resolution is pending. This
table is its resolved-entry core: it stores only interface-scoped IPv4-to-MAC
mappings and has no state machine or aging policy yet.
*/
typedef struct arp_entry {
  size_t interface_index;
  ipv4_address_t ip4;
  mac_address_t mac;
} arp_entry_t;

typedef struct arp_table {
  arp_entry_t* entries;
  size_t capacity;
  size_t count;
} arp_table_t;

/* Binds a caller-owned entry array to an initially empty ARP neighbor cache. */
void arp_table_init(arp_table_t* table, arp_entry_t* entries, size_t capacity);

/* Returns the resolved neighbor mapping on interface_index, or NULL when it is unknown. */
arp_entry_t* arp_table_find(arp_table_t* table, size_t interface_index, ipv4_address_t ip4);
const arp_entry_t* arp_table_find_const(const arp_table_t* table, size_t interface_index, ipv4_address_t ip4);

/* Learns or refreshes an ARP mapping, replacing one existing entry when the table is full. */
void arp_table_learn(arp_table_t* table, size_t interface_index, ipv4_address_t ip4, const mac_address_t mac);

/* Removes one resolved neighbor mapping. Returns false when it is absent. */
bool arp_table_remove(arp_table_t* table, size_t interface_index, ipv4_address_t ip4);
