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
#include "interface_table.h"

#include <string.h>

#define INTERFACE_NONE ((size_t)-1)

static bool interface_entry_init(interface_entry_t* entry, const char* path, const mac_address_t mac, ipv4_address_t ip4, ipv4_address_t mask, size_t parent_index, bool tagged, uint16_t vlan_id) {
  if (!entry || !path || !ipv4_mask_is_contiguous(mask)) return false;
  memset(entry, 0, sizeof(*entry));
  strncpy(entry->path, path, sizeof(entry->path) - 1);
  memcpy(entry->mac, mac, sizeof(entry->mac));
  entry->ip4 = ip4;
  entry->mask = mask;
  entry->ip6_prefix_length = 64;
  entry->parent_index = parent_index;
  entry->port_index = INTERFACE_NONE;
  entry->tagged = tagged;
  entry->vlan_id = vlan_id;
  ipv6_link_local_from_mac(mac, &entry->ip6_link_local);
  ipv6_ula_prefix_from_ipv4_network(ip4 & mask, &entry->ip6_prefix);
  if (!ipv6_slaac_address_from_prefix(&entry->ip6_prefix, entry->ip6_prefix_length, mac, &entry->ip6_global)) return false;
  entry->enabled = true;
  return true;
}

void interface_table_init(interface_table_t* table, interface_entry_t* entries, size_t capacity) {
  *table = (interface_table_t) {.entries = entries, .capacity = capacity};
}

interface_entry_t* interface_table_find_path(interface_table_t* table, const char* path) {
  for (size_t i = 0; i < table->count; ++i) {
    if (strcmpi(table->entries[i].path, path) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

interface_entry_t* interface_table_find_ip4(interface_table_t* table, ipv4_address_t ip4) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].ip4 == ip4) {
      return &table->entries[i];
    }
  }
  return NULL;
}

const interface_entry_t* interface_table_get(const interface_table_t* table, size_t index) {
  return index < table->count ? &table->entries[index] : NULL;
}

bool interface_table_index_valid(const interface_table_t* table, size_t index) {
  return table && index < table->count;
}

bool interface_table_is_subinterface(const interface_entry_t* entry) {
  return entry && entry->tagged;
}

bool interface_table_add_base(interface_table_t* table, const char* path, const mac_address_t mac, ipv4_address_t ip4, ipv4_address_t mask) {
  if (table->count == table->capacity || interface_table_find_path(table, path) || interface_table_find_ip4(table, ip4)) {
    return false;
  }
  interface_entry_t* entry = &table->entries[table->count++];
  return interface_entry_init(entry, path, mac, ip4, mask, INTERFACE_NONE, false, 0);
}

bool interface_table_add_subinterface(interface_table_t* table, size_t parent_index, uint16_t vlan_id, ipv4_address_t ip4, ipv4_address_t mask) {
  if (table->count == table->capacity || !interface_table_index_valid(table, parent_index) || vlan_id == 0 || vlan_id > ETHERNET_VLAN_ID_MAX || interface_table_find_ip4(table, ip4)) {
    return false;
  }
  const interface_entry_t* parent = &table->entries[parent_index];
  if (interface_table_is_subinterface(parent)) return false;
  for (size_t i = 0; i < table->count; ++i) {
    const interface_entry_t* entry = &table->entries[i];
    if (entry->tagged && entry->parent_index == parent_index && entry->vlan_id == vlan_id) return false;
  }
  interface_entry_t* entry = &table->entries[table->count++];
  return interface_entry_init(entry, parent->path, parent->mac, ip4, mask, parent_index, true, vlan_id);
}

bool interface_table_set_enabled(interface_table_t* table, size_t index, bool enabled) {
  if (index >= table->count) return false;
  table->entries[index].enabled = enabled;
  return true;
}
