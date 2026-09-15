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
#include "fdb_table.h"

#include <string.h>

void fdb_table_init(fdb_table_t* table, fdb_entry_t* entries, size_t capacity) {
  *table = (fdb_table_t) {.entries = entries, .capacity = capacity};
}

fdb_entry_t* fdb_table_find(fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].vlan_id == vlan_id && memcmp(table->entries[i].mac, mac, sizeof(table->entries[i].mac)) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

const fdb_entry_t* fdb_table_find_const(const fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].vlan_id == vlan_id && memcmp(table->entries[i].mac, mac, sizeof(table->entries[i].mac)) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

bool fdb_table_learn(fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id, size_t port) {
  if (ethernet_mac_is_group(mac)) {
    return false;
  }
  fdb_entry_t* entry = fdb_table_find(table, mac, vlan_id);
  if (entry) {
    entry->port = port;
    return true;
  }
  if (table->count == table->capacity) {
    return false;
  }
  entry = &table->entries[table->count++];
  memcpy(entry->mac, mac, sizeof(entry->mac));
  entry->vlan_id = vlan_id;
  entry->port = port;
  return true;
}

void fdb_table_remove_port(fdb_table_t* table, size_t port) {
  for (size_t i = 0; i < table->count;) {
    if (table->entries[i].port == port) {
      table->entries[i] = table->entries[--table->count];
    } else {
      ++i;
    }
  }
}

void fdb_table_clear(fdb_table_t* table) {
  table->count = 0;
}

bool fdb_table_remove(fdb_table_t* table, const mac_address_t mac, uint16_t vlan_id) {
  fdb_entry_t* entry = fdb_table_find(table, mac, vlan_id);
  if (!entry) return false;
  *entry = table->entries[--table->count];
  return true;
}
