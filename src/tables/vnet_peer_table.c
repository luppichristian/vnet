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
#include "vnet_peer_table.h"

#include <string.h>

void vnet_peer_table_init(vnet_peer_table_t* table, vnet_peer_entry_t* entries, size_t capacity) {
  *table = (vnet_peer_table_t) {.entries = entries, .capacity = capacity};
}

vnet_peer_entry_t* vnet_peer_table_find_path(vnet_peer_table_t* table, const char* path) {
  for (size_t i = 0; i < table->count; ++i) {
    if (strcmpi(table->entries[i].path, path) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

vnet_peer_entry_t* vnet_peer_table_find_mac(vnet_peer_table_t* table, const mac_address_t mac) {
  for (size_t i = 0; i < table->count; ++i) {
    if (table->entries[i].has_mac && memcmp(table->entries[i].mac, mac, sizeof(table->entries[i].mac)) == 0) {
      return &table->entries[i];
    }
  }
  return NULL;
}

bool vnet_peer_table_start(vnet_peer_table_t* table, const char* path) {
  if (vnet_peer_table_find_path(table, path)) {
    return true;
  }
  if (table->count == table->capacity) {
    return false;
  }
  vnet_peer_entry_t* entry = &table->entries[table->count++];
  memset(entry, 0, sizeof(*entry));
  strncpy(entry->path, path, sizeof(entry->path) - 1);
  return true;
}

void vnet_peer_table_end(vnet_peer_table_t* table, const char* path) {
  for (size_t i = 0; i < table->count; ++i) {
    if (strcmpi(table->entries[i].path, path) == 0) {
      table->entries[i] = table->entries[--table->count];
      return;
    }
  }
}

void vnet_peer_table_learn_mac(vnet_peer_table_t* table, const mac_address_t mac) {
  vnet_peer_entry_t* entry = vnet_peer_table_find_mac(table, mac);
  if (!entry && table->count > 0) {
    entry = &table->entries[table->count - 1];
  }
  if (entry) {
    memcpy(entry->mac, mac, sizeof(entry->mac));
    entry->has_mac = true;
  }
}
