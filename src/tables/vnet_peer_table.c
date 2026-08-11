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
