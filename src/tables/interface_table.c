#include "interface_table.h"

#include <string.h>

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

bool interface_table_add(interface_table_t* table, const char* path, const mac_address_t mac, ipv4_address_t ip4, ipv4_address_t mask) {
  if (table->count == table->capacity || !ipv4_mask_is_contiguous(mask) || interface_table_find_path(table, path) || interface_table_find_ip4(table, ip4)) {
    return false;
  }
  interface_entry_t* entry = &table->entries[table->count++];
  memset(entry, 0, sizeof(*entry));
  strncpy(entry->path, path, sizeof(entry->path) - 1);
  memcpy(entry->mac, mac, sizeof(entry->mac));
  entry->ip4 = ip4;
  entry->mask = mask;
  entry->enabled = true;
  return true;
}

bool interface_table_set_enabled(interface_table_t* table, size_t index, bool enabled) {
  if (index >= table->count) return false;
  table->entries[index].enabled = enabled;
  return true;
}
