#include "prefix_list.h"

#include <string.h>

static bool prefix_list_name_is_valid(const char* name) {
  return name && *name && strlen(name) < PREFIX_LIST_NAME_LEN;
}

static uint8_t prefix_list_length(ipv4_address_t mask) {
  uint8_t length = 0;
  while (mask) {
    length += (uint8_t)(mask & 1u);
    mask >>= 1;
  }
  return length;
}

void prefix_list_init(prefix_list_t* table, prefix_list_rule_t* entries, size_t capacity) {
  *table = (prefix_list_t) {.entries = entries, .capacity = capacity};
}

bool prefix_list_add(prefix_list_t* table, const char* name, uint16_t sequence, prefix_list_action_t action, ipv4_address_t network, ipv4_address_t mask, uint8_t minimum_length, uint8_t maximum_length) {
  const uint8_t network_length = prefix_list_length(mask);
  if (!table || table->count == table->capacity || !prefix_list_name_is_valid(name) || !sequence || action > PREFIX_LIST_DENY || !ipv4_mask_is_contiguous(mask) || (network & mask) != network || minimum_length < network_length || maximum_length < minimum_length || maximum_length > 32) return false;
  for (size_t i = 0; i < table->count; ++i) {
    if (strcmpi(table->entries[i].name, name) == 0 && table->entries[i].sequence == sequence) return false;
  }
  prefix_list_rule_t rule = {
      .sequence = sequence,
      .action = action,
      .network = network,
      .mask = mask,
      .minimum_length = minimum_length,
      .maximum_length = maximum_length,
  };
  strncpy(rule.name, name, sizeof(rule.name) - 1);
  size_t index = table->count++;
  while (index > 0 && strcmpi(table->entries[index - 1].name, name) == 0 && table->entries[index - 1].sequence > sequence) {
    table->entries[index] = table->entries[index - 1];
    --index;
  }
  table->entries[index] = rule;
  return true;
}

bool prefix_list_remove(prefix_list_t* table, const char* name, uint16_t sequence) {
  if (!table || !prefix_list_name_is_valid(name) || !sequence) return false;
  for (size_t i = 0; i < table->count; ++i) {
    if (strcmpi(table->entries[i].name, name) == 0 && table->entries[i].sequence == sequence) {
      memmove(&table->entries[i], &table->entries[i + 1], (table->count - i - 1) * sizeof(table->entries[0]));
      --table->count;
      return true;
    }
  }
  return false;
}

bool prefix_list_permits(const prefix_list_t* table, const char* name, ipv4_address_t network, ipv4_address_t mask) {
  if (!table || !prefix_list_name_is_valid(name) || !ipv4_mask_is_contiguous(mask) || (network & mask) != network) return false;
  const uint8_t length = prefix_list_length(mask);
  const prefix_list_rule_t* matched = NULL;
  for (size_t i = 0; i < table->count; ++i) {
    const prefix_list_rule_t* rule = &table->entries[i];
    if (strcmpi(rule->name, name) != 0 || (network & rule->mask) != rule->network || length < rule->minimum_length || length > rule->maximum_length) continue;
    if (!matched || rule->sequence < matched->sequence) matched = rule;
  }
  return matched && matched->action == PREFIX_LIST_PERMIT;
}

const char* prefix_list_action_name(prefix_list_action_t action) {
  return action == PREFIX_LIST_PERMIT ? "permit" : "deny";
}
