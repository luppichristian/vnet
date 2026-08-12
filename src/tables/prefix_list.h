#pragma once

#include <ipv4.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
================
IPv4 Prefix Lists
=================
A prefix list is an ordered, named IPv4 route-policy object. BGP and RIP use it
to permit or deny network prefixes. A rule matches a route only when the route
is within the rule's network and its prefix length is within the rule's
inclusive range. The first matching rule decides; no match denies. An
unassigned protocol policy does not filter that direction.
*/
#define PREFIX_LIST_NAME_LEN 32

typedef enum prefix_list_action {
  PREFIX_LIST_PERMIT,
  PREFIX_LIST_DENY,
} prefix_list_action_t;

typedef struct prefix_list_rule {
  char name[PREFIX_LIST_NAME_LEN];
  uint16_t sequence;
  prefix_list_action_t action;
  ipv4_address_t network;
  ipv4_address_t mask;
  uint8_t minimum_length;
  uint8_t maximum_length;
} prefix_list_rule_t;

typedef struct prefix_list {
  prefix_list_rule_t* entries;
  size_t capacity;
  size_t count;
} prefix_list_t;

/* Binds caller-owned rule storage to an initially empty prefix-list table. */
void prefix_list_init(prefix_list_t* table, prefix_list_rule_t* entries, size_t capacity);

/* Adds one uniquely sequenced permit or deny rule to a named prefix list. */
bool prefix_list_add(prefix_list_t* table, const char* name, uint16_t sequence, prefix_list_action_t action, ipv4_address_t network, ipv4_address_t mask, uint8_t minimum_length, uint8_t maximum_length);

/* Removes the rule with sequence from one named prefix list. */
bool prefix_list_remove(prefix_list_t* table, const char* name, uint16_t sequence);

/* Returns true when a named list permits a prefix; an absent list permits it. */
bool prefix_list_permits(const prefix_list_t* table, const char* name, ipv4_address_t network, ipv4_address_t mask);

/* Returns a stable human-readable action for CLI presentation. */
const char* prefix_list_action_name(prefix_list_action_t action);
