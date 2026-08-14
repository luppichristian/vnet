#pragma once

#include <ipv4.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
================================
Virtual VNet Socket Interface
================================

This is the public application-facing transport API for VNet targets. It
selects TCP or UDP without exposing either backend's implementation details.
A socket context does not own Ethernet, routing, ARP, or VNet files: its
caller supplies an IPv4 emission callback, so host and router retain their
Layer 2/3 responsibilities.
*/

#define SOCKET_CAPACITY          32
#define SOCKET_RECEIVE_CAPACITY  1400
#define SOCKET_EPHEMERAL_MIN     49152

typedef uint16_t socket_handle_t;
#define SOCKET_INVALID_HANDLE ((socket_handle_t)0)

typedef enum socket_protocol {
  SOCKET_PROTOCOL_TCP = 6,
  SOCKET_PROTOCOL_UDP = 17,
} socket_protocol_t;

typedef enum socket_state {
  SOCKET_STATE_CLOSED,
  SOCKET_STATE_OPEN,
  SOCKET_STATE_BOUND,
  SOCKET_STATE_LISTEN,
  SOCKET_STATE_SYN_SENT,
  SOCKET_STATE_SYN_RECEIVED,
  SOCKET_STATE_ESTABLISHED,
  SOCKET_STATE_CLOSE_WAIT,
  SOCKET_STATE_FIN_WAIT_1,
  SOCKET_STATE_FIN_WAIT_2,
  SOCKET_STATE_CLOSING,
  SOCKET_STATE_LAST_ACK,
} socket_state_t;

typedef bool (*socket_emit_ipv4_fn)(void* argument, ipv4_address_t destination, uint8_t protocol, const uint8_t* payload, uint16_t payload_length);

typedef struct socket_entry {
  socket_protocol_t protocol;
  socket_state_t state;
  ipv4_address_t remote_address;
  uint16_t local_port;
  uint16_t remote_port;
  uint32_t send_sequence;
  uint32_t send_unacknowledged;
  uint32_t receive_sequence;
  uint32_t acknowledged_sequence;
  uint16_t send_window;
  uint16_t transmit_length;
  uint16_t transmit_flags;
  uint32_t transmit_sequence;
  uint32_t retransmit_at;
  socket_handle_t parent_listener;
  socket_handle_t accepted;
  ipv4_address_t received_address;
  uint16_t received_port;
  uint8_t receive_buffer[SOCKET_RECEIVE_CAPACITY];
  uint8_t transmit_buffer[SOCKET_RECEIVE_CAPACITY];
  uint16_t receive_length;
  uint8_t retransmit_count;
  bool transmit_active;
  bool active;
} socket_entry_t;

typedef struct socket_context {
  ipv4_address_t local_address;
  socket_emit_ipv4_fn emit_ipv4;
  void* emit_argument;
  socket_entry_t entries[SOCKET_CAPACITY];
  uint16_t next_ephemeral_port;
} socket_context_t;

/* Initializes caller-owned VNet socket state and its target-owned IPv4 emission path. */
bool socket_context_init(socket_context_t* context, ipv4_address_t local_address, socket_emit_ipv4_fn emit_ipv4, void* emit_argument);

/* Allocates a TCP or UDP endpoint. TCP/UDP backend headers are intentionally private. */
bool socket_open(socket_context_t* context, socket_protocol_t protocol, socket_handle_t* handle);
bool socket_close(socket_context_t* context, socket_handle_t handle);

/* Binds a local transport port; zero asks the context for an ephemeral port. */
bool socket_bind(socket_context_t* context, socket_handle_t handle, uint16_t local_port);

/* Creates a connected TCP endpoint or records a UDP default peer. */
bool socket_connect(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port);

/* Makes a TCP endpoint accept incoming connections on its bound port. */
bool socket_listen(socket_context_t* context, socket_handle_t handle);
bool socket_accept(socket_context_t* context, socket_handle_t listener, socket_handle_t* connection);

/* Sends bytes through a connected TCP stream or connected UDP endpoint. */
bool socket_send(socket_context_t* context, socket_handle_t handle, const void* data, uint16_t length);

/* Sends a UDP datagram to an explicit peer. TCP sockets reject this operation. */
bool socket_send_to(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port, const void* data, uint16_t length);

/* Copies queued TCP stream bytes or one queued UDP datagram and consumes them. */
size_t socket_receive(socket_context_t* context, socket_handle_t handle, void* buffer, size_t capacity, ipv4_address_t* source_address, uint16_t* source_port);

/* Supplies one locally addressed IPv4 packet to the selected private transport backend. */
bool socket_receive_ipv4(socket_context_t* context, const ipv4_packet_view_t* packet);

/* Advances backend timers; targets call it from their existing polling loop. */
bool socket_tick(socket_context_t* context, uint32_t now);

/* Returns immutable descriptor state for command/status presentation. */
const socket_entry_t* socket_get(const socket_context_t* context, socket_handle_t handle);
