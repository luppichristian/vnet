#include <socket.h>

#include <socket_tcp.h>
#include <socket_udp.h>

#include <string.h>

static socket_entry_t* socket_find(socket_context_t* context, socket_handle_t handle) {
  if (!context || handle == SOCKET_INVALID_HANDLE || handle > SOCKET_CAPACITY) return NULL;
  socket_entry_t* entry = &context->entries[handle - 1];
  return entry->active ? entry : NULL;
}

static bool socket_port_in_use(const socket_context_t* context, socket_protocol_t protocol, uint16_t port) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    const socket_entry_t* entry = &context->entries[i];
    if (entry->active && entry->protocol == protocol && entry->local_port == port) return true;
  }
  return false;
}

static bool socket_assign_ephemeral(socket_context_t* context, socket_entry_t* entry) {
  for (uint32_t attempts = 0; attempts < UINT16_MAX - SOCKET_EPHEMERAL_MIN; ++attempts) {
    const uint16_t port = context->next_ephemeral_port < SOCKET_EPHEMERAL_MIN ? SOCKET_EPHEMERAL_MIN : context->next_ephemeral_port;
    context->next_ephemeral_port = port == UINT16_MAX ? SOCKET_EPHEMERAL_MIN : port + 1;
    if (!socket_port_in_use(context, entry->protocol, port)) {
      entry->local_port = port;
      entry->state = SOCKET_STATE_BOUND;
      return true;
    }
  }
  return false;
}

bool socket_context_init(socket_context_t* context, ipv4_address_t local_address, socket_emit_ipv4_fn emit_ipv4, void* emit_argument) {
  if (!context || !emit_ipv4) return false;
  memset(context, 0, sizeof(*context));
  context->local_address = local_address;
  context->emit_ipv4 = emit_ipv4;
  context->emit_argument = emit_argument;
  context->next_ephemeral_port = SOCKET_EPHEMERAL_MIN;
  return true;
}

bool socket_open(socket_context_t* context, socket_protocol_t protocol, socket_handle_t* handle) {
  if (!context || !handle || (protocol != SOCKET_PROTOCOL_TCP && protocol != SOCKET_PROTOCOL_UDP)) return false;
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    socket_entry_t* entry = &context->entries[i];
    if (!entry->active) {
      memset(entry, 0, sizeof(*entry));
      entry->active = true;
      entry->protocol = protocol;
      entry->state = SOCKET_STATE_OPEN;
      *handle = (socket_handle_t)(i + 1);
      return true;
    }
  }
  return false;
}

bool socket_close(socket_context_t* context, socket_handle_t handle) {
  socket_entry_t* entry = socket_find(context, handle);
  if (!entry) return false;
  if (entry->protocol == SOCKET_PROTOCOL_TCP) {
    const socket_state_t state = entry->state;
    if ((state == SOCKET_STATE_SYN_SENT || state == SOCKET_STATE_SYN_RECEIVED || state == SOCKET_STATE_ESTABLISHED || state == SOCKET_STATE_CLOSE_WAIT || state == SOCKET_STATE_FIN_WAIT_1 || state == SOCKET_STATE_FIN_WAIT_2 || state == SOCKET_STATE_CLOSING || state == SOCKET_STATE_LAST_ACK) && !socket_tcp_close(context, handle)) return false;
    if (entry->active) return true;
  }
  memset(entry, 0, sizeof(*entry));
  return true;
}

bool socket_bind(socket_context_t* context, socket_handle_t handle, uint16_t local_port) {
  socket_entry_t* entry = socket_find(context, handle);
  if (!entry || entry->state != SOCKET_STATE_OPEN) return false;
  if (local_port == 0) return socket_assign_ephemeral(context, entry);
  if (socket_port_in_use(context, entry->protocol, local_port)) return false;
  entry->local_port = local_port;
  entry->state = SOCKET_STATE_BOUND;
  return true;
}

bool socket_connect(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port) {
  socket_entry_t* entry = socket_find(context, handle);
  if (!entry || !destination || !destination_port) return false;
  if (entry->state == SOCKET_STATE_OPEN && !socket_bind(context, handle, 0)) return false;
  if (entry->state != SOCKET_STATE_BOUND) return false;
  return entry->protocol == SOCKET_PROTOCOL_TCP ? socket_tcp_connect(context, handle, destination, destination_port) : socket_udp_connect(context, handle, destination, destination_port);
}

bool socket_listen(socket_context_t* context, socket_handle_t handle) {
  socket_entry_t* entry = socket_find(context, handle);
  return entry && entry->protocol == SOCKET_PROTOCOL_TCP && entry->state == SOCKET_STATE_BOUND && socket_tcp_listen(context, handle);
}

bool socket_accept(socket_context_t* context, socket_handle_t listener, socket_handle_t* connection) {
  socket_entry_t* entry = socket_find(context, listener);
  if (!entry || entry->protocol != SOCKET_PROTOCOL_TCP || entry->state != SOCKET_STATE_LISTEN || !entry->accepted || !connection) return false;
  *connection = entry->accepted;
  entry->accepted = SOCKET_INVALID_HANDLE;
  return true;
}

bool socket_send(socket_context_t* context, socket_handle_t handle, const void* data, uint16_t length) {
  socket_entry_t* entry = socket_find(context, handle);
  if (!entry || !data || !length || !entry->remote_address || !entry->remote_port) return false;
  return entry->protocol == SOCKET_PROTOCOL_TCP ? socket_tcp_send(context, handle, data, length) : socket_udp_send(context, handle, entry->remote_address, entry->remote_port, data, length);
}

bool socket_send_to(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port, const void* data, uint16_t length) {
  socket_entry_t* entry = socket_find(context, handle);
  return entry && entry->protocol == SOCKET_PROTOCOL_UDP && (entry->state == SOCKET_STATE_BOUND || entry->state == SOCKET_STATE_ESTABLISHED) && destination && destination_port && data && length && socket_udp_send(context, handle, destination, destination_port, data, length);
}

size_t socket_receive(socket_context_t* context, socket_handle_t handle, void* buffer, size_t capacity, ipv4_address_t* source_address, uint16_t* source_port) {
  socket_entry_t* entry = socket_find(context, handle);
  if (!entry || !buffer || !capacity || !entry->receive_length) return 0;
  const size_t count = entry->receive_length < capacity ? entry->receive_length : capacity;
  memcpy(buffer, entry->receive_buffer, count);
  memmove(entry->receive_buffer, entry->receive_buffer + count, entry->receive_length - count);
  entry->receive_length -= (uint16_t)count;
  if (source_address) *source_address = entry->received_address;
  if (source_port) *source_port = entry->received_port;
  return count;
}

bool socket_receive_ipv4(socket_context_t* context, const ipv4_packet_view_t* packet) {
  if (!context || !packet || packet->header.dst_addr != context->local_address) return false;
  if (packet->header.protocol == SOCKET_PROTOCOL_TCP) return socket_tcp_receive_ipv4(context, packet);
  if (packet->header.protocol == SOCKET_PROTOCOL_UDP) return socket_udp_receive_ipv4(context, packet);
  return false;
}

bool socket_tick(socket_context_t* context, uint32_t now) {
  return context && socket_tcp_tick(context, now) && socket_udp_tick(context, now);
}

const socket_entry_t* socket_get(const socket_context_t* context, socket_handle_t handle) {
  if (!context || handle == SOCKET_INVALID_HANDLE || handle > SOCKET_CAPACITY) return NULL;
  const socket_entry_t* entry = &context->entries[handle - 1];
  return entry->active ? entry : NULL;
}
