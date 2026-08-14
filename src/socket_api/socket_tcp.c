#include <socket_tcp.h>

#include <tcp.h>

#include <string.h>

#define TCP_MAX_RETRANSMISSIONS     3u
#define TCP_RETRANSMIT_SECONDS      1u
#define TCP_SYN_RETRANSMIT_SECONDS  3u

static socket_entry_t* tcp_entry(socket_context_t* context, socket_handle_t handle) {
  return !context || handle == SOCKET_INVALID_HANDLE || handle > SOCKET_CAPACITY ? NULL : &context->entries[handle - 1];
}

static socket_handle_t tcp_handle(const socket_context_t* context, const socket_entry_t* entry) {
  return !context || !entry ? SOCKET_INVALID_HANDLE : (socket_handle_t)(entry - context->entries + 1);
}

static uint16_t tcp_receive_window(const socket_entry_t* entry) {
  return (uint16_t)(SOCKET_RECEIVE_CAPACITY - entry->receive_length);
}

static uint16_t tcp_segment_span(uint16_t flags, uint16_t data_length) {
  return (uint16_t)(data_length + ((flags & TCP_FLAG_SYN) != 0) + ((flags & TCP_FLAG_FIN) != 0));
}

static uint32_t tcp_retransmit_delay(uint16_t flags) {
  return (flags & TCP_FLAG_SYN) != 0 ? TCP_SYN_RETRANSMIT_SECONDS : TCP_RETRANSMIT_SECONDS;
}

static bool tcp_emit(socket_context_t* context, socket_entry_t* entry, uint32_t sequence_number, uint16_t flags, const void* data, uint16_t data_length) {
  uint8_t bytes[sizeof(tcp_header_t) + SOCKET_RECEIVE_CAPACITY] = {0};
  uint16_t length = 0;
  const tcp_packet_data_t packet = {
      .src_addr = context->local_address,
      .dst_addr = entry->remote_address,
      .src_port = entry->local_port,
      .dst_port = entry->remote_port,
      .sequence_number = sequence_number,
      .acknowledgement_number = entry->receive_sequence,
      .flags = flags,
      .window_size = tcp_receive_window(entry),
      .data = data,
      .data_length = data_length,
  };
  return tcp_serialize_packet(&packet, bytes, sizeof(bytes), &length) && context->emit_ipv4(context->emit_argument, entry->remote_address, TCP_IPV4_PROTOCOL, bytes, length);
}

static void tcp_clear_pending(socket_entry_t* entry) {
  entry->transmit_active = false;
  entry->transmit_length = 0;
  entry->transmit_flags = 0;
  entry->transmit_sequence = 0;
  entry->retransmit_at = 0;
  entry->retransmit_count = 0;
}

static socket_entry_t* tcp_find_connection(socket_context_t* context, uint16_t local_port, ipv4_address_t remote_address, uint16_t remote_port) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    socket_entry_t* entry = &context->entries[i];
    if (entry->active && entry->protocol == SOCKET_PROTOCOL_TCP && entry->state != SOCKET_STATE_LISTEN && entry->local_port == local_port && entry->remote_address == remote_address && entry->remote_port == remote_port) return entry;
  }
  return NULL;
}

static socket_entry_t* tcp_find_listener(socket_context_t* context, uint16_t local_port, socket_handle_t* handle) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    socket_entry_t* entry = &context->entries[i];
    if (entry->active && entry->protocol == SOCKET_PROTOCOL_TCP && entry->state == SOCKET_STATE_LISTEN && entry->local_port == local_port) {
      if (handle) *handle = (socket_handle_t)(i + 1);
      return entry;
    }
  }
  return NULL;
}

static socket_entry_t* tcp_allocate(socket_context_t* context, socket_handle_t* handle) {
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    if (!context->entries[i].active) {
      memset(&context->entries[i], 0, sizeof(context->entries[i]));
      context->entries[i].active = true;
      context->entries[i].protocol = SOCKET_PROTOCOL_TCP;
      context->entries[i].send_window = SOCKET_RECEIVE_CAPACITY;
      if (handle) *handle = (socket_handle_t)(i + 1);
      return &context->entries[i];
    }
  }
  return NULL;
}

static void tcp_release(socket_context_t* context, socket_entry_t* entry) {
  if (!context || !entry) return;
  const socket_handle_t handle = tcp_handle(context, entry);
  if (entry->parent_listener) {
    socket_entry_t* listener = tcp_entry(context, entry->parent_listener);
    if (listener && listener->active && listener->accepted == handle) listener->accepted = SOCKET_INVALID_HANDLE;
  }
  memset(entry, 0, sizeof(*entry));
}

static bool tcp_queue_segment(socket_context_t* context, socket_entry_t* entry, uint32_t sequence_number, uint16_t flags, const void* data, uint16_t data_length) {
  if (!context || !entry || entry->transmit_active || data_length > sizeof(entry->transmit_buffer)) return false;
  const uint32_t previous_send_sequence = entry->send_sequence;
  const uint16_t span = tcp_segment_span(flags, data_length);
  if (data_length) memcpy(entry->transmit_buffer, data, data_length);
  entry->transmit_active = true;
  entry->transmit_sequence = sequence_number;
  entry->transmit_flags = flags;
  entry->transmit_length = data_length;
  entry->retransmit_at = 0;
  entry->retransmit_count = 0;
  if (entry->send_sequence == sequence_number) entry->send_sequence += span;
  if (!tcp_emit(context, entry, sequence_number, flags, data, data_length)) {
    entry->send_sequence = previous_send_sequence;
    tcp_clear_pending(entry);
    return false;
  }
  return true;
}

static bool tcp_send_ack(socket_context_t* context, socket_entry_t* entry) {
  return tcp_emit(context, entry, entry->send_sequence, TCP_FLAG_ACK, NULL, 0);
}

static bool tcp_acknowledge(socket_context_t* context, socket_entry_t* entry, uint32_t acknowledgement_number) {
  if (!entry->transmit_active) {
    if (acknowledgement_number > entry->send_sequence) return false;
    entry->send_unacknowledged = acknowledgement_number > entry->send_unacknowledged ? acknowledgement_number : entry->send_unacknowledged;
    entry->acknowledged_sequence = entry->send_unacknowledged;
    return true;
  }

  const uint32_t pending_end = entry->transmit_sequence + tcp_segment_span(entry->transmit_flags, entry->transmit_length);
  if (acknowledgement_number < entry->send_unacknowledged || acknowledgement_number > entry->send_sequence) return false;
  if (acknowledgement_number < pending_end) return true;

  entry->send_unacknowledged = acknowledgement_number;
  entry->acknowledged_sequence = acknowledgement_number;
  const uint16_t flags = entry->transmit_flags;
  tcp_clear_pending(entry);
  if ((flags & TCP_FLAG_FIN) != 0) {
    if (entry->state == SOCKET_STATE_FIN_WAIT_1) entry->state = SOCKET_STATE_FIN_WAIT_2;
    else if (entry->state == SOCKET_STATE_LAST_ACK) {
      tcp_release(context, entry);
      return true;
    } else if (entry->state == SOCKET_STATE_CLOSING) {
      tcp_release(context, entry);
      return true;
    }
  }
  return true;
}

static void tcp_fail_entry(socket_context_t* context, socket_entry_t* entry) {
  tcp_release(context, entry);
}

bool socket_tcp_connect(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port) {
  socket_entry_t* entry = tcp_entry(context, handle);
  if (!entry || !entry->active || entry->state != SOCKET_STATE_BOUND) return false;
  entry->remote_address = destination;
  entry->remote_port = destination_port;
  entry->send_sequence = 1;
  entry->send_unacknowledged = 1;
  entry->acknowledged_sequence = 0;
  entry->send_window = SOCKET_RECEIVE_CAPACITY;
  entry->state = SOCKET_STATE_SYN_SENT;
  if (tcp_queue_segment(context, entry, entry->send_sequence, TCP_FLAG_SYN, NULL, 0)) return true;
  entry->remote_address = 0;
  entry->remote_port = 0;
  entry->send_sequence = 0;
  entry->send_unacknowledged = 0;
  entry->state = SOCKET_STATE_BOUND;
  return false;
}

bool socket_tcp_listen(socket_context_t* context, socket_handle_t handle) {
  socket_entry_t* entry = tcp_entry(context, handle);
  if (!entry || !entry->active || entry->state != SOCKET_STATE_BOUND) return false;
  entry->state = SOCKET_STATE_LISTEN;
  return true;
}

bool socket_tcp_send(socket_context_t* context, socket_handle_t handle, const void* data, uint16_t length) {
  socket_entry_t* entry = tcp_entry(context, handle);
  if (!entry || !entry->active || (entry->state != SOCKET_STATE_ESTABLISHED && entry->state != SOCKET_STATE_CLOSE_WAIT) || !data || !length || length > SOCKET_RECEIVE_CAPACITY || entry->transmit_active || length > entry->send_window) return false;
  return tcp_queue_segment(context, entry, entry->send_sequence, TCP_FLAG_ACK | TCP_FLAG_PSH, data, length);
}

bool socket_tcp_receive_ipv4(socket_context_t* context, const ipv4_packet_view_t* packet) {
  tcp_packet_view_t segment = {0};
  if (!tcp_parse_packet(packet->payload, packet->payload_length, packet->header.src_addr, packet->header.dst_addr, &segment)) return false;
  socket_entry_t* entry = tcp_find_connection(context, segment.header.dst_port, packet->header.src_addr, segment.header.src_port);

  if (!entry && segment.header.syn && !segment.header.ack) {
    socket_handle_t listener_handle = SOCKET_INVALID_HANDLE;
    socket_entry_t* listener = tcp_find_listener(context, segment.header.dst_port, &listener_handle);
    socket_handle_t child_handle = SOCKET_INVALID_HANDLE;
    if (!listener || listener->accepted || !(entry = tcp_allocate(context, &child_handle))) return false;
    entry->local_port = segment.header.dst_port;
    entry->remote_address = packet->header.src_addr;
    entry->remote_port = segment.header.src_port;
    entry->send_sequence = 1;
    entry->send_unacknowledged = 1;
    entry->receive_sequence = segment.header.sequence_number + 1;
    entry->acknowledged_sequence = 0;
    entry->send_window = segment.header.window_size;
    entry->parent_listener = listener_handle;
    entry->state = SOCKET_STATE_SYN_RECEIVED;
    if (!tcp_queue_segment(context, entry, entry->send_sequence, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0)) {
      tcp_release(context, entry);
      return false;
    }
    return true;
  }
  if (!entry) return false;

  entry->send_window = segment.header.window_size;

  if (segment.header.rst) {
    tcp_fail_entry(context, entry);
    return true;
  }

  if (entry->state == SOCKET_STATE_SYN_SENT) {
    if (!segment.header.syn || !segment.header.ack || segment.header.acknowledgement_number != entry->send_sequence) return false;
    entry->receive_sequence = segment.header.sequence_number + 1;
    if (!tcp_acknowledge(context, entry, segment.header.acknowledgement_number)) {
      tcp_fail_entry(context, entry);
      return false;
    }
    entry->state = SOCKET_STATE_ESTABLISHED;
    return tcp_send_ack(context, entry);
  }

  if (entry->state == SOCKET_STATE_SYN_RECEIVED) {
    if (!segment.header.ack || segment.header.syn || segment.header.acknowledgement_number != entry->send_sequence) return false;
    if (!tcp_acknowledge(context, entry, segment.header.acknowledgement_number)) {
      tcp_fail_entry(context, entry);
      return false;
    }
    entry->state = SOCKET_STATE_ESTABLISHED;
    if (entry->parent_listener) {
      socket_entry_t* listener = tcp_entry(context, entry->parent_listener);
      if (!listener || !listener->active || listener->state != SOCKET_STATE_LISTEN || listener->accepted) {
        tcp_fail_entry(context, entry);
        return false;
      }
      listener->accepted = tcp_handle(context, entry);
    }
    return true;
  }

  if (entry->state != SOCKET_STATE_ESTABLISHED && entry->state != SOCKET_STATE_CLOSE_WAIT && entry->state != SOCKET_STATE_FIN_WAIT_1 && entry->state != SOCKET_STATE_FIN_WAIT_2 && entry->state != SOCKET_STATE_CLOSING && entry->state != SOCKET_STATE_LAST_ACK) return false;

  if (segment.header.ack && !tcp_acknowledge(context, entry, segment.header.acknowledgement_number)) return false;

  if (segment.data_length) {
    if (segment.header.sequence_number != entry->receive_sequence || segment.data_length > tcp_receive_window(entry)) return tcp_send_ack(context, entry);
    memcpy(entry->receive_buffer + entry->receive_length, segment.data, segment.data_length);
    entry->receive_length += segment.data_length;
    entry->receive_sequence += segment.data_length;
    entry->received_address = packet->header.src_addr;
    entry->received_port = segment.header.src_port;
  }

  if (segment.header.fin) {
    if (segment.header.sequence_number + segment.data_length != entry->receive_sequence) return tcp_send_ack(context, entry);
    ++entry->receive_sequence;
    if (entry->state == SOCKET_STATE_ESTABLISHED) entry->state = SOCKET_STATE_CLOSE_WAIT;
    else if (entry->state == SOCKET_STATE_FIN_WAIT_1) entry->state = entry->transmit_active ? SOCKET_STATE_CLOSING : SOCKET_STATE_CLOSED;
    else if (entry->state == SOCKET_STATE_FIN_WAIT_2) {
      if (!tcp_send_ack(context, entry)) return false;
      tcp_release(context, entry);
      return true;
    } else if (entry->state == SOCKET_STATE_CLOSING) {
      if (!tcp_send_ack(context, entry)) return false;
      return true;
    } else if (entry->state == SOCKET_STATE_LAST_ACK || entry->state == SOCKET_STATE_CLOSE_WAIT) {
      if (!tcp_send_ack(context, entry)) return false;
      return true;
    }
    if (!tcp_send_ack(context, entry)) return false;
    if (entry->state == SOCKET_STATE_CLOSED) {
      tcp_release(context, entry);
      return true;
    }
    return true;
  }

  if (segment.data_length) return tcp_send_ack(context, entry);
  return true;
}

bool socket_tcp_close(socket_context_t* context, socket_handle_t handle) {
  socket_entry_t* entry = tcp_entry(context, handle);
  if (!entry || !entry->active) return false;

  if (entry->state == SOCKET_STATE_BOUND || entry->state == SOCKET_STATE_LISTEN || entry->state == SOCKET_STATE_OPEN) {
    tcp_release(context, entry);
    return true;
  }
  if (entry->state == SOCKET_STATE_SYN_SENT || entry->state == SOCKET_STATE_SYN_RECEIVED) {
    tcp_release(context, entry);
    return true;
  }
  if (entry->state == SOCKET_STATE_FIN_WAIT_1 || entry->state == SOCKET_STATE_FIN_WAIT_2 || entry->state == SOCKET_STATE_CLOSING || entry->state == SOCKET_STATE_LAST_ACK) return true;
  if (entry->state != SOCKET_STATE_ESTABLISHED && entry->state != SOCKET_STATE_CLOSE_WAIT) return false;
  if (entry->transmit_active) return false;

  const socket_state_t previous_state = entry->state;
  const socket_state_t next_state = entry->state == SOCKET_STATE_CLOSE_WAIT ? SOCKET_STATE_LAST_ACK : SOCKET_STATE_FIN_WAIT_1;
  entry->state = next_state;
  if (!tcp_queue_segment(context, entry, entry->send_sequence, TCP_FLAG_ACK | TCP_FLAG_FIN, NULL, 0)) {
    entry->state = previous_state;
    return false;
  }
  return true;
}

bool socket_tcp_tick(socket_context_t* context, uint32_t now) {
  if (!context) return false;
  for (size_t i = 0; i < SOCKET_CAPACITY; ++i) {
    socket_entry_t* entry = &context->entries[i];
    if (!entry->active || entry->protocol != SOCKET_PROTOCOL_TCP || !entry->transmit_active) continue;
    if (entry->retransmit_at == 0) {
      entry->retransmit_at = now + tcp_retransmit_delay(entry->transmit_flags);
      continue;
    }
    if (now < entry->retransmit_at) continue;
    if (entry->retransmit_count >= TCP_MAX_RETRANSMISSIONS || !tcp_emit(context, entry, entry->transmit_sequence, entry->transmit_flags, entry->transmit_length ? entry->transmit_buffer : NULL, entry->transmit_length)) {
      tcp_fail_entry(context, entry);
      continue;
    }
    ++entry->retransmit_count;
    entry->retransmit_at = now + tcp_retransmit_delay(entry->transmit_flags);
  }
  return true;
}
