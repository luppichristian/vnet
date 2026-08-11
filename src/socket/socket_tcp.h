#pragma once

#include <socket.h>

/* Private TCP backend used only by socket.c. */
bool socket_tcp_connect(socket_context_t* context, socket_handle_t handle, ipv4_address_t destination, uint16_t destination_port);
bool socket_tcp_listen(socket_context_t* context, socket_handle_t handle);
bool socket_tcp_send(socket_context_t* context, socket_handle_t handle, const void* data, uint16_t length);
bool socket_tcp_receive_ipv4(socket_context_t* context, const ipv4_packet_view_t* packet);
bool socket_tcp_close(socket_context_t* context, socket_handle_t handle);
bool socket_tcp_tick(socket_context_t* context, uint32_t now);
