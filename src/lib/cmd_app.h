#pragma once

#include <stdbool.h>
#include <signal.h>
#include <stdint.h>

#include "thread.h"

#define CMD_APP_MAX_COMMANDS 32

typedef void (*cmd_app_handler_t)(void* context, char* arguments);

typedef struct cmd_app_command_entry {
  const char* name;
  const char* description;
  cmd_app_handler_t handler;
  void* context;
} cmd_app_command_entry_t;

typedef struct cmd_app {
  volatile sig_atomic_t running;
  cmd_app_command_entry_t commands[CMD_APP_MAX_COMMANDS];
  uint16_t command_count;
  thread_t thread;
} cmd_app_t;

/* Initializes one running command application. */
void cmd_app_init(cmd_app_t* app);

/* Registers one uniquely named command with its help description and handler. */
bool cmd_app_register(cmd_app_t* app, const char* name, const char* description, cmd_app_handler_t handler, void* context);

/* Starts the command input loop on a separate thread. */
bool cmd_app_start(cmd_app_t* app);

/* Waits for the command input loop to finish. */
void cmd_app_join(cmd_app_t* app);

/* Requests that the command input loop stop. */
void cmd_app_stop(cmd_app_t* app);

/* Returns whether the command application remains active. */
bool cmd_app_is_running(const cmd_app_t* app);

/* Returns the next space-delimited argument and advances the input cursor. */
char* cmd_app_next_argument(char** arguments);

/* Returns true when an argument string contains no non-space characters. */
bool cmd_app_arguments_empty(const char* arguments);

/* Parses an unsigned decimal value that fits in the requested integer type. */
bool cmd_app_parse_uint16(const char* text, uint16_t* value);
bool cmd_app_parse_uint32(const char* text, uint32_t* value);
