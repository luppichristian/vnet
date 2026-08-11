#include "cmd_app.h"

#include <stdio.h>
#include <string.h>

#define CMD_APP_INPUT_MAX 2048

static cmd_app_t* signal_app;

static void handle_signal(int sig) {
  if (sig == SIGINT && signal_app) {
    signal_app->running = false;
  }
}

static bool command_name_is_valid(const char* name) {
  if (!name || !((*name >= 'A' && *name <= 'Z') || (*name >= 'a' && *name <= 'z'))) {
    return false;
  }
  for (++name; *name; ++name) {
    if (!((*name >= 'A' && *name <= 'Z') || (*name >= 'a' && *name <= 'z') || (*name >= '0' && *name <= '9') || *name == '-' || *name == '_')) {
      return false;
    }
  }
  return true;
}

static void print_help(const cmd_app_t* app) {
  fputs("Commands:\n  help              Show this command list.\n  quit              Stop the application.\n", stdout);
  for (uint16_t i = 0; i < app->command_count; ++i) {
    fprintf(stdout, "  %-17s %s\n", app->commands[i].name, app->commands[i].description);
  }
}

static cmd_app_command_entry_t* find_command(cmd_app_t* app, const char* name) {
  for (uint16_t i = 0; i < app->command_count; ++i) {
    if (strcmpi(app->commands[i].name, name) == 0) {
      return &app->commands[i];
    }
  }
  return NULL;
}

static void command_thread(void* argument) {
  cmd_app_t* app = argument;
  char input[CMD_APP_INPUT_MAX] = {0};
  print_help(app);
  while (cmd_app_is_running(app) && fputs("> ", stdout) >= 0 && fflush(stdout) == 0 && fgets(input, sizeof(input), stdin)) {
    input[strcspn(input, "\r\n")] = '\0';
    char* arguments = input;
    char* name = cmd_app_next_argument(&arguments);
    if (!name) {
      continue;
    }
    if (strcmpi(name, "help") == 0) {
      if (cmd_app_arguments_empty(arguments)) {
        print_help(app);
      } else {
        fputs("Usage: help\n", stderr);
      }
    } else if (strcmpi(name, "quit") == 0) {
      if (cmd_app_arguments_empty(arguments)) {
        cmd_app_stop(app);
      } else {
        fputs("Usage: quit\n", stderr);
      }
    } else {
      cmd_app_command_entry_t* command = find_command(app, name);
      if (command) {
        command->handler(command->context, arguments);
      } else {
        fputs("Unknown command. Type 'help'.\n", stderr);
      }
    }
  }
  cmd_app_stop(app);
}

void cmd_app_init(cmd_app_t* app) {
  *app = (cmd_app_t) {.running = true};
}

bool cmd_app_register(cmd_app_t* app, const char* name, const char* description, cmd_app_handler_t handler, void* context) {
  if (!app || !description || !handler || !command_name_is_valid(name) || app->command_count == CMD_APP_MAX_COMMANDS || strcmpi(name, "help") == 0 || strcmpi(name, "quit") == 0 || find_command(app, name)) {
    return false;
  }
  app->commands[app->command_count++] = (cmd_app_command_entry_t) {
      .name = name,
      .description = description,
      .handler = handler,
      .context = context,
  };
  return true;
}

bool cmd_app_start(cmd_app_t* app) {
  if (!app || !app->running || (signal_app && signal_app != app && cmd_app_is_running(signal_app))) {
    return false;
  }
  signal_app = app;
  if (signal(SIGINT, handle_signal) == SIG_ERR || !thread_start(&app->thread, command_thread, app)) {
    signal_app = NULL;
    return false;
  }
  return true;
}

void cmd_app_join(cmd_app_t* app) {
  thread_join(&app->thread);
}

void cmd_app_stop(cmd_app_t* app) {
  if (app) {
    app->running = false;
    if (signal_app == app) {
      signal_app = NULL;
    }
  }
}

bool cmd_app_is_running(const cmd_app_t* app) {
  return app && app->running;
}

char* cmd_app_next_argument(char** arguments) {
  while (**arguments == ' ') {
    ++*arguments;
  }
  if (**arguments == '\0') {
    return NULL;
  }
  char* argument = *arguments;
  while (**arguments != '\0' && **arguments != ' ') {
    ++*arguments;
  }
  if (**arguments == ' ') {
    *(*arguments)++ = '\0';
  }
  return argument;
}

bool cmd_app_arguments_empty(const char* arguments) {
  while (*arguments == ' ') {
    ++arguments;
  }
  return *arguments == '\0';
}

bool cmd_app_parse_uint16(const char* text, uint16_t* value) {
  uint64_t parsed = 0;
  if (!text || !*text || !value) {
    return false;
  }
  for (; *text; ++text) {
    if (*text < '0' || *text > '9') {
      return false;
    }
    parsed = parsed * 10 + (uint64_t)(*text - '0');
    if (parsed > UINT16_MAX) {
      return false;
    }
  }
  *value = (uint16_t)parsed;
  return true;
}

bool cmd_app_parse_uint32(const char* text, uint32_t* value) {
  uint64_t parsed = 0;
  if (!text || !*text || !value) {
    return false;
  }
  for (; *text; ++text) {
    if (*text < '0' || *text > '9') {
      return false;
    }
    parsed = parsed * 10 + (uint64_t)(*text - '0');
    if (parsed > UINT32_MAX) {
      return false;
    }
  }
  *value = (uint32_t)parsed;
  return true;
}
