#include "thread.h"
#include <stdlib.h>

#ifdef _WIN32
#  include <share.h>

typedef struct thread_start_data {
  thread_function_t function;
  void* argument;
} thread_start_data_t;

static DWORD WINAPI thread_entry(void* argument) {
  thread_start_data_t* data = argument;
  data->function(data->argument);
  free(data);
  return 0;
}
#else
#  include <time.h>

typedef struct thread_start_data {
  thread_function_t function;
  void* argument;
} thread_start_data_t;

static void* thread_entry(void* argument) {
  thread_start_data_t* data = argument;
  data->function(data->argument);
  free(data);
  return NULL;
}
#endif

bool thread_start(thread_t* thread, thread_function_t function, void* argument) {
  thread_start_data_t* data = malloc(sizeof(*data));
  if (!data) {
    return false;
  }
  data->function = function;
  data->argument = argument;
#ifdef _WIN32
  *thread = CreateThread(NULL, 0, thread_entry, data, 0, NULL);
  if (*thread) {
    return true;
  }
#else
  if (pthread_create(thread, NULL, thread_entry, data) == 0) {
    return true;
  }
#endif
  free(data);
  return false;
}

void thread_join(thread_t* thread) {
#ifdef _WIN32
  WaitForSingleObject(*thread, INFINITE);
  CloseHandle(*thread);
#else
  pthread_join(*thread, NULL);
#endif
}

void thread_sleep(uint32_t milliseconds) {
#ifdef _WIN32
  Sleep(milliseconds);
#else
  struct timespec duration = {
      .tv_sec = milliseconds / 1000u,
      .tv_nsec = (long)(milliseconds % 1000u) * 1000000L,
  };
  nanosleep(&duration, NULL);
#endif
}
