#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#  include <windows.h>
typedef HANDLE thread_t;
#else
#  include <pthread.h>
typedef pthread_t thread_t;
#endif

typedef void (*thread_function_t)(void* argument);

/* Starts one function on a new thread. The caller joins a successfully started thread. */
bool thread_start(thread_t* thread, thread_function_t function, void* argument);

/* Waits for a started thread to finish and releases platform resources. */
void thread_join(thread_t* thread);

/* Sleeps without exposing the host platform's timing API to callers. */
void thread_sleep(uint32_t milliseconds);
