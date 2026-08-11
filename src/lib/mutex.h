#pragma once

#include <stdbool.h>

#ifdef _WIN32
#  include <windows.h>
typedef CRITICAL_SECTION mutex_t;
#else
#  include <pthread.h>
typedef pthread_mutex_t mutex_t;
#endif

/* Initializes one mutex before any thread accesses its protected state. */
bool mutex_init(mutex_t* mutex);

/* Releases resources after all threads using the mutex have joined. */
void mutex_destroy(mutex_t* mutex);

void mutex_lock(mutex_t* mutex);
void mutex_unlock(mutex_t* mutex);
