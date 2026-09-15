/*
 * MIT License
 *
 * Copyright (c) 2026 Christian Luppi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "mutex.h"

bool mutex_init(mutex_t* mutex) {
#ifdef _WIN32
  InitializeCriticalSection(mutex);
  return true;
#else
  return pthread_mutex_init(mutex, NULL) == 0;
#endif
}

void mutex_destroy(mutex_t* mutex) {
#ifdef _WIN32
  DeleteCriticalSection(mutex);
#else
  pthread_mutex_destroy(mutex);
#endif
}

void mutex_lock(mutex_t* mutex) {
#ifdef _WIN32
  EnterCriticalSection(mutex);
#else
  pthread_mutex_lock(mutex);
#endif
}

void mutex_unlock(mutex_t* mutex) {
#ifdef _WIN32
  LeaveCriticalSection(mutex);
#else
  pthread_mutex_unlock(mutex);
#endif
}
