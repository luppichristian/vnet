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
