/**
 * Copyright (c) 2020 MIT License by 6.172 Staff
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 **/

/**
 * allocator.h
 *
 * You may include macros, inline helper function definitions, and helper
 * function prototypes here instead of in allocator.c, especially if you like to
 * test them in allocator_test.c.
 **/

#ifndef MM_ALLOCATOR_H
#define MM_ALLOCATOR_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <stddef.h>

// All blocks must have a specified minimum alignment.
// The alignment requirement (from config.h) is >= 8 bytes.
#ifndef ALIGNMENT
#define ALIGNMENT 8
#endif

// Rounds up to the nearest multiple of ALIGNMENT.
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

// The smallest aligned size that will hold a size_t value.
#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define HEADER_SIZE (sizeof(uint32_t))
#define FOOTER_SIZE (sizeof(uint32_t))

// Because our HEADER is 4 bytes, we need to do an initial
// request for 4 bytes to make sure the actual data is
// 8 byte aligned
#define INITIAL_OFFSET (ALIGN(HEADER_SIZE) - (HEADER_SIZE))

// If a block is in use, its flag is 1, otherwise if free
// it should be the size of the block
#define IN_USE_TAG 1

#define BITS_IN_UINT64_T 64

// Convert a size_t value to uint32_t for storing in header/footer
static inline uint32_t change_size_t_to_uint32_t(size_t size) {
  return (uint32_t)size;
}

// Convert a uint32_t value to size_t to fit other function type requirements
static inline size_t change_uint32_t_to_size_t(uint32_t size) {
  // return (size != 0)?(size_t)size:(1UL << 32);
  return (size_t) size;
}

// Get size of block from the header of a block
static inline size_t get_header(void* ptr) {
  uint32_t size = *(uint32_t*)((char*)ptr - HEADER_SIZE);
  return change_uint32_t_to_size_t(size);
}

// Get footer tag -> Either size of block or 1
static inline size_t get_footer(void* ptr, size_t size) {
  uint32_t tag = *(uint32_t*)((char*)ptr + size);
  return change_uint32_t_to_size_t(tag);
}

// In coalescing, we check the block before
// which we can access via its footer
static inline size_t get_previous_footer(void* ptr) {
  uint32_t tag = *(uint32_t*)((char*)ptr - HEADER_SIZE - FOOTER_SIZE);
  return change_uint32_t_to_size_t(tag);
}

// Set size of block in the header of the full block
static inline void set_header(void* ptr, size_t size) {
  *(uint32_t*)((char*)ptr - HEADER_SIZE) = change_size_t_to_uint32_t(size);
}

// Set footer of block to tag
static inline void set_footer(void* ptr, size_t size, size_t tag) {
  *(uint32_t*)((char*)ptr + size) = change_size_t_to_uint32_t(tag);
}

// Check if footer of block shows it is free or not
static inline bool is_free(size_t tag) {
  return (tag != IN_USE_TAG);
}

// Check a block if it is free
static inline bool block_is_free(void* ptr, size_t size) {
  return is_free(get_footer(ptr, size));
}

// Calculates the floor of log2(base)
static inline uint64_t floor_log2(uint64_t base) {
  return BITS_IN_UINT64_T - __builtin_clzl(base) - 1;
}

#endif  // MM_ALLOCATOR_H
