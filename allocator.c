/**
 * Copyright (c) 2015 MIT License by 6.172 Staff
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

#include "./allocator.h"

#include "./allocator_interface.h"
#include "./memlib.h"

// Don't call libc malloc!
#define malloc(...) (USE_MY_MALLOC)
#define free(...) (USE_MY_FREE)
#define realloc(...) (USE_MY_REALLOC)

// We have bins ranging from [2^4,2^5) to [2^31,2^32)
#define BIN_COUNT 28

// Our bins start with 2^4 and not 2^0 so we need a shift
// to ensure the index of a block is corrected
#define SMALLEST_BLOCK_POWER 4

// The smallest size if we only consider the memory space needed with headers
#define SMALLEST_BLOCK_THEORETICAL 16

// The smallest size if we consider the size of our
// free_block_t struct when blocks are free
#define SMALLEST_BLOCK_POSSIBLE 24

/*
  A memory allocator that can allocate, free and reallocate in the heap

      Assumes no allocation exceeds 2^32-1 bytes

  Each block allocated follows the below structure:

      HEADER of size HEADER_SIZE which stores the size of the data allocation

      DATA ALLOCATION of variable size depending on user request

      FOOTER of size FOOTER_SIZE which stores a tag, if in use IN_USE_TAG or
      the size of the data allocation

  Freed blocks are stored in a bins each representing a range of blocks

    The i-th bin contains the blocks of sizes in the range [2^(i+4), 2^(i+5))
    for multiples of 8 except for the first bin which starts at 24 due to the
  required minimum of our block (HEADER + free_block_t + FOOTER) = 24.

    [24,32)
    [32,64)
    [64,128)
    ...
    [2^31,2^32)
*/

typedef struct free_block_t free_block_t;
struct free_block_t {
  free_block_t* next;
  free_block_t* prev;
};

free_block_t* bins[BIN_COUNT];

void check_in_heap(char* lo, int size, int indicator) {
  // The payload must lie within the extent of the heap
  char* hi = lo + size - 1;
  if (lo < (char*)mem_heap_lo() || lo > (char*)mem_heap_hi()+1 ||
      hi < (char*)mem_heap_lo() || hi > (char*)mem_heap_hi()+1) {
    printf("bad %i", indicator);
  }
}

void check_shifting() {
  for (int i = 0; i < BIN_COUNT; ++i) {
    printf("index %d is size %d\n", i, 16 << i);
  }
}

int check_bins() {
  for (int i = 0; i < BIN_COUNT; ++i) {
    for (free_block_t* curr = bins[i]; curr != NULL; curr = curr->next) {
      if (curr->next != NULL) {
        if ((uintptr_t)curr->next->prev != (uintptr_t)curr) {
          printf("Index %d ::: Current: %lu, Next: %lu, Next->Prev: %lu\n", i,
                 (uintptr_t)curr, (uintptr_t)curr->next,
                 (uintptr_t)curr->next->prev);
          printf(
              "Next block's prev pointer doesn't point back to current "
              "block\n");
          return -1;
        }
      }
    }
  }
  return 0;
}

// check - This checks our invariant that the uint32_t header before every
// block points to either the beginning of the next block, or the end of the
// heap.
int my_check() {
  if (check_bins() == -1) {
    return -1;
  }

  char* ptr;
  char* lo = (char*)mem_heap_lo();
  char* hi = (char*)mem_heap_hi() + 1;
  size_t size = 0;

  ptr = lo;
  ptr = ptr + INITIAL_OFFSET;

  while (lo <= ptr && ptr < hi) {
    size = get_header((void*)(ptr + HEADER_SIZE)) + HEADER_SIZE +
           FOOTER_SIZE;
    ptr = (char*) ((char*)ptr + size);
  }

  if (ptr != hi) {
    printf("Bad headers did not end at heap_hi!\n");
    printf("heap_lo: %p, heap_hi: %p, size: %lu, p: %p\n", lo, hi, size, ptr);
    return -1;
  }

  return 0;
}

// init - Initialize the malloc package.  Called once before any other
// calls are made.  Since this is a very simple implementation, we just
// return success.
int my_init() {
  // The struct of free_block_t and the tags must fit in our smallest possible
  // allocation
  assert(SMALLEST_BLOCK_POSSIBLE >=
         HEADER_SIZE + sizeof(free_block_t) + FOOTER_SIZE);

#ifdef DEBUG
  printf("the next pointer of free_block_t is at offset %zu\n",
         offsetof(struct free_block_t, next));
  printf("the prev pointer of free_block_t is at offset %zu\n",
         offsetof(struct free_block_t, prev));
#endif

  // Because HEADER is 4 bytes, we need to allocate a small offset (4 bytes)
  // so the data of the block is 8-byte aligned
  mem_sbrk(INITIAL_OFFSET);

  // Set all bins to NULL
  for (int i = 0; i < BIN_COUNT; ++i) {
    bins[i] = NULL;
  }

  return 0;
}

// Given the size of the block including HEADER and FOOTER,
// get the index of the bin that the block fits in
// We start at blocks of size 16 so subtract the value to match
// bins[] sizes
static inline int get_block_index(size_t size) {
  return floor_log2(size) - SMALLEST_BLOCK_POWER;
}

// Given a pointer to a block, add it to the corresponding bin
// that has the correct range
void add_block_to_bins(void* ptr) {
  size_t curr_size = get_header(ptr);
  size_t size = get_header(ptr) + HEADER_SIZE + FOOTER_SIZE;

  assert(size % 8 == 0);
  assert(size >= SMALLEST_BLOCK_POSSIBLE);

  // We store the size of the block
  set_footer(ptr, curr_size, curr_size);

  // Get the bin index the block belongs to
  int index = get_block_index(size);

  // Put freed_block into the appropiate bin
  free_block_t* freed_block = (free_block_t*)ptr;

  if (bins[index] != NULL) {
    bins[index]->prev = freed_block;
  }

  freed_block->prev = NULL;
  freed_block->next = bins[index];
  bins[index] = freed_block;
  return;
}

// Given a pointer to a block, free it from the bins of free lists
// Because each free block has a pointer to the block before and after
// we access in O(1) time.
void remove_block_from_bins(void* ptr) {
  free_block_t* block = (free_block_t*)ptr;

  // If there was a block after the current then update its previous
  if (block->next != NULL) {
    assert(block->next->prev == block);
    block->next->prev = block->prev;
  }

  // Update the previous block, if current is at head then change head
  if (block->prev == NULL) {
    uint32_t size = get_header(ptr) + HEADER_SIZE + FOOTER_SIZE;
    int index = get_block_index(size);
    bins[index] = block->next;
  } else {
    block->prev->next = block->next;
  }
}

// Given the current ptr that we will eventually return,
// if the size of the ptr currently is enough for another,
// we break it off into its own block
void* split_excess_block(void* ptr, size_t needed_size) {
  // needed_size is requested size + HEADER_SIZE + FOOTER_SIZE

  size_t curr_size = get_header(ptr);
  size_t allocated_size = curr_size + HEADER_SIZE + FOOTER_SIZE;

  assert(allocated_size % 8 == 0);
  assert(allocated_size - needed_size >= 0);

  // Size of the block we return
  size_t partial_size = curr_size;

  // Split off extra space into new block, if have size for it
  // If remaining size can be used for a separate allocation,
  // make it into a block
  if (allocated_size - needed_size >= SMALLEST_BLOCK_POSSIBLE) {
    // Get offset of current ptr to ptr for the remaing block
    void* remaining_ptr = (void*)((char*)ptr + needed_size);

    // The remaining portion of the block that can be used for data.
    size_t remaining_size = curr_size - needed_size;

    // Add to free blocks
    // Set header to be the size of DATA it can contain
    // (EXCLUDING HEADER AND FOOTER)
    set_header(remaining_ptr, remaining_size);
    add_block_to_bins(remaining_ptr);

    // Remove the extra space for tags
    partial_size = needed_size - HEADER_SIZE - FOOTER_SIZE;
  }

  // Update header and footer to accurately represent an in use block
  set_header(ptr, partial_size);
  set_footer(ptr, partial_size, IN_USE_TAG);
  return ptr;
}

// Search through free blocks and if one can fit the needed size,
// allocate it. If possible split off the excess to new block
void* search_for_block(size_t needed_size) {
  assert(needed_size >= SMALLEST_BLOCK_POSSIBLE);

  size_t current_block_size = SMALLEST_BLOCK_POSSIBLE;

  // Search through bins[] until you get to minimum needed size
  for (int i = 0; i < BIN_COUNT; ++i) {
    if (needed_size <= current_block_size) {
      // Go through remaining bins until one has a free block
      for (int j = i; j < BIN_COUNT; ++j) {
        // If a block exists allocate and possibly split
        if (bins[j] != NULL) {
          void* ptr = (void*)bins[j];
          remove_block_from_bins(ptr);
          ptr = split_excess_block(ptr, needed_size);
          return ptr;
        }
      }
      // There are no bins that holds a valid block we can allocate
      break;
    }
    // Increase current size to double, special case when i == 0,
    // Need to change size from 24 to 16 before doubling
    if (i == 0) {
      current_block_size = SMALLEST_BLOCK_THEORETICAL;
    }
    current_block_size <<= 1;
  }

  // There are no bins that holds a valid block we can allocate
  // We will request one from OS
  return NULL;
}

// Given a size that we must allocate, we will either use a free space or
// request one from the OS. We will store the ALIGN(size) in the block safely in
// the HEADER and the status of the block (in use or not) in the FOOTER of the
// block.
void* my_malloc(size_t size) {
  size_t aligned_size = ALIGN(size + HEADER_SIZE + FOOTER_SIZE);
  aligned_size = (aligned_size < SMALLEST_BLOCK_POSSIBLE)
                     ? SMALLEST_BLOCK_POSSIBLE
                     : aligned_size;

  void* ptr = search_for_block(aligned_size);

  // Valid pointer, we are done
  if (ptr != NULL) {
    return ptr;
  }

  // We need to request OS for memory space
  ptr = mem_sbrk(aligned_size);

  assert((uintptr_t)((char*)mem_heap_hi() + 1) ==
         (uintptr_t)((char*)ptr + aligned_size));

  if (ptr == (void*)-1) {
    // Whoops, an error of some sort occurred.  We return NULL to let
    // the client code know that we weren't able to allocate memory.
    return NULL;
  } else {
    // Set header
    ptr = (void*)((char*)ptr + HEADER_SIZE);
    set_header(ptr, aligned_size - HEADER_SIZE - FOOTER_SIZE);
    set_footer(ptr, aligned_size - HEADER_SIZE - FOOTER_SIZE, IN_USE_TAG);
    return ptr;
  }
}

// Given a pointer and the size of the block including HEADER AND FOOTER,
// we continuously look at the neighboring blocks in memory and if they are
// free we will coalesce them together. This continues until the coalesced
// block is as big as possible.
void* new_coalesce(void* ptr, size_t block_size) {
  bool coalescing = true;
  while (coalescing) {
    coalescing = false;

    // Check block upstream of it (smaller address), if the heap can possibly
    // fit a block then there must exist a block, so check.
    if ((uintptr_t)mem_heap_lo() <=
        (uintptr_t)((char*)ptr - HEADER_SIZE - SMALLEST_BLOCK_POSSIBLE)) {
      // If free then size of full block is recorded
      size_t size_of_block_before = get_previous_footer(ptr);

      // If block is free then we can coalesce
      if (is_free(size_of_block_before)) {
        // We will coalesce so check further neighboring blocks
        coalescing = true;

        // Remove block before from binned free blocks
        void* ptr_before = (void*)((char*)ptr - size_of_block_before -
                                   HEADER_SIZE - FOOTER_SIZE);
        remove_block_from_bins(ptr_before);

        // Set ptr to start of the coalesced block
        ptr = ptr_before;

        // Set new pointer tags
        size_t coalesce_size = size_of_block_before + block_size;
        set_header(ptr, coalesce_size);
        set_footer(ptr, coalesce_size, coalesce_size);

        // Update the full block size
        block_size = coalesce_size + HEADER_SIZE + FOOTER_SIZE;
      }
    }

    // Check block downstream of it (larger address), if the heap can possibly
    // fit a block then there must exist a block, so check.
    if ((uintptr_t)mem_heap_hi()+1 >=
        (uintptr_t)((char*)ptr - HEADER_SIZE + block_size +
                    SMALLEST_BLOCK_POSSIBLE)) {
      // Get ptr_after
      void* ptr_after = (void*)((char*)ptr + block_size);
      size_t size_of_block_after = get_header(ptr_after);

      // If block is free then we can coalesce
      if (block_is_free(ptr_after, size_of_block_after)) {
        // We will coalesce so check further neighboring blocks
        coalescing = true;

        // Remove block after from binned free blocks
        remove_block_from_bins(ptr_after);

        // Because we are coalescing with the right side, the ptr of the new
        // block is the same as the one passed in.

        // Set new pointer tags
        size_t coalesce_size = size_of_block_after + block_size;
        set_header(ptr, coalesce_size);
        set_footer(ptr, coalesce_size, coalesce_size);

        // Update the full block size
        block_size = coalesce_size + HEADER_SIZE + FOOTER_SIZE;
      }
    }
  }
  return ptr;
}

void my_free(void* ptr) {
  // If input ptr is NULL, do nothing
  if (ptr == NULL) return;

  // During coalescing of two blocks, there exists two HEADERS and FOOTERS
  // so we can use one set as the actual memory space that is requested
  size_t aligned_size = get_header(ptr) + HEADER_SIZE + FOOTER_SIZE;

  // Coalesce if possible
  ptr = new_coalesce(ptr, aligned_size);

  // Add to binned free blocks
  add_block_to_bins(ptr);

  if (bins[BIN_COUNT-1] != NULL) {
    assert(false);
  }

  return;
}

// Given a pointer and the size of the memory space we want allocated
// we try to as efficiently as possible allocate the space needed.
void* my_realloc(void* ptr, size_t size) {
  void* newptr;
  // If ptr is null, then we want a new pointer to the requested size
  if (ptr == NULL) {
    newptr = my_malloc(size);
    return newptr;
  }

  // If size is 0 then we should free the pointer
  if (size == 0) {
    my_free(ptr);
    return ptr;
  }

  size_t copy_size = get_header(ptr);
  // We store the ALIGN(size) in the ptr for convenience
  size = ALIGN(size);
  // If the current pointer satisfies the size needed then just return it
  if (size <= copy_size) {
    return ptr;
  } else {
    // Else if the ptr given is at the end of the heap we can extend its
    // size as needed
    if ((((char*)ptr) + copy_size + FOOTER_SIZE) == (mem_heap_hi() + 1)) {
      assert((size - copy_size) % 8 == 0);
      mem_sbrk(size - copy_size);
      set_header(ptr, size);
      set_footer(ptr, size, IN_USE_TAG);
      return ptr;
    }
  }

  // Allocate a new chunk of memory, and fail if that allocation fails.
  newptr = my_malloc(size);
  if (NULL == newptr) {
    return NULL;
  }

  copy_size = (size < copy_size) ? size : copy_size;

  // This is a standard library call that performs a simple memory copy.
  memcpy(newptr, ptr, copy_size);

  // Release the old block.
  my_free(ptr);

  // Return a pointer to the new block.
  return newptr;
}
