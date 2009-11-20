/* Demonstrate that the page can be replaced.
   This must succeed. */

#include <string.h>
#include <stdint.h>
#include "tests/lib.h"
#include "tests/main.h"

/* LOGOS-ADDED TEST */

/* Functions and macros for working with virtual addresses.

   See pte.h for functions and macros specifically for x86
   hardware page tables. */

#define BITMASK(SHIFT, CNT) (((1ul << (CNT)) - 1) << (SHIFT))

/* Page offset (bits 0:12). */
#define PGSHIFT 0                          /* Index of first offset bit. */
#define PGBITS  12                         /* Number of offset bits. */
#define PGSIZE  (1 << PGBITS)              /* Bytes in a page. */
#define PGMASK  BITMASK(PGSHIFT, PGBITS)   /* Page offset bits (0:12). */

/* A system call for this test. */
void lru_test_start (void);
void lru_test_middle (void);

/* Offset within a page. */
static inline unsigned pg_ofs (const volatile void *va) {
  return (uintptr_t) va & PGMASK;
}

/* Test main. */
void
test_main (void)
{
  volatile int jump;

  volatile char stack_unused1[PGSIZE];
  *(stack_unused1) = 0xff;

  jump = (pg_ofs (stack_unused1) - PGSIZE) % PGSIZE;

  volatile char stack_unused2[PGSIZE];
  *(stack_unused2 - jump) = 0xff;

  volatile char stack_unused3[PGSIZE];
  volatile char stack_unused4[PGSIZE];

  if (stack_unused3 == stack_unused4)
    jump = jump;

  lru_test_start ();

  volatile char stack_obj2[PGSIZE];
  *(stack_obj2 - jump) = 2;

  volatile char stack_obj3[PGSIZE];
  *(stack_obj3 - jump) = 3;

  *(stack_obj2 - jump) = 2;

  volatile char stack_obj1[PGSIZE];
  *(stack_obj1 - jump) = 1;

  lru_test_middle ();

  volatile char stack_obj5[PGSIZE];
  *(stack_obj5 - jump) = 5;

  *(stack_obj2 - jump) = 2;

  volatile char stack_obj4[PGSIZE];
  *(stack_obj4 - jump) = 4;

  *(stack_obj5 - jump) = 5;
  *(stack_obj3 - jump) = 3;
  *(stack_obj2 - jump) = 2;
  *(stack_obj5 - jump) = 5;
  *(stack_obj2 - jump) = 2;

  msg ("[Object Table]");
  msg ("obj1: %x", (int)(stack_obj1 - jump));
  msg ("obj2: %x", (int)(stack_obj2 - jump));
  msg ("obj3: %x", (int)(stack_obj3 - jump));
  msg ("obj4: %x", (int)(stack_obj4 - jump));
  msg ("obj5: %x", (int)(stack_obj5 - jump));
}
