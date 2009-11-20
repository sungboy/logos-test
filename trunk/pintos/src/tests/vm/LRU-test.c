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
static inline unsigned pg_ofs (const void *va) {
  return (uintptr_t) va & PGMASK;
}

/* Test main. */
void
test_main (void)
{
  int jump;

  volatile char stack_unused1[PGSIZE];
  memset (stack_unused1, 0xff, 1);

  jump = pg_ofs (stack_unused1) - PGSIZE;

  volatile char stack_unused2[PGSIZE];
  memset (stack_unused2 - jump, 0xff, 1);
  volatile char stack_unused3[PGSIZE];
  volatile char stack_unused4[PGSIZE];

  lru_test_start ();

  volatile char stack_obj1[PGSIZE];
  memset (stack_obj1 - jump, 1, 1);

  volatile char stack_obj2[PGSIZE];
  memset (stack_obj2 - jump, 2, 1);

  volatile char stack_obj3[PGSIZE];
  memset (stack_obj3 - jump, 3, 1);
  
  lru_test_middle ();

  volatile char stack_obj4[PGSIZE];
  memset (stack_obj4 - jump, 4, 1);

  volatile char stack_obj5[PGSIZE];
  memset (stack_obj5 - jump, 5, 1);

  memset (stack_obj1 - jump, 1, 1);
  memset (stack_obj2 - jump, 2, 1);
  memset (stack_obj3 - jump, 3, 1);
  memset (stack_obj4 - jump, 4, 1);
  memset (stack_obj5 - jump, 5, 1);

  msg ("[Object Table]\n");
  msg ("obj1: %x", (int)stack_obj1 - jump);
  msg ("obj2: %x", (int)stack_obj2 - jump);
  msg ("obj3: %x", (int)stack_obj3 - jump);
  msg ("obj4: %x", (int)stack_obj4 - jump);
  msg ("obj5: %x", (int)stack_obj5 - jump);
}
