/* Demonstrate that the page can be replaced.
   This must succeed. */

#include <string.h>
#include "tests/lib.h"
#include "tests/main.h"

/* A system call for this test. */
void lru_test_start (void);
void lru_test_middle (void);

void
test_main (void)
{
  char stack_unused1[4096];
  memset (stack_unused1, 0xff, 1);
  char stack_unused2[4096];
  memset (stack_unused2, 0xff, 1);
  char stack_unused3[4096];
  memset (stack_unused3, 0xff, 1);
  char stack_unused4[4096];
  memset (stack_unused4, 0xff, 1);

  lru_test_start ();

  char stack_obj1[4096];
  memset (stack_obj1, 1, 1);

  char stack_obj2[4096];
  memset (stack_obj2, 2, 1);

  char stack_obj3[4096];
  memset (stack_obj3, 3, 1);
  

  lru_test_middle ();

  char stack_obj4[4096];
  memset (stack_obj4, 4, 1);

  char stack_obj5[4096];
  memset (stack_obj5, 5, 1);

  memset (stack_obj1, 1, 1);
  memset (stack_obj2, 2, 1);
  memset (stack_obj3, 3, 1);
  memset (stack_obj4, 4, 1);
  memset (stack_obj5, 5, 1);

  msg ("obj1: %x", (int)stack_obj1);
  msg ("obj2: %x", (int)stack_obj2);
  msg ("obj3: %x", (int)stack_obj3);
  msg ("obj4: %x", (int)stack_obj4);
  msg ("obj5: %x", (int)stack_obj5);
}
