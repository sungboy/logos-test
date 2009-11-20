/* Demonstrate that the page can be replaced.
   This must succeed. */

#include <string.h>
#include "tests/lib.h"
#include "tests/main.h"

/* A system call for this test. */
void lru_test_start (void);

void
test_main (void)
{
  char stack_obj2[4096];
  memset (stack_obj2, 0, 1);
  msg ("obj2: %x", (int)stack_obj2);

  char stack_obj3[4096];
  memset (stack_obj3, 0, 1);
  msg ("obj3: %x", (int)stack_obj3);

  memset (stack_obj2, 0, 1);

  char stack_obj1[4096];
  memset (stack_obj1, 0, 1);
  msg ("obj1: %x", (int)stack_obj1);

  lru_test_start ();

  char stack_obj5[4096];
  memset (stack_obj5, 0, 1);
  msg ("obj5: %x", (int)stack_obj5);

  memset (stack_obj2, 0, 1);

  char stack_obj4[4096];
  memset (stack_obj4, 0, 1);
  msg ("obj4: %x", (int)stack_obj4);

  memset (stack_obj5, 0, 1);
  memset (stack_obj3, 0, 1);
  memset (stack_obj2, 0, 1);
  memset (stack_obj5, 0, 1);
  memset (stack_obj2, 0, 1);
}
