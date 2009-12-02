#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "tests/lib.h"

/* LOGOS-ADDED TEST */

/* A system call for this test. */
void buffcache_test_start (int pn, int stage, int64_t* context);

#define BUFFER_SIZE 256

/* Test main. */
int
main (int argc , char *argv[]) 
{
  int64_t context = 0;
  char buffer[BUFFER_SIZE];
  int i;
  const int test_program_count = 10;
  pid_t child;

  ASSERT (test_program_count < 100);

  test_name = argv[0];

  if (argc == 1)
    {
      for (i=1; i<=test_program_count; i++)
	    {
          snprintf (buffer, BUFFER_SIZE, "logos_5-%d", i);
          CHECK (create (buffer, 512 * 5), "create %s", buffer);
	    }

      snprintf (buffer, BUFFER_SIZE, "%s %d", argv[0], test_program_count);
      buffcache_test_start (0, 1, &context);

      child = exec (buffer);
	  if (child == -1)
        return 1;

	  CHECK (wait (child) == 0, "wait child %d", test_program_count);

      buffcache_test_start (0, 2, &context);

      child = exec (buffer);
	  if (child == -1)
        return 1;

	  CHECK (wait (child) == 0, "wait child %d", test_program_count);

	  buffcache_test_start (0, 3, &context);

      for (i=1; i<=test_program_count; i++)
	    {
          snprintf (buffer, BUFFER_SIZE, "logos_5-%d", i);
          CHECK (remove (buffer), "remove %s", buffer);
	    }
    }
  else
    {
      int id = atoi (argv[1]);

      if (id > 1)
        {
          snprintf (buffer, BUFFER_SIZE, "%s %d", argv[0], id - 1);

          child = exec (buffer);
          if (child == -1)
            return 1;
        }

      buffcache_test_start (id, 1, &context);
      
      if (id > 1)
        {
	      CHECK (wait (child) == 0, "wait child %d", id - 1);
        }
    }

  return 0;
}
