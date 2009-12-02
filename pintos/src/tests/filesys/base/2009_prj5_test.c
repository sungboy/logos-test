#include <string.h>
#include <stdint.h>
#include "tests/lib.h"
#include "tests/main.h"

/* LOGOS-ADDED TEST */

/* A system call for this test. */
void buffcache_test_start (void);

/* Test main. */
void
test_main (void)
{
  CHECK (create ("logos_prj5.dat", 512 * 60), "create logos_prj5.dat");
  buffcache_test_start ();
  CHECK (remove ("logos_prj5.dat"), "remove logos_prj5.dat");
}
