/* Test the command-line arguments passing in variety ways
   referenced testset 'args'. */

#include "tests/lib.h"

int
main (int argc, char *argv[]) 
{
  int i;

  test_name = "arg-pass";

  msg ("begin");

  if (argc > 1) // 인자가 전달된 경우
  {
    msg ("argc = %d", argc);
    for (i = 0; i <= argc; i++)
      if (argv[i] != NULL)
        msg ("argv[%d] = '%s' (length:%d)", i, argv[i], strlen(argv[i]));
      else
        msg ("argv[%d] = null", i);
  }
  else  // 인자가 전달되지 않은 경우, 테스트 셋 출력 
  {
    msg ("test arg-pass many being manny 1 22 333 4444 55555 66666 77777 88888  dbl-space \"quote\"");
    exec ("arg-pass many being manny 1 22 333 4444 55555 66666 77777 88888  dbl-space \"quote\"");
  }

  msg ("end");

  return 0;
}
