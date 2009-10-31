/* Test the command-line arguments passing in variety ways
   referenced testset 'args'. */

#include "tests/lib.h"

int
main (int argc, char *argv[]) 
{
  int i;

  test_name = "arg-pass";

  if (argc > 1) // 인자가 전달된 경우
  {
    msg ("argc = %d", argc);
    for (i = 0; i < argc; i++)
      if (argv[i] != NULL)
        msg ("argv[%d] = '%s' (length:%d)", i, argv[i], strlen(argv[i]));
      else
        msg ("argv[%d] = null", i);
  }
  else  // 인자가 전달되지 않은 경우, 테스트 셋 출력 
  {
    msg ("Let's test arg-pass ..\\userprog 1 22 333 4444 55555 666666 7777777 88888888 999999999 dbl-space lllllllllllllllllong");
    exec ("arg-pass ..\\userprog 1 22 333 4444 55555 666666 7777777 88888888 999999999  dbl-space lllllllllllllllllong");
  }

  return 0;
}
