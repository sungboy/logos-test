/* Reverse a file. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

/* LOGOS-ADDED FUNCTION */
void
test_main (void) 
{
  int handle, handle2, byte_cnt;
  char file_name[11] = "sample.txt";
  char file_name2[9] = "test.txt";
  size_t ofs = 0;
  size_t file_size;

  CHECK ((handle = open ("sample.txt")) > 1, "open \"%s\" for reversal",
         file_name);
  if (handle < 2)
    fail ("open() returned %d", handle);
  file_size = filesize (handle);

  CHECK (create ("test.txt", file_size), "create \"test.txt\"");
  CHECK ((handle2 = open ("test.txt")) > 1, "open \"test.txt\"");

  /* Read the file block-by-block, reversing data as we go. */
  while (ofs < file_size)
    {
      char block[512];
      size_t block_size, ret_val;

      block_size = 1;
      ret_val = read (handle, block, block_size);
      if (ret_val != block_size)
        fail ("read of %zu bytes at offset %zu in \"%s\" returned %zu",
              block_size, ofs, file_name, ret_val);

      seek(handle2, file_size - 1 - ofs);
      if (tell(handle2) != file_size - 1 - ofs)
        fail ("seek at offset %zu in \"%s\" returned %zu",
              file_size - 1 - ofs, file_name2, tell(handle2));

      byte_cnt = write (handle2, block, block_size);
      if (byte_cnt != block_size)
        fail ("write() returned %d instead of %zu", byte_cnt, block_size);
      ofs += block_size;
    }

  msg ("reversed contents of \"%s\"", file_name);

  msg ("close \"%s\"", file_name);
  close (handle);
  msg ("close \"%s\"", file_name2);
  close (handle2);

  CHECK ((handle = open ("test.txt")) > 1, "open \"%s\" for printing",
         file_name2);
  handle2 = open ("test.txt");
  if (handle2 < 2)
    fail ("open() returned %d", handle2);
  file_size = filesize (handle2);

  /* Read the file block-by-block, printing data as we go. */
  ofs = 0;
  while (ofs < file_size)
    {
      char block[512];
      size_t block_size, ret_val;

      block_size = file_size - ofs;
      if (block_size > sizeof block - 1)
        block_size = sizeof block - 1;

      ret_val = read (handle2, block, block_size);
      if (ret_val != block_size)
        fail ("read of %zu bytes at offset %zu in \"%s\" returned %zu",
              block_size, ofs, file_name2, ret_val);

      block[block_size] = '\0';
      msg("%s", block);
      ofs += block_size;
    }

  msg ("printed contents of \"%s\"", file_name2);

  remove("sample.txt");
  msg ("remove \"%s\"", file_name);

  handle = open ("sample.txt");
  if (handle < 2)
    fail ("open() returned %d", handle);
}
