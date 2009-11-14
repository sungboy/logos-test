#include "vm/swap-disk.h"

/*#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include <kernel/hash.h>
#include "threads/malloc.h"*/

//static thread_func execute_thread NO_RETURN;
//static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* LOGOS-ADDED FUNCTION
   Check whether the address, uvaddr is a valid user virtual address. */
/*bool
process_is_valid_user_virtual_address (const void *uvaddr, size_t size, bool writable)
{
  void *upage, *upagec;
  uintptr_t pg_count;
  struct thread *t;
  uintptr_t ui;
  uint32_t *pd;

  if (!is_user_vaddr (uvaddr))
    return false;

  upage = pg_round_down (uvaddr);
  pg_count = pg_no (pg_round_down (uvaddr + size - 1)) - pg_no (upage) + 1;

  t = thread_current ();
  pd = t->pagedir;

  for (ui=0; ui<pg_count; ui++)
    {
	  upagec = upage + (ui << PGBITS);
	  if (writable)
        {
          if (!pagedir_is_writable (pd, upagec))
            return false;
        }
	  else
	    {
	      if (!pagedir_is_readable (pd, upagec))
		    return false;
	    }
    }

  return true;
}
*/