#include "userprog/process.h"
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
#include "threads/malloc.h"
#ifdef VM
#include "vm/vm.h"
#endif //VM

static thread_func execute_thread NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static bool process_is_valid_user_virtual_address_for_string_read_internal (const void *ustr, void *esp, bool check_func (const void *, size_t, bool, void*));
static bool process_is_valid_user_virtual_address_wo_stack_growth_internal (const void *uvaddr, size_t size, bool writable, void *esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create_for_user_process (file_name, PRI_DEFAULT, execute_thread, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
execute_thread (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

#ifdef VM
  thread_current ()->stack_allocation_limit = 0;
#endif

  /* LOGOS-ADDED parsing arguments */

  char **argv = malloc (sizeof (char*));
  int argc = 0;

  char *token, *save_ptr;

  for (token = strtok_r (file_name, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr))
  {
    int len = strlen (token) + 1;
    argv[argc] = (char*)malloc (sizeof (char) * len);
    strlcpy (argv[argc], token, len);
    argc++;
    argv = (char**)realloc (argv, sizeof (char*) * (argc + 1));
  }  

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (argv[0], &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* LOGOS-ADDED: passing arguments */
  int i;
  char **argp = malloc (sizeof (char*) * argc);
  char *arg;
  for (i = 1; i <= argc; i++)
  {
    arg = argv[argc - i];
    int len = strlen (arg) + 1; // 1 for null
    if_.esp = (char *)if_.esp - len;
    argp[argc - i] = if_.esp;
    strlcpy (if_.esp, arg, len);
  }

  if_.esp = (uint8_t*)if_.esp - 1;  // for word-align
  memset (if_.esp, 0, 1);

  if_.esp = (char **)if_.esp - 1; // for last null argv
  memset (if_.esp, 0, sizeof (char *));

  for (i = 1; i <= argc; i++)
  {
    if_.esp = (char **)if_.esp - 1;
    *(char **)if_.esp = argp[argc - i];
  }

  char** pargv = if_.esp;
  if_.esp = (char ***)if_.esp - 1;
  *(char ***)if_.esp = pargv;

  if_.esp = (int*)if_.esp - 1;
  *(int *)if_.esp = argc;

  if_.esp = (void **)if_.esp - 1;
  *(void **)if_.esp = (void *)0;

  free (argp);

  for (i = 0; i < argc; i++)
  {
    free (argv[i]);
  }

  free (argv);


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct thread* t = thread_current();
  struct thread* child;
  struct list_elem *e, *next;
  bool found = false;
  int ret = -1;
  struct semaphore* exit_sync_for_parent;

  /* Find the child. */
  lock_acquire (&thread_relation_lock);

  for (e = list_begin (&t->child_list); e != list_end (&t->child_list);
       e = next)
    {
      child = list_entry (e, struct thread, sibling_elem);
      next = list_next (e);

      if(child->tid == child_tid)
        {
          found = 1;
          break;
        }
    }
  if (!found || !child->is_user_process)
    {
      lock_release (&thread_relation_lock);
      return -1;
    }

  exit_sync_for_parent = child->exit_sync_for_parent;

  lock_release (&thread_relation_lock);

  /* Wait for the child to call 'exit'. */
  sema_down (exit_sync_for_parent);

  /* Read exit code. */
  ASSERT(child->user_process_state == PROCESS_ZOMBIE);
  ret = child->exit_code;

  /* Wait for the child to release resource. */
  sema_up (&child->exit_sync_for_child);
  sema_down (exit_sync_for_parent);
  free(exit_sync_for_parent);

  /* Return. */
  return ret;
}

/* Free the current process's resources. */
void
process_exit (int status)
{
  struct thread *cur = thread_current ();
  pagedir_t pd;
  struct thread *parent;
  
  if(cur->is_user_process)
    {
      /* Termination Message */
      printf("%s: exit(%d)\n", thread_name (), status);

      /* Move children. */
      thread_remove_child_relation (true);

      /* Set exit code, interact with parent, and release. */
      cur->exit_code = status;

      lock_acquire (&thread_relation_lock);
      cur->user_process_state = PROCESS_ZOMBIE;
      parent = cur->parent;
      lock_release (&thread_relation_lock);

      if(parent != NULL)
        {
          sema_up (cur->exit_sync_for_parent);
          sema_down (&cur->exit_sync_for_child);
        }

      thread_remove_parent_relation(true);

      if(parent != NULL)
        sema_up (cur->exit_sync_for_parent);
    }
  else
    thread_remove_relation (true);

#ifdef VM
  /* Free all user memory. */
  vm_free_all_thread_user_memory (cur);
#endif //VM

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
#ifdef VM
  lock_acquire (&cur->pagedir_lock);
#endif
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
#ifdef VM
  lock_release (&cur->pagedir_lock);
#endif

  /* Destory the file table of the current process. */
  process_destroy_file_table(cur);

  /* Allow write. */
  if(cur->exe_file)
    {
      file_allow_write (cur->exe_file);
      file_close(cur->exe_file);
    }
}

/* Sets up the CPU for running user code in the current
   thread. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_set_esp0 ((uint8_t *) t + PGSIZE);
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
#ifdef VM
  lock_acquire (&t->pagedir_lock);
#endif
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    {
#ifdef VM
	  lock_release (&t->pagedir_lock);
#endif
      goto done;
    }
  process_activate ();
#ifdef VM
  lock_release (&t->pagedir_lock);
#endif

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Deny Write. */
  file_deny_write (file);
  t->exe_file = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
#ifdef VM
			  ASSERT ((mem_page + read_bytes + zero_bytes) % PGSIZE == 0);
              if (thread_current ()->stack_allocation_limit < ((void*)mem_page) + read_bytes + zero_bytes)
                thread_current ()->stack_allocation_limit = ((void*)mem_page) + read_bytes + zero_bytes;
#endif
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

#ifdef VM
  thread_current ()->stack_allocated_lower = PHYS_BASE - PGSIZE;
#endif

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
#ifdef VM
  lock_acquire (&t->pagedir_lock);
#endif
  if (pagedir_get_page (t->pagedir, upage) != NULL)
    {
      ASSERT (0);
#ifdef VM
	  lock_release (&t->pagedir_lock);
#endif
      return false;
    }

  if (!pagedir_set_page (t->pagedir, upage, kpage, writable))
    {
#ifdef VM
      lock_release (&t->pagedir_lock);
#endif
      return false;
    }

#ifdef VM
  pagedir_set_dirty (t->pagedir, upage, true); /* The page first loaded must be written when it is requested to be replaced. */
  pagedir_set_accessed (t->pagedir, upage, true); /* For the clock algorithm, we set this page accessed. */
#endif

#ifdef VM
  /* Make the page pageable. */
  if (!vm_set_page_pageable (t, upage))
    {
      pagedir_clear_page (t->pagedir, upage);
      lock_release (&t->pagedir_lock);
      return false;
    }
  lock_release (&t->pagedir_lock);
#endif

  return true;      
}

/* LOGOS-ADDED FUNCTION
   Check whether the address, uvaddr is a valid user virtual address. */
bool
process_is_valid_user_virtual_address (const void *uvaddr, size_t size, bool writable, void *esp)
{
  bool b;
  b = process_is_valid_user_virtual_address_wo_stack_growth (uvaddr, size, writable);

  if(b)
    return true;

#ifdef VM
  b = vm_is_address_in_growable_stack_area (thread_current (), uvaddr, esp);

  if(b)
    return true;
#endif

  return false;
}

/* LOGOS-ADDED FUNCTION */
static bool
process_is_valid_user_virtual_address_for_string_read_internal (const void *ustr, void *esp, bool (*check_func) (const void *, size_t, bool, void*))
{
  const char *p = (const char*)ustr;
  while (1)
  {
    if (!check_func (p, 1, false, esp))
      return false;

    if(*p == '\0')
      break;

    p++;
  }
  return true;
}

/* LOGOS-ADDED FUNCTION
   Check whether the address, uvaddr is a vaild user virtual address of a string. */
bool
process_is_valid_user_virtual_address_for_string_read (const void *ustr, void *esp)
{
  return process_is_valid_user_virtual_address_for_string_read_internal (ustr, esp, process_is_valid_user_virtual_address);
}

/* LOGOS-ADDED FUNCTION */
static bool
process_is_valid_user_virtual_address_wo_stack_growth_internal (const void *uvaddr, size_t size, bool writable, void *esp)
{
  void *upage, *upagec;
  uintptr_t pg_count;
  struct thread *t;
  uintptr_t ui;
  pagedir_t pd;

  ASSERT (esp == NULL);

  if (!is_user_vaddr (uvaddr))
    return false;

  upage = pg_round_down (uvaddr);
  pg_count = pg_no (pg_round_down (uvaddr + size - 1)) - pg_no (upage) + 1;

  t = thread_current ();
#ifdef VM
  lock_acquire (&t->pagedir_lock);
#endif
  pd = t->pagedir;

  for (ui=0; ui<pg_count; ui++)
    {
	  upagec = upage + (ui << PGBITS);
	  if (writable)
        {
          if (!pagedir_is_writable (pd, upagec))
            {
#ifdef VM
              lock_release (&t->pagedir_lock);
#endif
              return false;
            }
        }
	  else
	    {
	      if (!pagedir_is_readable (pd, upagec))
            {
#ifdef VM
              lock_release (&t->pagedir_lock);
#endif
		      return false;
            }
	    }
    }
#ifdef VM
  lock_release (&t->pagedir_lock);
#endif

  return true;
}

/* LOGOS-ADDED FUNCTION
   Check whether the address, uvaddr is a valid user virtual address even without using the stack growth. */
bool
process_is_valid_user_virtual_address_wo_stack_growth (const void *uvaddr, size_t size, bool writable)
{
  return process_is_valid_user_virtual_address_wo_stack_growth_internal (uvaddr, size, writable, NULL);
}

/* LOGOS-ADDED FUNCTION
   Check whether the address, uvaddr is a vaild user virtual address of a string even without using the stack growth. */
bool
process_is_valid_user_virtual_address_for_string_read_wo_stack_growth (const void *ustr)
{
  return process_is_valid_user_virtual_address_for_string_read_internal (ustr, NULL, process_is_valid_user_virtual_address_wo_stack_growth_internal);
}

/* LOGOS-ADDED FUNCTION
   */
static unsigned
hash_hash_file_table_struct (const struct hash_elem *element, void *aux UNUSED)
{
  struct file_table_struct* fts = hash_entry (element, struct file_table_struct, elem);
  return hash_int (fts->fd);
}

/* LOGOS-ADDED FUNCTION
   */
static bool
hash_less_file_table_struct (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct file_table_struct* ftsa = hash_entry (a, struct file_table_struct, elem);
  struct file_table_struct* ftsb = hash_entry (b, struct file_table_struct, elem);

  return ftsa->fd < ftsb->fd;
}

/* LOGOS-ADDED FUNCTION
   */
static void
hash_release_action_file_table_struct (struct hash_elem *element, void *aux UNUSED)
{
  struct file_table_struct* fts = hash_entry (element, struct file_table_struct, elem);
  if(fts->file)
    file_close (fts->file);
  free(fts);
}

/* LOGOS-ADDED FUNCTION
   */
static struct file_table_struct*
process_get_new_file_table_struct (struct thread* t, struct file* f)
{
  int startfd;
  bool first;
  struct file_table_struct* ret;
  struct file_table_struct temp;

  ret = (struct file_table_struct*)malloc (sizeof (struct file_table_struct));
  if(ret == NULL)
	  return NULL;

  ASSERT (t->nextfd >= 3);

  /* Allocate fd to use. */
  startfd = t->nextfd;
  first = true;
  while (1)
    {
      /* No fd to allocate. */
	  if (!first && t->nextfd == startfd)
        {
		  free (ret);
		  return NULL;
        }

      temp.fd = t->nextfd;
	  temp.file = NULL;
	  /* If current fd is not used */
      if (hash_find (&t->file_table, &temp.elem) == NULL)
        {
          ret->fd = t->nextfd;
          t->nextfd++;
          if(t->nextfd < 3)
            t->nextfd = 3;
          break;
        }

      t->nextfd++;
      if(t->nextfd < 3)
        t->nextfd = 3;
      first = false;
    }
  
  /* Fill other fields in struct file_table_struct. */
  ret->file = f;
  hash_insert (&t->file_table, &ret->elem);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   */
static struct file*
process_get_file (struct thread* t, int fd)
{
  struct hash_elem* elem;
  struct file_table_struct* fts;
  struct file_table_struct temp_fts;

  temp_fts.fd = fd;
  temp_fts.file = NULL;

  elem = hash_find (&t->file_table, &temp_fts.elem);
  if(elem == NULL)
	  return NULL;

  fts = hash_entry (elem, struct file_table_struct, elem);

  return fts->file;
}

/* LOGOS-ADDED FUNCTION
   */
bool
process_init_file_table (struct thread* t)
{
  lock_init(&t->file_table_lock);
  t->nextfd = 3;

  #define EXPTECTED_MAX_FILE_COUNT 128 /* According to pintos document, we can use 128 as max file count per process if necessary. */

  /* Set initial size EXPTECTED_MAX_FILE_COUNT * 2 to ensure approximately O(1) access time for EXPTECTED_MAX_FILE_COUNT files per process.
  Although we can't ensure O(1) access time, we can use more than EXPTECTED_MAX_FILE_COUNT files per process because the hash table using chaining is flexible enough to allow it. */
  size_t initial_size = EXPTECTED_MAX_FILE_COUNT * 2; // Must be 2^k. 
  return hash_init_with_init_size (&t->file_table, hash_hash_file_table_struct, hash_less_file_table_struct, t, initial_size);
}

/* LOGOS-ADDED FUNCTION
   */
void
process_destroy_file_table(struct thread* t)
{
  lock_acquire (&t->file_table_lock);
  hash_destroy (&t->file_table, hash_release_action_file_table_struct);
  lock_release (&t->file_table_lock);
}

/* LOGOS-ADDED FUNCTION
   */
int 
process_open_file(struct thread* t, const char* file_name)
{
  struct file_table_struct* fts;
  struct file * f;
  int ret;
  
  f = filesys_open (file_name);
  if (f == NULL)
    return -1;

  lock_acquire (&t->file_table_lock);
  fts = process_get_new_file_table_struct (t, f);
  if (fts == NULL)
    {
      lock_release (&t->file_table_lock);
      file_close (f);
	  return -1;
    }

  ret = fts->fd;
  lock_release (&t->file_table_lock);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   */
int
process_read_file(struct thread* t, int fd, void *buffer, unsigned size)
{
  struct file* f;
  int ret;

  lock_acquire (&t->file_table_lock);

  f = process_get_file (t, fd);
  if(f == NULL)
    {
      lock_release (&t->file_table_lock);
      return -1;
    }
  ret = file_read (f, buffer, size);

  lock_release (&t->file_table_lock);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   */
int
process_write_file(struct thread* t, int fd, const void *buffer, unsigned size)
{
  struct file* f;
  int ret;

  lock_acquire (&t->file_table_lock);

  f = process_get_file (t, fd);
  if(f == NULL)
    {
      lock_release (&t->file_table_lock);
      return -1;
    }
  ret = file_write (f, buffer, size);

  lock_release (&t->file_table_lock);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   */
bool
process_close_file(struct thread* t, int fd)
{
  struct hash_elem* temp_elem;
  struct file_table_struct temp_fts;

  temp_fts.fd = fd;
  temp_fts.file = NULL;

  lock_acquire (&t->file_table_lock);

  temp_elem = hash_find (&t->file_table, &temp_fts.elem);
  if(temp_elem == NULL)
    {
      lock_release (&t->file_table_lock);
      return false;
    }

  hash_delete (&t->file_table, temp_elem);
  hash_release_action_file_table_struct (temp_elem, NULL);
  lock_release (&t->file_table_lock);

  return true;
}

/* LOGOS-ADDED FUNCTION
   */
int process_get_filesize(struct thread* t, int fd)
{
  struct file* f;
  int ret;

  lock_acquire (&t->file_table_lock);

  f = process_get_file (t, fd);
  if(f == NULL)
    {
      lock_release (&t->file_table_lock);
      return -1;
    }
  ret = file_length (f);

  lock_release (&t->file_table_lock);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   */
void process_seek_file(struct thread* t, int fd, unsigned position)
{
  struct file* f;

  lock_acquire (&t->file_table_lock);

  f = process_get_file (t, fd);
  if(f == NULL)
    {
      lock_release (&t->file_table_lock);
      return;
    }
  file_seek (f, position);

  lock_release (&t->file_table_lock);
}

/* LOGOS-ADDED FUNCTION
   */
unsigned process_tell_file(struct thread* t, int fd)
{
  struct file* f;
  unsigned ret;

  lock_acquire (&t->file_table_lock);

  f = process_get_file (t, fd);
  if(f == NULL)
    {
      lock_release (&t->file_table_lock);
      return 0;
    }
  ret = file_tell (f);

  lock_release (&t->file_table_lock);

  return ret;
}
