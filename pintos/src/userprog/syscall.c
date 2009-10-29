#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <user/syscall.h>
#include "userprog/process.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);

static void sys_halt (void);
static void sys_exit (int status);
static pid_t sys_exec (const char *file);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);
static mapid_t sys_mmap (int fd, void *addr);
static void sys_munmap (mapid_t mapid);
static bool sys_chdir (const char *dir);
static bool sys_mkdir (const char *dir);
static bool sys_readdir (int fd, char name[READDIR_MAX_LEN + 1]);
static bool sys_isdir (int fd);
static int sys_inumber (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* System call parameter counts. */
  const int arg_no[] = 
  {
    /* Projects 2 and later. */
    0, /* SYS_HALT */
    1, /* SYS_EXIT */
    1, /* SYS_EXEC */
    1, /* SYS_WAIT */
    2, /* SYS_CREATE */
    1, /* SYS_REMOVE */
    1, /* SYS_OPEN */
    1, /* SYS_FILESIZE */
    3, /* SYS_READ */
    3, /* SYS_WRITE */
    2, /* SYS_SEEK */
    1, /* SYS_TELL */
    1, /* SYS_CLOSE */

    /* Project 3 and optionally project 4. */
    2, /* SYS_MMAP */
    1, /* SYS_MUNMAP */

    /* Project 4 only. */
    1, /* SYS_CHDIR */
    1, /* SYS_MKDIR */
    2, /* SYS_READDIR */
    1, /* SYS_ISDIR */
    1, /* SYS_INUMBER */

	/* Add new system call here */

	/* The number of system calls */
	-1, /* SYS_CALL_COUNT */
  };

  /* System call functions. */
  const void* syscall_func[] = 
  {
    /* Projects 2 and later. */
    sys_halt, /* SYS_HALT */
    sys_exit, /* SYS_EXIT */
    sys_exec, /* SYS_EXEC */
    sys_wait, /* SYS_WAIT */
    sys_create, /* SYS_CREATE */
    sys_remove, /* SYS_REMOVE */
    sys_open, /* SYS_OPEN */
    sys_filesize, /* SYS_FILESIZE */
    sys_read, /* SYS_READ */
    sys_write, /* SYS_WRITE */
    sys_seek, /* SYS_SEEK */
    sys_tell, /* SYS_TELL */
    sys_close, /* SYS_CLOSE */

    /* Project 3 and optionally project 4. */
    sys_mmap, /* SYS_MMAP */
    sys_munmap, /* SYS_MUNMAP */

    /* Project 4 only. */
    sys_chdir, /* SYS_CHDIR */
    sys_mkdir, /* SYS_MKDIR */
    sys_readdir, /* SYS_READDIR */
    sys_isdir, /* SYS_ISDIR */
    sys_inumber, /* SYS_INUMBER */

	/* Add new system call here */

	/* The number of system calls */
	NULL, /* SYS_CALL_COUNT */
  };

  /* Whether system call functions return a value. */
  const bool syscall_func_ret[] = 
  {
    /* Projects 2 and later. */
    false, /* SYS_HALT */
    false, /* SYS_EXIT */
    true, /* SYS_EXEC */
    true, /* SYS_WAIT */
    true, /* SYS_CREATE */
    true, /* SYS_REMOVE */
    true, /* SYS_OPEN */
    true, /* SYS_FILESIZE */
    true, /* SYS_READ */
    true, /* SYS_WRITE */
    false, /* SYS_SEEK */
    true, /* SYS_TELL */
    false, /* SYS_CLOSE */

    /* Project 3 and optionally project 4. */
    true, /* SYS_MMAP */
    false, /* SYS_MUNMAP */

    /* Project 4 only. */
    true, /* SYS_CHDIR */
    true, /* SYS_MKDIR */
    true, /* SYS_READDIR */
    true, /* SYS_ISDIR */
    true, /* SYS_INUMBER */

	/* Add new system call here */

	/* The number of system calls */
	false, /* SYS_CALL_COUNT */
  };

  const int MAX_ARG = 3;

  uint32_t syscall_num;
  uint32_t arg[MAX_ARG];
  uint32_t ret = 0;

  int i;

  if (!process_is_valid_user_virtual_address (f->esp, sizeof(int), false))
    {
      /* TODO : Add some code if necessary. */
      printf("Invalid System Call : Invalid ESP. \n");
	  thread_exit ();
    }

  syscall_num = *((uint32_t*)f->esp);
  if (syscall_num >= SYS_CALL_COUNT)
    {
      /* TODO : Add some code if necessary. */
      printf("Invalid System Call : Invalid System Call Number. \n");
	  thread_exit ();
    }

  ASSERT (0 <= arg_no[syscall_num] && arg_no[syscall_num] <= MAX_ARG);

  for(i=0; i<arg_no[syscall_num]; i++)
    {
	  if (!process_is_valid_user_virtual_address (((uint32_t*)f->esp) + 1 + i, sizeof(int), false))
	    {
	      /* TODO : Add some code if necessary. */
          printf("Invalid System Call : Invalid Argument %d. \n", i);
	  	  thread_exit ();
	    }

      arg[i] = *(((uint32_t*)f->esp) + 1 + i);
    }

  switch (arg_no[syscall_num])
    {
    case 0:
      if(syscall_func_ret[syscall_num])
        ret = ( (uint32_t (*) (void))syscall_func[syscall_num] ) ();
	  else
        ( (void (*) (void))syscall_func[syscall_num] ) ();
      break;
    case 1:
      if(syscall_func_ret[syscall_num])
        ret = ( (uint32_t (*) (uint32_t))syscall_func[syscall_num] ) (arg[0]);
	  else
        ( (void (*) (uint32_t))syscall_func[syscall_num] ) (arg[0]);
      break;
    case 2:
      if(syscall_func_ret[syscall_num])
        ret = ( (uint32_t (*) (uint32_t, uint32_t))syscall_func[syscall_num] ) (arg[0], arg[1]);
	  else
        ( (void (*) (uint32_t, uint32_t))syscall_func[syscall_num] ) (arg[0], arg[1]);
      break;
    case 3:
      if(syscall_func_ret[syscall_num])
        ret = ( (uint32_t (*) (uint32_t, uint32_t, uint32_t))syscall_func[syscall_num] ) (arg[0], arg[1], arg[2]);
	  else
        ( (void (*) (uint32_t, uint32_t, uint32_t))syscall_func[syscall_num] ) (arg[0], arg[1], arg[2]); 
      break;
    default:
      ASSERT(0);
      break;
    }

  if(syscall_func_ret[syscall_num])
    f->eax = ret;
}

/* LOGOS-ADDED FUNCTION */
static void
sys_halt (void) 
{
  /* The Relevant user code is as follows. */
  /* syscall0 (SYS_HALT); */
  /* NOT_REACHED (); */

  /* TODO : Implement Here Correctly. */
  /* ... */
  power_off ();
  NOT_REACHED ();
}

/* LOGOS-ADDED FUNCTION */
static void
sys_exit (int status)
{
  /* The Relevant user code is as follows. */
  /* syscall1 (SYS_EXIT, status); */
  /* NOT_REACHED (); */

  /* TODO : Add some code to return status. */
  
  /* Termination Message */
  printf("%s: exit(%d)\n", thread_name (), status);

  /* TODO : Add some code if necessary. */
  thread_exit ();
  NOT_REACHED ();
}

/* LOGOS-ADDED FUNCTION */
static pid_t
sys_exec (const char *file)
{
  /* The Relevant user code is as follows. */
  /* return (pid_t) syscall1 (SYS_EXEC, file); */

  /* TODO : Implement Here Correctly. */
  /* ... */
  return process_execute (file);
}

/* LOGOS-ADDED FUNCTION */
static int
sys_wait (pid_t pid)
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_WAIT, pid); */

  /* TODO : Implement Here. */
  printf("sys_wait : not implemented yet. \n");
  return -1;
}

/* LOGOS-ADDED FUNCTION */
static bool
sys_create (const char *file, unsigned initial_size)
{
  /* The Relevant user code is as follows. */
  /* return syscall2 (SYS_CREATE, file, initial_size); */

  /* TODO : Implement Here. */
  printf("sys_create : not implemented yet. \n");
  return false;
}

/* LOGOS-ADDED FUNCTION */
static bool
sys_remove (const char *file)
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_REMOVE, file); */

  /* TODO : Implement Here. */
  printf("sys_remove : not implemented yet. \n");
  return false;
}

/* LOGOS-ADDED FUNCTION */
static int
sys_open (const char *file)
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_OPEN, file); */

  /* TODO : Implement Here. */
  printf("sys_open : not implemented yet. \n");
  return -1;
}

/* LOGOS-ADDED FUNCTION */
static int
sys_filesize (int fd) 
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_FILESIZE, fd); */

  /* TODO : Implement Here. */
  printf("sys_filesize : not implemented yet. \n");
  return -1;
}

/* LOGOS-ADDED FUNCTION */
static int
sys_read (int fd, void *buffer, unsigned size)
{
  /* The Relevant user code is as follows. */
  /* return syscall3 (SYS_READ, fd, buffer, size); */

  int i;

  if (!process_is_valid_user_virtual_address (buffer, size, true))
	{
	  /* TODO : Add some code if necessary. */
		printf("Invalid System Call(sys_read) : Invalid Buffer\n");
      thread_exit ();
    }

  /* Standard Input/Output Processing */
  switch(fd)
    {
    case STDIN_FILENO:
        for (i=0; i<size; i++)
          ((uint8_t*)buffer)[i] = input_getc ();
        return size;
    case STDOUT_FILENO:
		/* Do Nothing. */
		return 0;
    case 2:
		/* Do Nothing. */
		return 0;
    default:
		break;
    }

  /* TODO : Implement Here Correctly. */
  /* ... */
  printf("sys_read : not implemented yet. \n");
  return -1;
}

/* LOGOS-ADDED FUNCTION */
static int
sys_write (int fd, const void *buffer, unsigned size)
{
  /* The Relevant user code is as follows. */
  /* return syscall3 (SYS_WRITE, fd, buffer, size); */

  if (!process_is_valid_user_virtual_address (buffer, size, false))
	{
	  /* TODO : Add some code if necessary. */
      printf("Invalid System Call(sys_write) : Invalid Buffer\n");
      thread_exit ();
    }

  /* Standard Input/Output Processing */
  switch(fd)
    {
    case STDIN_FILENO:
		/* Do Nothing. */
		return 0;
    case STDOUT_FILENO:
		putbuf (buffer, size);
		return size;
    case 2:
		/* Do Nothing. */
		return 0;
    default:
		break;
    }

  /* TODO : Implement Here Correctly. */
  /* ... */
  printf("sys_write : not implemented yet. \n");

  return -1;
}

/* LOGOS-ADDED FUNCTION */
static void
sys_seek (int fd, unsigned position) 
{
  /* The Relevant user code is as follows. */
  /* syscall2 (SYS_SEEK, fd, position); */

  /* TODO : Implement Here. */
  printf("sys_seek : not implemented yet. \n");
  return;
}

/* LOGOS-ADDED FUNCTION */
static unsigned
sys_tell (int fd) 
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_TELL, fd); */

  /* TODO : Implement Here. */
  printf("sys_tell : not implemented yet. \n");
  return 0;
}

/* LOGOS-ADDED FUNCTION */
static void
sys_close (int fd)
{
  /* The Relevant user code is as follows. */
  /* syscall1 (SYS_CLOSE, fd); */

  /* TODO : Implement Here. */
  printf("sys_close : not implemented yet. \n");
  return;
}

/* LOGOS-ADDED FUNCTION */
static mapid_t
sys_mmap (int fd, void *addr)
{
  /* The Relevant user code is as follows. */
  /* return syscall2 (SYS_MMAP, fd, addr); */

  /* TODO : Implement Here. */
  printf("sys_mmap : not implemented yet. \n");
  return -1;
}

/* LOGOS-ADDED FUNCTION */
static void
sys_munmap (mapid_t mapid)
{
  /* The Relevant user code is as follows. */
  /* syscall1 (SYS_MUNMAP, mapid); */

  /* TODO : Implement Here. */
  printf("sys_munmap : not implemented yet. \n");
  return;
}

/* LOGOS-ADDED FUNCTION */
static bool
sys_chdir (const char *dir)
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_CHDIR, dir); */

  /* TODO : Implement Here. */
  printf("sys_chdir : not implemented yet. \n");
  return false;
}

/* LOGOS-ADDED FUNCTION */
static bool
sys_mkdir (const char *dir)
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_MKDIR, dir); */

  /* TODO : Implement Here. */
  printf("sys_mkdir : not implemented yet. \n");
  return false;
}

/* LOGOS-ADDED FUNCTION */
static bool
sys_readdir (int fd, char name[READDIR_MAX_LEN + 1]) 
{
  /* The Relevant user code is as follows. */
  /* return syscall2 (SYS_READDIR, fd, name); */

  /* TODO : Implement Here. */
  printf("sys_readdir : not implemented yet. \n");
  return false;
}

/* LOGOS-ADDED FUNCTION */
static bool
sys_isdir (int fd) 
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_ISDIR, fd); */

  /* TODO : Implement Here. */
  printf("sys_isdir : not implemented yet. \n");
  return false;
}

/* LOGOS-ADDED FUNCTION */
static int
sys_inumber (int fd) 
{
  /* The Relevant user code is as follows. */
  /* return syscall1 (SYS_INUMBER, fd); */

  /* TODO : Implement Here. */
  printf("sys_inumber : not implemented yet. \n");
  return -1;
}