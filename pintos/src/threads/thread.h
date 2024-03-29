#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#ifdef USERPROG
#include "userprog/pagedir.h"
#endif
#include "synch.h"
#include <kernel/hash.h>

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

#ifdef USERPROG
/* User Process States */
enum process_status
  {
    PROCESS_NORMAL,     /* Normal. Processed according to thread state. */
    PROCESS_ZOMBIE,     /* Process was terminated but the struct thread has not released yet. Waiting for the 'wait' system call by parent to pass exit code. */
  };

/* LOGOS-ADDED VARIABLE */
extern struct lock thread_relation_lock;
#endif

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    int remained_ticks;                 /* LOGOS-ADDED */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /* LOGOS-ADDED VARIABLE */
    int64_t thread_ticks_total;

#ifdef USERPROG
	/* LOGOS-ADDED VARIABLE START */
	/* Variables for general thread relation. */
    struct thread* parent;              /* List for child. For use, acquire thread_relation_lock first. */
    struct list child_list;             /* List for child. For use, acquire thread_relation_lock first. */
    struct list_elem sibling_elem;      /* List element for connecting siblings. For use, acquire thread_relation_lock first. */
    /* LOGOS-ADDED VARIABLE END */

#ifdef VM
	struct lock pagedir_lock;           /* LOGOS-ADDED VARIABLE. Page directory Lock. If you want to change the page table of a thread, you may have to acquire more related locks. */
#endif
    pagedir_t pagedir;                  /* Page directory. */

#ifdef VM
	void* stack_allocated_lower;        /* LOGOS-ADDED VARIABLE. */
    void* stack_allocation_limit;       /* LOGOS-ADDED VARIABLE. */
#endif

	/* Owned by userprog/process.c. */
	/* LOGOS-ADDED VARIABLE START */
    bool is_user_process;                   /* Whether this thread is for user process or not. Can't be changed. */
    enum process_status user_process_state; /* User process state. For use, acquire thread_relation_lock first. */

    struct semaphore exit_sync_for_child;   /* Used by child to wait for a parent. */
    struct semaphore* exit_sync_for_parent; /* Used by parent to wait for a child. */
    int exit_code;                          /* Saved Exit Code. */

    struct lock file_table_lock;        /* Lock for the file table. */
    struct hash file_table;             /* File table for the user process. For use, qcquire file_table_lock lock first. */
    int nextfd;                         /* Next fd to allocate. For use, qcquire file_table_lock lock first. */

    struct file* exe_file;              /* The struct file pointer for the executable file. User process only. */
    /* LOGOS-ADDED VARIABLE END */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);
#ifdef USERPROG
tid_t thread_create_for_user_process (const char *name, int priority, thread_func *, void *);
#endif

void thread_block (void);
void thread_unblock (struct thread *);
void thread_unblock_without_preemption (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
#ifdef USERPROG
void thread_exit_with_exit_code (int status) NO_RETURN;
void thread_remove_relation (bool lock);
void thread_remove_child_relation (bool lock);
void thread_remove_parent_relation (bool lock);
#endif
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

int64_t thread_ticks_total (void);

#endif /* threads/thread.h */
