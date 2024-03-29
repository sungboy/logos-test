#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#include "threads/malloc.h"

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
//static struct list ready_list;	// LOGOS-DELETED

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

#ifdef USERPROG
/* LOGOS-ADDED VARIABLE */
struct lock thread_relation_lock;
#endif

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */

/* LOGOS-ADD-START */
struct prio_array
  {
    char bitmap_buf[16];
    struct bitmap *bm;
    struct list queue[PRI_MAX-PRI_MIN+1];	// 0~63 : total 64
  };

struct runqueue
  {
    struct prio_array *active;	// for scheduling
    struct prio_array *expired;
    struct prio_array arrays[2];
  };

struct runqueue run_queue;

bool is_scheduling_started;
/* LOGOS-ADD-END */

// LOGOS-EDITED we don't need it more.
//#define TIME_SLICE 4            /* # of timer ticks to give each thread. */

#define TIME_SLICE_MIN ((unsigned)5)  /* LOGOS-ADDED */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
static bool is_thread_time_slice_expired (void);
static unsigned thread_get_time_slice (void);
static tid_t thread_create_internal (const char *name, int priority, thread_func *function, void *aux, bool for_kernel_only);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
	
	// LOGOS-ADDED
  int i = 0;
	for (; PRI_MAX - PRI_MIN >= i; i++)
  {
    list_init (&run_queue.arrays[0].queue[i]);
    list_init (&run_queue.arrays[1].queue[i]);
  };

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();

  /* Initialize a stat var. */
  initial_thread->thread_ticks_total = 0;

#ifdef USERPROG
#ifdef VM
  lock_init_as_recursive_lock (&initial_thread->pagedir_lock);
#endif

  lock_init (&thread_relation_lock);

  initial_thread->parent = NULL;
  list_init (&initial_thread->child_list);

  initial_thread->is_user_process = false;
  initial_thread->user_process_state = PROCESS_NORMAL;
  sema_init (&initial_thread->exit_sync_for_child, 0);
  /* The following code is moved because it requires a new page. */
  //initial_thread->exit_sync_for_parent = (struct semaphore*)malloc (sizeof (struct semaphore));
  //ASSERT (initial_thread->exit_sync_for_parent != NULL);
  //sema_init (initial_thread->exit_sync_for_parent, 0);
  initial_thread->exit_code = -1;

  /* The following code is moved because it requires a new page. */
  // process_init_file_table(initial_thread);

  initial_thread->exe_file = NULL;
#endif

  // LOGOS-ADDED
  run_queue.arrays[0].bm = bitmap_create_in_buf (PRI_MAX-PRI_MIN+1, run_queue.arrays[0].bitmap_buf, sizeof(run_queue.arrays[0].bitmap_buf));
  run_queue.arrays[1].bm = bitmap_create_in_buf (PRI_MAX-PRI_MIN+1, run_queue.arrays[1].bitmap_buf, sizeof(run_queue.arrays[1].bitmap_buf));

  run_queue.active = &run_queue.arrays[0];
  run_queue.expired = &run_queue.arrays[1];

  is_scheduling_started = false;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  is_scheduling_started = true;
  intr_enable ();

#ifdef USERPROG
  /* Initialization code moved from thread_init. */
  initial_thread->exit_sync_for_parent = (struct semaphore*)malloc (sizeof (struct semaphore));
  ASSERT (initial_thread->exit_sync_for_parent != NULL);
  sema_init (initial_thread->exit_sync_for_parent, 0);

  process_init_file_table(initial_thread);
#endif

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* LOGOS_ADDED */
static bool
is_thread_time_slice_expired (void)
{
  struct thread *t = thread_current ();
  if (t->remained_ticks && ((int)thread_ticks) >= t->remained_ticks)
	return true;
 
  if (thread_ticks >= thread_get_time_slice())
    return true;
  return false;
}

/* LOGOS_ADDED */
static unsigned 
thread_get_time_slice (void)
{
  return thread_get_priority() + TIME_SLICE_MIN;  // time slice = priority + TIME_SLICE_MIN(5 tick)
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  ASSERT (intr_context ());

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  ++thread_ticks;

  t->thread_ticks_total++;

  /* Enforce preemption. */
  /* LOGOS-EDITED */
  if(is_thread_time_slice_expired())
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux)
{
  return thread_create_internal (name, priority, function, aux, true); 
}

#ifdef USERPROG
/* LOGOS-ADDED FUNCTION
   Creates a new thread for user process named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering. */
tid_t
thread_create_for_user_process (const char *name, int priority,
               thread_func *function, void *aux)
{
  return thread_create_internal (name, priority, function, aux, false); 
}
#endif

/* LOGOS-ADDED FUNCTION
   Creates a new thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering. */
static tid_t
thread_create_internal (const char *name, int priority,
               thread_func *function, void *aux, bool for_kernel_only) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();
  t->remained_ticks = 0;

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;

  /* Initialize a stat var. */
  t->thread_ticks_total = 0;

#ifdef USERPROG
  /* Initialize some variables for user process. */
#ifdef VM
  lock_init_as_recursive_lock (&t->pagedir_lock);
#endif

  if(for_kernel_only)
    t->is_user_process = false;
  else
    t->is_user_process = true;

  t->user_process_state = PROCESS_NORMAL;
  sema_init (&t->exit_sync_for_child, 0);
  t->exit_sync_for_parent = (struct semaphore*)malloc (sizeof (struct semaphore));
  ASSERT (t->exit_sync_for_parent != NULL);
  sema_init (t->exit_sync_for_parent, 0);
  t->exit_code = -1;

  process_init_file_table(t);

  t->exe_file = NULL;

  /* Build thread relation. */
  t->parent = thread_current ();
  list_init (&t->child_list);

  lock_acquire (&thread_relation_lock);
  list_push_back (&t->parent->child_list, &t->sibling_elem);
  lock_release (&thread_relation_lock);
#endif

  /* Add to run queue. */
  thread_unblock (t);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  struct thread* cur = thread_current ();

  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  if(!cur->remained_ticks)
		  cur->remained_ticks = thread_get_time_slice();
  cur->remained_ticks = cur->remained_ticks - thread_ticks;  // save ticks remained
  cur->status = THREAD_BLOCKED;

  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)
   + Reschedule if neccessary. */
void
thread_unblock (struct thread *t) 
{
  /* LOGOS-ADDED */
  enum intr_level old_level;

  ASSERT(!is_scheduling_started || intr_context () || intr_get_level () == INTR_ON);

  old_level = intr_disable ();
  thread_unblock_without_preemption (t);
  /* LOGOS-ADDED */
  if (is_scheduling_started && thread_get_priority() < t->priority)
  {
	  if(intr_context ())
		intr_yield_on_return();
	  else
		thread_yield();
  }
  intr_set_level (old_level);
}

/* LOGOS-ADDED
   Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.) */
void
thread_unblock_without_preemption (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

  // LOGOS-EDIT-START
  ASSERT (0 < t->priority || PRI_MAX > t->priority);
  list_push_back (&run_queue.active->queue[PRI_MAX - t->priority], &t->elem);
  bitmap_mark (run_queue.active->bm, PRI_MAX - t->priority);


	// LOGOS-EDIT-END

  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it without exit code for kernel threads or user processes killed by kernel. 
   Never returns to the caller. */
void
thread_exit (void) 
{
  thread_exit_with_exit_code (-1); // -1 means that the current thread is being killed by kernel. 
  NOT_REACHED ();
}

/* LOGOS-ADDED FUNCTION
   Deschedules the current thread and destroys it with exit code. The exit code is only valid with user processes. 
   Never returns to the caller. */
void
thread_exit_with_exit_code (int status) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  /* For User Process */
  process_exit (status);
#endif

  /* Just set our status to dying and schedule another process.
     We will be destroyed during the call to schedule_tail(). */
  intr_disable ();
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

#ifdef USERPROG
/* LOGOS-ADDED FUNCTION
   Remove the relation of the current thread to other threads. */
void
thread_remove_relation (bool lock) 
{
  thread_remove_child_relation (lock);
  thread_remove_parent_relation (lock);
}

/* LOGOS-ADDED FUNCTION
   Remove the child relation of the current thread. */
void
thread_remove_child_relation (bool lock) 
{
  struct thread* tempt;
  struct list_elem *e, *next;

  /* Rebulid thread child relation. */
  if(lock)
    lock_acquire (&thread_relation_lock);

  for (e = list_begin (&thread_current()->child_list); e != list_end (&thread_current()->child_list);
       e = next)
    {
      tempt = list_entry (e, struct thread, sibling_elem);
      next = list_next (e);

	  if (tempt->is_user_process && tempt->user_process_state == PROCESS_ZOMBIE)
        continue;

      tempt->parent = initial_thread;
      list_remove (e);
	  list_push_back (&initial_thread->child_list, e);
    }
  
  ASSERT (list_empty (&thread_current()->child_list));

  if(lock)
    lock_release (&thread_relation_lock);

  /* Call wait for the remaining zombie user processes. 
     Warning : No other threads will use child relation of this thread, so we don't have to get a lock. */
  for (e = list_begin (&thread_current()->child_list); e != list_end (&thread_current()->child_list);
       e = next)
    {
      tempt = list_entry (e, struct thread, sibling_elem);
      next = list_next (e);

	  ASSERT (tempt->is_user_process && tempt->user_process_state == PROCESS_ZOMBIE);
      process_wait(tempt->tid);
    }
}

/* LOGOS-ADDED FUNCTION
   Remove the parent relation of the current thread. */
void
thread_remove_parent_relation (bool lock) 
{
  struct thread* parent;

  /* Remove thread parent relation. */
  if(lock)
    lock_acquire (&thread_relation_lock);

  parent = thread_current()->parent;
  if(parent)
      list_remove (&thread_current()->sibling_elem);
  thread_current()->parent = NULL;

  if(lock)
    lock_release (&thread_relation_lock);
}
#endif

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  if(!is_scheduling_started)
	  return;

  old_level = intr_disable ();
  if (cur != idle_thread)
	{
	  // LOGOS-EDITED 
      if (is_thread_time_slice_expired())
      {
        list_push_back (&(run_queue.expired->queue[PRI_MAX - cur->priority]), &cur->elem);
        bitmap_mark (run_queue.expired->bm, PRI_MAX - cur->priority);
		cur->remained_ticks = 0;
      }
      else
      {
        list_push_back (&(run_queue.active->queue[PRI_MAX - cur->priority]), &cur->elem);
        bitmap_mark (run_queue.active->bm, PRI_MAX - cur->priority);
		if(!cur->remained_ticks)
		  cur->remained_ticks = thread_get_time_slice();
        cur->remained_ticks = cur->remained_ticks - thread_ticks;  // save ticks remained
      }
	}
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  /* LOGOS-ADDED */
  ASSERT(!is_scheduling_started || intr_get_level () == INTR_ON);

  int old__priority = thread_current ()->priority;
  enum intr_level old_level;

  old_level = intr_disable ();
  thread_current ()->priority = new_priority;

  if (is_scheduling_started && old__priority > new_priority)
    {
      unsigned idx = bitmap_scan (run_queue.active->bm, 0, 1, true);
      if (BITMAP_ERROR != idx && PRI_MAX - idx > (unsigned)new_priority)
        thread_yield();
    }
  intr_set_level (old_level);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  /* Not yet implemented. */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  return 0;
}

/* LOGOS-ADDED FUNCTION */
int64_t
thread_ticks_total (void)
{
  return thread_current ()->thread_ticks_total;
}


/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  // LOGOS-EDITED
  ASSERT (run_queue.active->bm);
  ASSERT (run_queue.expired->bm);

  unsigned idx = bitmap_scan (run_queue.active->bm, 0, 1, true);
	if (BITMAP_ERROR == idx)
    {
      idx = bitmap_scan (run_queue.expired->bm, 0, 1, true);
      if (BITMAP_ERROR == idx)
        {
          // no task
          return idle_thread;
        }
      else
        {
          // all tasks are expired
          struct prio_array *swap = run_queue.active;
          run_queue.active = run_queue.expired;
          run_queue.expired = swap;
        }
    }

  struct thread* task = list_entry (list_pop_front (&run_queue.active->queue[idx]), struct thread, elem);
  if (list_empty (&run_queue.active->queue[idx]))
    bitmap_reset (run_queue.active->bm, idx);

  return task;
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
schedule_tail (struct thread *prev) 
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  /* Strictly speaking, we must get the page directory lock, cur->pagedir_lock, if VM is defined. 
     But it is hard to implement the code getting the lock in scheduler, and the current code setting and removing the page directory allows us to forget about the lock, so we do it without acquiring the lock. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until schedule_tail() has
   completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  schedule_tail (prev); 
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
