#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

static void busy_wait (int64_t loops);
static void iterator (void *t_);
static int64_t test_scheduler_performance_test (int thread_cnt);
void test_alarm_logos_O1_scheduler (void);

/* LOGOS-ADDED FUNCTION
   a test for O(1) scheduler. */
void
test_alarm_logos (void)
{
  test_alarm_logos_O1_scheduler ();
}

/* LOGOS-ADDED FUNCTION
   a test for O(1) scheduler. */
void
test_alarm_logos_O1_scheduler (void)
{
  int cnta, cntb;
  int64_t itera, iterb;

  msg ("O(1) Scheduler Test");

  cnta = 2;
  msg ("Scheduler Performane Test For %d Threads", cnta);
  itera = test_scheduler_performance_test (cnta);
  msg ("");

  cntb = 200;
  msg ("Scheduler Performane Test For %d Threads", cntb);
  iterb = test_scheduler_performance_test (cntb);
  msg ("");

  msg ("Scheduler Performance Result");
  msg ("Thread %d : %lld iteration(s), Thread %d : %lld iteration(s)", cnta, itera, cntb, iterb);
  msg ("Thread %d / Thread %d * 100 : %lld", cntb, cnta, iterb * 100 / itera);
}

/* LOGOS-ADDED TYPE
   Information about the test. */
struct scheduler_performance_test 
  {
    int64_t start;              /* The start time of test. */
    int64_t ticks;              /* The test duration in ticks. */
    int thread_cnt;             /* Number of threads. */
    bool end;                   /* Does the test end? */
    int exited_thread_cnt;      /* The number of exited threads. */
  };

/* LOGOS-ADDED TYPE
   Information about an individual thread in the test. */
struct iteration_thread 
  {
    struct scheduler_performance_test *test;    /* Info shared between all threads. */
    int64_t iterations;	                        /* Total Iterations executed. */
  };

#define START_TICKS_PER_THREAD  20
#define TEST_TICKS              1000
#define LOOPS_PER_ITERATION     100

/* LOGOS-ADDED FUNCTION
   a test for scheduler performance. */
static int64_t
test_scheduler_performance_test (int thread_cnt)
{
  struct scheduler_performance_test test;
  struct iteration_thread *threads;
  int i;
  int64_t ret;
  enum intr_level old_level;

  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  /* Allocate memory. */
  threads = (struct iteration_thread *) malloc (sizeof *threads * thread_cnt);
  if (threads == NULL)
    PANIC ("couldn't allocate memory for test");

  /* Initialize test. */
  test.start = timer_ticks () + START_TICKS_PER_THREAD * thread_cnt;
  test.ticks = TEST_TICKS;
  test.thread_cnt = thread_cnt;
  test.end = false;
  test.exited_thread_cnt = 0;

  /* Start threads. */
  msg ("Starting threads... [%lld]", timer_ticks ());
  for (i = 0; i < thread_cnt; i++)
    {
      struct iteration_thread *t = threads + i;
      char name[16];
      
      t->test = &test;
      t->iterations = 0;

      snprintf (name, sizeof name, "thread %d", i);
      thread_create (name, PRI_DEFAULT-5, iterator, t);
    }

  /* Wait. */
  msg ("Waiting threads... test.ticks = %lld, test.start = %lld [%lld]", test.ticks, test.start, timer_ticks ());
  timer_sleep (test.ticks + test.start - timer_ticks ());

  /* Calculate the total iteration count. */
  old_level = intr_disable ();
  msg("Calculating... [%lld]", timer_ticks ());
  ret = 0;
  for(i=0; i < thread_cnt; i++)
    ret += threads[i].iterations;
  test.end = true;
  intr_set_level (old_level);

  /* Wait for all threads to finish. */
  i = 1;
  while(i)
    {
      old_level = intr_disable ();
      if(test.exited_thread_cnt == thread_cnt)
        i = 0;
      intr_set_level (old_level);
    }

  /* Release Memory. */
  free (threads);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   Iteration thread. */
static void
iterator (void *t_) 
{
  struct iteration_thread *t = t_;
  struct scheduler_performance_test *test = t->test;
  enum intr_level old_level;
  int64_t sleep_ticks = test->start - timer_ticks ();

  ASSERT (sleep_ticks > 0);

  timer_sleep (sleep_ticks);

  int64_t thread_working_start = timer_ticks ();

  while (!test->end)
    {
      busy_wait (LOOPS_PER_ITERATION);
      t->iterations++;
    }

  msg("%s Exiting... thread_working_start = %lld [%lld]", thread_name (), thread_working_start, timer_ticks ());

  old_level = intr_disable ();
  test->exited_thread_cnt++;
  intr_set_level (old_level);
}

/* LOGOS-ADDED FUNCTION
   This function comes from timer.c. 

   Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) 
{
  while (loops-- > 0)
    barrier ();
}