#include "filesys/buffcache.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <debug.h>
#include <string.h>
#include <stdio.h>
#include <kernel/hash.h>
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

#ifdef BUFFCACHE

/* LOGOS-ADDED TYPE */
struct buffcache_entry_status
  {
    struct lock status_lock;                      /* Lock for this struct. */
    int64_t access_time;                          /* Access time expressed by timer ticks. Before using this variable, acquire status_lock first. */
    int64_t access_seq;                           /* The sequence of access among entries with the same access time. Before using this variable, acquire status_lock first. */
    int64_t dirty_write_time;                     /* Dirty write time expressed by timer ticks. Before using this variable, acquire status_lock first. */
    bool dirty;                                   /* Dirty bit. Before using this variable, acquire status_lock first. */
  };

/* LOGOS-ADDED TYPE */
struct buffcache_entry
  {
    struct hash_elem elem;                        /* Hash table element. */
    struct disk *d;                               /* Disk. A portion of the key. Cannot be changed. */
    disk_sector_t sec_no;                         /* Data sector. A portion of the key. Cannot be changed. */
    struct buffcache_entry_status status;         /* Status. */
    struct lock io_lock;                          /* Lock for I/Os. */
    void* buffer;                                 /* Data. Before using this variable, acquire io_lock first. */
  };

/* LOGOS-ADDED TYPE */
struct bcra_work
  {
    struct list_elem elem;                        /* Linked list element. */
    struct disk *d;                               /* Disk. */
    disk_sector_t sec_no;                         /* Data sector. */
  };

/* LOGOS-ADDED VALUE START */
#define BUFFCACHE_LIMIT 64                        /* The limit of entry count. Must be 2^k. */

#define BCRA_WORKER_PRIORITY (PRI_DEFAULT - 2)    /* The thread priority of the read-ahead worker. */

#define BCPWB_WORKER_PRIORITY (PRI_DEFAULT - 4)   /* The thread priority of the periodic write-behind worker. */
#define BCPWB_SLEEP_TICKS (10 * TIMER_FREQ)       /* The sleep duration of the periodic write-behind worker in timer ticks. */
/* LOGOS-ADDED VALUE END */

/* LOGOS-ADDED VARIABLE BEGIN */
static struct hash buffcache;                     /* Buffer Cache. Before using this variable, acquire buffcache_global_lock first. */

static struct lock buffcache_global_lock;         /* Lock for buffer cache data structures. */
static struct lock buffcache_new_entry_lock;      /* Lock used when new buffer cache entry is being created. */
static struct lock buffcache_new_access_seq_lock; /* Lock for a new access sequence number. */

static int64_t last_access_time;                  /* The last access time expressed by timer ticks. Before using this variable, acquire buffcache_new_access_seq_lock first. */
static int64_t last_access_seq;                   /* The last sequencial number of access among entries with the same access time. Before using this variable, acquire buffcache_new_access_seq_lock first. */

static bool buffcache_deny;                       /* Buffer cache operation deny. Before using this variable, acquire buffcache_global_lock first. */

static struct list bcra_work_list;                /* Linked list for read-ahead works to be processed. Before using this variable, acquire bcra_work_lock first. */
static struct lock bcra_work_lock;                /* Lock for data structures related to read-ahead works. */
static struct semaphore bcra_worker_sem;          /* Counting semaphore to indicate that there are more read-ahead works to be processed. */

static int64_t buffcache_total_hit_count;         /* For debug */
/* LOGOS-ADDED VARIABLE END */

static void buffcache_read_ahead_worker (void *aux);
static void buffcache_periodic_write_behind_worker (void *aux);
static void buffcache_set_access_stat (struct buffcache_entry_status *status);
static unsigned hash_hash_buffcache_entry (const struct hash_elem *element, void *aux);
static bool hash_less_buffcache_entry (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void hash_release_action_buffcache_entry (struct hash_elem *element, void *aux);
static struct buffcache_entry *buffcache_get_entry (struct disk *d, disk_sector_t sec_no);
static void buffcache_remove_entry (struct buffcache_entry *bce);
static struct buffcache_entry *buffcache_get_new_entry_internal (struct disk *d, disk_sector_t sec_no, bool with_buffer);
static struct buffcache_entry *buffcache_get_new_entry (struct disk *d, disk_sector_t sec_no);
static bool buffcache_read_internal (struct disk *d, disk_sector_t sec_no, void *buffer, struct disk *d_next, disk_sector_t sec_no_next);

static int64_t buffcache_get_total_hit_count (void);
static void buffcache_clear_total_hit_count (void);

static void buffcache_test_internal (int test_count, int sector_count, int id);
void buffcache_test_start (int pn, int stage, int64_t* context);

/* LOGOS-ADDED FUNCTION */
void
buffcache_init (void)
{
  bool b;
  tid_t tid;

  buffcache_clear_total_hit_count ();
  
  b = hash_init_with_init_size (&buffcache, hash_hash_buffcache_entry, hash_less_buffcache_entry, NULL, BUFFCACHE_LIMIT * 2);
  ASSERT (b);

  lock_init (&buffcache_global_lock);
  lock_init (&buffcache_new_entry_lock);
  lock_init (&buffcache_new_access_seq_lock);

  last_access_time = timer_ticks ();
  last_access_seq = -1;

  buffcache_deny = false;

  list_init (&bcra_work_list);
  lock_init (&bcra_work_lock);
  sema_init (&bcra_worker_sem, 0);

  tid = thread_create ("bcra_worker", BCRA_WORKER_PRIORITY, buffcache_read_ahead_worker, NULL);
  ASSERT (tid != TID_ERROR);
  tid = thread_create ("bcpwb_worker", BCPWB_WORKER_PRIORITY, buffcache_periodic_write_behind_worker, NULL);
  ASSERT (tid != TID_ERROR);
}

/* LOGOS-ADDED FUNCTION */
static void
buffcache_read_ahead_worker (void *aux UNUSED)
{
  struct bcra_work *bcraw;

  while (1)
    {
      sema_down (&bcra_worker_sem);

	  /* Now, There are at least one read-ahead work to be processed. */
	  lock_acquire (&bcra_work_lock);
      bcraw = list_entry(list_pop_front (&bcra_work_list), struct bcra_work, elem);
      lock_release (&bcra_work_lock);

	  ASSERT (bcraw->d != NULL);

	  buffcache_read_internal (bcraw->d, bcraw->sec_no, NULL, NULL, 0);

      free (bcraw);
    }
}

/* LOGOS-ADDED FUNCTION */
static void
buffcache_periodic_write_behind_worker (void *aux UNUSED)
{
  while (1)
    {
      timer_sleep (BCPWB_SLEEP_TICKS);

      buffcache_write_all_dirty_blocks (false, false);
    }
}

/* LOGOS-ADDED FUNCTION
   Before using this function, acquire status->status_lock first. */
static void
buffcache_set_access_stat (struct buffcache_entry_status *status)
{
  ASSERT (status != NULL);

  lock_acquire (&buffcache_new_access_seq_lock);

  status->access_time = timer_ticks ();

  ASSERT (status->access_time >= last_access_time);

  if (status->access_time > last_access_time)
  {
    last_access_time = status->access_time;
    last_access_seq = -1;
  }

  last_access_seq++;
  status->access_seq = last_access_seq;

  lock_release (&buffcache_new_access_seq_lock);
}

/* LOGOS-ADDED FUNCTION */
static unsigned
hash_hash_buffcache_entry (const struct hash_elem *element, void *aux UNUSED)
{
  struct buffcache_entry *bce = hash_entry (element, struct buffcache_entry, elem);
  int64_t temp[2];
  temp[0] = (int64_t)(bce->d);
  temp[1] = (int64_t)(bce->sec_no);
  return hash_bytes (temp, sizeof (temp));
}

/* LOGOS-ADDED FUNCTION */
static bool
hash_less_buffcache_entry (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct buffcache_entry *bcea = hash_entry (a, struct buffcache_entry, elem);
  struct buffcache_entry *bceb = hash_entry (b, struct buffcache_entry, elem);

  return bcea->d < bceb->d || (bcea->d == bceb->d && bcea->sec_no < bceb->sec_no);
}

/* LOGOS-ADDED FUNCTION */
static void
hash_release_action_buffcache_entry (struct hash_elem *element, void *aux UNUSED)
{
  struct buffcache_entry *bce = hash_entry (element, struct buffcache_entry, elem);
  if(bce->buffer)
    free (bce->buffer);
  free(bce);
}

/* LOGOS-ADDED FUNCTION
   Before using this function, acquire buffcache_global_lock first. */
static struct buffcache_entry *
buffcache_get_entry (struct disk *d, disk_sector_t sec_no)
{
  struct hash_elem *elem;
  struct buffcache_entry temp_bce;

  ASSERT (d != NULL);

  temp_bce.d = d;
  temp_bce.sec_no = sec_no;

  elem = hash_find (&buffcache, &temp_bce.elem);
  if(elem == NULL)
	  return NULL;

  return hash_entry (elem, struct buffcache_entry, elem);
}

/* LOGOS-ADDED FUNCTION
   Before using this function, acquire buffcache_global_lock, bce->io_lock, and bce->status.status_lock first. */
static void
buffcache_remove_entry (struct buffcache_entry *bce)
{
  ASSERT (bce != NULL);

  hash_delete (&buffcache, &bce->elem);
}

/* LOGOS-ADDED FUNCTION
   Before using this function, acquire buffcache_global_lock first. */
static struct buffcache_entry *
buffcache_get_new_entry_internal (struct disk *d, disk_sector_t sec_no, bool with_buffer)
{
  struct buffcache_entry *ret;

  ASSERT (d != NULL);

  ret = (struct buffcache_entry *)malloc (sizeof (struct buffcache_entry));
  if(ret == NULL)
	return NULL;
  
  ret->buffer = NULL;
  if (with_buffer)
    {
      ret->buffer = malloc (DISK_SECTOR_SIZE);
      if(ret->buffer == NULL)
        {
          free (ret);
          return NULL;
        }
    }

  lock_init (&ret->io_lock);

  ret->d = d;
  ret->sec_no = sec_no;

  lock_init (&ret->status.status_lock);
  ret->status.dirty = false;
  /* ret->status.dirty_write_time = timer_ticks (); */ /* It's not needed because ret->status.dirty is false. */
  buffcache_set_access_stat (&ret->status);

  hash_insert (&buffcache, &ret->elem);

  return ret;
}

/* LOGOS-ADDED FUNCTION
   Before using this function, acquire buffcache_global_lock first. */
static struct buffcache_entry *
buffcache_replacement_policy (struct disk *d, disk_sector_t sec_no)
{
  int64_t lr_access_time;
  int64_t lr_access_seq;
  struct hash_iterator iter;
  struct buffcache_entry *bce, *lre;

  ASSERT (!buffcache_deny);

  lr_access_time = timer_ticks () + 1;
  lr_access_seq = -1;
  lre = NULL;

  hash_first (&iter, &buffcache);
  while (hash_next (&iter))
    {
      bce = hash_entry (hash_cur (&iter), struct buffcache_entry, elem);

      if (bce->d != d || bce->sec_no != sec_no)
        {
          lock_acquire (&bce->status.status_lock);
          if (lr_access_seq == -1 || bce->status.access_time < lr_access_time || (bce->status.access_time == lr_access_time && bce->status.access_seq < lr_access_seq))
            {
              lr_access_time = bce->status.access_time;
              ASSERT (bce->status.access_seq != -1);
              lr_access_seq = bce->status.access_seq;
              lre = bce;
            }
          lock_release (&bce->status.status_lock);
        }
    }

  ASSERT (lre != NULL);
 
  return lre;
}

/* LOGOS-ADDED FUNCTION
   Before using this function, acquire buffcache_global_lock first. 
   This function can release and acquire buffcache_global_lock again internally. */
static struct buffcache_entry *
buffcache_get_new_entry (struct disk *d, disk_sector_t sec_no)
{ 
  struct buffcache_entry *ret = NULL;

  ASSERT (d != NULL);

  lock_acquire (&buffcache_new_entry_lock);

  ASSERT (hash_size (&buffcache) <= BUFFCACHE_LIMIT);
  ASSERT (!buffcache_deny);

  if (hash_size (&buffcache) == BUFFCACHE_LIMIT)
    {
      /* If the buffer cache is full, replace a buffer cache entry. */

      /* The count limit of execution of 'do ~ while(~);' is defined as follws. Because we first try to get a new entry with a little locking, it can result in something like thrashing. 
         If it reach the limit, we get a new entry with more locking to ensure that this thread doesn't starve. 
	     */
      #define WHILE_LIMIT 3

      int while_count = 0;

      do
        {
          struct buffcache_entry *new_bce;
          struct buffcache_entry *being_replaced;

          while_count++;

		  ASSERT (while_count <= WHILE_LIMIT);

		  /* Allocate a new buffer cache entry first. */
          new_bce = buffcache_get_new_entry_internal (d, sec_no, true);
          if (new_bce == NULL)
            {
              lock_release (&buffcache_new_entry_lock);
              return NULL;
            }

          /* Prevent other threads to use the new buffer cache entry that is not fully initialized. Acquire locks. */
          lock_acquire (&new_bce->io_lock);
          lock_acquire (&new_bce->status.status_lock);

		  /* Select a buffer cache entry to be replaced. */
          being_replaced = buffcache_replacement_policy (d, sec_no);
          ASSERT (being_replaced != NULL);
		  ASSERT (being_replaced->d != NULL && being_replaced->buffer != NULL);

		  /* Prevent other threads to use this buffer cache entry that is being replaced. Acquire locks. */
          lock_acquire (&being_replaced->io_lock);
          lock_acquire (&being_replaced->status.status_lock);

          /* Now, remove the buffer cache entry that is being replaced from buffcache. */
          buffcache_remove_entry (being_replaced);

		  /* Release buffcache_global_lock if necessary not to block other threads too long. 
             Although we release buffcache_global_lock, we've acquired buffcache_new_entry_lock, so no more thread can try to get a new buffer cache entry. */
          if (while_count != WHILE_LIMIT)
            lock_release (&buffcache_global_lock);

          /* Write being_replaced->buffer to the disk if necessary. */
          if (being_replaced->status.dirty)
            disk_write (being_replaced->d, being_replaced->sec_no, being_replaced->buffer);

          /* Release small locks and free memory. */
          lock_release (&being_replaced->status.status_lock);
          lock_release (&being_replaced->io_lock);

          hash_release_action_buffcache_entry (&being_replaced->elem, NULL);

          lock_release (&new_bce->io_lock);
          lock_release (&new_bce->status.status_lock);

          /* Acquire buffcache_global_lock again if necessary. 
		     Because of lock ordering, we release buffcache_new_entry_lock first, acquire buffcache_global_lock, and acquire buffcache_new_entry_lock again. */
          if (while_count != WHILE_LIMIT)
            {
              lock_release (&buffcache_new_entry_lock);

              lock_acquire (&buffcache_global_lock);
              lock_acquire (&buffcache_new_entry_lock);
            }

          /* Now, check the condition. */
          ret = buffcache_get_entry (d, sec_no);

		  ASSERT (while_count < WHILE_LIMIT || ret != NULL);

          /* If ret is NULL and the buffer cache is not full now, just allocate a new buffer cache entry. */
          if (ret == NULL && hash_size (&buffcache) < BUFFCACHE_LIMIT)
            {
              ret = buffcache_get_new_entry_internal (d, sec_no, true);
              if (ret == NULL)
              {
                lock_release (&buffcache_new_entry_lock);
                return NULL;
              }
            }

        }while (ret == NULL); 
        /* When we use a little locking and ret is NULL, the buffer cache entry has been removed between lock_release (&buffcache_new_entry_lock) and lock_acquire (&buffcache_global_lock) in if (while_count != WHILE_LIMIT) {...}.
		   It means that the system is too busy. It can be something like thrashing. Although this happens rarely, we must consider this situation. */
    }
  else
    {
      /* If the buffer cache is not full, just allocate a new buffer cache entry. */
      ret = buffcache_get_new_entry_internal (d, sec_no, true);
      if (ret == NULL)
        {
          lock_release (&buffcache_new_entry_lock);
		  return NULL;
        }
    }

  lock_release (&buffcache_new_entry_lock);

  return ret;
}

/* LOGOS-ADDED FUNCTION */
static bool
buffcache_read_internal (struct disk *d, disk_sector_t sec_no, void *buffer, struct disk *d_next, disk_sector_t sec_no_next)
{
  struct buffcache_entry *bce;
  bool is_new_bce;

  if (d != NULL)
    {
      lock_acquire (&buffcache_global_lock);

      if (buffcache_deny)
        {
          lock_release (&buffcache_global_lock);
    	  return false;
        }

      /* Get the buffer cache entry related to d and sec_no. */
      is_new_bce = false;
      bce = buffcache_get_entry (d, sec_no);
      if (bce == NULL)
        {
          is_new_bce = true;
          bce = buffcache_get_new_entry (d, sec_no);
          if (bce == NULL)
            {
              lock_release (&buffcache_global_lock);
    	      return false;
            }
        }

      /* Read I/O. */
      if (is_new_bce || buffer != NULL)
        {
          lock_acquire (&bce->io_lock);

          lock_acquire (&bce->status.status_lock);
          buffcache_set_access_stat (&bce->status);
          lock_release (&bce->status.status_lock);

          lock_release (&buffcache_global_lock);

          if (is_new_bce)
            disk_read (d, sec_no, bce->buffer);
		  else
            buffcache_total_hit_count++;

          if (buffer != NULL)
            memcpy (buffer, bce->buffer, DISK_SECTOR_SIZE);

          lock_acquire (&bce->status.status_lock);
          buffcache_set_access_stat (&bce->status);
          lock_release (&bce->status.status_lock);

          lock_release (&bce->io_lock);
        }
      else
        {
          /* Sync read ahead request for a cached block. Do nothing. */
          lock_release (&buffcache_global_lock);
        }
    }

  /* Read-ahead. */
  if (d_next != NULL)
    {
      struct bcra_work *bcraw;

	  bcraw = (struct bcra_work *)malloc (sizeof (struct bcra_work));
	  /* Read-ahead failed. Success anyway. */
	  if (bcraw == NULL)
        return true;

	  bcraw->d = d_next;
      bcraw->sec_no = sec_no_next;

      lock_acquire (&bcra_work_lock);
      list_push_back (&bcra_work_list, &bcraw->elem);
      lock_release (&bcra_work_lock);

      sema_up (&bcra_worker_sem);
    }

  return true;
}

/* LOGOS-ADDED FUNCTION */
bool
buffcache_read (struct disk *d, disk_sector_t sec_no, void *buffer, struct disk *d_next, disk_sector_t sec_no_next)
{
  return buffcache_read_internal (d, sec_no, buffer, d_next, sec_no_next);
}

/* LOGOS-ADDED FUNCTION */
bool
buffcache_write (struct disk *d, disk_sector_t sec_no, const void *buffer)
{
  struct buffcache_entry *bce;

  ASSERT (d != NULL && buffer != NULL);

  lock_acquire (&buffcache_global_lock);

  if (buffcache_deny)
    {
      lock_release (&buffcache_global_lock);
	  return false;
    }

  /* Get the buffer cache entry related to d and sec_no. */
  bce = buffcache_get_entry (d, sec_no);
  if (bce == NULL)
    {
      bce = buffcache_get_new_entry (d, sec_no);
      if (bce == NULL)
        {
          lock_release (&buffcache_global_lock);
	      return false;
        }
    }

  /* Dirty write I/O. */
  lock_acquire (&bce->io_lock);

  lock_acquire (&bce->status.status_lock);
  bce->status.dirty_write_time = timer_ticks ();
  bce->status.dirty = true;
  buffcache_set_access_stat (&bce->status);
  lock_release (&bce->status.status_lock);

  lock_release (&buffcache_global_lock);

  memcpy (bce->buffer, buffer, DISK_SECTOR_SIZE);
  buffcache_total_hit_count++;

  lock_acquire (&bce->status.status_lock);
  bce->status.dirty_write_time = timer_ticks ();
  ASSERT (bce->status.dirty);
  buffcache_set_access_stat (&bce->status);
  lock_release (&bce->status.status_lock);

  lock_release (&bce->io_lock);

  return true;
}

/* LOGOS-ADDED FUNCTION */
void
buffcache_write_all_dirty_blocks (bool for_power_off, bool all)
{
  int64_t now;
  bool stop;
  struct hash_iterator iter;
  struct buffcache_entry *bce;

  lock_acquire (&buffcache_global_lock);

  if (buffcache_deny)
    {
      lock_release (&buffcache_global_lock);
	  return;
    }

  buffcache_deny |= for_power_off;

  now = timer_ticks ();

  stop = false;
  while (!stop)
    {
      stop = true;

      bce = NULL;
      hash_first (&iter, &buffcache);
      while (hash_next (&iter))
        {
          bce = hash_entry (hash_cur (&iter), struct buffcache_entry, elem);

          lock_acquire (&bce->status.status_lock);
          if (bce->status.dirty && (bce->status.dirty_write_time < now || all || for_power_off))
            {
              lock_release (&bce->status.status_lock);
              stop=false;
              break;
            }
		  lock_release (&bce->status.status_lock);
        }

      if (stop)
        break;

      lock_acquire (&bce->io_lock);

      if (!for_power_off && !all)
        lock_release (&buffcache_global_lock);

      disk_write (bce->d, bce->sec_no, bce->buffer);

	  lock_acquire (&bce->status.status_lock);
      bce->status.dirty = false;
      /* bce->status.dirty_write_time = timer_ticks (); */ /* It's not needed because bce->status.dirty is false. */
      lock_release (&bce->status.status_lock);

      lock_release (&bce->io_lock);

      if (!for_power_off && !all)
        lock_acquire (&buffcache_global_lock);
    }

  lock_release (&buffcache_global_lock);
}

/* LOGOS-ADDED FUNCTION */
static int64_t
buffcache_get_total_hit_count (void)
{
  return buffcache_total_hit_count;
}

/* LOGOS-ADDED FUNCTION */
static void
buffcache_clear_total_hit_count (void)
{
  buffcache_total_hit_count = 0;
}

/* LOGOS-ADDED FUNCTION */
static void
buffcache_test_internal (int test_count, int sector_count, int id)
{
#define BUFFER_SIZE 256

  struct file * f;
  int i, j;
  char temp[DISK_SECTOR_SIZE] = {0};
  char buffer[BUFFER_SIZE];

  snprintf(buffer, BUFFER_SIZE, "logos_5-%d", id);

  f = filesys_open (buffer);
  for (i=0; i<test_count; i++)
    {
      for (j=0; j<sector_count; j++)
	    {
          file_seek (f, j * DISK_SECTOR_SIZE);
          file_read (f, temp, DISK_SECTOR_SIZE);
	    }
    }
  file_close (f);
}

/* LOGOS-ADDED FUNCTION */
void
buffcache_test_start (int pn, int stage, int64_t* context)
{
  const int test_count = 50;
  const int sector_count = 1;

  if (pn == 0)
    {
      switch (stage)
        {
        case 1:
          buffcache_write_all_dirty_blocks (false, true);

          printf ("test start without buffer cache\n");
          inode_set_write_through (true);

		  disk_clear_total_io_count ();
          buffcache_clear_total_hit_count ();

          break;
        case 2:
          printf ("Disk I/O : %d, No Hit\n", (int)disk_get_total_io_count ());
          printf ("test end\n");

          printf ("test start(%d times) with buffer cache\n", test_count);
          inode_set_write_through (false);

          disk_clear_total_io_count ();
          buffcache_clear_total_hit_count ();

          break;
        case 3:
          printf ("Disk I/O : %d, Cache Hit : %d\n", (int)disk_get_total_io_count (), (int)buffcache_get_total_hit_count ());
          printf ("test end\n");
          break;
        }
    }
  else
    {
      buffcache_test_internal (test_count, sector_count, pn);
    }
}

#endif //BUFFCACHE