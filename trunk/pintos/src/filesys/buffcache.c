#include "filesys/buffcache.h"
#include <debug.h>
#include <string.h>
#include <kernel/hash.h>
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/synch.h"

#ifdef BUFFCACHE

/* LOGOS-ADDED TYPE */
struct buffcache_entry_status
  {
    struct lock status_lock;              /* Lock for this struct. */
    int64_t access_time;                  /* Access time expressed by timer ticks. Before using this variable, acquire status_lock first. */
	int64_t access_seq;                   /* The sequence of access among entries with the same access time. Before using this variable, acquire status_lock first. */
	int64_t dirty_write_time;             /* Dirty write time expressed by timer ticks. Before using this variable, acquire status_lock first. */
    bool dirty;                           /* Dirty bit. Before using this variable, acquire status_lock first. */
  };

/* LOGOS-ADDED TYPE */
struct buffcache_entry
  {
    struct hash_elem elem;                 /* Hash table element. */
    struct disk *d;                        /* Disk. A portion of the key. Cannot be changed. */
    disk_sector_t sec_no;                  /* Data sector. A portion of the key. Cannot be changed. */
    struct buffcache_entry_status status;  /* Status. */
    struct lock io_lock;                   /* Lock for I/Os. */
    void* buffer;                          /* Data. Before using this variable, acquire io_lock first. */
  };

/* LOGOS-ADDED VALUE */
#define BUFFCACHE_LIMIT 64                 /* The limit of entry count. Must be 2^k. */

/* LOGOS-ADDED VARIABLE BEGIN */
static struct hash buffcache;              /* Buffer Cache. Before using this variable, acquire buffcache_global_lock first. */

struct lock buffcache_global_lock;         /* Lock for buffer cache data structures. */
struct lock buffcache_new_entry_lock;      /* Lock used when new buffer cache entry is being created. */
struct lock buffcache_new_access_seq_lock; /* Lock for a new access sequence number. */

int64_t last_access_time;                  /* The last access time expressed by timer ticks. Before using this variable, acquire buffcache_global_lock first. */
int64_t last_access_seq;                   /* The last sequencial number of access among entries with the same access time. Before using this variable, acquire buffcache_global_lock first. */

bool buffcache_deny;                       /* Buffer cache operation deny. Before using this variable, acquire buffcache_global_lock first. */
/* LOGOS-ADDED VARIABLE END */

static void buffcache_set_access_stat (struct buffcache_entry_status *status);
static unsigned hash_hash_buffcache_entry (const struct hash_elem *element, void *aux);
static bool hash_less_buffcache_entry (const struct hash_elem *a, const struct hash_elem *b, void *aux);
static void hash_release_action_buffcache_entry (struct hash_elem *element, void *aux);
static struct buffcache_entry *buffcache_get_entry (struct disk *d, disk_sector_t sec_no);
static void buffcache_remove_entry (struct buffcache_entry *bce);
static struct buffcache_entry *buffcache_get_new_entry_internal (struct disk *d, disk_sector_t sec_no, bool with_buffer);
static struct buffcache_entry *buffcache_get_new_entry (struct disk *d, disk_sector_t sec_no);

/* LOGOS-ADDED FUNCTION */
void
buffcache_init (void)
{
  bool b;
  
  b = hash_init_with_init_size (&buffcache, hash_hash_buffcache_entry, hash_less_buffcache_entry, NULL, BUFFCACHE_LIMIT * 2);
  ASSERT (b);

  lock_init (&buffcache_global_lock);
  lock_init (&buffcache_new_entry_lock);
  lock_init (&buffcache_new_access_seq_lock);

  last_access_time = timer_ticks ();
  last_access_seq = -1;

  buffcache_deny = false;
}

/* LOGOS-ADDED FUNCTION */
static void
buffcache_set_access_stat (struct buffcache_entry_status *status)
{
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

/* LOGOS-ADDED FUNCTION */
static struct buffcache_entry *
buffcache_get_entry (struct disk *d, disk_sector_t sec_no)
{
  struct hash_elem *elem;
  struct buffcache_entry temp_bce;

  temp_bce.d = d;
  temp_bce.sec_no = sec_no;

  elem = hash_find (&buffcache, &temp_bce.elem);
  if(elem == NULL)
	  return NULL;

  return hash_entry (elem, struct buffcache_entry, elem);
}

/* LOGOS-ADDED FUNCTION */
static void
buffcache_remove_entry (struct buffcache_entry *bce)
{
  lock_acquire (&bce->io_lock);
  lock_acquire (&bce->status.status_lock);

  hash_delete (&buffcache, &bce->elem);
  
  lock_release (&bce->status.status_lock);
  lock_release (&bce->io_lock);
}

/* LOGOS-ADDED FUNCTION */
static struct buffcache_entry *
buffcache_get_new_entry_internal (struct disk *d, disk_sector_t sec_no, bool with_buffer)
{
  struct buffcache_entry *ret;

  ASSERT (hash_size (&buffcache) < BUFFCACHE_LIMIT);

  ret = (struct buffcache_entry *)malloc (sizeof (struct buffcache_entry));
  if(ret == NULL)
	return NULL;

  if (with_buffer)
    {
      ret->buffer = malloc (DISK_SECTOR_SIZE);
      if(ret->buffer == NULL)
        {
          free (ret);
          return NULL;
        }
    }

  ret->buffer = NULL;

  lock_init (&ret->io_lock);

  ret->d = d;
  ret->sec_no = sec_no;

  lock_init (&ret->status.status_lock);
  ret->status.dirty = false;
  /*dirty_write_time = timer_ticks (); */ /* It's not needed because ret->status.dirty is false. */
  buffcache_set_access_stat (&ret->status);

  hash_insert (&buffcache, &ret->elem);

  return ret;
}

/* LOGOS-ADDED FUNCTION */
static struct buffcache_entry *
buffcache_replacement_policy (struct disk *d UNUSED, disk_sector_t sec_no UNUSED)
{
  /* TODO : Implement here correctly. */
  return NULL;
}

/* LOGOS-ADDED FUNCTION */
static struct buffcache_entry *
buffcache_get_new_entry (struct disk *d, disk_sector_t sec_no)
{ 
  struct buffcache_entry *ret = NULL;

  lock_acquire (&buffcache_new_entry_lock);

  ASSERT (hash_size (&buffcache) <= BUFFCACHE_LIMIT);

  if (hash_size (&buffcache) == BUFFCACHE_LIMIT)
    {
      /* The count limit of execution of 'do ~ while(~);'. Because we first try to get a new entry with a little locking, it can result in something like thrashing. 
         If it reach the limit, we get a new entry with more locking to ensure this thread doesn't starve. 
	     */
      #define WHILE_LIMIT 3
      int while_count = 0;

      do
        {
          struct buffcache_entry *new_bce;
          struct buffcache_entry *being_replaced;

          while_count++;

		  ASSERT (while_count <= WHILE_LIMIT);

          new_bce = buffcache_get_new_entry_internal (d, sec_no, true);

          lock_acquire (&new_bce->io_lock);
          lock_acquire (&new_bce->status.status_lock);

          being_replaced = buffcache_replacement_policy (d, sec_no);
          ASSERT (being_replaced != NULL);

          lock_acquire (&being_replaced->io_lock);
          lock_acquire (&being_replaced->status.status_lock);

          buffcache_remove_entry (being_replaced);

          if (while_count != WHILE_LIMIT)
            lock_release (&buffcache_global_lock);

          /*To Disk. */
          if (being_replaced->status.dirty)
            disk_write (being_replaced->d, being_replaced->sec_no, being_replaced->buffer);

          lock_release (&being_replaced->status.status_lock);
          lock_release (&being_replaced->io_lock);

          hash_release_action_buffcache_entry (&being_replaced->elem, NULL);

          lock_release (&new_bce->io_lock);
          lock_release (&new_bce->status.status_lock);

          lock_release (&buffcache_new_entry_lock);

          if (while_count != WHILE_LIMIT)
            lock_acquire (&buffcache_global_lock);

          ret = buffcache_get_entry (d, sec_no);

		  ASSERT (while_count < WHILE_LIMIT || ret != NULL);
        }while (ret == NULL); 
        /* When ret is NULL, the buffer cache entry has been released between lock_release (&buffcache_new_entry_lock) and lock_acquire (&buffcache_global_lock).
		   It means that the system is too busy. It can be something like thrashing. Although this happens rarely, we must consider this situation. */
    }
  else
    {
      ret = buffcache_get_new_entry_internal (d, sec_no, true);

      lock_release (&buffcache_new_entry_lock);
    }

  return ret;
}

/* LOGOS-ADDED FUNCTION */
bool
buffcache_read (struct disk *d, disk_sector_t sec_no, void *buffer)
{
  struct buffcache_entry *bce;
  bool is_new_bce;

  lock_acquire (&buffcache_global_lock);

  if (buffcache_deny)
    {
      lock_release (&buffcache_global_lock);
	  return false;
    }

  is_new_bce = false;
  bce = buffcache_get_entry (d, sec_no);
  if (bce == NULL)
    {
      is_new_bce = true;
      bce = buffcache_get_new_entry (d, sec_no);
    }

  lock_acquire (&bce->io_lock);

  lock_acquire (&bce->status.status_lock);
  buffcache_set_access_stat (&bce->status);
  lock_release (&bce->status.status_lock);

  lock_release (&buffcache_global_lock);

  if (is_new_bce)
    disk_read (d, sec_no, bce->buffer);

  memcpy (buffer, bce->buffer, DISK_SECTOR_SIZE);

  lock_acquire (&bce->status.status_lock);
  buffcache_set_access_stat (&bce->status);
  lock_release (&bce->status.status_lock);

  lock_release (&bce->io_lock);

  return true;
}

/* LOGOS-ADDED FUNCTION */
bool
buffcache_write (struct disk *d, disk_sector_t sec_no, const void *buffer)
{
  struct buffcache_entry *bce;

  lock_acquire (&buffcache_global_lock);

  if (buffcache_deny)
    {
      lock_release (&buffcache_global_lock);
	  return false;
    }

  bce = buffcache_get_entry (d, sec_no);
  if (bce == NULL)
      bce = buffcache_get_new_entry (d, sec_no);

  lock_acquire (&bce->io_lock);

  lock_acquire (&bce->status.status_lock);
  buffcache_set_access_stat (&bce->status);
  bce->status.dirty = true;
  lock_release (&bce->status.status_lock);

  lock_release (&buffcache_global_lock);

  memcpy (bce->buffer, buffer, DISK_SECTOR_SIZE);

  lock_acquire (&bce->status.status_lock);
  buffcache_set_access_stat (&bce->status);
  ASSERT (bce->status.dirty);
  lock_release (&bce->status.status_lock);

  lock_release (&bce->io_lock);

  return true;
}

/* LOGOS-ADDED FUNCTION */
void
buffcache_write_all_dirty_blocks (bool for_power_off)
{
  /* ... */
}

#endif //BUFFCACHE