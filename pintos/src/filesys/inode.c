#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#ifdef BUFFCACHE
#include "filesys/buffcache.h"
#endif

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* LOGOS-ADDED TYPE
   Inode Information. */
struct inode_info
  {
    disk_sector_t start;                /* First data sector. */
    off_t length;                       /* File size in bytes. */
  };

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    struct inode_info info;             /* Inode Information. */
    unsigned magic;                     /* Magic number. */
    uint32_t unused[125];               /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */

	/* LOGOS-ADDED VARIABLE */
    struct lock inode_lock;            /* Lock for this inode only. */

    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
#ifdef BUFFCACHE
    struct inode_info data;             /* Inode content. */
#else
    struct inode_disk data;             /* Inode content. */
#endif
  };

/* Returns the disk sector that contains byte offset POS within
   INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
#ifdef BUFFCACHE
  if (pos < inode->data.length)
    return inode->data.start + pos / DISK_SECTOR_SIZE;  
#else
  if (pos < inode->data.info.length)
    return inode->data.info.start + pos / DISK_SECTOR_SIZE;
#endif
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* LOGOS-ADDED VARIABLE
   Lock for shared data structures. */
static struct lock inode_global_lock;

#ifdef BUFFCACHE
/* LOGOS-ADDED VARIABLE */
static bool write_through;
#endif

/* Initializes the inode module. */
void
inode_init (void) 
{
  lock_init_as_recursive_lock (&inode_global_lock);

  list_init (&open_inodes);

#ifdef BUFFCACHE
  buffcache_init ();

  write_through = false;
#endif
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->info.length = length;
      disk_inode->magic = INODE_MAGIC;
      if (free_map_allocate (sectors, &disk_inode->info.start))
        {
#ifdef BUFFCACHE
          if (!write_through)
            buffcache_write (filesys_disk, sector, disk_inode);
		  else
#endif
            disk_write (filesys_disk, sector, disk_inode);

          if (sectors > 0) 
            {
              static char zeros[DISK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                {
#ifdef BUFFCACHE
                  if (!write_through)
                    buffcache_write (filesys_disk, disk_inode->info.start + i, zeros); 
				  else
#endif
                    disk_write (filesys_disk, disk_inode->info.start + i, zeros); 
                }
            }
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;
#ifdef BUFFCACHE
  struct inode_disk temp_inode_disk;
#endif

  lock_acquire (&inode_global_lock);

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
		  lock_release (&inode_global_lock);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    {
      lock_release (&inode_global_lock);
      return NULL;
    }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init_as_recursive_lock (&inode->inode_lock);
#ifdef BUFFCACHE
  if (write_through)
      disk_read (filesys_disk, inode->sector, &temp_inode_disk);
  else
    {
      buffcache_read (filesys_disk, inode->sector, &temp_inode_disk, NULL, 0);
      if (temp_inode_disk.info.length > 0)
        buffcache_read (NULL, 0, NULL, filesys_disk, temp_inode_disk.info.start);
    }
  memcpy (&inode->data, &temp_inode_disk.info, sizeof (inode->data));
#else
  disk_read (filesys_disk, inode->sector, &inode->data);
#endif

  lock_release (&inode_global_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
  {
    lock_acquire (&inode->inode_lock);
    inode->open_cnt++;
    lock_release (&inode->inode_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (struct inode *inode)
{
  disk_sector_t ret;

  ASSERT (inode!=NULL);

  lock_acquire (&inode->inode_lock);
  ret = inode->sector;
  lock_release (&inode->inode_lock);

  return ret;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire (&inode_global_lock);
  lock_acquire (&inode->inode_lock);

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
#ifdef BUFFCACHE
          free_map_release (inode->data.start,
                            bytes_to_sectors (inode->data.length)); 
#else
          free_map_release (inode->data.info.start,
                            bytes_to_sectors (inode->data.info.length)); 
#endif
        }

	  lock_release (&inode->inode_lock);

      free (inode); 
    }
  else
    lock_release (&inode->inode_lock);

  lock_release (&inode_global_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);

  lock_acquire (&inode->inode_lock);
  inode->removed = true;
  lock_release (&inode->inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  lock_acquire (&inode->inode_lock);

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Read full sector directly into caller's buffer. */
#ifdef BUFFCACHE
          if (!write_through)
            {
              if ((off_t)((sector_idx - inode->data.start + 1) * DISK_SECTOR_SIZE) < inode_length (inode))
                buffcache_read (filesys_disk, sector_idx, buffer + bytes_read, filesys_disk, sector_idx + 1);
              else
                buffcache_read (filesys_disk, sector_idx, buffer + bytes_read, NULL, 0);
            }
		  else
#endif
            disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
#ifdef BUFFCACHE
          if (!write_through)
            {
              if ((off_t)((sector_idx - inode->data.start + 1) * DISK_SECTOR_SIZE) < inode_length (inode))
                buffcache_read (filesys_disk, sector_idx, bounce, filesys_disk, sector_idx + 1);
              else
                buffcache_read (filesys_disk, sector_idx, bounce, NULL, 0);
            }
		  else
#endif
            disk_read (filesys_disk, sector_idx, bounce);

          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  lock_release (&inode->inode_lock);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  lock_acquire (&inode->inode_lock);

  if (inode->deny_write_cnt)
    {
      lock_release (&inode->inode_lock);
      return 0;
    }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % DISK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = DISK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) 
        {
          /* Write full sector directly to disk. */
#ifdef BUFFCACHE
          if (!write_through)
            buffcache_write (filesys_disk, sector_idx, buffer + bytes_written); 
          else
#endif
            disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (DISK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            {
#ifdef BUFFCACHE
              if (!write_through)
                {
                  if ((off_t)((sector_idx - inode->data.start + 1) * DISK_SECTOR_SIZE) < inode_length (inode))
                    buffcache_read (filesys_disk, sector_idx, bounce, filesys_disk, sector_idx + 1);
                  else
                    buffcache_read (filesys_disk, sector_idx, bounce, NULL, 0);
                }
              else
#endif
                disk_read (filesys_disk, sector_idx, bounce);
            }
          else
            memset (bounce, 0, DISK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
#ifdef BUFFCACHE
          if (!write_through)
            buffcache_write (filesys_disk, sector_idx, bounce); 
		  else
#endif
            disk_write (filesys_disk, sector_idx, bounce); 
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  lock_release (&inode->inode_lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  lock_acquire (&inode->inode_lock);

  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);

  lock_release (&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  lock_acquire (&inode->inode_lock);

  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;

  lock_release (&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (struct inode *inode)
{
  off_t ret;

  lock_acquire (&inode->inode_lock);
#ifdef BUFFCACHE
  ret = inode->data.length;
#else
  ret = inode->data.info.length;
#endif
  lock_release (&inode->inode_lock);

  return ret;
}

/* LOGOS-ADDED FUNCTION */
void
inode_lock (struct inode *inode)
{
  lock_acquire (&inode_global_lock);
  lock_acquire (&inode->inode_lock);
}

/* LOGOS-ADDED FUNCTION */
void
inode_unlock (struct inode *inode)
{
  lock_release (&inode->inode_lock);
  lock_release (&inode_global_lock);
}

#ifdef BUFFCACHE
/* LOGOS-ADDED FUNCTION */
void
inode_set_write_through (bool wt)
{
  write_through = wt;
}
#endif