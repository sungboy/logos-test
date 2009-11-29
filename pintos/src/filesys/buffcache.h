#ifndef FILESYS_BUFFCACHE_H
#define FILESYS_BUFFCACHE_H

#ifdef BUFFCACHE
#include <stdbool.h>
#include "devices/disk.h"

void buffcache_init (void);
bool buffcache_read (struct disk *, disk_sector_t, void *);
bool buffcache_write (struct disk *, disk_sector_t, const void *);
void buffcache_write_all_dirty_blocks (bool);
#endif //BUFFCACHE

#endif /* filesys/buffcache.h */
