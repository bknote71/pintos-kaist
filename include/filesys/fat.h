#ifndef FILESYS_FAT_H
#define FILESYS_FAT_H

#include "devices/disk.h"
#include "filesys/file.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FAT_MAGIC 0xEB3C9000 /* MAGIC string to identify FAT disk */
#define EOChain 0x0FFFFFFF   /* End of cluster chain */

typedef uint32_t cluster_t;

/* Sectors of FAT information. */
#define SECTORS_PER_CLUSTER 1 /* Number of sectors per cluster */
#define FAT_BOOT_SECTOR 0     /* FAT boot sector. */
#define ROOT_DIR_CLUSTER 1    /* Cluster for the root directory */

void fat_init(void);
void fat_open(void);
void fat_close(void);
void fat_create(void);
void fat_close(void);

cluster_t fat_create_chain(
    cluster_t clst /* Cluster # to stretch, 0: Create a new chain */
);
void fat_remove_chain(
    cluster_t clst, /* Cluster # to be removed */
    cluster_t pclst /* Previous cluster of clst, 0: clst is the start of chain */
);
cluster_t fat_get(cluster_t clst);
void fat_put(cluster_t clst, cluster_t val);
disk_sector_t cluster_to_sector(cluster_t clst);
cluster_t
find_cluster_after_clusters(cluster_t sclst, int clusters);
int *allocate_length_array();
#endif /* filesys/fat.h */
