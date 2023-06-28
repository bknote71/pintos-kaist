#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot
{
    unsigned int magic;
    unsigned int sectors_per_cluster; /* Fixed to 1 */
    unsigned int total_sectors;
    unsigned int fat_start;
    unsigned int fat_sectors; /* Size of FAT in sectors. */
    unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs
{
    struct fat_boot bs;
    unsigned int *fat;
    unsigned int fat_length;
    disk_sector_t data_start;
    cluster_t last_clst;
    struct lock write_lock;
};

static struct fat_fs *fat_fs;

void fat_boot_create(void);
void fat_fs_init(void);

void fat_init(void)
{
    fat_fs = calloc(1, sizeof(struct fat_fs));
    if (fat_fs == NULL)
        PANIC("FAT init failed");

    // Read boot sector from the disk
    unsigned int *bounce = malloc(DISK_SECTOR_SIZE);
    if (bounce == NULL)
        PANIC("FAT init failed");
    disk_read(filesys_disk, FAT_BOOT_SECTOR, bounce);
    memcpy(&fat_fs->bs, bounce, sizeof(fat_fs->bs));
    free(bounce);

    // Extract FAT info
    if (fat_fs->bs.magic != FAT_MAGIC)
        fat_boot_create();
    fat_fs_init();
}

void fat_open(void)
{
    fat_fs->fat = calloc(fat_fs->fat_length, sizeof(cluster_t));
    if (fat_fs->fat == NULL)
        PANIC("FAT load failed");

    // Load FAT directly from the disk
    uint8_t *buffer = (uint8_t *)fat_fs->fat;
    off_t bytes_read = 0;
    off_t bytes_left = sizeof(fat_fs->fat);
    const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof(cluster_t);
    for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++)
    {
        bytes_left = fat_size_in_bytes - bytes_read;
        if (bytes_left >= DISK_SECTOR_SIZE)
        {
            disk_read(filesys_disk, fat_fs->bs.fat_start + i,
                      buffer + bytes_read);
            bytes_read += DISK_SECTOR_SIZE;
        }
        else
        {
            uint8_t *bounce = malloc(DISK_SECTOR_SIZE);
            if (bounce == NULL)
                PANIC("FAT load failed");
            disk_read(filesys_disk, fat_fs->bs.fat_start + i, bounce);
            memcpy(buffer + bytes_read, bounce, bytes_left);
            bytes_read += bytes_left;
            free(bounce);
        }
    }
}

void fat_close(void)
{
    // Write FAT boot sector
    uint8_t *bounce = calloc(1, DISK_SECTOR_SIZE);
    if (bounce == NULL)
        PANIC("FAT close failed");
    memcpy(bounce, &fat_fs->bs, sizeof(fat_fs->bs));
    disk_write(filesys_disk, FAT_BOOT_SECTOR, bounce);
    free(bounce);

    // Write FAT directly to the disk
    uint8_t *buffer = (uint8_t *)fat_fs->fat;
    off_t bytes_wrote = 0;
    off_t bytes_left = sizeof(fat_fs->fat);
    const off_t fat_size_in_bytes = fat_fs->fat_length * sizeof(cluster_t);
    for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++)
    {
        bytes_left = fat_size_in_bytes - bytes_wrote;
        if (bytes_left >= DISK_SECTOR_SIZE)
        {
            disk_write(filesys_disk, fat_fs->bs.fat_start + i,
                       buffer + bytes_wrote);
            bytes_wrote += DISK_SECTOR_SIZE;
        }
        else
        {
            bounce = calloc(1, DISK_SECTOR_SIZE);
            if (bounce == NULL)
                PANIC("FAT close failed");
            memcpy(bounce, buffer + bytes_wrote, bytes_left);
            disk_write(filesys_disk, fat_fs->bs.fat_start + i, bounce);
            bytes_wrote += bytes_left;
            free(bounce);
        }
    }
}

void fat_create(void)
{
    // Create FAT boot
    fat_boot_create();
    fat_fs_init();

    // Create FAT table
    fat_fs->fat = calloc(fat_fs->fat_length, sizeof(cluster_t));
    if (fat_fs->fat == NULL)
        PANIC("FAT creation failed");

    // Set up ROOT_DIR_CLST
    fat_put(ROOT_DIR_CLUSTER, EOChain);

    // Fill up ROOT_DIR_CLUSTER region with 0
    uint8_t *buf = calloc(1, DISK_SECTOR_SIZE);
    if (buf == NULL)
        PANIC("FAT create failed due to OOM");
    disk_write(filesys_disk, cluster_to_sector(ROOT_DIR_CLUSTER), buf);
    free(buf);
}

void fat_boot_create(void)
{
    unsigned int fat_sectors =
        (disk_size(filesys_disk) - 1) / (DISK_SECTOR_SIZE / sizeof(cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
    fat_fs->bs = (struct fat_boot){
        .magic = FAT_MAGIC,
        .sectors_per_cluster = SECTORS_PER_CLUSTER,
        .total_sectors = disk_size(filesys_disk),
        .fat_start = 1, // FAT 볼륨 시작 위치(0) + boot sector (1) == 1
        .fat_sectors = fat_sectors,
        .root_dir_cluster = ROOT_DIR_CLUSTER,
    };
}

void fat_fs_init(void)
{
    /* TODO: Your code goes here. */
    struct fat_boot fb = fat_fs->bs;
    fat_fs->fat_length = fb.total_sectors / fb.sectors_per_cluster; // how many clusters in fs
    fat_fs->data_start = fb.fat_start + fb.fat_sectors;             // fat 시작 위치(fat_start) + fat 섹터 개수
    fat_fs->last_clst = 1;
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
cluster_t
fat_create_chain(cluster_t clst)
{
    /* TODO: Your code goes here. */

    // 1. Find Free Cluster
    int newclst = -1;
    for (int idx = 2; idx < fat_fs->fat_length; ++idx)
    {
        if (fat_fs->fat[idx] == 0)
            newclst = idx;
    }

    if (newclst == -1)
    {
        PANIC("빈 클러스터를 찾지 못함");
    }

    // 2. EoC 갱신
    fat_fs->fat[newclst] = -1;

    if (clst != 0)
    {
        ASSERT(fat_fs->fat[clst] == -1);
        fat_fs->fat[clst] = newclst;
    }
    return newclst;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
void fat_remove_chain(cluster_t clst, cluster_t pclst)
{
    /* TODO: Your code goes here. */
    int p = clst, ncluster;
    while (p != EOChain)
    {
        ncluster = fat_fs->fat[p];
        fat_fs->fat[p] = 0; // free 로 변환
        p = ncluster;
    }

    if (pclst != 0)
        fat_fs->fat[pclst] = EOChain;
}

/* Update a value in the FAT table. */
void fat_put(cluster_t clst, cluster_t val)
{
    /* TODO: Your code goes here. */
    fat_fs->fat[clst] = val;
}

/* Fetch a value in the FAT table. */
cluster_t
fat_get(cluster_t clst)
{
    /* TODO: Your code goes here. */
    return fat_fs->fat[clst];
}

/* Covert a cluster # to a sector number. */
disk_sector_t
cluster_to_sector(cluster_t clst)
{
    /* TODO: Your code goes here. */
    disk_sector_t ret = fat_fs->data_start;
    for (int i = 0; i < clst - ROOT_DIR_CLUSTER; ++i)
    {
        ret += fat_fs->bs.sectors_per_cluster;
    }
    return ret;
}

cluster_t
find_cluster_after_clusters(cluster_t sclst, int clusters)
{
    cluster_t p = sclst;
    for (int i = 0; i < clusters - 1; ++i)
    {
        p = fat_fs->fat[p];
    }
    return p;
}

int *allocate_length_array()
{
    int *ret = calloc(fat_fs->fat_length, sizeof(int));
    return ret;
}