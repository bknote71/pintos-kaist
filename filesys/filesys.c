#include "filesys/filesys.h"
#include "devices/disk.h"
#include "filesys/directory.h"
#include "filesys/fat.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>

#define EFILESYS

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format(void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void filesys_init(bool format)
{
    filesys_disk = disk_get(0, 1);
    if (filesys_disk == NULL)
        PANIC("hd0:1 (hdb) not present, file system initialization failed");

    inode_init();

#ifdef EFILESYS
    fat_init();

    if (format)
        do_format();

    fat_open();
#else
    /* Original FS */
    free_map_init();

    if (format)
        do_format();

    free_map_open();
#endif
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void filesys_done(void)
{
    /* Original FS */
#ifdef EFILESYS
    fat_close();
#else
    free_map_close();
#endif
}

static struct path *
parse_filename(const char *filename)
{
    int flength;
    if ((flength = strlen(filename)) == 0)
        return NULL;

    struct path *path = malloc(sizeof(struct path));
    path->dirs = calloc(sizeof(char *), 30);

    char tmp_name[20] = { 0 };
    strlcpy(tmp_name, filename, flength + 1);

    path->absolute = (filename[0] == '/');
    if (path->absolute)
        path->dirs[path->dcnt++] = "/";

    char *token, *save;
    token = strtok_r(tmp_name, "/", save);
    while (token != NULL)
    {
        path->dirs[path->dcnt++] = token;
        token = strtok_r(NULL, "/", save);
    }

    path->dcnt -= 1;
    path->filename = path->dirs[path->dcnt];

    return path;
}

static void
path_close(struct path *path)
{
    free(path->dirs);
    free(path);
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size)
{
    disk_sector_t inode_sector = 0;
    struct path *path = parse_filename(name);

    struct dir *dir = find_subdir(path->dirs, path->dcnt, path->absolute);

    bool success = false;
    struct inode *inode = NULL;
    if (dir_lookup(dir, path->filename, &inode))
        goto done;

#ifdef EFILESYS

    success = (dir != NULL &&
               inode_create_by_fat(&inode_sector, initial_size) &&
               dir_add_by_fat(dir, path->filename, inode_sector, initial_size));

#else

    success = (dir != NULL && free_map_allocate(1, &inode_sector) && inode_create(inode_sector, initial_size, false) && dir_add(dir, name, inode_sector));
    if (!success && inode_sector != 0)
        free_map_release(inode_sector, 1);

#endif

done:
    dir_close(dir);
    path_close(path);

    return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open(const char *name)
{
    struct dir *dir = dir_open_root();
    struct inode *inode = NULL;

    if (dir != NULL)
        dir_lookup(dir, name, &inode);
    dir_close(dir);

    return file_open(inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool filesys_remove(const char *name)
{
    struct dir *dir = dir_open_root();
    bool success = dir != NULL && dir_remove(dir, name);
    dir_close(dir);

    return success;
}

/* Formats the file system. */
static void
do_format(void)
{
    printf("Formatting file system...");

#ifdef EFILESYS
    /* Create FAT and save it to the disk. */
    fat_create();
    fat_close();
#else
    free_map_create();
    if (!dir_create(ROOT_DIR_SECTOR, 16))
        PANIC("root directory creation failed");
    free_map_close();
#endif

    printf("done.\n");
}
