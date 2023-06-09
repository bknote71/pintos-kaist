#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page
{
    struct file *file;
    off_t offset;
    off_t read_bytes;
    off_t zero_bytes;
};

struct mmap_file
{
    struct file *file;
    void *start;
    struct list_elem m_elem;
    struct list page_list;
};

void vm_file_init(void);
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
              struct file *file, off_t offset);
void do_munmap(void *va);

bool load_file(struct page *page, void *aux);
struct mmap_file *find_mmfile(void *addr);

#endif
