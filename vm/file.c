/* file.c: Implementation of memory backed file object (mmaped object). */

#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "vm/vm.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void)
{
}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;
    file_page->file = NULL;
    file_page->offset = 0;
    file_page->read_bytes = 0;
    file_page->zero_bytes = 0;
    return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in(struct page *page, void *kva)
{
    struct file_page *file_page = &page->file;
    size_t page_read_bytes = file_page->read_bytes;
    size_t page_zero_bytes = file_page->zero_bytes;

    if (file_read_at(file_page->file, kva, page_read_bytes, file_page->offset) != (int)page_read_bytes)
    {
        printf("read 실패\n");
        return false;
    }
    memset(kva + page_read_bytes, 0, page_zero_bytes);

    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out(struct page *page)
{
    struct file_page *file_page = &page->file;
    uint64_t *pml4 = thread_current()->pml4;

    if (pml4_is_dirty(pml4, page->va))
    {
        file_write_at(file_page->file, page->frame->kva, file_page->read_bytes, file_page->offset);
    }

    pml4_set_dirty(pml4, page->va, 0);
    pml4_clear_page(pml4, page->va);
    page->frame = NULL;

    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy(struct page *page)
{
    struct file_page *file_page = &page->file;
    struct frame *frame = page->frame;

    if (frame != NULL)
    {
        vm_free_frame(frame);
    }
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable,
        struct file *file, off_t offset)
{
    struct thread *curr = thread_current();
    struct file *refile = file_reopen(file);
    struct file_page *fp;
    struct page *mpage;

    struct mmap_file *mf = (struct mmap_file *)malloc(sizeof(struct mmap_file));

    if (refile == NULL || mf == NULL)
    {
        return NULL;
    }

    if (writable == 0)
        file_deny_write(refile);

    list_init(&mf->page_list);
    list_push_back(&curr->mmap_list, &mf->m_elem);

    mf->start = addr;

    while (length > 0)
    {
        size_t page_read_bytes = length < PGSIZE ? length : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        fp = (struct file_page *)malloc(sizeof(struct file_page));
        fp->file = refile;
        fp->offset = offset;
        fp->read_bytes = page_read_bytes;
        fp->zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr,
                                            writable, load_file, fp))
        {
            file_close(refile);
            return NULL;
        }

        mpage = spt_find_page(&curr->spt, addr);
        list_push_back(&mf->page_list, &mpage->p_elem);

        length -= page_read_bytes;
        offset += page_read_bytes;
        addr += PGSIZE;
    }

    return mf->start; // 시작 주소 리턴
}

/* Do the munmap */
void do_munmap(void *addr)
{
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct file *file = spt_find_page(spt, addr)->file.file;
    struct mmap_file *mf = find_mmfile(addr);
    struct list *pagelist = &mf->page_list;

    struct page *page;
    struct list_elem *p;
    while (!list_empty(pagelist))
    {
        page = list_entry(list_pop_front(pagelist), struct page, p_elem);
        if (pml4_is_dirty(thread_current()->pml4, page->va))
        {
            file_write_at(file, page->frame->kva, page->file.read_bytes, page->file.offset);
        }
        hash_delete(&spt->pages, &page->h_elem);
        spt_remove_page(spt, page);
    }

    // 스레드에 mf 를 위한 락을 하나 설정해주자 나중에
    file_close(file);
    list_remove(&mf->m_elem);
    free(mf);
}

bool load_file(struct page *page, void *aux)
{
    ASSERT(page->frame != NULL);
    ASSERT(aux != NULL);

    struct file_page *fp = (struct file_page *)aux;
    struct file *file = fp->file;
    off_t offset = fp->offset;
    size_t page_read_bytes = fp->read_bytes;
    size_t page_zero_bytes = fp->zero_bytes;

    free(aux);

    page->file = (struct file_page){
        .file = file,
        .offset = offset,
        .read_bytes = page_read_bytes,
        .zero_bytes = page_zero_bytes
    };

    void *kpage = page->frame->kva;

    if (file_read_at(file, kpage, page_read_bytes, offset) != (int)page_read_bytes)
    {
        vm_dealloc_page(page);
        return false;
    }

    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    return true;
}

struct mmap_file *find_mmfile(void *addr)
{
    struct thread *curr = thread_current();
    struct list *mlist = &curr->mmap_list;
    struct list_elem *p;
    for (p = list_begin(mlist); p != list_end(mlist); p = list_next(p))
    {
        struct mmap_file *mf = list_entry(p, struct mmap_file, m_elem);
        if (mf->start == addr)
            return mf;
    }
    return NULL;
}