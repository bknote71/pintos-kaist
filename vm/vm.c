/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/inspect.h"

struct list lru_list;

static uint64_t page_hash(const struct hash_elem *e, void *aux);
static bool page_less(const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void)
{
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
    list_init(&lru_list);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type(struct page *page)
{
    int ty = VM_TYPE(page->operations->type);
    switch (ty)
    {
    case VM_UNINIT:
        return VM_TYPE(page->uninit.type);
    default:
        return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux)
{

    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL)
    {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */

        /* TODO: Insert the page into the spt. */
        struct page *page = (struct page *)malloc(sizeof(struct page));
        bool (*page_init)(struct page *, enum vm_type, void *) = type == VM_ANON ? anon_initializer : file_backed_initializer;
        uninit_new(page, upage, init, type, aux, page_init);
        page->rw = writable;
        spt_insert_page(spt, page);
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
    struct hash_elem *hm;
    struct page *page;
    struct page tp;
    tp.va = va;
    /* TODO: Fill this function. */
    lock_acquire(&spt->page_lock);
    hm = hash_find(&spt->pages, &tp.h_elem);
    page = hash_entry(hm, struct page, h_elem);
    lock_release(&spt->page_lock);
    return hm != NULL ? page : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED)
{
    /* TODO: Fill this function. */
    if (spt_find_page(spt, page->va) != NULL)
    {
        return false;
    }
    lock_acquire(&spt->page_lock);
    struct hash_elem *hm = hash_insert(&spt->pages, &page->h_elem);
    lock_release(&spt->page_lock);
    return hm != NULL;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim(void)
{
    struct frame *victim = NULL;
    struct frame *frame = NULL;
    /* TODO: The policy for eviction is up to you. */
    while (victim == NULL)
    {
        struct list_elem *p;
        for (p = list_begin(&lru_list); p != list_end(&lru_list); p = list_next(p))
        {
            frame = list_entry(p, struct frame, l_elem);
            uint64_t *pml4 = frame->th->pml4;
            void *va = frame->page->va;
            // find pte
            if (pml4_is_accessed(pml4, va))
                pml4_set_accessed(pml4, va, 0);
            else if (pml4_is_dirty(pml4, va))
                ;
            else
            {
                victim = frame;
                list_remove(p);
                break;
            }
        }
    }
    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame(void)
{
    struct frame *victim = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */
    swap_out(victim->page);
    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame(void)
{
    struct frame *frame = NULL;
    struct frame *victim = NULL;
    /* TODO: Fill this function. */
    if (frame = palloc_get_page(PAL_USER) == NULL)
        frame = vm_evict_frame();

    if (frame == NULL)
        ; // exit(-1) ?

    list_push_back(&lru_list, &frame->l_elem);

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
    // rsp 가 addr 보다 작아질 때까지
    void *sp = NULL;
    while (sp >= addr)
    {
        sp -= PGSIZE;
        vm_alloc_page(VM_ANON, sp, 1);
    }
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp(struct page *page UNUSED)
{
}

// Page Fault Handler
/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;
    enum vm_type vmtype;
    void *sp = NULL;
    bool success = false;
    bool stack_growth = (addr < sp && addr >= sp - 8);
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (is_kernel_vaddr(addr))
    {
        // 커널에서 페이지 폴트? 그냥 palloc ??
        if (user)
            return false;
    }

    page = spt_find_page(spt, addr);

    if (page == NULL)
        return false;

    if (page->rw < write)
        return false;

    vmtype = page_get_type(page);

    if (vmtype == VM_ANON)
        success = vm_do_claim_page(page);
    else if (vmtype == VM_FILE)
        ;
    else if (stack_growth)
        vm_stack_growth(addr);
    else
        success = false;

    return success;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page)
{
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED)
{
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Fill this function */
    page = spt_find_page(spt, va);
    if (page == NULL)
        return false;

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page(struct page *page)
{
    ASSERT(page != NULL);

    struct thread *curr = thread_current();
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    pml4_set_page(curr->pml4, page->va, frame->kva, page->rw);

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
    hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED)
{
    lock_acquire(&dst->page_lock);
    struct hash_iterator iter;
    hash_first(&iter, &dst->pages);
    while (hash_next(&iter))
    {
        struct page *page = hash_entry(hash_cur(&iter), struct page, h_elem);
        struct page *new_page = vm_alloc_page(page_get_type(page), page->va, page->rw);
        spt_insert_page(src, new_page);
        vm_do_claim_page(new_page);
    }
    lock_release(&dst->page_lock);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    lock_acquire(&spt->page_lock);
    struct hash_iterator iter;
    hash_first(&iter, &spt->pages);
    while (hash_next(&iter))
    {
        destroy(hash_entry(hash_cur(&iter), struct page, h_elem));
    }
    lock_release(&spt->page_lock);
}

static uint64_t page_hash(const struct hash_elem *e, void *aux)
{
    struct page *page = hash_entry(e, struct page, h_elem);
    struct supplemental_page_table *spt = &thread_current()->spt;
    return hash_bytes(&page->va, sizeof page->va);
}
static bool page_less(const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux)
{
    struct page *p1 = hash_entry(a, struct page, h_elem);
    struct page *p2 = hash_entry(b, struct page, h_elem);
    return p1->va < p2->va;
}
