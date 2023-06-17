/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"
#include "string.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include "vm/inspect.h"

#define USER_STACK_LIMIT (1 << 20)

static struct list lru_list;

static bool validate_fault(void *addr, bool user, bool not_present);
static uint64_t page_hash(const struct hash_elem *e, void *aux);
static bool page_less(const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux);
static void page_destructor(struct hash_elem *e, void *aux);

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
    lock_init(&lru_lock);
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
    // printf("type: %d, upage: %p\n", type, upage);

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL)
    {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */

        /* TODO: Insert the page into the spt. */
        struct page *page = (struct page *)malloc(sizeof(struct page));
        if (page == NULL)
            goto err;

        bool (*page_init)(struct page *, enum vm_type, void *) = (VM_TYPE(type) == VM_ANON ? anon_initializer : file_backed_initializer);
        uninit_new(page, upage, init, type, aux, page_init);
        page->rw = writable;
        if (!spt_insert_page(spt, page))
            goto err;
    }
    else
    {
        printf("upage is already existed\n");
        goto err;
    }

    return true;
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED)
{
    // printf("spt find page\n");
    struct hash_elem *hm;
    struct page *page;
    struct page tp;
    tp.va = va;

    /* TODO: Fill this function. */
    // lock_acquire(&spt->page_lock);
    hm = hash_find(&spt->pages, &tp.h_elem);
    page = hash_entry(hm, struct page, h_elem);
    // lock_release(&spt->page_lock);

    return hm != NULL ? page : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED)
{
    // printf("spt insert page %p, %d\n", page->va, page_get_type(page));
    struct hash_elem *hm = NULL;
    /* TODO: Fill this function. */
    // checks that the virtual address does not exist in the given spt
    if (spt_find_page(spt, page->va) != NULL)
    {
        return false;
    }

    // lock_acquire(&spt->page_lock);
    hm = hash_insert(&spt->pages, &page->h_elem);
    // lock_release(&spt->page_lock);

    return hm == NULL;
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
        lock_acquire(&lru_lock);

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

        lock_release(&lru_lock);
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
    victim->page = NULL;
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
    void *kva;
    /* TODO: Fill this function. */
    if ((kva = palloc_get_page(PAL_USER | PAL_ZERO)) == NULL)
    {
        frame = vm_evict_frame();
        frame->th = thread_current();
        return frame;
    }

    frame = (struct frame *)malloc(sizeof(struct frame));
    frame->kva = kva;
    frame->page = NULL;
    frame->th = thread_current();

    lock_acquire(&lru_lock);
    list_push_back(&lru_list, &frame->l_elem);
    lock_release(&lru_lock);

    ASSERT(frame != NULL);
    ASSERT(frame->kva != NULL);
    ASSERT(frame->page == NULL);

    return frame;
}

void vm_free_frame(struct frame *frame)
{
    ASSERT(frame != NULL);

    lock_acquire(&lru_lock);
    list_remove(&frame->l_elem);
    lock_release(&lru_lock);

    palloc_free_page(frame->kva);
    free(frame);
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
    // rsp 가 addr 보다 작아질 때까지
    struct thread *curr = thread_current();
    uintptr_t sp = curr->isp;
    uintptr_t va = addr;

    while (sp >= va)
    {
        sp -= PGSIZE;
        if (USER_STACK - sp > USER_STACK_LIMIT)
            if (vm_alloc_page(VM_ANON, sp, 1))
            {
                vm_claim_page(sp);
            }
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
    // printf("addr? %p\n", addr);
    // printf("page fault! %d %d %d\n", user, write, not_present);
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;
    enum vm_type vmtype;
    bool stack_growth = false;
    bool success = false;

    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (!validate_fault(addr, user, not_present))
        return false;

    // addr to page addr, abs??
    void *va = pg_round_down(addr);
    page = spt_find_page(spt, va);
    // printf("%p, %p, page find 성공? %d\n", addr, va, page != NULL);
    // if (page == NULL || page->rw < write)
    //     return false;

    if (page == NULL) // stack growth 가능성?
    {
        // allocated stack boundary
        uintptr_t sp = thread_current()->isp;
        uintptr_t asb = (uintptr_t)pg_round_down(sp);
        stack_growth = (asb > (uintptr_t)addr && sp - 8 <= (uintptr_t)addr);
    }
    else if (page->rw < write)
        return false;

    if (page != NULL)
    {
        vmtype = page_get_type(page);

        switch (vmtype)
        {
        case VM_ANON:
            success = vm_do_claim_page(page);
            break;
        case VM_FILE:
            success = vm_do_claim_page(page);
            break;

        default:
            break;
        }
    }
    else if (stack_growth)
        vm_stack_growth(addr);
    else
        success = false;

    return success;
}

static bool validate_fault(void *addr, bool user, bool not_present)
{
    if (!not_present)
        return false;

    if (is_kernel_vaddr(addr))
    {
        // 커널에서 페이지 폴트? 그냥 palloc ??
        if (user)
            return false;
    }
    return true;
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
    struct page *page;

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
    bool success;

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    // success = pml4_set_page(curr->pml4, page->va, frame->kva, page->rw);
    if (!setup_page_table(page->va, frame->kva, page->rw))
    {
        // frame 해제 ?
        printf("fail setup (%p to %p) page table\n", page->va, frame->kva);
        return false;
    }

    return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
    hash_init(&spt->pages, page_hash, page_less, NULL);
    lock_init(&spt->page_lock);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED)
{
    struct hash_iterator iter;
    struct page *new_page;
    struct page *entry;
    enum vm_type type;

    // lock_acquire(&src->page_lock);

    hash_first(&iter, &src->pages);
    while (hash_next(&iter))
    {
        entry = hash_entry(hash_cur(&iter), struct page, h_elem);
        type = entry->operations->type;
        // printf("copy type: %d, va: %p\n", type, entry->va);

        if (type == VM_UNINIT)
        {
            // copy 를 해야할까요?
            vm_initializer *init = entry->uninit.init;
            void *aux = entry->uninit.aux;
            if (init != NULL)
            {
                aux = (struct file_page *)malloc(sizeof(struct file_page));
                memcpy(aux, entry->uninit.aux, sizeof(struct file_page));
            }

            vm_alloc_page_with_initializer(page_get_type(entry), entry->va, entry->rw, init, aux);
        }
        else if (type == VM_ANON)
        {
            if (!vm_alloc_page(type, entry->va, entry->rw))
            {
                printf("ANON 페이지 카피 실패\n");
                return false;
            }
            if (!vm_claim_page(entry->va))
                return false;
            void *dest = spt_find_page(dst, entry->va)->frame->kva;
            memcpy(dest, entry->frame->kva, PGSIZE);
        }
    }
    // lock_release(&src->page_lock);
    return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->pages, page_destructor);
}

bool setup_page_table(void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current();
    return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
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

static void page_destructor(struct hash_elem *e, void *aux)
{
    struct page *entry;
    entry = hash_entry(e, struct page, h_elem);
    vm_dealloc_page(entry);
}
