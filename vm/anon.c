/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "devices/disk.h"
#include "lib/kernel/bitmap.h"
#include "lib/string.h"
#include "threads/mmu.h"
#include "vm/vm.h"

#define SLOT 8

struct bitmap *swap_bitmap;
size_t swap_slots;
disk_sector_t sectors;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void)
{
    /* TODO: Set up the swap_disk. */
    // 페이지 사이즈: 4KB, 섹터 사이즈: 512 B: 8 개의 섹터 = 1 Swap slot
    // 따라서 스왑 디스크의 섹터 개수 / 8 = Swap slot 개수
    swap_disk = disk_get(1, 1);
    sectors = disk_size(swap_disk);
    swap_bitmap = bitmap_create(sectors);
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    anon_page->offset = 0;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in(struct page *page, void *kva)
{
    ASSERT(page != NULL);

    struct anon_page *anon_page = &page->anon;
    for (int i = 0; i < SLOT; ++i)
    {
        disk_read(swap_disk, anon_page->offset + i, kva + (i * DISK_SECTOR_SIZE));
        bitmap_flip(swap_bitmap, anon_page->offset + i);
    }
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out(struct page *page)
{
    ASSERT(page != NULL);

    struct anon_page *anon_page = &page->anon;
    uint64_t *pml4 = page->frame->th->pml4;
    void *buff;
    size_t offset;

    buff = page->frame->kva;
    page->frame = NULL;
    pml4_clear_page(pml4, page->va);

    offset = bitmap_scan_and_flip(swap_bitmap, 0, SLOT, 0);
    if (offset == BITMAP_ERROR)
    {
        return false;
    }
    anon_page->offset = offset;
    // 512 바이트 단위로 끊어서 작성? 8 번
    for (int i = 0; i < SLOT; ++i)
    {
        disk_write(swap_disk, offset + i, buff + (i * DISK_SECTOR_SIZE));
    }

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy(struct page *page)
{
    struct anon_page *anon_page = &page->anon;
    struct frame *frame = page->frame;
    size_t offset;
    if (frame != NULL)
    {
        uint64_t *pml4 = frame->th->pml4;
        pml4_clear_page(pml4, page->va);
        palloc_free_page(frame);
    }
    else if ((offset = bitmap_scan(swap_bitmap, anon_page->offset, SLOT, 1)) == anon_page->offset) // in swap space
    {
        bitmap_set_multiple(swap_bitmap, offset, 8, 0);
    }
}
