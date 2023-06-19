#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "userprog/process.h"

#include "devices/input.h"
#include "lib/kernel/console.h"

#include "string.h"
#include "threads/palloc.h"

// #ifdef VM
#include "vm/file.h"
#include "vm/vm.h"
// #endif

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* syscall handler function */

static int fork(char *, struct intr_frame *);
static void exec(const char *cmd_line);
static int wait(tid_t tid);

static int open(char *);
static int write(int, void *, size_t);
static int read(int, void *, size_t);

static void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);
static void munmap(void *addr);

static struct file *get_file(int fd);
static int set_file_to_nextfd(struct file *file);
static void validate_address(void *ptr);

static void fd_validate(int fd);
static bool mmap_validate(void *addr, size_t length, off_t);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f)
{
    struct thread *curr = thread_current();
    struct thread *child;
    enum intr_level intr;

    char *tn, *fn;
    unsigned size, position;
    int pid, status, fd, fret, ret, nd;
    struct file *ff;

    curr->isp = f->rsp;
    int sysnum = f->R.rax;
    printf("sysnum: %d\n", sysnum);

    switch (sysnum)
    {
    case SYS_HALT:
        power_off();
        break;

    case SYS_EXIT:
        status = f->R.rdi;
        exit(status);

        break;
    case SYS_FORK:
        f->R.rax = fork(f->R.rdi, f);
        break;

    case SYS_EXEC:
        exec(f->R.rdi);
        break;

    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);
        break;

    case SYS_CREATE:
        fn = f->R.rdi;
        size = f->R.rsi;

        validate_address(fn);

        lock_acquire(&filesys_lock);
        fret = filesys_create(fn, (off_t)size);
        lock_release(&filesys_lock);

        f->R.rax = fret;
        break;

    case SYS_REMOVE:
        fn = f->R.rdi;

        validate_address(fn);

        lock_acquire(&filesys_lock);
        fret = filesys_remove(fn);

        lock_release(&filesys_lock);

        f->R.rax = fret;
        break;

    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;

    case SYS_FILESIZE:
        fd = f->R.rdi;
        fd_validate(fd);

        lock_acquire(&filesys_lock);
        ff = get_file(fd);
        fret = ff == NULL ? -1 : (int)file_length(ff);

        lock_release(&filesys_lock);

        f->R.rax = fret;
        break;

    case SYS_READ:
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_SEEK:
        fd = f->R.rdi;
        position = f->R.rsi;

        fd_validate(fd);
        file_seek(get_file(fd), position);
        break;

    case SYS_TELL:
        fd = f->R.rdi;

        position = file_tell(get_file(fd));
        f->R.rax = position;
        break;

    case SYS_CLOSE:
        fd = f->R.rdi;

        ff = get_file(fd);
        *(curr->fdt + fd) = NULL;
        file_close(ff);
        break;

    case SYS_MMAP:
        f->R.rax = (uint64_t)mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
        break;

    case SYS_MUNMAP:
        munmap(f->R.rdi);

    default:
        break;
    }

    do_iret(f);
}

static int fork(char *name, struct intr_frame *if_)
{
    validate_address(name);

    struct thread *child;
    int pid;

    // 자식 id 반환
    pid = process_fork(name, if_);
    if (pid != TID_ERROR)
    {
        child = find_child_by_id(pid);
        sema_down(&child->create_wait);
        pid = child->exit == TID_ERROR ? TID_ERROR : pid;
    }

    return pid;
}

static void exec(const char *cmd_line)
{
    validate_address(cmd_line);

    // page 를 만들어야 하나?
    char *exec_cmd = palloc_get_page(0);
    if (exec_cmd == NULL)
        exit(-1);
    strlcpy(exec_cmd, cmd_line, PGSIZE);
    process_exec(exec_cmd);
    exit(-1);
}

static int wait(tid_t tid)
{
    return process_wait(tid);
}

static int open(char *name)
{
    validate_address(name);

    struct file *file;
    int nextfd;
    // char *filename = allocate_name_page(name);

    lock_acquire(&filesys_lock);

    file = filesys_open(name);
    if (file == NULL)
        nextfd = -1;
    else
    {
        nextfd = set_file_to_nextfd(file);
        if (nextfd == -1)
            file_close(file);
    }

    lock_release(&filesys_lock);

    return nextfd;
}
static int write(int fd, void *buffer, size_t size)
{
    fd_validate(fd);
    validate_address(buffer);

    int ret;

    if (fd == 0)
        exit(-1);
    else if (fd == 1)
    {
        putbuf(buffer, size);
        ret = size;
    }
    else
    {
        lock_acquire(&filesys_lock);
        ret = (int)file_write(get_file(fd), buffer, size);
        lock_release(&filesys_lock);
    }
    return ret;
}

static int read(int fd, void *buffer, size_t size)
{
    fd_validate(fd);
    validate_address(buffer);
    // buffer 페이지에 대해서 읽기만 있으면 안된다.
#ifdef VM

    // 진짜 중요: spt find page 에서 va 로 찾을 때 va 는 페이지 단위여야 한다.
    // 꼭 명심하도록 하자!!!

    struct page *page = spt_find_page(&thread_current()->spt, pg_round_down(buffer));
    if (page == NULL || !page->rw)
        exit(-1);
    // 페이지가 존재하지만 스택영역 + 그중에서도 sp 보다 더 작다? 그러면 안된다!
    uintptr_t isp = thread_current()->isp;
    if (page->va == pg_round_down(isp) && buffer < isp)
        exit(-1);
#endif

    int ret;

    if (fd == 0)
        ret = (int)input_getc();
    else if (fd == 1) // could not read
        ret = -1;
    else
    {
        lock_acquire(&filesys_lock);
        ret = (int)file_read(get_file(fd), buffer, size);
        lock_release(&filesys_lock);
    }

    return ret;
}

static void *mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
    fd_validate(fd);
    if (!mmap_validate(addr, length, offset))
        return NULL;
    // validate_address(addr);

    struct thread *curr = thread_current();
    struct file *file = get_file(fd);

    if (file == NULL)
        return NULL;

    off_t filelength = file_length(file);

    if (length > filelength)
        length = filelength;

    if (offset > length)
        return NULL;
    void *ret = do_mmap(addr, length, writable, file, offset);
    // printf("ret: %p\n", ret);
    return ret;
}
static void munmap(void *addr)
{
    validate_address(addr);
    // addr 가 PGSIZE 배수가 아니면 또 에러
    if (((uint64_t)addr % PGSIZE) != 0)
        exit(-1);

    struct mmap_file *mf = find_mmfile(addr);
    if (mf == NULL)
        exit(-1);

    do_munmap(addr);
}

static struct file *
get_file(int fd)
{
    if (fd < 2 || fd >= FDT_MAX_COUNT)
        exit(-1);
    struct file *file = *(thread_current()->fdt + fd);
    if (file == NULL)
        exit(-1);
    return file;
}

static int
set_file_to_nextfd(struct file *file)
{
    struct thread *curr = thread_current();
    int next_fd = curr->next_fd;
    for (int i = 0; i < FDT_MAX_COUNT; ++i)
    {
        next_fd = (next_fd + 1) % FDT_MAX_COUNT;
        if (next_fd > 2 && *(curr->fdt + next_fd) == NULL)
        {
            *(curr->fdt + next_fd) = file;
            curr->next_fd = next_fd;
            return next_fd;
        }
    }
    return -1;
}

static void validate_address(void *ptr)
{
    if (ptr == NULL || !is_user_vaddr((uint64_t)ptr))
    {
        exit(-1);
    }
}

static void fd_validate(int fd)
{
    if (fd < 0 || fd >= 128)
    {
        exit(-1);
    }
}

static bool mmap_validate(void *addr, size_t length, off_t offset)
{
    if (addr == NULL || ((uint64_t)addr % PGSIZE))
        return false;

    if (spt_find_page(&thread_current()->spt, addr))
    {
        // printf("실패\n");
        return false;
    }

    if (!is_user_vaddr((uint64_t)addr) || !is_user_vaddr(addr + length))
        return false;

    if ((int)length <= 0)
        return false;

    if (offset > length)
        return NULL;

    return true;
}
