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

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* syscall handler function */
static int exec(const char *cmd_line);
static int wait(tid_t tid);
static struct file *get_file(int fd);
static void set_next_fd();
static void address_validate(void *ptr, void *lock);
static void fd_validate(int fd, void *lock);
static struct thread *find_child(int pid);

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
    int sysnum = f->R.rax;

    char *tn, *fn;
    unsigned size, position;
    int pid, status, fd, fret;
    struct file *ff;
    void *buffer;

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
        tn = f->R.rdi;
        address_validate(tn, NULL);

        // 자식 id 반환
        pid = process_fork(tn, f);
        child = find_child(pid);
        sema_down(&child->create_wait);
        f->R.rax = pid;
        break;

    case SYS_EXEC:
        fn = f->R.rdi;
        address_validate(fn, NULL);

        // page 를 만들어야 하나?
        char *exec_cmd = palloc_get_page(0);
        strlcpy(exec_cmd, fn, strlen(fn) + 1);
        exec(exec_cmd);
        exit(-1);
        break;
    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);

        break;

    case SYS_CREATE:
        lock_acquire(&filesys_lock);

        fn = f->R.rdi;
        address_validate(fn, &filesys_lock);

        size = f->R.rsi;
        fret = filesys_create(fn, (off_t)size);
        f->R.rax = fret;

        lock_release(&filesys_lock);
        break;

    case SYS_REMOVE:
        lock_acquire(&filesys_lock);

        fn = f->R.rdi;

        address_validate(fn, &filesys_lock);

        fret = filesys_remove(fn);
        f->R.rax = fret;

        lock_release(&filesys_lock);
        break;

    case SYS_OPEN:
        lock_acquire(&filesys_lock);

        fn = f->R.rdi;

        address_validate(fn, &filesys_lock);
        // printf("file name :%s start open\n", fn);
        ff = filesys_open(fn);
        if (ff == NULL)
            f->R.rax = -1;
        else
        {
            set_next_fd();
            *(curr->fdt + curr->next_fd) = ff;
            f->R.rax = curr->next_fd;
        }

        lock_release(&filesys_lock);
        break;

    case SYS_FILESIZE:
        lock_acquire(&filesys_lock);

        fd = f->R.rdi;
        // fd 를 사용해서 파일 탐색
        ff = get_file(fd);
        fret = (int)file_length(ff);
        f->R.rax = fret;

        lock_release(&filesys_lock);
        break;

    case SYS_READ:
        lock_acquire(&filesys_lock);

        fd = f->R.rdi;
        buffer = (void *)f->R.rsi;
        size = (unsigned)f->R.rdx;

        fd_validate(fd, &filesys_lock);
        address_validate(buffer, NULL);

        if (fd == 0)
            fret = (int)input_getc();
        else if (fd == 1) // could not read
            fret = -1;
        else
            fret = (int)file_read(get_file(fd), buffer, size);

        f->R.rax = fret; // read bytes?
        lock_release(&filesys_lock);
        break;

    case SYS_WRITE:
        lock_acquire(&filesys_lock);

        fd = f->R.rdi;
        buffer = (void *)f->R.rsi;
        size = (unsigned)f->R.rdx;

        fd_validate(fd, &filesys_lock);
        address_validate(buffer, NULL);

        if (fd == 0)
            exit(-1);
        else if (fd == 1)
        {
            putbuf(buffer, size);
            fret = size;
        }
        else
            fret = (int)file_write(get_file(fd), buffer, size);
        f->R.rax = fret; // write bytes?

        lock_release(&filesys_lock);
        break;

    case SYS_SEEK:
        lock_acquire(&filesys_lock);

        fd = f->R.rdi;
        position = (unsigned)f->R.rsi;

        fd_validate(fd, &filesys_lock);

        file_seek(get_file(fd), position);

        lock_release(&filesys_lock);
        break;

    case SYS_TELL:
        lock_acquire(&filesys_lock);

        fd = f->R.rdi;
        position = file_tell(get_file(fd));
        f->R.rax = position;

        lock_release(&filesys_lock);
        break;

    case SYS_CLOSE:
        lock_acquire(&filesys_lock);

        fd = f->R.rdi;
        ff = get_file(fd);
        if (ff == NULL)
            exit(-1);

        // fd 삭제 방식
        *(curr->fdt + fd) = NULL;
        file_close(ff);

        // how to free ff?
        lock_release(&filesys_lock);
        break;

    default:
        break;
    }

    do_iret(f);
}

static int exec(const char *cmd_line)
{
    return process_exec(cmd_line);
}

static int wait(tid_t tid)
{
    return process_wait(tid);
}

static struct file *
get_file(int fd)
{
    if (fd >= 128)
        return NULL;
    struct thread *curr = thread_current();
    struct file *file = file = *(curr->fdt + fd);
    return file;
}

static void
set_next_fd()
{
    struct thread *curr = thread_current();
    int next_fd = curr->next_fd;
    for (int i = 0; i < 128; ++i)
    {
        next_fd = (next_fd + 1) % 128;
        if (next_fd > 2 && *(curr->fdt + next_fd) == NULL)
        {
            curr->next_fd = next_fd;
            return;
        }
    }
    return -1;
}

static void address_validate(void *ptr, void *lock)
{
    if (ptr == NULL || !is_user_vaddr((uint64_t)ptr) || pml4_get_page(thread_current()->pml4, ptr) == NULL)
    {
        if (lock != NULL)
            lock_release(((struct lock *)lock));
        exit(-1);
    }
}

static void fd_validate(int fd, void *lock)
{
    if (fd < 0 || fd >= 128)
    {
        if (lock != NULL)
            lock_release(((struct lock *)lock));
        exit(-1);
    }
}

static struct thread *find_child(int pid)
{
    struct thread *curr = thread_current();
    struct list *children = &(curr->children);
    for (struct list_elem *p = list_begin(children); p != list_end(children); p = list_next(p))
    {
        struct thread *entry = list_entry(p, struct thread, c_elem);
        if (entry->tid == pid)
            return entry;
    }
    return NULL;
}