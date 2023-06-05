#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

#include "threads/init.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* syscall handler function */
static int exec(const char *cmd_line);
static int wait(tid_t tid);
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
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
    printf("system call!\n");
    // TODO: Your implementation goes here.
    // int sysnum = f->R.rax;
    // switch (sysnum)
    // {
    // case SYS_HALT:
    //     power_off();
    //     break;
    // case SYS_EXIT:
    //     process_exit();
    //     // exit 상태?

    //     break;

    // case SYS_EXEC:
    //     f->R.rax = exec(f->R.rdi);

    //     break;
    // case SYS_WAIT:
    //     f->R.rax = wait(f->R.rdi);

    //     break;
    // default:
    //     break;
    // }

    // do_iret ???????????????????/

    thread_exit();
}

static int exec(const char *cmd_line)
{
    return process_exec(cmd_line);
}

static int wait(tid_t tid)
{
    return process_wait(tid);
}
