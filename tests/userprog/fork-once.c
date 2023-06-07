/* Forks and waits for a single child process. */

#include "tests/lib.h"
#include "tests/main.h"
#include <stdio.h>
#include <syscall.h>

void test_main(void)
{
    int pid;

    if ((pid = fork("child")))
    {
        int status = wait(pid);
        msg("Parent: child exit status is %d", status);
    }
    else
    {
        msg("child run");
        exit(81);
    }
}
