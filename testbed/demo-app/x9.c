/*
 * x9.c - HARMLESS test payload for the PROVBIND demo (SF9-26, SIIT). NOT malware.
 *
 * It is the run-time payload the test package requestz-helper drops and executes in scenario
 * attack-1 (Test Plan §7). Its whole purpose is to give PROVBIND's runtime verifier two things
 * to catch and to give Falco something to compare against:
 *
 *   1. an EXEC of a file (/tmp/.x9) that is in no layer of the attested image  -> D_exec undeclared
 *   2. a WRITE to a declared file (/etc/passwd)                                -> D_write
 *
 * Safety:
 *   - It runs ONLY inside the throwaway demo container, never on a real host.
 *   - The line it appends uses /bin/false as the login shell, so it creates no usable account.
 *   - It performs no network, no privilege change, nothing destructive; then it just sleeps.
 *
 * Build it statically so it runs on any base image (see gen_payload.sh):
 *   gcc -static -Os -s -o x9 x9.c
 */
#include <stdio.h>
#include <unistd.h>

/* An inert marker line. /bin/false as the shell means the "account" can never log in. */
static const char *MARKER = "provbind-test:x:0:0::/:/bin/false\n";

int main(void) {
    FILE *f = fopen("/etc/passwd", "a");   /* the declared-file write PROVBIND should flag */
    if (f) {
        fputs(MARKER, f);
        fclose(f);
    }
    /* Stay alive so the demo can show the process and its provenance, then exit on its own. */
    sleep(600);
    return 0;
}
