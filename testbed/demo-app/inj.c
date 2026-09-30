/*
 * inj.c - HARMLESS shared library for the PROVBIND demo (SF9-26, SIIT). NOT malware.
 *
 * Scenario R-K3 (library injection, comparison test plan section 3) LD_PRELOADs this .so into
 * `python3 -c pass` (see testbed/demo-app/tier2.py, preload_injection). Its only purpose is to make
 * the loader map a shared library that is in no layer of the attested image, so PROVBIND reports
 * D_load undeclared, and to give the syscall trace a library-injection shape for the estimators.
 *
 * Safety:
 *   - Its constructor only appends one inert marker line to /tmp/.inj-marker and returns.
 *   - It performs no network, no privilege change, nothing destructive.
 *   - It runs ONLY inside the throwaway demo container, never on a real host.
 *
 * Build it as a shared object (see gen_payload.sh):
 *   gcc -shared -fPIC -Os -s -o inj.so inj.c
 */
#include <stdio.h>

__attribute__((constructor))
static void provbind_inj_init(void) {
    FILE *f = fopen("/tmp/.inj-marker", "a");
    if (f) {
        fputs("provbind-preload-test\n", f);
        fclose(f);
    }
}
