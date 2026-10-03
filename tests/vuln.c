/* Deliberately vulnerable test binary for pwn_triage/bindiff verification. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() { system("/bin/sh"); }           /* ret2win target */

void vuln() {
    char buf[64];
    puts("name? ");
    gets(buf);                               /* classic stack overflow */
    printf(buf);                             /* format string too */
}

int main() {
    setvbuf(stdout, NULL, 0, 0);
    vuln();
    return 0;
}
