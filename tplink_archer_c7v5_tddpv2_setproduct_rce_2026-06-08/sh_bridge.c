#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void log_argv(int argc, char **argv) {
    FILE *fp = fopen("/tmp/sh_bridge_argv.log", "a");
    if (!fp) {
        return;
    }
    fprintf(fp, "argc=%d\n", argc);
    for (int i = 0; i < argc; i++) {
        fprintf(fp, "argv[%d]=%s\n", i, argv[i] ? argv[i] : "(null)");
    }
    fclose(fp);
}

int main(int argc, char **argv, char **envp) {
    log_argv(argc, argv);

    char **next = calloc((size_t)argc + 5, sizeof(char *));
    if (!next) {
        perror("calloc");
        return 127;
    }

    int n = 0;
    next[n++] = "/usr/bin/qemu-mips-static";
    next[n++] = "-L";
    next[n++] = "/";
    next[n++] = "/bin/busybox";
    next[n++] = "sh";
    for (int i = 1; i < argc; i++) {
        next[n++] = argv[i];
    }
    next[n] = NULL;

    execve(next[0], next, envp);
    perror("execve qemu-mips-static busybox sh");
    return 127;
}
