//
// Created by qtfreet on 2016/11/24.
//

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include "Utils.h"

int getProcessName(unsigned char *buffer) {
    char path_t[256] = {0};
    pid_t pid = getpid();
    memset(path_t, 0, sizeof(path_t));
    sprintf(path_t, "/proc/%d/cmdline", pid);
    int fd_t = open(path_t, O_RDONLY);
    if (fd_t > 0) {
        int read_count = read(fd_t, buffer, 1024);

        if (read_count > 0) {
            int processIndex = 0;
            for (processIndex = 0; processIndex < strlen((const char *) buffer); processIndex++) {
                if (buffer[processIndex] == ':') {
                    buffer[processIndex] = '_';
                }
            }
            return 1;
        }
    }
    return 0;
}


void *get_module_base(pid_t pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];
    if (pid < 0) {
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }
    fp = fopen(filename, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    return (void *) addr;
}