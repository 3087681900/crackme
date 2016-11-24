//
// Created by qtfreet on 2016/11/24.
//

#ifndef CRACKME001_UTILS_H
#define CRACKME001_UTILS_H


extern int getProcessName(unsigned char *);

extern void *get_module_base(pid_t pid, const char *module_name);

#endif //CRACKME001_UTILS_H
