#include "antidebug.h"
#include <android/log.h>
#include <sys/syscall.h>
#include <sys/inotify.h>

#define CHECK_TIME 10
#define MAX 128
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "qtfreet00", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "qtfreet00", __VA_ARGS__)
#define WCHAN_ELSE 0;
#define WCHAN_RUNNING 1;
#define WCHAN_TRACING 2;

int getWchanStatus() {
    char *wchaninfo = new char[128];
    int result = WCHAN_ELSE;
    char *cmd = new char[128];
    pid_t pid = syscall(__NR_getpid);
    sprintf(cmd, "cat /proc/%d/wchan", pid);
    //LOGE("cmd= %s", cmd);
    if (cmd == NULL) {
        return WCHAN_ELSE;
    }
    FILE *ptr;
    if ((ptr = popen(cmd, "r")) != NULL) {
        if (fgets(wchaninfo, 128, ptr) != NULL) {
//            LOGE("wchaninfo= %s", wchaninfo);
        }
    }
    if (strncasecmp(wchaninfo, "sys_epoll\0", strlen("sys_epoll\0")) == 0) {
        result = WCHAN_RUNNING;
    }
    else if (strncasecmp(wchaninfo, "ptrace_stop\0", strlen("ptrace_stop\0")) == 0) {
        result = WCHAN_TRACING;
    }
    return result;
}

void AntiDebug() {
    // LOGE("Call inotify");
    pid_t ppid = syscall(__NR_getpid);
    char buf[1024];
    char readbuf[MAX];
    int wd, ret, len, i;
    int fd;
    fd_set readfds;
    //防止调试子进程
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    fd = inotify_init();
    sprintf(buf, "/proc/%d/maps", ppid);

    //wd = inotify_add_watch(fd, "/proc/self/mem", IN_ALL_EVENTS);
    wd = inotify_add_watch(fd, buf, IN_ALL_EVENTS);
    if (wd < 0) {
        // LOGD("can't watch %s", buf);
        return;
    }
    while (1) {
        i = 0;
        //注意要对fd_set进行初始化
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        //第一个参数固定要+1，第二个参数是读的fdset，第三个是写的fdset，最后一个是等待的时间
        //最后一个为NULL则为阻塞
        ret = select(fd + 1, &readfds, 0, 0, 0);
        if (ret == -1)
            break;
        if (ret) {
            len = read(fd, readbuf, MAX);
//            LOGE("come in!");

            while (i < len) {
                //   LOGE("comeeeeee i n ...");
                //返回的buf中可能存了多个inotify_event
                struct inotify_event *event = (struct inotify_event *) &readbuf[i];
                //  LOGE("event mask %d\n", (event->mask & IN_ACCESS) || (event->mask & IN_OPEN));
                //这里监控读和打开事件
                if ((event->mask & IN_ACCESS) || (event->mask & IN_OPEN)) {
                    //    LOGD("kill!!!!!\n");
                    //事件出现则杀死父进程
                    int ret = kill(ppid, SIGKILL);
                    //  LOGD("ret = %d", ret);
                    return;
                }
                i += sizeof(struct inotify_event) + event->len;
            }
        }
        sleep(CHECK_TIME);
    }
    inotify_rm_watch(fd, wd);
    close(fd);
}

void CalcTime(int res, int des) {
    int pid = getpid();
    if (des - res >= 2) {
        kill(pid, SIGKILL);
    } else {

    }


}

void readStatus() {
    FILE *fd;
    char filename[MAX];
    char line[MAX];
    pid_t pid = syscall(__NR_getpid);
    int ret = getWchanStatus();
    if (2 == ret) {
        kill(pid, SIGKILL);
    }
    sprintf(filename, "/proc/%d/status", pid);// 读取proc/pid/status中的TracerPid
    if (fork() == 0) {
        int pt;
        pt = ptrace(PTRACE_TRACEME, 0, 0, 0); //子进程反调试
        if (pt == -1)
            exit(0);
//        LOGE("jklasjkldjkldjaskjdlkas");
        while (1) {
            fd = fopen(filename, "r");
            while (fgets(line, MAX, fd)) {
                if (strncmp(line, "TracerPid", 9) == 0) {
                    int statue = atoi(&line[10]);
//                    LOGE("########## statue = %d,%s", statue, line);
                    fclose(fd);
                    syscall(__NR_close, fd);
                    if (statue != 0) {
                        // LOGE("########## here");
                        int ret = kill(pid, SIGKILL);
                        // LOGE("########## kill = %d", ret);
                        return;
                    }

                    break;
                }
            }
            sleep(CHECK_TIME);
        }
    } else {
//        LOGE("fork error");
    }
}


