#include "antidebug.h"
#include <android/log.h>
#include <sys/syscall.h>
#include <sys/inotify.h>
#include<pthread.h>
#include<sys/prctl.h>
#include<sys/wait.h>

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
            LOGE("wchaninfo= %s", wchaninfo);
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


void CalcTime(int res, int des) {
    int pid = getpid();
    if (des - res >= 2) {
        kill(pid, SIGKILL);
    } else {

    }


}

void checkAndroidServer() {
    char szLines[1024] = {0};
    //监听23946端口
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (fp != NULL) {
        while (fgets(szLines, sizeof(szLines), fp)) {
            //23946端口
            if (strstr(szLines, "00000000:5D8A")) {
                kill(getpid(), SIGKILL);
                break;
            }
        }

        fclose(fp);
    }

    LOGE("no find android server");
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
        while (1) {
            checkAndroidServer();
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

int event_check(int fd) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    return select(FD_SETSIZE, &rfds, NULL, NULL, NULL);
}

int read_event(int fd) {
    char buffer[16384] = {0};
    size_t index = 0;
    struct inotify_event *ptr_event;

    ssize_t r = read(fd, buffer, 16384);
    if (r <= 0) {
        LOGE("read_event");
        return r;
    }

    while (index < r) {
        ptr_event = (struct inotify_event *) &buffer[index];
        LOGE("wd = %d mask = %d cookie = %d len = %d dir = %s\n",
             ptr_event->wd, ptr_event->mask, ptr_event->cookie, ptr_event->len,
             (ptr_event->mask & IN_ISDIR) ? "yes" : "no");
        if (ptr_event->len)
            LOGE("name = %s", ptr_event->name);
        index += sizeof(struct inotify_event) + ptr_event->len;
    }
    return 0;
}

void signal_handle(int sum) {
    LOGE("Task ============== Start");
}

void runInotify() {
    int keep_running = 1;

    if (signal(SIGINT, signal_handle) == SIG_IGN) {
        signal(SIGINT, SIG_IGN);

    }
    int fd;
    fd = inotify_init();//初始化
    if (fd == -1) { //错误处理
        LOGE("inotify_init error");
        switch (errno) {
            case EMFILE:
                LOGE("errno: EMFILE");
                break;
            case ENFILE:
                LOGE("errno: ENFILE");
                break;
            case ENOMEM:
                LOGE("errno: ENOMEM");
                break;
            default:
                LOGE("unkonw errno");

        }
        return;
    }
    int wd;
    wd = inotify_add_watch(fd, "/data/data/com.qtfreet.crackme001/lib", IN_ALL_EVENTS); //添加监视
    if (wd == -1) { //错误处理
        LOGE("inotify_add_watch");
        switch (errno) {
            case EACCES:
                LOGE("errno: EACCES");
                break;
            case EBADF:
                LOGE("errno: EBADF");
                break;
            case EFAULT:
                LOGE("errno: EFAULT");
                break;
            case EINVAL:
                LOGE("errno: EINVAL");
                break;
            case ENOMEM:
                LOGE("errno: ENOMEM");
                break;
            case ENOSPC:
                LOGE("errno: ENOSPC");
                break;
            default:
                LOGE("unkonw errno");
        }
        return;
    }

    while (keep_running) {
        if (event_check(fd) > 0) {
            read_event(fd);
        }
    }
    return;
}
//以下方法暂不清楚如何利用


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
            LOGE("come in!");

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

int gpipe[2];

void *parent_read_thread(void *param) {
    LOGD("wait for child process to write decode data");
    int readPipe = gpipe[0];
    read(readPipe, 0, 0x10);
    close(readPipe);
    return 0;
}

void *child_attach_thread(void *param) {
    int pid = *(int *) param;
    LOGD("check child status %d", pid);
    safe_attach(pid);
    handle_events();
    LOGE("watch thread exit");

    kill(getpid(), 9);
}


int checkDebugger() {
// use Multi process to protect itself
    int forktime = 0;

    FORKLABEL:
    forktime++;
    if (forktime > 5) {
        return 0;
    }

    if (pipe(gpipe)) {
        return 0;
    }
    int pid = fork();
    prctl(PR_SET_DUMPABLE, 1);

    if (pid != 0) {
        // parent
        close(gpipe[1]);
        LOGD("start new thread to read decode data");
        pthread_t ntid;
        pthread_create(&ntid, NULL, parent_read_thread, &pid);
        bool flag = false;
        do {
            int childstatus;
            int childpid = waitpid(pid, &childstatus, WNOHANG);
            bool succ = childpid == 0;
            if (childpid > 0) {
                succ = childstatus == 1;
                LOGD("Child process end!");
            }
            if (!succ) {
                kill(pid, 9);
                goto FORKLABEL;
            }
            flag = true;
        } while (!flag);
    } else {
        // child
        // Write key to pipe
        int cpid = getppid();
        safe_attach(cpid);
        LOGD("child process Attach success, try to write data");

        close(gpipe[0]);
        int writepipe = gpipe[1];

        char tflag[0x10 + 1] = {
                0x4A, 0x75, 0x73, 0x74, 0x48, 0x61, 0x76, 0x65,
                0x41, 0x54, 0x72, 0x79, 0x21, 0x21, 0x21, 0x21
        };

        write(writepipe, tflag, 0x10);
        close(writepipe);
        handle_events();
        exit(EXIT_FAILURE);

    }
    return 0;
}

bool may_cause_group_stop(int signo) {
    switch (signo) {
        case SIGSTOP:
        case SIGTSTP:
        case SIGTTIN:
        case SIGTTOU:
            return true;
            break;
        default:
            break;
    }

    return false;
}

void handle_events() {
    int status = 0;
    pid_t pid = 0;

    do {
        pid = TEMP_FAILURE_RETRY(waitpid(-1, &status, __WALL));
        if (pid < 0) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }

        if (WIFEXITED(status)) {
            LOGE("%d exited, status=%d\n", pid, WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status)) {
            LOGE("%d killed by signal %d\n", pid, WTERMSIG(status));
        }
        else if (WIFSTOPPED(status)) {
            int signo = WSTOPSIG(status);
            LOGE("%d stopped by signal %d\n", pid, signo);

            if (may_cause_group_stop(signo)) {
                signo = 0;
            }

            long err = ptrace(PTRACE_CONT, pid, NULL, signo);
            if (err < 0) {
                perror("PTRACE_CONT");
                exit(EXIT_FAILURE);
            }
        }

    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

}

void safe_attach(pid_t pid) {
    long err = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if (err < 0) {
        LOGE("PTRACE_ATTACH");
        exit(EXIT_FAILURE);
    }

    int status = 0;
    err = TEMP_FAILURE_RETRY(waitpid(pid, &status, __WALL));
    if (err < 0) {
        LOGE("waitpid");
        exit(EXIT_FAILURE);
    }

    if (WIFEXITED(status)) {
        LOGE("%d exited, status=%d\n", pid, WEXITSTATUS(status));
        exit(EXIT_SUCCESS);
    }
    else if (WIFSIGNALED(status)) {
        LOGE("%d killed by signal %d\n", pid, WTERMSIG(status));
        exit(EXIT_SUCCESS);
    }
    else if (WIFSTOPPED(status)) {
        int signo = WSTOPSIG(status);
        LOGE("%d stopped by signal %d\n", pid, signo);

        if (may_cause_group_stop(signo)) {
            signo = 0;
        }

        err = ptrace(PTRACE_CONT, pid, NULL, signo);
        if (err < 0) {
            LOGE("PTRACE_CONT");
            exit(EXIT_FAILURE);
        }
    }

    LOGD("Debugger: attached to process %d\n", pid);
}


