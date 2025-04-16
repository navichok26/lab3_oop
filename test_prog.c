#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <errno.h>
#include <string.h>


volatile sig_atomic_t running = 1;

int check_debugger() {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        if (errno == EPERM) {
            return 1;
        }
    } else {
        ptrace(PTRACE_DETACH, 0, 0, 0);
    }

    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                printf("TracerPid: %s", line + 10);
                int tracer_pid = atoi(line + 10);
                if (tracer_pid != 0) {
                    fclose(f);
                    return 1;
                }
                break;
            }
        }
        fclose(f);
    }
    
    return 0;
}

void anti_debug_check() {
    static time_t last_check = 0;
    time_t now = time(NULL);
    
    if (now - last_check >= 2) {
        last_check = now;
        
        if (check_debugger()) {
            printf("\n!!! Обнаружена попытка отладки! Завершение работы !!!\n");
            fflush(stdout);
            exit(1);
        }
    }
}

void handle_signal(int sig) {
    printf("Получен сигнал: %d\n", sig);
    running = 0;
}

int main() {
    printf("PID программы: %d\n", getpid());

    prctl(PR_SET_DUMPABLE, 0);

    #ifdef PR_SET_PTRACER
    prctl(PR_SET_PTRACER, 0);
    #endif
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    int counter = 1;
    
    while (running) {
        anti_debug_check();
        printf("Текущее число: %d из 20\n", counter);
        fflush(stdout);
        
        sleep(1);
        
        counter++;
        if (counter > 20) {
            counter = 1;
            printf("--------- Начинаем новый цикл ---------\n");
        }
    }
    
    printf("Программа завершена\n");
    return 0;
}